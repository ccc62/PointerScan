#pragma once

// Compact, sorted cache format for very large text pointer-chain files.
// Format: 16-byte magic header, then repeated [uint32_le length][key bytes].
// Records are normalized, sorted and deduplicated. This format is intentionally
// separate from the project's native tree-based .bin format.

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <queue>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace chainer { namespace keybin {

static constexpr char kMagic[16] = {'N','S','K','E','Y','B','I','N','1','\0','\0','\0','\0','\0','\0','\0'};
static constexpr char kSep = '\x1f';
static constexpr size_t kMiB = 1024ULL * 1024ULL;

inline void write_u32(FILE *f, uint32_t v) {
  unsigned char b[4] = {static_cast<unsigned char>(v), static_cast<unsigned char>(v >> 8),
                        static_cast<unsigned char>(v >> 16), static_cast<unsigned char>(v >> 24)};
  if (std::fwrite(b, 1, 4, f) != 4) throw std::runtime_error("写入紧凑二进制记录失败，可能磁盘空间不足");
}
inline bool read_u32(FILE *f, uint32_t &v) {
  unsigned char b[4];
  size_t n = std::fread(b, 1, 4, f);
  if (n == 0 && std::feof(f)) return false;
  if (n != 4) throw std::runtime_error("紧凑二进制文件记录长度损坏");
  v = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
      (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
  return true;
}
inline void write_record(FILE *f, const std::string &s) {
  if (s.empty() || s.size() > std::numeric_limits<uint32_t>::max())
    throw std::runtime_error("单条指针链长度超出紧凑二进制格式范围");
  write_u32(f, static_cast<uint32_t>(s.size()));
  if (std::fwrite(s.data(), 1, s.size(), f) != s.size())
    throw std::runtime_error("写入紧凑二进制记录失败，可能磁盘空间不足");
}
inline bool read_record(FILE *f, std::string &s) {
  uint32_t n = 0;
  if (!read_u32(f, n)) return false;
  if (n == 0 || n > 64U * 1024U * 1024U)
    throw std::runtime_error("紧凑二进制文件包含非法记录长度");
  s.resize(n);
  if (std::fread(&s[0], 1, n, f) != n) throw std::runtime_error("紧凑二进制文件记录不完整");
  return true;
}

inline bool make_key(const std::string &line, std::string &key) {
  static constexpr char hex[] = "0123456789ABCDEF";
  const char *p = line.c_str(), *end = p + line.size();
  while (p < end && std::isspace(static_cast<unsigned char>(*p))) ++p;
  if (p >= end) return false;
  const char *bracket = static_cast<const char *>(std::memchr(p, '[', static_cast<size_t>(end-p)));
  if (!bracket || bracket == p) return false;
  const char *is = bracket + 1; char *ie = nullptr;
  long index = std::strtol(is, &ie, 10);
  if (ie == is || ie >= end || *ie != ']') return false;
  key.clear(); key.reserve(static_cast<size_t>(bracket-p) + 64);
  key.append(p, static_cast<size_t>(bracket-p)); key.push_back(kSep);
  key.append(std::to_string(index)); key.push_back(kSep);
  p = ie + 1; size_t count = 0;
  while (p < end) {
    const char *plus = std::strstr(p, "+ 0x");
    if (!plus || plus >= end) break;
    const char *hs = plus + 4; if (hs >= end) break;
    char *he = nullptr; errno = 0;
    unsigned long long value = std::strtoull(hs, &he, 16);
    if (he == hs || he > end || errno == ERANGE) break;
    if (count++) key.push_back(',');
    // This project is built for ARM64 in the intended Android configuration.
    // Store offsets as 16 hex digits, matching ccompare<size_t>'s key format.
    const size_t width = sizeof(size_t) * 2;
    size_t start = key.size(); key.resize(start + width, '0');
    for (size_t i = 0; i < width; ++i) { key[start + width - 1 - i] = hex[value & 0xFULL]; value >>= 4; }
    p = he;
  }
  return count != 0;
}

inline std::string make_temp(const std::string &near_path) {
  std::string pattern = near_path + ".tmp.XXXXXX";
  std::vector<char> buf(pattern.begin(), pattern.end()); buf.push_back('\0');
  int fd = mkstemp(buf.data());
  if (fd < 0) throw std::runtime_error("无法创建临时文件：请检查输出目录权限和剩余空间");
  close(fd); return std::string(buf.data());
}
struct TempFiles {
  std::vector<std::string> paths;
  ~TempFiles() { for (const auto &p : paths) std::remove(p.c_str()); }
  std::string create(const std::string &near_path) { auto p = make_temp(near_path); paths.push_back(p); return p; }
  void forget_and_remove(const std::string &p) { std::remove(p.c_str()); }
};

inline size_t rss_mb() {
  FILE *f = std::fopen("/proc/self/status", "r"); if (!f) return 0;
  char line[256]; size_t result = 0;
  while (std::fgets(line, sizeof(line), f)) if (std::strncmp(line, "VmRSS:", 6) == 0) { unsigned long long kb=0; if (std::sscanf(line+6,"%llu",&kb)==1) result=static_cast<size_t>(kb/1024); break; }
  std::fclose(f); return result;
}
inline size_t available_mb() {
  FILE *f = std::fopen("/proc/meminfo", "r"); if (!f) return 0;
  char line[256]; size_t result = 0;
  while (std::fgets(line, sizeof(line), f)) if (std::strncmp(line, "MemAvailable:", 13) == 0) { unsigned long long kb=0; if (std::sscanf(line+13,"%llu",&kb)==1) result=static_cast<size_t>(kb/1024); break; }
  std::fclose(f); return result;
}

inline void write_run(const std::string &path, const std::vector<std::string> &keys) {
  FILE *f = std::fopen(path.c_str(), "wb"); if (!f) throw std::runtime_error("无法写入排序临时文件");
  try { for (const auto &k : keys) write_record(f, k); if (std::fclose(f)!=0) { f=nullptr; throw std::runtime_error("关闭排序临时文件失败"); } f=nullptr; }
  catch (...) { if (f) std::fclose(f); throw; }
}

inline void convert_text_to_sorted_keybin(const std::string &input, const std::string &output,
                                           size_t memory_mib=2048, size_t chunk_mib=128) {
  if (memory_mib == 0 || chunk_mib == 0) throw std::runtime_error("内存预算和工作块必须大于 0 MiB");
  if (input == output) throw std::runtime_error("输入和输出路径不能相同");
  struct stat in_st{}, out_st{};
  if (stat(input.c_str(), &in_st)==0 && stat(output.c_str(), &out_st)==0 && in_st.st_dev==out_st.st_dev && in_st.st_ino==out_st.st_ino)
    throw std::runtime_error("输入和输出指向同一个文件，拒绝覆盖源文件");
  std::ifstream in(input, std::ios::binary); if (!in) throw std::runtime_error("无法打开文本文件："+input);
  const size_t budget = memory_mib > std::numeric_limits<size_t>::max()/kMiB ? std::numeric_limits<size_t>::max() : memory_mib*kMiB;
  // Leave headroom for string allocator overhead, sorting, I/O buffers and the rest of Android.
  size_t target = std::min(chunk_mib > std::numeric_limits<size_t>::max()/kMiB ? budget : chunk_mib*kMiB,
                           std::max<size_t>(8*kMiB, budget/8));
  target = std::min(target, budget);
  size_t avail = available_mb();
  if (avail > 0) target = std::min(target, std::max<size_t>(8*kMiB, (avail*kMiB)/5));
  target = std::min(budget, target);
  std::printf("[转换] 内存预算 %zu MiB，工作块目标约 %zu MiB（非 RSS 硬上限）\n", memory_mib, target/kMiB);
  std::printf("[内存] 初始 RSS %zu MiB，可用内存 %zu MiB\n", rss_mb(), available_mb());

  TempFiles temps; std::vector<std::string> runs; std::vector<std::string> chunk;
  chunk.reserve(4096); size_t estimate=0, total=0, skipped=0; std::string line;
  auto flush = [&]() {
    if (chunk.empty()) return;
    std::sort(chunk.begin(), chunk.end());
    chunk.erase(std::unique(chunk.begin(), chunk.end()), chunk.end());
    std::string p = temps.create(output); write_run(p, chunk); runs.push_back(p);
    // The run is now on disk; release string allocations rather than retaining capacity.
    std::vector<std::string>().swap(chunk); chunk.reserve(4096); estimate=0;
    if ((runs.size() % 16)==0) { std::printf("\r[转换] 已生成 %zu 个排序块，解析 %zu 条有效链，RSS %zu MiB   ", runs.size(), total, rss_mb()); std::fflush(stdout); }
  };
  size_t checks=0; auto last=std::chrono::steady_clock::now();
  while (std::getline(in,line)) {
    std::string key;
    if (make_key(line,key)) { estimate += key.size()+sizeof(std::string)+64; chunk.emplace_back(std::move(key)); ++total; if (estimate >= target) flush(); }
    else if (!line.empty()) ++skipped;
    if ((++checks & 4095U)==0) {
      size_t av=available_mb(), rss=rss_mb();
      if ((av>0 && av<1024) || (rss>0 && rss>=memory_mib/2)) {
        if (!chunk.empty()) flush();
        target=std::min(target, 8*kMiB);
        std::printf("\n[内存保护] 检测到压力，后续工作块降至最多 8 MiB；RSS %zu MiB，可用 %zu MiB\n",rss,av);
      }
    }
    auto now=std::chrono::steady_clock::now();
    if (now-last>=std::chrono::seconds(5)) { std::printf("\r[转换] 已解析 %zu 条有效链，排序块 %zu，RSS %zu MiB   ",total,runs.size(),rss_mb()); std::fflush(stdout); last=now; }
  }
  if (in.bad()) throw std::runtime_error("读取文本文件失败："+input);
  flush(); std::printf("\n[转换] 解析完成：有效链 %zu，格式不匹配行 %zu，初始块 %zu\n",total,skipped,runs.size());

  // Multi-pass external merge. Each temporary run is a sorted stream of length-prefixed keys.
  auto merge_group = [&](const std::vector<std::string> &group, const std::string &outpath) {
    std::vector<FILE*> fs; fs.reserve(group.size());
    struct Node { std::string key; size_t file; };
    auto cmp=[](const Node&a,const Node&b){return a.key>b.key;};
    std::priority_queue<Node,std::vector<Node>,decltype(cmp)> heap(cmp);
    try {
      for (size_t i=0;i<group.size();++i) { FILE *f=std::fopen(group[i].c_str(),"rb"); if(!f) throw std::runtime_error("无法读取排序临时文件"); fs.push_back(f); std::string k; if(read_record(f,k)) heap.push(Node{std::move(k),i}); }
      FILE *out=std::fopen(outpath.c_str(),"wb"); if(!out) throw std::runtime_error("无法创建归并临时文件");
      std::string prev; bool have=false;
      try { while(!heap.empty()) { Node n=heap.top();heap.pop(); if(!have||n.key!=prev){write_record(out,n.key);prev=n.key;have=true;} std::string k; if(read_record(fs[n.file],k))heap.push(Node{std::move(k),n.file}); }
        int close_rc = std::fclose(out); out = nullptr; if(close_rc!=0) throw std::runtime_error("归并写入失败"); }
      catch (...) { if(out) std::fclose(out); throw; }
      for(FILE*f:fs)std::fclose(f); fs.clear();
    } catch (...) { for(FILE*f:fs)std::fclose(f); throw; }
  };
  size_t fanin = 16; // Conservative FD and per-reader-buffer use on Android.
  size_t round=0;
  while (runs.size()>1) {
    ++round; std::vector<std::string> next; next.reserve((runs.size()+fanin-1)/fanin);
    std::printf("[转换归并] 第 %zu 轮：%zu 个块，扇入 %zu\n",round,runs.size(),fanin);
    for(size_t i=0;i<runs.size();) {
      size_t e=i+std::min(fanin,runs.size()-i);
      if(e-i==1) next.push_back(runs[i]);
      else { std::string p=temps.create(output); merge_group(std::vector<std::string>(runs.begin()+i,runs.begin()+e),p); next.push_back(p); for(size_t j=i;j<e;++j) temps.forget_and_remove(runs[j]); }
      i=e;
    }
    runs.swap(next);
  }

  std::string finaltmp=temps.create(output); FILE *out=std::fopen(finaltmp.c_str(),"wb");
  if(!out) throw std::runtime_error("无法创建最终紧凑二进制文件");
  try {
    if(std::fwrite(kMagic,1,sizeof(kMagic),out)!=sizeof(kMagic)) throw std::runtime_error("写入紧凑二进制文件头失败");
    if(!runs.empty()) { FILE *src=std::fopen(runs.front().c_str(),"rb"); if(!src) throw std::runtime_error("无法读取最终排序结果"); try { std::string k; while(read_record(src,k)) write_record(out,k); std::fclose(src); } catch (...) { std::fclose(src); throw; } }
    if(std::fclose(out)!=0) { out=nullptr; throw std::runtime_error("关闭紧凑二进制文件失败"); } out=nullptr;
  } catch (...) { if(out)std::fclose(out); throw; }
  if (std::rename(finaltmp.c_str(),output.c_str())!=0) throw std::runtime_error("无法将转换结果保存到目标路径（目标可能被占用或目录不可写）");
  temps.forget_and_remove(finaltmp);
  std::printf("[转换] 完成：%s；记录已排序并去重。后续可直接用紧凑二进制对比。\n",output.c_str());
}

inline bool open_keybin(FILE *f, const std::string &path) {
  char h[sizeof(kMagic)]; if(std::fread(h,1,sizeof(h),f)!=sizeof(h) || std::memcmp(h,kMagic,sizeof(h))!=0) throw std::runtime_error("不是 newscan 紧凑二进制缓存文件："+path);
  return true;
}
inline bool decode_key(const std::string &key, std::string &module, int &index, std::vector<unsigned long long> &offsets) {
  size_t a=key.find(kSep); if(a==std::string::npos)return false; size_t b=key.find(kSep,a+1); if(b==std::string::npos)return false;
  module.assign(key.data(),a); try { size_t used=0; index=std::stoi(key.substr(a+1,b-a-1),&used); if(used!=b-a-1)return false; } catch(...) {return false;}
  offsets.clear(); size_t p=b+1; while(p<key.size()){size_t e=key.find(',',p); std::string token=key.substr(p,e==std::string::npos?std::string::npos:e-p); if(token.empty())return false; try {size_t used=0; auto v=std::stoull(token,&used,16); if(used!=token.size())return false; offsets.push_back(v);}catch(...){return false;} if(e==std::string::npos)break;p=e+1;}
  return !offsets.empty();
}
inline size_t compare_keybin_files(const std::string &lhs_path,const std::string &rhs_path,FILE *report, size_t *lhs_unique=nullptr, size_t *rhs_unique=nullptr) {
  if(lhs_path==rhs_path) throw std::runtime_error("旧文件和新文件不能是同一个路径");
  FILE *l=std::fopen(lhs_path.c_str(),"rb"), *r=std::fopen(rhs_path.c_str(),"rb");
  if(!l||!r){if(l)std::fclose(l);if(r)std::fclose(r);throw std::runtime_error("无法打开紧凑二进制文件");}
  size_t common=0, lc=0, rc=0;
  try {
    open_keybin(l,lhs_path); open_keybin(r,rhs_path);
    std::string lk,rk; bool hl=read_record(l,lk),hr=read_record(r,rk); std::string last_module; int last_index=-1; std::vector<unsigned long long> offsets;
    while(hl&&hr){if(lk<rk){hl=read_record(l,lk);++lc;}else if(rk<lk){hr=read_record(r,rk);++rc;}else{++common;++lc;++rc;std::string module;int index=0;if(report&&decode_key(lk,module,index,offsets)){if(module!=last_module||index!=last_index){if(!last_module.empty())std::fputc('\n',report);std::fprintf(report,"模块: %s[%d]\n  保持不变的链:\n",module.c_str(),index);last_module=module;last_index=index;}std::fprintf(report,"    = %s[%d]",module.c_str(),index);for(size_t i=0;i<offsets.size();++i)std::fprintf(report,"%s0x%llX",i?" -> + ":" + ",offsets[i]);std::fputc('\n',report);}hl=read_record(l,lk);hr=read_record(r,rk);}}
    while(hl){++lc;hl=read_record(l,lk);}while(hr){++rc;hr=read_record(r,rk);}
    std::fclose(l);std::fclose(r); if(report)std::fflush(report);
  } catch(...) {std::fclose(l);std::fclose(r);throw;}
  if(lhs_unique) *lhs_unique=lc; if(rhs_unique) *rhs_unique=rc;
  std::printf("[紧凑二进制对比] 旧文件唯一链数 %zu，新文件唯一链数 %zu，共同链 %zu\n",lc,rc,common);
  return common;
}

}} // namespace chainer::keybin
