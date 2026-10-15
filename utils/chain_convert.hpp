#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace chain_convert {
static constexpr char kMagic[16] = {'N','S','C','H','A','I','N','L','I','S','T','1','\0','\0','\0','\0'};
inline bool is_chain_list_bin(const std::string &path) {
  FILE *f = std::fopen(path.c_str(), "rb");
  if (!f) throw std::runtime_error("无法打开输入文件：" + path);
  char magic[16]{}; size_t n = std::fread(magic, 1, sizeof(magic), f); std::fclose(f);
  return n == sizeof(magic) && std::memcmp(magic, kMagic, sizeof(magic)) == 0;
}
inline size_t text_to_bin(const std::string &src, const std::string &dst) {
  std::ifstream in(src, std::ios::binary);
  if (!in) throw std::runtime_error("无法打开文本文件：" + src);
  FILE *out = std::fopen(dst.c_str(), "wb");
  if (!out) throw std::runtime_error("无法创建二进制文件：" + dst);
  if (std::fwrite(kMagic, 1, sizeof(kMagic), out) != sizeof(kMagic)) { std::fclose(out); throw std::runtime_error("写入失败"); }
  size_t count = 0; std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    if (line.size() > 16 * 1024 * 1024) { std::fclose(out); throw std::runtime_error("文本行超过 16 MiB"); }
    uint32_t len = static_cast<uint32_t>(line.size());
    unsigned char b[4] = {static_cast<unsigned char>(len), static_cast<unsigned char>(len >> 8), static_cast<unsigned char>(len >> 16), static_cast<unsigned char>(len >> 24)};
    if (std::fwrite(b, 1, 4, out) != 4 || std::fwrite(line.data(), 1, line.size(), out) != line.size()) { std::fclose(out); throw std::runtime_error("写入失败"); }
    ++count;
  }
  bool ok = !in.bad();
  if (std::fclose(out) != 0 || !ok) throw std::runtime_error("文本转二进制时发生错误");
  return count;
}
inline size_t bin_to_text(const std::string &src, const std::string &dst) {
  FILE *in = std::fopen(src.c_str(), "rb");
  if (!in) throw std::runtime_error("无法打开二进制文件：" + src);
  char magic[16]{};
  if (std::fread(magic, 1, 16, in) != 16 || std::memcmp(magic, kMagic, 16) != 0) { std::fclose(in); throw std::runtime_error("不是本工具的链记录二进制文件；原生扫描器 .bin 文件需要使用原生格式转换器"); }
  FILE *out = std::fopen(dst.c_str(), "wb");
  if (!out) { std::fclose(in); throw std::runtime_error("无法创建文本文件：" + dst); }
  size_t count = 0;
  for (;;) {
    unsigned char b[4]; size_t n = std::fread(b, 1, 4, in);
    if (n == 0 && std::feof(in)) break;
    if (n != 4) { std::fclose(in); std::fclose(out); throw std::runtime_error("二进制记录长度不完整"); }
    uint32_t len = uint32_t(b[0]) | (uint32_t(b[1]) << 8) | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
    if (len == 0 || len > 16 * 1024 * 1024) { std::fclose(in); std::fclose(out); throw std::runtime_error("二进制记录长度无效"); }
    std::string line(len, '\0');
    if (std::fread(line.data(), 1, len, in) != len) { std::fclose(in); std::fclose(out); throw std::runtime_error("二进制记录内容不完整"); }
    if (std::fwrite(line.data(), 1, line.size(), out) != line.size() || std::fputc('\n', out) == EOF) { std::fclose(in); std::fclose(out); throw std::runtime_error("text output 写入失败"); }
    ++count;
  }
  std::fclose(in); if (std::fclose(out) != 0) throw std::runtime_error("关闭文本输出文件失败");
  return count;
}
}
