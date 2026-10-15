#pragma once

#include "ccompare.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>
#include <queue>
#include <iomanip>
#include <limits>
#include <cerrno>
#include <thread>

namespace chainer {

// ============ 二进制文件验证 ============

template <class T>
void ccompare<T>::validate_bin_file(FILE *file, const std::string &path) {
  if (file == nullptr) {
    throw std::runtime_error("无效的文件句柄: " + path);
  }

  if (fseek(file, 0, SEEK_SET) != 0) {
    throw std::runtime_error("无法定位到文件开头: " + path);
  }

  cprog_header header {};
  if (fread(&header, sizeof(header), 1, file) != 1) {
    throw std::runtime_error("文件过小或不是指针链二进制文件: " + path);
  }

  constexpr char kSignaturePrefix[] = ".bin from chainer";
  if (std::strncmp(header.sign, kSignaturePrefix,
                   sizeof(kSignaturePrefix) - 1) != 0) {
    throw std::runtime_error("检测到非指针链二进制文件: " + path);
  }

  if (header.module_count < 0 || header.level < 0 ||
      header.size != static_cast<int>(sizeof(T))) {
    throw std::runtime_error("指针链文件头字段非法: " + path);
  }

  struct stat st {};
  if (fstat(fileno(file), &st) != 0) {
    throw std::runtime_error("无法获取文件大小: " + path);
  }

  size_t min_size =
      sizeof(cprog_header) +
      static_cast<size_t>(header.module_count) * sizeof(cprog_sym<T>) +
      static_cast<size_t>(header.level) * sizeof(cprog_llen);
  if (static_cast<size_t>(st.st_size) < min_size) {
    throw std::runtime_error("指针链二进制文件损坏或不完整: " + path);
  }

  rewind(file);
}

// ============ 前缀和：O(N) 统计链数量 ============

template <class T>
auto ccompare<T>::build_prefix_sums(const cprog_chain_info<T> &info)
    -> prefix_sums_t {
  size_t level_count = info.contents.size();
  prefix_sums_t prefix_sums;
  prefix_sums.reserve(level_count);

  for (size_t k = 0; k < level_count; ++k) {
    auto &nodes = info.contents[k];
    size_t n = nodes.size();
    std::vector<uint64_t> prefix(n + 1, 0);

    if (k == 0) {
      // level 0: 每个节点 = 1 条链
      for (size_t i = 0; i < n; ++i) {
        prefix[i + 1] = prefix[i] + 1;
      }
    } else {
      // level k: 每个节点的链数 = prefix_sums[k-1][end] - prefix_sums[k-1][start]
      auto &prev = prefix_sums[k - 1];
      size_t prev_len = prev.size();
      for (size_t i = 0; i < n; ++i) {
        size_t start = std::min(static_cast<size_t>(nodes[i].start), prev_len - 1);
        size_t end = std::min(static_cast<size_t>(nodes[i].end), prev_len - 1);
        uint64_t node_chains = prev[end] - prev[start];
        prefix[i + 1] = prefix[i] + node_chains;
      }
    }

    prefix_sums.push_back(std::move(prefix));
  }

  return prefix_sums;
}

template <class T>
uint64_t ccompare<T>::chains_of(const prefix_sums_t &prefix,
                                 const cprog_data<T> &dir, int level) {
  if (level == 0) return 1;
  int child_level = level - 1;
  if (child_level < 0 ||
      static_cast<size_t>(child_level) >= prefix.size()) {
    return 0;
  }
  auto &prev = prefix[child_level];
  size_t prev_len = prev.size();
  size_t start = std::min(static_cast<size_t>(dir.start), prev_len - 1);
  size_t end = std::min(static_cast<size_t>(dir.end), prev_len - 1);
  return prev[end] - prev[start];
}

template <class T>
size_t ccompare<T>::count_chains_prefix_sum(const cprog_chain_info<T> &info,
                                             const char *label,
                                             prefix_sums_t &out_prefix) {
  out_prefix = build_prefix_sums(info);

  uint64_t total = 0;
  for (size_t idx = 0; idx < info.syms.size(); ++idx) {
    auto &sym = info.syms[idx];
    if (sym.sym == nullptr || sym.data.size() == 0) continue;
    int level = sym.sym->level;
    uint64_t sym_count = 0;
    for (size_t i = 0; i < sym.data.size(); ++i) {
      sym_count += chains_of(out_prefix, sym.data[i], level);
    }
    if (sym_count > 0) {
      printf("  [%s] [%zu/%zu] %s[%d]: %llu 条链\n",
             label, idx + 1, info.syms.size(),
             sym.sym->name, sym.sym->count,
             static_cast<unsigned long long>(sym_count));
    }
    total += sym_count;
  }

  return static_cast<size_t>(total);
}

// ============ 将匹配链写入文件 ============

template <class T>
void ccompare<T>::emit_chain_line(FILE *f, const char *module_name,
                                   int module_index,
                                   const std::vector<T> &path) {
  if (f == nullptr || path.empty()) return;
  fprintf(f, "    = %s[%d]", module_name, module_index);
  for (size_t i = 0; i < path.size(); ++i) {
    fprintf(f, "%s 0x%lX", (i == 0 ? " + " : " -> + "),
            static_cast<unsigned long>(path[i]));
  }
  fputc('\n', f);
}

// ============ 树上递归匹配子树（双指针归并 + 前缀和剪枝 + level 1 快速路径） ============

template <class T>
size_t ccompare<T>::match_subtrees(
    const cprog_chain_info<T> &lhs_info,
    const cprog_chain_info<T> &rhs_info,
    const prefix_sums_t &lhs_prefix,
    const prefix_sums_t &rhs_prefix,
    const cprog_data<T> &lhs_dir,
    const cprog_data<T> &rhs_dir,
    int level,
    std::vector<T> &path,
    const char *module_name, int module_index,
    FILE *report,
    match_progress &progress)
{
  if (level == 0) {
    if (report != nullptr) {
      emit_chain_line(report, module_name, module_index, path);
    }
    return 1;
  }

  int child_level = level - 1;
  if (child_level < 0 ||
      static_cast<size_t>(child_level) >= lhs_info.contents.size() ||
      static_cast<size_t>(child_level) >= rhs_info.contents.size()) {
    return 0;
  }

  auto &lhs_children = lhs_info.contents[child_level];
  auto &rhs_children = rhs_info.contents[child_level];

  uint32_t lhs_start = lhs_dir.start;
  uint32_t lhs_end = std::min(lhs_dir.end, static_cast<uint32_t>(lhs_children.size()));
  uint32_t rhs_start = rhs_dir.start;
  uint32_t rhs_end = std::min(rhs_dir.end, static_cast<uint32_t>(rhs_children.size()));

  // level == 1 快速路径：子节点是叶子，直接计数，避免逐个递归到 level 0
  if (level == 1) {
    uint32_t li = lhs_start, ri = rhs_start;
    size_t count = 0;

    while (li < lhs_end && ri < rhs_end) {
      T lhs_off = lhs_children[li].address - lhs_dir.value;
      T rhs_off = rhs_children[ri].address - rhs_dir.value;

      if (lhs_off < rhs_off) {
        ++li;
      } else if (lhs_off > rhs_off) {
        ++ri;
      } else {
        // 找出两侧重复节点的范围
        uint32_t lhs_dup_end = li + 1;
        while (lhs_dup_end < lhs_end &&
               lhs_children[lhs_dup_end].address - lhs_dir.value == lhs_off) {
          ++lhs_dup_end;
        }
        uint32_t rhs_dup_end = ri + 1;
        while (rhs_dup_end < rhs_end &&
               rhs_children[rhs_dup_end].address - rhs_dir.value == lhs_off) {
          ++rhs_dup_end;
        }

        size_t pairs = static_cast<size_t>(lhs_dup_end - li) *
                       static_cast<size_t>(rhs_dup_end - ri);
        if (report != nullptr) {
          path.push_back(lhs_off);
          for (size_t p = 0; p < pairs; ++p) {
            emit_chain_line(report, module_name, module_index, path);
          }
          path.pop_back();
        }
        count += pairs;
        progress.add(pairs);

        li = lhs_dup_end;
        ri = rhs_dup_end;
      }
    }
    return count;
  }

  // 通用路径：双指针归并 + 前缀和剪枝 + 递归
  uint32_t li = lhs_start, ri = rhs_start;
  size_t count = 0;

  while (li < lhs_end && ri < rhs_end) {
    T lhs_off = lhs_children[li].address - lhs_dir.value;
    T rhs_off = rhs_children[ri].address - rhs_dir.value;

    if (lhs_off < rhs_off) {
      ++li;
    } else if (lhs_off > rhs_off) {
      ++ri;
    } else {
      uint32_t lhs_dup_end = li + 1;
      while (lhs_dup_end < lhs_end &&
             lhs_children[lhs_dup_end].address - lhs_dir.value == lhs_off) {
        ++lhs_dup_end;
      }
      uint32_t rhs_dup_end = ri + 1;
      while (rhs_dup_end < rhs_end &&
             rhs_children[rhs_dup_end].address - rhs_dir.value == lhs_off) {
        ++rhs_dup_end;
      }

      path.push_back(lhs_off);
      for (uint32_t lx = li; lx < lhs_dup_end; ++lx) {
        // 前缀和剪枝：跳过空分支
        if (chains_of(lhs_prefix, lhs_children[lx], child_level) == 0) {
          continue;
        }
        for (uint32_t rx = ri; rx < rhs_dup_end; ++rx) {
          if (chains_of(rhs_prefix, rhs_children[rx], child_level) == 0) {
            continue;
          }
          count += match_subtrees(
              lhs_info, rhs_info,
              lhs_prefix, rhs_prefix,
              lhs_children[lx], rhs_children[rx],
              child_level, path,
              module_name, module_index,
              report, progress);
        }
      }
      path.pop_back();

      li = lhs_dup_end;
      ri = rhs_dup_end;
    }
  }

  return count;
}

// ============ 匹配模块根节点（双指针归并 + 前缀和剪枝） ============

template <class T>
size_t ccompare<T>::match_module_roots(
    const cprog_chain_info<T> &lhs_info,
    const cprog_chain_info<T> &rhs_info,
    const prefix_sums_t &lhs_prefix,
    const prefix_sums_t &rhs_prefix,
    const cprog_sym_integr<T> &lhs_sym,
    const cprog_sym_integr<T> &rhs_sym,
    uint64_t lhs_chains, uint64_t rhs_chains,
    FILE *report)
{
  if (lhs_sym.sym == nullptr || rhs_sym.sym == nullptr) return 0;
  if (lhs_sym.data.size() == 0 || rhs_sym.data.size() == 0) return 0;

  std::vector<T> path;
  path.reserve(lhs_sym.sym->level + 1);
  const char *module_name = lhs_sym.sym->name;
  int module_index = lhs_sym.sym->count;
  int level = lhs_sym.sym->level;

  if (report != nullptr) {
    fprintf(report, "  保持不变的链:\n");
  }

  printf("    根节点: 旧=%zu 新=%zu, 链数: 旧=%llu 新=%llu, 上界=%llu\n",
         lhs_sym.data.size(), rhs_sym.data.size(),
         static_cast<unsigned long long>(lhs_chains),
         static_cast<unsigned long long>(rhs_chains),
         static_cast<unsigned long long>(std::min(lhs_chains, rhs_chains)));

  size_t lhs_total_roots = lhs_sym.data.size();
  match_progress progress;

  // 双指针归并：根节点按 address 排序 → offset (address - sym.start) 也有序
  size_t li = 0, ri = 0;
  size_t count = 0;

  while (li < lhs_sym.data.size() && ri < rhs_sym.data.size()) {
    T lhs_off = lhs_sym.data[li].address - lhs_sym.sym->start;
    T rhs_off = rhs_sym.data[ri].address - rhs_sym.sym->start;

    if (lhs_off < rhs_off) {
      ++li;
    } else if (lhs_off > rhs_off) {
      ++ri;
    } else {
      // 找出两侧重复节点的范围
      size_t lhs_dup_end = li + 1;
      while (lhs_dup_end < lhs_sym.data.size() &&
             lhs_sym.data[lhs_dup_end].address - lhs_sym.sym->start == lhs_off) {
        ++lhs_dup_end;
      }
      size_t rhs_dup_end = ri + 1;
      while (rhs_dup_end < rhs_sym.data.size() &&
             rhs_sym.data[rhs_dup_end].address - rhs_sym.sym->start == lhs_off) {
        ++rhs_dup_end;
      }

      // 交叉匹配所有重复对，用前缀和剪枝
      for (size_t lx = li; lx < lhs_dup_end; ++lx) {
        if (chains_of(lhs_prefix, lhs_sym.data[lx], level) == 0) {
          continue;
        }
        for (size_t rx = ri; rx < rhs_dup_end; ++rx) {
          if (chains_of(rhs_prefix, rhs_sym.data[rx], level) == 0) {
            continue;
          }
          path.clear();
          path.push_back(lhs_off);
          count += match_subtrees(
              lhs_info, rhs_info,
              lhs_prefix, rhs_prefix,
              lhs_sym.data[lx], rhs_sym.data[rx],
              level, path,
              module_name, module_index,
              report, progress);
        }
      }

      li = lhs_dup_end;
      ri = rhs_dup_end;
    }
  }

  // 最终进度
  if (progress.matched > 0) {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - progress.timer).count();
    printf("    根节点遍历完成: %zu/%zu, 匹配 %zu 条链, %.3fs\n",
           std::min(li, lhs_total_roots), lhs_total_roots, count, elapsed);
  }

  return count;
}

// ============ 二进制文件对比主函数 ============

template <class T>
bin_compare_result<T> ccompare<T>::compare_bin_files(
    const std::string &lhs_path,
    const std::string &rhs_path,
    FILE *report)
{
  // 打开并验证文件
  std::unique_ptr<FILE, decltype(&fclose)> lhs_file(
      fopen(lhs_path.c_str(), "rb"), &fclose);
  std::unique_ptr<FILE, decltype(&fclose)> rhs_file(
      fopen(rhs_path.c_str(), "rb"), &fclose);

  if (!lhs_file) {
    throw std::runtime_error("无法打开指针链文件: " + lhs_path);
  }
  if (!rhs_file) {
    throw std::runtime_error("无法打开指针链文件: " + rhs_path);
  }

  validate_bin_file(lhs_file.get(), lhs_path);
  validate_bin_file(rhs_file.get(), rhs_path);

  // 解析二进制数据（mmap，不展开链）
  printf("[对比] 解析二进制数据...\n");
  auto lhs_info = this->parse_cprog_bin_data(lhs_file.get());
  auto rhs_info = this->parse_cprog_bin_data(rhs_file.get());
  printf("  旧文件: %zu 个模块, %zu 层\n", lhs_info.syms.size(), lhs_info.contents.size());
  printf("  新文件: %zu 个模块, %zu 层\n", rhs_info.syms.size(), rhs_info.contents.size());

  bin_compare_result<T> result;

  // 用前缀和统计链总数（O(N) 替代递归 O(total_chains)）
  printf("[对比] 统计链数量...\n");
  prefix_sums_t lhs_prefix, rhs_prefix;
  result.lhs_total = count_chains_prefix_sum(lhs_info, "旧", lhs_prefix);
  result.rhs_total = count_chains_prefix_sum(rhs_info, "新", rhs_prefix);
  printf("  旧文件总计: %zu 条链\n", result.lhs_total);
  printf("  新文件总计: %zu 条链\n", result.rhs_total);

  // 构建 rhs 模块索引：(name, index) -> sym index
  std::unordered_map<chain_module_key, size_t, chain_module_key_hash> rhs_module_map;
  for (size_t i = 0; i < rhs_info.syms.size(); ++i) {
    if (rhs_info.syms[i].sym == nullptr) continue;
    chain_module_key key(rhs_info.syms[i].sym->name, rhs_info.syms[i].sym->count);
    rhs_module_map[key] = i;
  }

  // 遍历 lhs 模块，在 rhs 中查找匹配
  printf("[对比] 匹配模块...\n");
  auto match_start = std::chrono::steady_clock::now();
  size_t total_common = 0;
  size_t module_count = lhs_info.syms.size();

  for (size_t idx = 0; idx < lhs_info.syms.size(); ++idx) {
    auto &lhs_sym = lhs_info.syms[idx];
    if (lhs_sym.sym == nullptr) continue;

    chain_module_key key(lhs_sym.sym->name, lhs_sym.sym->count);
    auto it = rhs_module_map.find(key);
    if (it == rhs_module_map.end()) continue;

    size_t rhs_idx = it->second;

    // 用前缀和计算该模块的链数量
    int lhs_level = lhs_sym.sym->level;
    int rhs_level = rhs_info.syms[rhs_idx].sym->level;
    uint64_t lhs_chains = 0;
    for (size_t i = 0; i < lhs_sym.data.size(); ++i) {
      lhs_chains += chains_of(lhs_prefix, lhs_sym.data[i], lhs_level);
    }
    uint64_t rhs_chains = 0;
    for (size_t i = 0; i < rhs_info.syms[rhs_idx].data.size(); ++i) {
      rhs_chains += chains_of(rhs_prefix, rhs_info.syms[rhs_idx].data[i], rhs_level);
    }

    // 任一侧为 0 则跳过
    if (lhs_chains == 0 || rhs_chains == 0) continue;

    if (report != nullptr) {
      fprintf(report, "模块: %s[%d]\n", lhs_sym.sym->name, lhs_sym.sym->count);
    }

    printf("  [%zu/%zu] %s[%d] 开始匹配...\n",
           idx + 1, module_count, lhs_sym.sym->name, lhs_sym.sym->count);

    auto mod_start = std::chrono::steady_clock::now();
    size_t common_count = match_module_roots(
        lhs_info, rhs_info,
        lhs_prefix, rhs_prefix,
        lhs_sym, rhs_info.syms[rhs_idx],
        lhs_chains, rhs_chains,
        report);

    double mod_elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - mod_start).count();
    total_common += common_count;

    if (common_count > 0) {
      printf("  [%zu/%zu] %s[%d]: %zu 条匹配链, 模块耗时 %.3fs, 累计 %zu 条\n",
             idx + 1, module_count, lhs_sym.sym->name, lhs_sym.sym->count,
             common_count, mod_elapsed, total_common);
      module_chain_diff<T> diff;
      diff.module_name = lhs_sym.sym->name;
      diff.module_index = lhs_sym.sym->count;
      diff.common_count = common_count;
      result.modules.push_back(std::move(diff));
    } else {
      printf("  [%zu/%zu] %s[%d]: 无匹配, 模块耗时 %.3fs\n",
             idx + 1, module_count, lhs_sym.sym->name, lhs_sym.sym->count,
             mod_elapsed);
    }

    if (report != nullptr) {
      fprintf(report, "\n");
    }
  }

  double match_elapsed = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - match_start).count();
  printf("[对比] 匹配完成, 共 %zu 条匹配链, 匹配阶段耗时 %.3fs\n",
         total_common, match_elapsed);

  result.unchanged = total_common;
  return result;
}

// ============ 文本文件对比 ============

template <class T>
bool ccompare<T>::parse_txt_line(const std::string &line,
                                 chain_signature<T> &out) {
  const char *p = line.c_str();
  const char *end = p + line.size();

  // 跳过前导空白
  while (p < end && std::isspace(static_cast<unsigned char>(*p))) ++p;
  if (p >= end) return false;

  // 查找 '[' — 模块名结束
  const char *bracket_l = static_cast<const char*>(std::memchr(p, '[', end - p));
  if (bracket_l == nullptr || bracket_l == p) return false;

  out.module_name.assign(p, bracket_l);

  // 解析 module_index
  const char *idx_start = bracket_l + 1;
  char *idx_end = nullptr;
  long idx_val = std::strtol(idx_start, &idx_end, 10);
  if (idx_end == idx_start || idx_end >= end || *idx_end != ']') return false;
  out.module_index = static_cast<int>(idx_val);

  // 从 ']' 之后解析偏移
  out.offsets.clear();
  p = idx_end + 1;

  while (p < end) {
    // 查找 "+ 0x"
    const char *plus = std::strstr(p, "+ 0x");
    if (plus == nullptr) break;

    const char *hex_start = plus + 4;
    if (hex_start >= end) break;

    char *hex_end = nullptr;
    unsigned long value = std::strtoul(hex_start, &hex_end, 16);
    if (hex_end == hex_start) break;

    out.offsets.emplace_back(static_cast<T>(value));
    p = hex_end;
  }

  return !out.offsets.empty();
}

// 获取当前进程常驻内存（RSS），单位 MiB。仅用于显示诊断信息；
// 文本对比采用外部排序，不会因达到软上限而主动终止任务。
inline size_t current_process_rss_mb() {
  std::ifstream status("/proc/self/status");
  std::string key;
  while (status >> key) {
    if (key == "VmRSS:") {
      size_t kb = 0;
      std::string unit;
      status >> kb >> unit;
      return kb / 1024;
    }
    std::string rest;
    std::getline(status, rest);
  }
  return 0;
}

// Android/Linux 系统当前可用内存（MemAvailable），读取失败时返回 0。
inline size_t current_mem_available_mb() {
  std::ifstream meminfo("/proc/meminfo");
  std::string key;
  while (meminfo >> key) {
    if (key == "MemAvailable:") {
      size_t kb = 0;
      std::string unit;
      meminfo >> kb >> unit;
      return kb / 1024;
    }
    std::string rest;
    std::getline(meminfo, rest);
  }
  return 0;
}

template <class T>
bin_compare_result<T> ccompare<T>::compare_txt_files(
    const std::string &lhs_path,
    const std::string &rhs_path,
    FILE *report,
    size_t memory_limit_mb,
    size_t chunk_mib,
    size_t sort_threads,
    size_t merge_fan_in) {
  constexpr size_t kMiB = 1024ULL * 1024ULL;
  if (memory_limit_mb == 0) throw std::runtime_error("内存预算必须大于 0 MiB");
  if (chunk_mib == 0) throw std::runtime_error("工作块大小必须大于 0 MiB");
  if (sort_threads == 0) throw std::runtime_error("排序线程数必须大于 0");
  if (merge_fan_in < 2) throw std::runtime_error("归并扇入必须至少为 2");
  if (memory_limit_mb > std::numeric_limits<size_t>::max() / kMiB ||
      chunk_mib > std::numeric_limits<size_t>::max() / kMiB) {
    throw std::runtime_error("输入值超出当前系统可表示的 MiB 范围");
  }

  // 用户可分别设置工作预算、工作块大小、排序线程数和归并扇入。
  // 输入不设人为上限；仅受 size_t 表示范围、实际内存和操作系统资源限制。
  // 工作预算是自适应参考值，不是 Android 对进程 RSS 的硬限制。
  const size_t budget_bytes = memory_limit_mb * kMiB;
  const size_t normal_chunk_bytes = chunk_mib * kMiB;
  const size_t normal_sort_threads = sort_threads;
  const size_t normal_merge_fan_in = merge_fan_in;
  const size_t lowmem_chunk_bytes = std::min<size_t>(normal_chunk_bytes, kMiB);
  size_t chunk_bytes = normal_chunk_bytes;
  size_t active_sort_threads = normal_sort_threads;
  size_t active_merge_fan_in = normal_merge_fan_in;
  bool low_memory_mode = false;
  const char *tmp_env = std::getenv("TMPDIR");
  std::string tmp_dir = (tmp_env && *tmp_env) ? tmp_env : "/data/local/tmp";

  std::vector<std::string> temp_paths;
  auto make_temp_path = [&]() -> std::string {
    std::string pattern = tmp_dir + "/pointerscan-sort-XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    int fd = mkstemp(writable.data());
    if (fd < 0 && tmp_dir != "/tmp") {
      pattern = "/tmp/pointerscan-sort-XXXXXX";
      writable.assign(pattern.begin(), pattern.end());
      writable.push_back('\0');
      fd = mkstemp(writable.data());
    }
    if (fd < 0) {
      throw std::runtime_error("无法创建文本对比临时文件，请检查临时目录空间和权限");
    }
    close(fd);
    std::string path(writable.data());
    temp_paths.push_back(path);
    return path;
  };
  struct TempCleanup {
    std::vector<std::string> &paths;
    ~TempCleanup() { for (const auto &p : paths) std::remove(p.c_str()); }
  } cleanup{temp_paths};

  // 规范化键：模块名、模块序号、偏移链。偏移使用固定宽度十六进制，
  // 确保同一条链在两个文件中具有完全相同的键。
  const char sep = '\x1f';
  auto make_key = [&](const chain_signature<T> &sig) {
    std::ostringstream out;
    out << sig.module_name << sep << sig.module_index << sep
        << std::uppercase << std::hex << std::setfill('0');
    for (size_t i = 0; i < sig.offsets.size(); ++i) {
      if (i) out << ',';
      out << std::setw(static_cast<int>(sizeof(T) * 2))
          << static_cast<unsigned long long>(sig.offsets[i]);
    }
    return out.str();
  };
  auto key_less = [](const std::string &a, const std::string &b) {
    return a < b;
  };
  auto write_key = [](FILE *f, const std::string &key) {
    if (std::fwrite(key.data(), 1, key.size(), f) != key.size() ||
        std::fputc('\n', f) == EOF) {
      throw std::runtime_error("写入文本对比临时文件失败，可能是存储空间不足");
    }
  };
  auto read_key = [](FILE *f, std::string &key) -> bool {
    key.clear();
    int c;
    while ((c = std::fgetc(f)) != EOF) {
      if (c == '\n') return true;
      key.push_back(static_cast<char>(c));
    }
    return !key.empty();
  };

  auto merge_group = [&](const std::vector<std::string> &inputs) -> std::string {
    std::string output_path = make_temp_path();
    std::vector<FILE *> files;
    files.reserve(inputs.size());
    for (const auto &path : inputs) {
      FILE *f = std::fopen(path.c_str(), "rb");
      if (!f) {
        for (FILE *opened : files) std::fclose(opened);
        throw std::runtime_error("无法读取文本对比临时文件");
      }
      files.push_back(f);
    }
    FILE *out = std::fopen(output_path.c_str(), "wb");
    if (!out) {
      for (FILE *f : files) std::fclose(f);
      throw std::runtime_error("无法写入文本对比临时文件");
    }
    struct Item { std::string key; size_t file_index; };
    auto cmp = [](const Item &a, const Item &b) { return a.key > b.key; };
    std::priority_queue<Item, std::vector<Item>, decltype(cmp)> heap(cmp);
    for (size_t i = 0; i < files.size(); ++i) {
      std::string key;
      if (read_key(files[i], key)) heap.push(Item{std::move(key), i});
    }
    std::string previous;
    bool have_previous = false;
    try {
      while (!heap.empty()) {
        Item item = heap.top(); heap.pop();
        if (!have_previous || item.key != previous) {
          write_key(out, item.key);
          previous = item.key;
          have_previous = true;
        }
        std::string next;
        if (read_key(files[item.file_index], next))
          heap.push(Item{std::move(next), item.file_index});
      }
      if (std::fclose(out) != 0) {
        out = nullptr;
        throw std::runtime_error("关闭文本对比临时文件失败，可能是存储空间不足");
      }
      out = nullptr;
    } catch (...) {
      if (out) std::fclose(out);
      for (FILE *f : files) std::fclose(f);
      throw;
    }
    for (FILE *f : files) std::fclose(f);
    return output_path;
  };

  auto sort_chunk = [&](std::vector<std::string> &items) {
    if (items.size() < 2 || active_sort_threads <= 1) {
      std::sort(items.begin(), items.end(), key_less);
      return;
    }
    // 用户输入不设固定上限，但单个块最多只能拆成 items.size() 个排序段。
    const size_t workers = std::min(active_sort_threads, items.size());
    if (workers <= 1) {
      std::sort(items.begin(), items.end(), key_less);
      return;
    }
    const size_t n = items.size();
    auto boundary = [n, workers](size_t i) {
      return (n / workers) * i + std::min(i, n % workers);
    };
    std::vector<std::thread> pool;
    pool.reserve(workers - 1);
    try {
      for (size_t i = 0; i + 1 < workers; ++i) {
        const size_t begin = boundary(i), end = boundary(i + 1);
        pool.emplace_back([&, begin, end] {
          std::sort(items.begin() + begin, items.begin() + end, key_less);
        });
      }
      const size_t begin = boundary(workers - 1), end = boundary(workers);
      std::sort(items.begin() + begin, items.begin() + end, key_less);
    } catch (...) {
      for (auto &t : pool) if (t.joinable()) t.join();
      // 线程创建失败时回退到单线程排序，保证任务可以继续。
      std::sort(items.begin(), items.end(), key_less);
      return;
    }
    for (auto &t : pool) if (t.joinable()) t.join();
    for (size_t width = 1; width < workers;) {
      for (size_t left = 0; left < workers; left += width * 2) {
        const size_t mid_index = std::min(workers, left + width);
        const size_t right_index = std::min(workers, left + width * 2);
        if (mid_index < right_index) {
          std::inplace_merge(items.begin() + boundary(left),
                             items.begin() + boundary(mid_index),
                             items.begin() + boundary(right_index), key_less);
        }
      }
      if (width > workers / 2) break;
      width *= 2;
    }
  };

  auto external_sort = [&](const std::string &input_path, size_t &total) -> std::string {
    std::ifstream in(input_path);
    if (!in) throw std::runtime_error("无法打开指针链文本文件: " + input_path);
    std::vector<std::string> chunk;
    chunk.reserve(4096);
    size_t chunk_size = 0;
    total = 0;
    std::vector<std::string> runs;
    std::string line;
    chain_signature<T> sig;
    auto flush_chunk = [&]() {
      if (chunk.empty()) return;
      sort_chunk(chunk);
      chunk.erase(std::unique(chunk.begin(), chunk.end()), chunk.end());
      std::string run_path = make_temp_path();
      FILE *f = std::fopen(run_path.c_str(), "wb");
      if (!f) throw std::runtime_error("无法创建排序分块文件");
      try {
        for (const auto &key : chunk) write_key(f, key);
        if (std::fclose(f) != 0) {
          f = nullptr;
          throw std::runtime_error("写入排序分块失败，可能是存储空间不足");
        }
        f = nullptr;
      } catch (...) { if (f) std::fclose(f); throw; }
      runs.push_back(run_path);
      chunk.clear();
      chunk_size = 0;
    };
    size_t pressure_check_counter = 0;
    while (std::getline(in, line)) {
      if (parse_txt_line(line, sig)) {
        chunk.emplace_back(make_key(sig));
        chunk_size += chunk.back().size() + sizeof(std::string) + 32;
        ++total; // 统计解析成功的原始链行，重复项仍计入总数
        if (chunk_size >= chunk_bytes) flush_chunk();

        // 每 4096 条有效链检查一次，避免每行读取 /proc 造成明显开销。
        if ((++pressure_check_counter & 4095U) == 0) {
          const size_t rss_mb = current_process_rss_mb();
          const size_t available_mb = current_mem_available_mb();
          const size_t rss_budget_threshold_mb = (memory_limit_mb / 4) * 3 +
              ((memory_limit_mb % 4) * 3) / 4;
          const bool rss_pressure = rss_mb > 0 && rss_mb >= rss_budget_threshold_mb;
          const bool system_pressure = available_mb > 0 && available_mb < 768;
          if ((rss_pressure || system_pressure) && !low_memory_mode) {
            low_memory_mode = true;
            chunk_bytes = lowmem_chunk_bytes;
            active_sort_threads = 1;
            active_merge_fan_in = std::min<size_t>(normal_merge_fan_in, 4);
            printf("\n[内存保护] 检测到内存压力（RSS约 %zu MiB，可用内存约 %zu MiB），切换为小块、单线程、低扇入模式。\n",
                   rss_mb, available_mb);
            fflush(stdout);
          } else if (!rss_pressure && !system_pressure && low_memory_mode &&
                     (available_mb == 0 || available_mb >= 1024) &&
                     (rss_mb == 0 || rss_mb < memory_limit_mb / 2)) {
            low_memory_mode = false;
            chunk_bytes = normal_chunk_bytes;
            active_sort_threads = normal_sort_threads;
            active_merge_fan_in = normal_merge_fan_in;
            printf("\n[内存保护] 内存压力缓解，恢复用户设置的工作块、线程数和归并扇入。\n");
            fflush(stdout);
          }
        }
      }
    }
    if (in.bad()) throw std::runtime_error("读取指针链文本文件失败: " + input_path);
    flush_chunk();
    if (runs.empty()) {
      std::string empty = make_temp_path();
      FILE *f = std::fopen(empty.c_str(), "wb");
      if (f) std::fclose(f);
      return empty;
    }
    // 分多轮归并；常规模式最多 16 路，检测到内存压力后降为 4 路。
    while (runs.size() > 1) {
      std::vector<std::string> next_runs;
      for (size_t i = 0; i < runs.size();) {
        size_t e = i + std::min(active_merge_fan_in, runs.size() - i);
        if (e - i == 1) next_runs.push_back(runs[i]);
        else {
          std::vector<std::string> group(runs.begin() + i, runs.begin() + e);
          next_runs.push_back(merge_group(group));
        }
        i = e;
      }
      runs.swap(next_runs);
    }
    return runs.front();
  };

  // 解码规范化键以输出原报告格式。
  auto decode_key = [&](const std::string &key, std::string &module, int &index,
                        std::vector<T> &offsets) -> bool {
    size_t a = key.find(sep);
    if (a == std::string::npos) return false;
    size_t b = key.find(sep, a + 1);
    if (b == std::string::npos) return false;
    module.assign(key.data(), a);
    try { index = std::stoi(key.substr(a + 1, b - a - 1)); }
    catch (...) { return false; }
    offsets.clear();
    size_t pos = b + 1;
    while (pos < key.size()) {
      size_t comma = key.find(',', pos);
      std::string token = key.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
      if (token.empty()) return false;
      unsigned long long value = 0;
      try { value = std::stoull(token, nullptr, 16); }
      catch (...) { return false; }
      offsets.push_back(static_cast<T>(value));
      if (comma == std::string::npos) break;
      pos = comma + 1;
    }
    return !offsets.empty();
  };

  printf("[对比] 自适应外部排序：内存工作预算 %zu MiB，工作块 %zu MiB，排序线程 %zu，归并扇入 %zu。\n",
         memory_limit_mb, chunk_mib, sort_threads, merge_fan_in);
  printf("[说明] 内存预算不是 RSS 硬上限；检测到内存压力时会自动降档。\n");
  printf("[内存] 开始排序前 RSS 约 %zu MiB，可用内存约 %zu MiB\n",
         current_process_rss_mb(), current_mem_available_mb());
  bin_compare_result<T> result;
  std::string lhs_sorted = external_sort(lhs_path, result.lhs_total);
  printf("  旧文件解析完成: %zu 条链；当前 RSS 约 %zu MiB\n",
         result.lhs_total, current_process_rss_mb());
  std::string rhs_sorted = external_sort(rhs_path, result.rhs_total);
  printf("  新文件解析完成: %zu 条链；当前 RSS 约 %zu MiB\n",
         result.rhs_total, current_process_rss_mb());

  FILE *lhs = std::fopen(lhs_sorted.c_str(), "rb");
  FILE *rhs = std::fopen(rhs_sorted.c_str(), "rb");
  if (!lhs || !rhs) {
    if (lhs) std::fclose(lhs);
    if (rhs) std::fclose(rhs);
    throw std::runtime_error("无法打开已排序的临时文件");
  }
  std::string lk, rk, current_module;
  bool has_l = read_key(lhs, lk), has_r = read_key(rhs, rk);
  size_t unchanged = 0;
  std::string report_module;
  int report_index = 0;
  std::vector<T> offsets;
  while (has_l && has_r) {
    if (lk < rk) {
      has_l = read_key(lhs, lk);
    } else if (rk < lk) {
      has_r = read_key(rhs, rk);
    } else {
      std::string module;
      int index = 0;
      if (decode_key(lk, module, index, offsets)) {
        if (report != nullptr) {
          if (module != report_module || index != report_index) {
            if (!report_module.empty()) fputc('\n', report);
            fprintf(report, "模块: %s[%d]\n  保持不变的链:\n", module.c_str(), index);
            report_module = module;
            report_index = index;
          }
          fprintf(report, "    = %s[%d]", module.c_str(), index);
          for (size_t i = 0; i < offsets.size(); ++i) {
            fprintf(report, "%s0x%lX", i == 0 ? " + " : " -> + ",
                    static_cast<unsigned long>(offsets[i]));
          }
          fputc('\n', report);
        }
        ++unchanged;
        if (result.modules.empty() || result.modules.back().module_name != module ||
            result.modules.back().module_index != index) {
          module_chain_diff<T> diff;
          diff.module_name = module;
          diff.module_index = index;
          diff.common_count = 1;
          result.modules.emplace_back(std::move(diff));
        } else {
          ++result.modules.back().common_count;
        }
      }
      has_l = read_key(lhs, lk);
      has_r = read_key(rhs, rk);
    }
  }
  std::fclose(lhs);
  std::fclose(rhs);
  if (report != nullptr) std::fflush(report);
  result.unchanged = unchanged;
  printf("[对比] 完成，保持不变链数量: %zu\n", result.unchanged);
  printf("[内存] 当前 RSS 约 %zu MiB，可用内存约 %zu MiB（观测值，不是系统级硬限制）\n",
         current_process_rss_mb(), current_mem_available_mb());
  return result;
}

// 显式实例化
template class ccompare<uint32_t>;
template class ccompare<size_t>;

}  // namespace chainer
