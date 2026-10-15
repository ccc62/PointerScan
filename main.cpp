#include "memtool/membase.hpp"

#include "memtool/memextend.hpp"

#include "chainer/ccscan.hpp"  // IWYU pragma: keep
#include "chainer/ccformat.hpp"  // native binary -> text conversion
#include "chainer/ccompare.hpp"  // IWYU pragma: keep
#include "chainer/keybin.hpp"

#include "utils/cmd_parser.h"
#include <cstdint>
#include <limits>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <sstream>

using namespace utils;

int run_app(int argc, char *argv[]);

namespace {

std::string format_chain_line(const std::string &module_name, int module_index,
                              const std::vector<size_t> &offsets) {
  std::ostringstream oss;
  oss << module_name << "[" << module_index << "]";
  if (!offsets.empty()) {
    oss << std::hex << std::uppercase;
    for (size_t i = 0; i < offsets.size(); ++i) {
      oss << (i == 0 ? " + 0x" : " -> + 0x") << offsets[i];
    }
    oss << std::nouppercase << std::dec;
  }
  return oss.str();
}


bool g_interactive_mode = false;

std::string ask_text(const std::string &prompt, const std::string &def = "") {
  std::string value;
  std::cout << prompt;
  if (!def.empty()) std::cout << " [" << def << "]";
  std::cout << "：";
  std::getline(std::cin, value);
  if (value.empty()) return def;
  return value;
}

bool ask_yes_no(const std::string &prompt, bool def = true) {
  std::string value = ask_text(prompt, def ? "Y" : "N");
  return value == "y" || value == "Y" || value == "是" ||
         value == "yes" || value == "YES" || value == "1";
}

void interactive_module_filter() {
  if (!g_interactive_mode || memtool::extend::vm_static_list.empty()) return;

  std::vector<std::string> names;
  for (auto *mod : memtool::extend::vm_static_list) {
    std::string name(mod->name);
    if (std::find(names.begin(), names.end(), name) == names.end())
      names.push_back(name);
  }
  if (names.empty()) return;

  std::cout << "\n可选择作为指针链基址的模块（中间指针仍可经过其他内存区域）：\n";
  std::cout << "  0. 全部模块\n";
  for (size_t i = 0; i < names.size(); ++i)
    std::cout << "  " << (i + 1) << ". " << names[i] << "\n";
  std::cout << "输入模块编号，多个编号用逗号分隔；直接回车表示全部：\n> ";

  std::string line;
  std::getline(std::cin, line);
  if (line.empty() || line == "0") return;

  std::vector<std::string> selected;
  std::stringstream ss(line);
  std::string item;
  while (std::getline(ss, item, ',')) {
    try {
      size_t idx = std::stoul(item);
      if (idx > 0 && idx <= names.size()) selected.push_back(names[idx - 1]);
    } catch (...) {}
  }
  if (selected.empty()) {
    std::cout << "未识别有效编号，保留全部模块。\n";
    return;
  }

  auto &mods = memtool::extend::vm_static_list;
  for (auto it = mods.begin(); it != mods.end();) {
    if (std::find(selected.begin(), selected.end(), std::string((*it)->name)) == selected.end()) {
      delete *it;
      it = mods.erase(it);
    } else {
      ++it;
    }
  }
  std::cout << "已选择 " << selected.size() << " 个模块作为链基址。\n";
}

int interactive_main() {
  std::cout << "\n========== newscan 指针链分析工具 ==========\n"
            << "1. 指针链扫描\n"
            << "2. 指针路径扫描\n"
            << "3. 对比文本指针链文件\n"
            << "4. 对比二进制指针链文件\n"
            << "5. 文本转紧凑二进制缓存（排序/去重）\n"
            << "6. 对比紧凑二进制缓存\n"
            << "7. 原生二进制转文本\n"
            << "8. 查看命令行帮助\n"
            << "0. 退出\n";
  std::string choice = ask_text("请选择功能（0-8）", "1");
  if (choice == "0") return 0;

  std::vector<std::string> args = {"newscan"};
  auto add = [&args](const std::string &k, const std::string &v) {
    args.push_back(k); args.push_back(v);
  };

  if (choice == "8") {
    args.push_back("--help");
  } else if (choice == "1") {
    add("-p", ask_text("目标进程名称或 PID"));
    add("-a", ask_text("目标地址（十六进制，不带 0x）"));
    add("-d", ask_text("最大搜索深度", "4"));
    add("-o", ask_text("最大偏移量（十六进制，不带 0x）", "2000"));
    add("-l", ask_text("最多输出多少条结果（0 表示不限制）", "0"));
    std::string fmt = ask_text("输出格式：txt 文本 / bin 原生二进制", "txt");
    if (fmt != "txt" && fmt != "bin") fmt = "txt";
    add("--format", fmt);
    add("-f", ask_text("结果文件路径", fmt == "bin" ? "/data/local/tmp/pointer_chains.bin" : "/data/local/tmp/pointer_chains.txt"));
    if (ask_yes_no("是否使用 /proc/PID/mem 读取模式？", false))
      args.push_back("--io");
  } else if (choice == "2") {
    add("-p", ask_text("目标进程名称或 PID"));
    args.push_back("--path");
    add("--from", ask_text("起始地址（十六进制，不带 0x）"));
    add("--to", ask_text("目标地址（十六进制，不带 0x）"));
    add("-d", ask_text("最大搜索深度", "4"));
    add("-o", ask_text("最大偏移量（十六进制，不带 0x）", "2000"));
    add("-f", ask_text("结果文件路径", "/data/local/tmp/pointer_paths.txt"));
  } else if (choice == "3" || choice == "4") {
    args.push_back(choice == "3" ? "--compare-txt" : "--compare-bin");
    add("--lhs", ask_text("旧版文件路径"));
    add("--rhs", ask_text("新版文件路径"));
    add("--report", ask_text("对比报告保存路径", "/data/local/tmp/chain_compare.txt"));
    if (choice == "3") {
      std::cout << "\n文本对比参数（内存预算是参考值，不是 RSS 硬上限）\n";
      add("--mem-limit", ask_text("内存工作预算（MiB）", "2048"));
      add("--chunk-mib", ask_text("工作块大小（MiB）", "128"));
      add("--sort-threads", ask_text("排序线程数（至少 1）", "4"));
      add("--merge-fan-in", ask_text("归并扇入/同时归并输入文件数（至少 2）", "32"));
    }
  } else if (choice == "5") {
    args.push_back("--convert-keybin");
    add("--lhs", ask_text("待转换的文本指针链文件路径"));
    add("--out", ask_text("紧凑二进制缓存输出路径", "/data/local/tmp/pointer_chains.pskb"));
    add("--mem-limit", ask_text("内存工作预算（MiB；参考值）", "2048"));
    add("--chunk-mib", ask_text("工作块大小（MiB）", "128"));
  } else if (choice == "6") {
    args.push_back("--compare-keybin");
    add("--lhs", ask_text("旧版紧凑二进制缓存路径"));
    add("--rhs", ask_text("新版紧凑二进制缓存路径"));
    add("--report", ask_text("对比报告保存路径", "/data/local/tmp/chain_compare.txt"));
  } else if (choice == "7") {
    args.push_back("--convert-bin-to-txt");
    add("--lhs", ask_text("原生 .bin 指针链文件路径"));
    add("--out", ask_text("输出文本文件路径", "/data/local/tmp/pointer_chains.txt"));
  } else {
    std::cerr << "无效的菜单选项。\n";
    return 2;
  }

  std::vector<char *> argv;
  for (auto &arg : args) argv.push_back(&arg[0]);
  g_interactive_mode = true;
  int result = run_app(static_cast<int>(argv.size()), argv.data());
  g_interactive_mode = false;
  std::cout << "\n操作结束，返回代码：" << result << "\n";
  return result;
}

}  // namespace

int run_app(int argc, char *argv[]) {
  // 创建命令行解析器
  CommandLineParser parser("newscan", "高性能内存指针链分析工具");

  // 添加命令行选项
  parser.addOption({'p', "process", "目标进程名称或PID", true, false});
  parser.addOption({'a', "address", "目标地址(16进制，不带0x前缀)", true, false});
  parser.addOption({'d', "depth", "最大搜索深度", true, false, "10"});
  parser.addOption({'o', "offset", "最大偏移量(16进制，不带0x前缀)", true, false, "500"});
  parser.addOption({'l', "limit", "结果限制数量", true, false, "0"});
  parser.addOption({'f', "file", "输出文件名", true, false, "pointer_chains.txt"});
  parser.addOption({0, "format", "扫描输出格式：txt 或原生 bin", true, false, "txt"});
  parser.addOption({0, "convert-bin-to-txt", "把 newscan 原生二进制链文件转换为文本", false, false});
  parser.addOption({0, "compare-bin", "比较两份指针链二进制文件", false, false});
  parser.addOption({0, "compare-txt", "比较两份指针链文本文件", false, false});
  parser.addOption({0, "convert-keybin", "把文本指针链转换为排序去重的紧凑二进制缓存", false, false});
  parser.addOption({0, "compare-keybin", "比较两份 newscan 紧凑二进制缓存", false, false});
  parser.addOption({0, "lhs", "旧版指针链二进制文件路径", true, false});
  parser.addOption({0, "rhs", "新版指针链文件路径", true, false});
  parser.addOption({0, "out", "转换输出路径（文本或紧凑二进制缓存）", true, false});
  parser.addOption({0, "report", "对比输出文件名", true, false,
                    "chain_compare.txt"});
  parser.addOption({0, "mem-limit", "文本对比内存工作预算（MiB；自适应参考值，不是 RSS 硬上限）", true, false, "2048"});
  parser.addOption({0, "chunk-mib", "文本对比工作块大小（MiB）", true, false, "128"});
  parser.addOption({0, "sort-threads", "文本对比排序线程数（至少 1）", true, false, "4"});
  parser.addOption({0, "merge-fan-in", "文本对比归并扇入/同时归并输入文件数（至少 2）", true, false, "32"});
  parser.addOption({'v', "verbose", "详细输出模式", false, false});
  parser.addOption({0, "io", "使用/proc/pid/mem IO读取内存(解决不可读内存问题)", false, false});
  parser.addOption({0, "path", "路径扫描模式：查找两个地址之间的指针路径", false, false});
  parser.addOption({0, "from", "路径扫描的源地址(16进制)", true, false});
  parser.addOption({0, "to", "路径扫描的目标地址(16进制)", true, false});
  parser.addOption({'h', "help", "显示帮助信息", false, false});

  // 设置用法说明
  parser.setUsage("[扫描] -p <进程名/PID> -a <地址> [--format txt|bin] | "
                  "[路径] -p <进程名/PID> --path --from <源地址> --to <目标地址> | "
                  "[对比] (--compare-bin|--compare-txt|--compare-keybin) --lhs <旧文件> --rhs <新文件> | "
                  "[转换] --convert-keybin 或 --convert-bin-to-txt --lhs <输入> --out <输出>");

  // 解析命令行参数
  if (!parser.parse(argc, argv)) {
    std::cerr << "错误: " << parser.getErrorMessage() << std::endl;
    parser.showHelp();
    return 1;
  }

  // 如果请求帮助，显示帮助信息并退出
  if (parser.hasOption("help")) {
    parser.showHelp();
    return 0;
  }

  bool convert_bin_to_txt = parser.getBoolOption("convert-bin-to-txt", false);
  if (convert_bin_to_txt) {
    if (!parser.hasOption("lhs") || !parser.hasOption("out")) {
      std::cerr << "错误: --convert-bin-to-txt 需要 --lhs 原生二进制路径和 --out 文本输出路径\n";
      return 1;
    }
    const std::string in_path = parser.getOptionValue("lhs");
    const std::string out_path = parser.getOptionValue("out");
    if (in_path == out_path) { std::cerr << "错误: 输入和输出路径不能相同\n"; return 1; }
    if (in_path == out_path) { std::cerr << "错误: 输入和输出路径不能相同\n"; return 1; }
    struct stat in_st{}, out_st{};
    if (stat(in_path.c_str(), &in_st) == 0 && stat(out_path.c_str(), &out_st) == 0 &&
        in_st.st_dev == out_st.st_dev && in_st.st_ino == out_st.st_ino) {
      std::cerr << "错误: 输入和输出指向同一个文件\n"; return 1;
    }
    FILE *in = std::fopen(in_path.c_str(), "rb");
    if (!in) { std::cerr << "错误: 无法打开二进制文件: " << in_path << "\n"; return 1; }
    chainer::cprog_header hdr{};
    struct stat bin_st{};
    bool valid_header = fstat(fileno(in), &bin_st) == 0 && bin_st.st_size >= (off_t)sizeof(hdr) &&
        std::fread(&hdr, sizeof(hdr), 1, in) == 1 &&
        std::strncmp(hdr.sign, ".bin from chainer", 17) == 0 &&
        hdr.size == (int)sizeof(size_t) && hdr.version == 101 &&
        hdr.module_count >= 0 && hdr.module_count <= 1000000 &&
        hdr.level >= 0 && hdr.level <= 128;
    if (!valid_header) {
      std::fclose(in);
      std::cerr << "错误: 文件不是当前 64 位 newscan 原生二进制格式，或文件头损坏\n";
      return 1;
    }
    std::rewind(in);
    FILE *out = std::fopen(out_path.c_str(), "w");
    if (!out) { std::fclose(in); std::cerr << "错误: 无法创建文本文件: " << out_path << "\n"; return 1; }
    try {
      chainer::format<size_t> formatter;
      size_t n = formatter.format_bin_chain_data(in, out);
      std::fclose(in); in = nullptr;
      if (std::fclose(out) != 0) { std::cerr << "错误: 文本文件写入/关闭失败，可能存储空间不足\n"; return 1; }
      out = nullptr;
      std::printf("二进制转文本完成：%zu 条链 -> %s\n", n, out_path.c_str());
    } catch (const std::exception &ex) {
      if (in) std::fclose(in); if (out) std::fclose(out);
      std::cerr << "转换失败: " << ex.what() << "\n"; return 1;
    }
    return 0;
  }
  bool convert_keybin_mode = parser.getBoolOption("convert-keybin", false);
  bool compare_keybin_mode = parser.getBoolOption("compare-keybin", false);
  if (convert_keybin_mode) {
    if (!parser.hasOption("lhs") || !parser.hasOption("out")) {
      std::cerr << "错误: --convert-keybin 需要 --lhs 文本路径和 --out 输出路径\n";
      return 1;
    }
    auto parse_mib = [&](const std::string &name, size_t fallback, size_t &out) -> bool {
      try { std::string raw=parser.getOptionValue(name, std::to_string(fallback)); if(raw.empty()||raw[0]=='-')return false; size_t used=0; unsigned long long v=std::stoull(raw,&used); if(used!=raw.size()||v==0||v>std::numeric_limits<size_t>::max())return false; out=static_cast<size_t>(v); return true; } catch(...) { return false; }
    };
    size_t mem=2048, chunk=128;
    if(!parse_mib("mem-limit",2048,mem)||!parse_mib("chunk-mib",128,chunk)){std::cerr<<"错误: --mem-limit 和 --chunk-mib 必须是正整数\n";return 1;}
    try { chainer::keybin::convert_text_to_sorted_keybin(parser.getOptionValue("lhs"),parser.getOptionValue("out"),mem,chunk); }
    catch(const std::exception &ex){std::cerr<<"转换失败: "<<ex.what()<<"\n";return 1;}
    return 0;
  }
  if (compare_keybin_mode) {
    if (!parser.hasOption("lhs") || !parser.hasOption("rhs")) { std::cerr << "错误: --compare-keybin 需要 --lhs 和 --rhs\n"; return 1; }
    std::string report_path=parser.getOptionValue("report","chain_compare.txt");
    FILE *report=std::fopen(report_path.c_str(),"w");
    if(!report) { std::cerr << "错误: 无法创建报告文件: " << report_path << "\n"; return 1; }
    try { std::fprintf(report,"=== newscan 紧凑二进制缓存对比结果 ===\n\n"); size_t lhs_unique=0,rhs_unique=0; size_t common=chainer::keybin::compare_keybin_files(parser.getOptionValue("lhs"),parser.getOptionValue("rhs"),report,&lhs_unique,&rhs_unique); std::fprintf(report,"\n--- 统计 ---\n旧文件唯一链数量: %zu\n新文件唯一链数量: %zu\n共同链数量: %zu\n",lhs_unique,rhs_unique,common); std::fclose(report); std::printf("对比报告已保存至: %s\n",report_path.c_str()); }
    catch(const std::exception &ex){std::fclose(report);std::cerr<<"对比失败: "<<ex.what()<<"\n";return 1;}
    return 0;
  }
  bool compare_bin_mode = parser.getBoolOption("compare-bin", false);
  bool compare_txt_mode = parser.getBoolOption("compare-txt", false);
  if (compare_bin_mode || compare_txt_mode) {
    if (!parser.hasOption("lhs") || !parser.hasOption("rhs")) {
      std::cerr << "错误: 对比模式需要提供 --lhs 与 --rhs 选项" << std::endl;
      return 1;
    }

    auto lhs_path = parser.getOptionValue("lhs");
    auto rhs_path = parser.getOptionValue("rhs");

    std::string report_path =
        parser.getOptionValue("report", "chain_compare.txt");
    FILE *report = fopen(report_path.c_str(), "w");
    if (report == nullptr) {
      std::cerr << "警告: 无法创建报告文件: " << report_path << std::endl;
    }

    chainer::ccompare<size_t> comparer;
    chainer::bin_compare_result<size_t> compare_result;
    size_t memory_limit_mb = 2048;
    size_t chunk_mib = 128;
    size_t sort_threads = 4;
    size_t merge_fan_in = 32;
    if (compare_txt_mode) {
      auto parse_positive_size = [&](const std::string &option, const std::string &fallback,
                                     size_t &out, size_t minimum) -> bool {
        try {
          const std::string raw = parser.getOptionValue(option, fallback);
          if (raw.empty() || raw[0] == '-') return false;
          size_t used = 0;
          unsigned long long value = std::stoull(raw, &used, 10);
          if (used != raw.size() || value < minimum || value > std::numeric_limits<size_t>::max()) return false;
          out = static_cast<size_t>(value);
          return true;
        } catch (...) { return false; }
      };
      if (!parse_positive_size("mem-limit", "2048", memory_limit_mb, 1) ||
          !parse_positive_size("chunk-mib", "128", chunk_mib, 1) ||
          !parse_positive_size("sort-threads", "4", sort_threads, 1) ||
          !parse_positive_size("merge-fan-in", "32", merge_fan_in, 2)) {
        std::cerr << "错误: 参数必须是有效的正整数；工作预算/工作块/线程数至少为 1，归并扇入至少为 2。\n";
        if (report != nullptr) fclose(report);
        return 1;
      }
    }

    try {
      if (compare_bin_mode) {
        // 二进制对比：匹配链直接流式写入 report，不存储在内存中
        if (report != nullptr) {
          fprintf(report, "=== 指针链二进制文件对比结果 ===\n\n");
        }
        compare_result = comparer.compare_bin_files(lhs_path, rhs_path, report);
      } else {
        if (report != nullptr) {
          fprintf(report, "=== 指针链文本文件对比结果 ===\n\n");
          fflush(report);
        }
        compare_result = comparer.compare_txt_files(lhs_path, rhs_path, report,
                                                    memory_limit_mb, chunk_mib,
                                                    sort_threads, merge_fan_in);
      }
    } catch (const std::exception &ex) {
      if (report != nullptr) fclose(report);
      std::cerr << "错误: " << ex.what() << std::endl;
      return 1;
    }

    // 写入统计摘要
    if (report != nullptr) {
      // 链详情在比较过程中流式写入，这里追加统计
      fprintf(report, "--- 统计 ---\n");
      fprintf(report, "旧文件链数量: %zu\n", compare_result.lhs_total);
      fprintf(report, "新文件链数量: %zu\n", compare_result.rhs_total);
      fprintf(report, "保持不变链数量: %zu\n", compare_result.unchanged);
      fprintf(report, "\n");

      if (compare_txt_mode && compare_result.unchanged == 0) {
        fprintf(report, "未找到共同存在的指针链。\n");
      }

      fclose(report);
      printf("对比报告已保存至: %s\n", report_path.c_str());
    }

    return 0;
  }

  // ============ 路径扫描模式 ============
  bool path_mode = parser.getBoolOption("path", false);
  if (path_mode) {
    if (!parser.hasOption("process")) {
      std::cerr << "错误: 路径扫描模式需要提供目标进程 (-p/--process)" << std::endl;
      return 1;
    }
    if (!parser.hasOption("from") || !parser.hasOption("to")) {
      std::cerr << "错误: 路径扫描模式需要提供 --from 和 --to 地址" << std::endl;
      return 1;
    }

    std::string target_process = parser.getOptionValue("process");
    int target_pid = -1;
    try {
      target_pid = std::stoi(target_process);
    } catch (...) {
      target_pid = memtool::base::get_pid(target_process.c_str());
      if (target_pid == -1) {
        std::cerr << "错误: 无法找到进程: " << target_process << std::endl;
        return 1;
      }
    }

    printf("目标进程：%s -> PID %d\n", target_process.c_str(), target_pid);

    uint32_t max_depth = parser.getIntOption("depth", 5);
    uint32_t max_offset = static_cast<uint32_t>(
        std::stoul(parser.getOptionValue("offset", "500"), nullptr, 16));

    memtool::base::target_pid = target_pid;
    if (parser.getBoolOption("io", false)) {
      memtool::base::mode = memtool::read_mode::PROC_MEM_IO;
      printf("使用 /proc/%d/mem IO 读取模式\n", target_pid);
    }

    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc +
                                    memtool::C_bss + memtool::C_data);
    interactive_module_filter();

    size_t pointer_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
    printf("发现潜在指针：%ld 个\n", pointer_count);

    uint64_t from_addr = std::stoull(parser.getOptionValue("from"), nullptr, 16);
    uint64_t to_addr = std::stoull(parser.getOptionValue("to"), nullptr, 16);

    std::string output_file = parser.getOptionValue("file", "pointer_paths.txt");
    FILE *output = fopen(output_file.c_str(), "w");
    if (output == nullptr) {
      std::cerr << "错误: 无法创建输出文件: " << output_file << std::endl;
      return 1;
    }

    size_t path_count = scanner.scan_pointer_path(
        static_cast<size_t>(from_addr), static_cast<size_t>(to_addr),
        max_depth, max_offset, output);
    printf("找到路径：%ld 条\n", path_count);
    fclose(output);

    return 0;
  }

  if (!parser.hasOption("process")) {
    std::cerr << "错误: 扫描模式需要提供目标进程 (-p/--process)" << std::endl;
    return 1;
  }
  if (!parser.hasOption("address")) {
    std::cerr << "错误: 扫描模式需要提供目标地址 (-a/--address)" << std::endl;
    return 1;
  }

  // 第一步：获取目标进程
  std::string target_process = parser.getOptionValue("process");
  int target_pid = -1;

  // 尝试解析进程ID
  try {
    target_pid = std::stoi(target_process);
  } catch (...) {
    // 不是数字，认为是进程名
    target_pid = memtool::base::get_pid(target_process.c_str());
    if (target_pid == -1) {
      std::cerr << "错误: 无法找到进程: " << target_process << std::endl;
      return 1;
    }
  }

  printf("目标进程：%s -> PID %d\n", target_process.c_str(), target_pid);

  // 获取命令行参数
  uint32_t max_depth = parser.getIntOption("depth", 5);
  uint32_t max_offset = static_cast<uint32_t>(std::stoul(parser.getOptionValue("offset", "500"), nullptr, 16));

  // 第二步：初始化扫描器
  memtool::base::target_pid = target_pid;

  // 设置内存读取模式
  if (parser.getBoolOption("io", false)) {
    memtool::base::mode = memtool::read_mode::PROC_MEM_IO;
    printf("使用 /proc/%d/mem IO 读取模式\n", target_pid);
  }

  chainer::cscan<size_t> scanner;  // 64位进程，32位使用 uint32_t

  // 第三步：获取目标进程内存布局
  memtool::extend::get_target_mem();
  memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc +
                                  memtool::C_bss + memtool::C_data);
  interactive_module_filter();

  // 第四步：扫描潜在指针
  auto start_time = std::chrono::high_resolution_clock::now();
  // 参数：起始地址=0, 结束地址=0(不限制), 全扫描=false, 缓冲区数=10, 缓冲区大小=1MB
  size_t pointer_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
  printf("发现潜在指针：%ld 个\n", pointer_count);

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  printf("指针扫描耗时：%lld 毫秒\n", static_cast<long long>(duration.count()));

  // 第五步：构建指针链
  uint64_t target_addr = std::stoull(parser.getOptionValue("address"), nullptr, 16);
  std::vector<size_t> target_addrs;
  target_addrs.emplace_back(target_addr);

  // 扫描输出支持文本与项目原生二进制两种格式。
  std::string output_file = parser.getOptionValue("file", "pointer_chains.txt");
  std::string output_format = parser.getOptionValue("format", "txt");
  if (output_format != "txt" && output_format != "bin") {
    std::cerr << "错误: --format 只能是 txt 或 bin\n";
    return 1;
  }
  FILE *output = fopen(output_file.c_str(), output_format == "bin" ? "wb" : "w");
  if (output == nullptr) {
    std::cerr << "错误: 无法创建输出文件: " << output_file << std::endl;
    return 1;
  }

  size_t chain_count;
  if (output_format == "bin") {
    chain_count = scanner.scan_pointer_chain(
        target_addrs, max_depth, max_offset,
        parser.getIntOption("limit", 0) > 0,
        static_cast<size_t>(std::max(0, parser.getIntOption("limit", 0))), output);
  } else {
    chain_count = scanner.scan_pointer_chain_to_txt(
        target_addrs, max_depth, max_offset,
        parser.getIntOption("limit", 0) > 0,
        static_cast<size_t>(std::max(0, parser.getIntOption("limit", 0))), output);
  }
  if (fclose(output) != 0) {
    std::cerr << "错误: 输出文件关闭失败，可能存储空间不足\n";
    return 1;
  }
  printf("找到指针链：%ld 条\n", chain_count);
  printf("输出格式：%s；文件：%s\n", output_format.c_str(), output_file.c_str());

  /* 方式2: 原始二进制格式（需要二次转换）
  auto f = fopen("1", "wb+");
  auto chaincount =
      t.scan_pointer_chain(addrs, maxDepth, maxOffset, false, 0, f);
  printf("chaincount %ld\n", chaincount); // 10层 偏移500
  fclose(f);
  // 格式化输出
  chainer::cformat<size_t> t2;
  auto f2 = fopen("1", "rb+");

  printf("%ld\n", t2.format_bin_chain_data(f2, "2", false)); // 文件
  // printf("%ld\n", t2.format_bin_chain_data(f2, "2", true)); // 文件夹
  // 需要在当前目录有2文件夹

  fclose(f2);
  */
  
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc == 1) return interactive_main();
  return run_app(argc, argv);
}
