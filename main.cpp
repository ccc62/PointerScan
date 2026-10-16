#include <algorithm>
#include "memtool/membase.hpp"

#include "memtool/memextend.hpp"

#include "chainer/ccscan.hpp"  // IWYU pragma: keep
#include "chainer/ccompare.hpp"  // IWYU pragma: keep
#include "chainer/chain_locator.hpp"

#include "utils/cmd_parser.h"
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <ctime>
#include <limits.h>
#include <unistd.h>
#include <cstdlib>
#include <cctype>

using namespace utils;

int main(int argc, char *argv[]);

namespace {

std::string executable_dir(const char *argv0) {
  char path[PATH_MAX + 1] = {0};
  ssize_t n = readlink("/proc/self/exe", path, PATH_MAX);
  std::string full;
  if (n > 0) {
    path[n] = '\0';
    full = path;
  } else if (argv0 && *argv0) {
    full = argv0;
  } else {
    full = ".";
  }
  const auto pos = full.find_last_of('/');
  if (pos == std::string::npos) return ".";
  if (pos == 0) return "/";
  return full.substr(0, pos);
}

std::string timestamp_now() {
  std::time_t now = std::time(nullptr);
  std::tm tm_now{};
#if defined(_WIN32)
  localtime_s(&tm_now, &now);
#else
  localtime_r(&now, &tm_now);
#endif
  char buffer[32];
  std::strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", &tm_now);
  return buffer;
}

std::string default_output_path(const char *argv0, const std::string &kind,
                                const std::string &ext = ".txt") {
  return executable_dir(argv0) + "/" + kind + "_" + timestamp_now() + ext;
}

std::string ask_line(const std::string &prompt, const std::string &default_value = "") {
  std::cout << prompt;
  if (!default_value.empty()) std::cout << " [" << default_value << "]";
  std::cout << "：";
  std::string value;
  std::getline(std::cin, value);
  if (value.empty()) return default_value;
  return value;
}

int interactive_menu(const char *argv0) {
  for (;;) {
    std::cout << "\n========== newscan 指针链分析工具 =========="
              << "\n1. 指针链扫描"
              << "\n2. 指针路径扫描"
              << "\n3. 按目标地址验证基址链"
              << "\n4. 按目标数值定位基址链"
              << "\n5. 对比文本指针链文件"
              << "\n6. 对比二进制指针链文件"
              << "\n7. 查看命令行帮助"
              << "\n0. 退出\n";
    std::string choice = ask_line("请选择功能（0-7）", "1");
    if (choice == "0") return 0;
    if (choice == "7") {
      std::vector<std::string> storage{argv0 ? argv0 : "newscan", "--help"};
      std::vector<char *> args; for (auto &x : storage) args.push_back(x.data());
      int rc = main(static_cast<int>(args.size()), args.data());
      std::cout << "\n操作结束，返回代码：" << rc << "\n";
      continue;
    }

    std::vector<std::string> storage{argv0 ? argv0 : "newscan"};
    auto add = [&](const std::string &flag, const std::string &value) {
      storage.push_back(flag); storage.push_back(value);
    };
    auto add_flag = [&](const std::string &flag) { storage.push_back(flag); };
    if (choice == "1") {
      add("--process", ask_line("目标进程名称或 PID"));
      add("--address", ask_line("目标地址（十六进制，不带 0x）"));
      add("--depth", ask_line("最大搜索深度", "4"));
      add("--offset", ask_line("最大偏移量（十六进制，不带 0x）", "2000"));
      add("--limit", ask_line("结果数量限制（0 表示不限制）", "0"));
      std::string output_format = ask_line("输出格式（txt/bin）", "txt");
      add("--output-format", output_format);
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "2") {
      add("--process", ask_line("目标进程名称或 PID"));
      add_flag("--path");
      add("--from", ask_line("路径起始地址（十六进制）"));
      add("--to", ask_line("路径目标地址（十六进制）"));
      add("--depth", ask_line("最大搜索深度", "4"));
      add("--offset", ask_line("最大偏移量（十六进制）", "2000"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "3") {
      add("--process", ask_line("目标进程名称或 PID")); add_flag("--locate-address");
      add("--chains", ask_line("基址链文件路径"));
      add("--target-address", ask_line("目标地址（十六进制，可带 0x）"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "4") {
      add("--process", ask_line("目标进程名称或 PID")); add_flag("--locate-value");
      add("--chains", ask_line("基址链文件路径"));
      add("--value", ask_line("目标数值"));
      add("--value-type", ask_line("数值类型（i32/u32/i64/u64/f32/f64）", "i32"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "5" || choice == "6") {
      add_flag(choice == "5" ? "--compare-txt" : "--compare-bin");
      add("--lhs", ask_line("旧版文件路径"));
      add("--rhs", ask_line("新版文件路径"));
    } else {
      std::cout << "无效选项，请输入 0-7。\n";
      continue;
    }
    std::vector<char *> args;
    for (auto &x : storage) args.push_back(x.data());
    int rc = main(static_cast<int>(args.size()), args.data());
    std::cout << "\n操作结束，返回代码：" << rc << "\n";
  }
}

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

}  // namespace

int main(int argc, char *argv[]) {
  if (argc == 1) return interactive_menu(argv[0]);
  // 创建命令行解析器
  CommandLineParser parser("newscan", "高性能内存指针链分析工具");

  // 添加命令行选项
  parser.addOption({'p', "process", "目标进程名称或PID", true, false});
  parser.addOption({'a', "address", "目标地址(16进制，不带0x前缀)", true, false});
  parser.addOption({'d', "depth", "最大搜索深度", true, false, "10"});
  parser.addOption({'o', "offset", "最大偏移量(16进制，不带0x前缀)", true, false, "500"});
  parser.addOption({'l', "limit", "结果限制数量", true, false, "0"});
  parser.addOption({'f', "file", "输出文件路径（默认保存到程序所在目录并附加时间）", true, false});
  parser.addOption({0, "output-format", "扫描输出格式：txt（默认）或 bin（二进制）", true, false, "txt"});
  parser.addOption({0, "compare-bin", "比较两份指针链二进制文件", false, false});
  parser.addOption({0, "compare-txt", "比较两份指针链文本文件", false, false});
  parser.addOption({0, "lhs", "旧版指针链二进制文件路径", true, false});
  parser.addOption({0, "rhs", "新版指针链二进制文件路径", true, false});
  parser.addOption({0, "report", "对比报告路径（默认保存到程序所在目录并附加时间）", true, false});
  parser.addOption({'v', "verbose", "详细输出模式", false, false});
  parser.addOption({0, "io", "使用/proc/pid/mem IO读取内存(解决不可读内存问题)", false, false});
  parser.addOption({0, "path", "路径扫描模式：查找两个地址之间的指针路径", false, false});
  parser.addOption({0, "from", "路径扫描的源地址(16进制)", true, false});
  parser.addOption({0, "to", "路径扫描的目标地址(16进制)", true, false});
  parser.addOption({0, "locate-address", "按目标地址验证基址链文件", false, false});
  parser.addOption({0, "locate-value", "按目标数值验证基址链文件", false, false});
  parser.addOption({0, "chains", "待验证的文本基址链文件", true, false});
  parser.addOption({0, "target-address", "目标地址(十六进制，可带0x)", true, false});
  parser.addOption({0, "value", "要匹配的目标数值", true, false});
  parser.addOption({0, "value-type", "数值类型: i32/u32/i64/u64/f32/f64", true, false, "i32"});
  parser.addOption({0, "locate-report", "定位报告路径（默认保存到程序所在目录并附加时间）", true, false});
  parser.addOption({'h', "help", "显示帮助信息", false, false});

  // 设置用法说明
  parser.setUsage("[扫描] -p <进程名/PID> -a <地址> | "
                  "[路径] -p <进程名/PID> --path --from <源地址> --to <目标地址> | "
                  "[定位] (--locate-address|--locate-value) -p <进程> --chains <链文件> ... | "
                  "[对比] (--compare-bin|--compare-txt) --lhs <旧文件> --rhs <新文件> | "
                  "[扫描输出] --output-format txt|bin（默认 txt）");

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

  std::string output_format = parser.getOptionValue("output-format", "txt");
  std::transform(output_format.begin(), output_format.end(), output_format.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (output_format != "txt" && output_format != "bin") {
    std::cerr << "错误: --output-format 仅支持 txt 或 bin" << std::endl;
    return 1;
  }

  // ============ 基址链文件定位/验证模式（逐行流式处理，适合超大文件） ============
  bool locate_address_mode = parser.getBoolOption("locate-address", false);
  bool locate_value_mode = parser.getBoolOption("locate-value", false);
  if (locate_address_mode || locate_value_mode) {
    if (locate_address_mode && locate_value_mode) {
      std::cerr << "错误: --locate-address 与 --locate-value 只能选择一个" << std::endl;
      return 1;
    }
    if (!parser.hasOption("process") || !parser.hasOption("chains")) {
      std::cerr << "错误: 定位模式需要 -p/--process 和 --chains" << std::endl;
      return 1;
    }
    uint64_t target_address = 0;
    if (locate_address_mode) {
      if (!parser.hasOption("target-address") ||
          !chainer::locator::parse_hex(parser.getOptionValue("target-address"), target_address)) {
        std::cerr << "错误: --locate-address 需要有效的 --target-address 十六进制地址" << std::endl;
        return 1;
      }
    } else if (!parser.hasOption("value")) {
      std::cerr << "错误: --locate-value 需要 --value" << std::endl;
      return 1;
    }

    std::string proc = parser.getOptionValue("process");
    int pid = -1;
    try { pid = std::stoi(proc); }
    catch (...) { pid = memtool::base::get_pid(proc.c_str()); }
    if (pid <= 0) { std::cerr << "错误: 无法找到目标进程: " << proc << std::endl; return 1; }
    memtool::base::target_pid = pid;
    if (parser.getBoolOption("io", false)) memtool::base::mode = memtool::read_mode::PROC_MEM_IO;

    const std::string chain_path = parser.getOptionValue("chains");
    std::ifstream input(chain_path);
    if (!input) { std::cerr << "错误: 无法打开链文件: " << chain_path << std::endl; return 1; }
    std::string report_path = parser.getOptionValue("locate-report", "");
    if (report_path.empty()) report_path = default_output_path(argv[0], locate_address_mode ? "地址定位报告" : "数值定位报告");
    std::ofstream report(report_path, std::ios::out | std::ios::trunc);
    if (!report) { std::cerr << "错误: 无法创建报告: " << report_path << std::endl; return 1; }

    std::vector<chainer::locator::Mapping> maps;
    std::string maps_error;
    if (!chainer::locator::read_maps(pid, maps, maps_error)) {
      std::cerr << "错误: " << maps_error << std::endl; return 1;
    }
    const std::string value_type = parser.getOptionValue("value-type", "i32");
    const std::string wanted_value = parser.getOptionValue("value", "");
    if (locate_value_mode && value_type != "i32" && value_type != "int32" &&
        value_type != "u32" && value_type != "uint32" && value_type != "i64" &&
        value_type != "int64" && value_type != "u64" && value_type != "uint64" &&
        value_type != "f32" && value_type != "float" && value_type != "f64" && value_type != "double") {
      std::cerr << "错误: 不支持的 --value-type: " << value_type << std::endl; return 1;
    }

    report << "=== 基址链文件定位报告 ===\n目标 PID: " << pid << "\n模式: "
           << (locate_address_mode ? "目标地址匹配" : "目标数值匹配") << "\n";
    if (locate_address_mode) report << "目标地址: 0x" << std::hex << std::uppercase << target_address << std::dec << "\n";
    else report << "目标数值: " << wanted_value << "\n数值类型: " << value_type << "\n";
    report << "\n";

    uint64_t total = 0, parsed = 0, matched = 0, invalid = 0, unreadable = 0, module_missing = 0;
    std::string line;
    while (std::getline(input, line)) {
      ++total;
      chainer::locator::ParsedChain chain;
      std::string error;
      if (!chainer::locator::parse_chain(line, chain, error)) {
        if (!chainer::locator::trim(line).empty() && chainer::locator::trim(line)[0] != '#') ++invalid;
        continue;
      }
      ++parsed;
      uint64_t module_base = 0;
      if (!chainer::locator::resolve_module_base(chain, maps, module_base, error)) {
        ++module_missing; continue;
      }
      uint64_t final_address = 0;
      if (!chainer::locator::resolve_chain(chain, module_base, final_address, error)) {
        ++unreadable; continue;
      }
      bool hit = false;
      std::string actual_value;
      if (locate_address_mode) hit = (final_address == target_address);
      else hit = chainer::locator::value_matches(final_address, value_type, wanted_value, actual_value);
      if (hit) {
        ++matched;
        report << "命中: " << chain.original << "\n最终地址: 0x" << std::hex << std::uppercase
               << final_address << std::dec;
        if (locate_value_mode) report << "\n读取数值: " << actual_value;
        report << "\n模块基址: 0x" << std::hex << std::uppercase << module_base << std::dec << "\n\n";
      }
      if (total % 1000000 == 0) {
        std::cerr << "已处理 " << total << " 行，解析 " << parsed << " 条，命中 " << matched << " 条\n";
      }
    }
    report << "--- 统计 ---\n总行数: " << total << "\n有效链: " << parsed
           << "\n命中: " << matched << "\n格式无效: " << invalid
           << "\n模块未找到: " << module_missing << "\n解引用失败/数值不可读: " << unreadable << "\n";
    report.close();
    std::cout << "定位完成。总行数=" << total << "，有效链=" << parsed << "，命中=" << matched
              << "，格式无效=" << invalid << "，模块未找到=" << module_missing
              << "，解引用失败/数值不可读=" << unreadable << "\n报告: " << report_path << std::endl;
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

    std::string report_path = parser.getOptionValue("report", "");
    if (report_path.empty()) report_path = default_output_path(argv[0], compare_txt_mode ? "文本对比报告" : "二进制对比报告");
    FILE *report = fopen(report_path.c_str(), "w");
    if (report == nullptr) {
      std::cerr << "警告: 无法创建报告文件: " << report_path << std::endl;
    }

    chainer::ccompare<size_t> comparer;
    chainer::bin_compare_result<size_t> compare_result;

    try {
      if (compare_bin_mode) {
        // 二进制对比：匹配链直接流式写入 report，不存储在内存中
        if (report != nullptr) {
          fprintf(report, "=== 指针链二进制文件对比结果 ===\n\n");
        }
        compare_result = comparer.compare_bin_files(lhs_path, rhs_path, report);
      } else {
        compare_result = comparer.compare_txt_files(lhs_path, rhs_path);
      }
    } catch (const std::exception &ex) {
      if (report != nullptr) fclose(report);
      std::cerr << "错误: " << ex.what() << std::endl;
      return 1;
    }

    // 写入统计摘要
    if (report != nullptr) {
      if (compare_txt_mode) {
        fprintf(report, "=== 指针链文本文件对比结果 ===\n\n");
      }

      // 二进制模式下链详情已在比较过程中写入，这里追加统计
      fprintf(report, "--- 统计 ---\n");
      fprintf(report, "旧文件链数量: %zu\n", compare_result.lhs_total);
      fprintf(report, "新文件链数量: %zu\n", compare_result.rhs_total);
      fprintf(report, "保持不变链数量: %zu\n", compare_result.unchanged);
      fprintf(report, "\n");

      if (compare_txt_mode) {
        // 文本对比：链存储在内存中，在此输出
        if (compare_result.modules.empty()) {
          fprintf(report, "未找到共同存在的指针链。\n");
        } else {
          for (const auto &diff : compare_result.modules) {
            fprintf(report, "模块: %s[%d]\n", diff.module_name.c_str(),
                    diff.module_index);
            if (!diff.common.empty()) {
              fprintf(report, "  保持不变的链:\n");
              for (const auto &chain : diff.common) {
                fprintf(report, "    = %s\n",
                        format_chain_line(diff.module_name, diff.module_index,
                                          chain).c_str());
              }
            }
            fprintf(report, "\n");
          }
        }
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

    printf("目标进程: %s -> PID %d\n", target_process.c_str(), target_pid);

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

    size_t pointer_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
    printf("发现候选指针数量: %ld\n", pointer_count);

    uint64_t from_addr = std::stoull(parser.getOptionValue("from"), nullptr, 16);
    uint64_t to_addr = std::stoull(parser.getOptionValue("to"), nullptr, 16);

    std::string output_file = parser.getOptionValue("file", "");
    if (output_file.empty()) output_file = default_output_path(argv[0], "路径扫描结果");
    FILE *output = fopen(output_file.c_str(), "w");
    if (output == nullptr) {
      std::cerr << "错误: 无法创建输出文件: " << output_file << std::endl;
      return 1;
    }

    size_t path_count = scanner.scan_pointer_path(
        static_cast<size_t>(from_addr), static_cast<size_t>(to_addr),
        max_depth, max_offset, output);
    printf("找到的指针路径数量: %ld\n", path_count);
    fclose(output);
    printf("路径扫描结果已保存至: %s\n", output_file.c_str());

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

  printf("目标进程: %s -> PID %d\n", target_process.c_str(), target_pid);

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

  // 第四步：扫描潜在指针
  auto start_time = std::chrono::high_resolution_clock::now();
  // 参数：起始地址=0, 结束地址=0(不限制), 全扫描=false, 缓冲区数=10, 缓冲区大小=1MB
  size_t pointer_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
  printf("发现候选指针数量: %ld\n", pointer_count);

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  printf("扫描耗时: %lld 毫秒\n", static_cast<long long>(duration.count()));

  // 第五步：构建指针链
  uint64_t target_addr = std::stoull(parser.getOptionValue("address"), nullptr, 16);
  std::vector<size_t> target_addrs;
  target_addrs.emplace_back(target_addr);

  // 输出格式：文本（默认）或项目原生二进制格式（可用于 --compare-bin）
  std::string output_file = parser.getOptionValue("file", "");
  if (output_file.empty()) {
    output_file = default_output_path(argv[0], "指针链扫描结果",
                                      output_format == "bin" ? ".bin" : ".txt");
  }
  FILE *output = fopen(output_file.c_str(), output_format == "bin" ? "wb" : "w");
  if (output == nullptr) {
    std::cerr << "错误: 无法创建输出文件: " << output_file << std::endl;
    return 1;
  }

  size_t chain_count = 0;
  if (output_format == "bin") {
    chain_count = scanner.scan_pointer_chain(
        target_addrs, max_depth, max_offset, false, 0, output);
  } else {
    chain_count = scanner.scan_pointer_chain_to_txt(
        target_addrs, max_depth, max_offset, false, 0, output);
  }
  if (fclose(output) != 0) {
    std::cerr << "错误: 写入输出文件时发生错误: " << output_file << std::endl;
    return 1;
  }
  printf("输出格式: %s\n", output_format == "bin" ? "二进制" : "文本");
  printf("找到的指针链数量: %ld\n", chain_count);
  printf("扫描结果已保存至: %s\n", output_file.c_str());

  
  return 0;
}