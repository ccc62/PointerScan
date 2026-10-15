#include "memtool/membase.hpp"

#include "memtool/memextend.hpp"

#include "chainer/ccscan.hpp"  // IWYU pragma: keep
#include "chainer/ccompare.hpp"  // IWYU pragma: keep
#include "chainer/ccformat.hpp"

#include "utils/cmd_parser.h"
#include <cstdint>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <sstream>
#include <filesystem>
#include <limits.h>
#include <unistd.h>
#include "utils/chain_convert.hpp"

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
std::string g_exe_dir = ".";

std::string resolve_output_path(const std::string &path) {
  if (path.empty()) return path;
  std::filesystem::path p(path);
  if (p.is_absolute()) return p.lexically_normal().string();
  return (std::filesystem::path(g_exe_dir) / p).lexically_normal().string();
}

std::string native_bin_to_text(const std::string &src, const std::string &dst) {
  FILE *in = std::fopen(src.c_str(), "rb");
  if (!in) throw std::runtime_error("无法打开原生二进制文件：" + src);
  try {
    chainer::cprog_header header{};
    if (std::fread(&header, sizeof(header), 1, in) != 1 ||
        std::strncmp(header.sign, ".bin from chainer", 17) != 0 ||
        header.size != static_cast<int>(sizeof(size_t)) || header.module_count < 0 || header.level < 0) {
      throw std::runtime_error("文件格式不正确：既不是本工具的链记录二进制，也不是可识别的原生扫描二进制");
    }
    std::rewind(in);
    chainer::cformat<size_t> formatter;
    size_t count = formatter.format_bin_chain_data(in, dst.c_str(), false);
    std::fclose(in);
    return std::to_string(count);
  } catch (...) { std::fclose(in); throw; }
}

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
  std::cout << "\n========== newscan 指针链工具 ==========\n"
            << "1. 扫描基址链\n"
            << "2. 扫描指针路径\n"
            << "3. 对比文本链文件\n"
            << "4. 对比二进制链文件\n"
            << "5. 文本转二进制\n"
            << "6. 二进制转文本\n"
            << "7. 查看命令行帮助\n"
            << "0. 退出\n";
  std::string choice = ask_text("请选择功能（0-7）", "1");
  if (choice == "0") return 0;

  std::vector<std::string> args = {"newscan"};
  auto add = [&args](const std::string &k, const std::string &v) {
    args.push_back(k); args.push_back(v);
  };

  if (choice == "1") {
    add("-p", ask_text("目标进程名称或 PID"));
    add("-a", ask_text("目标地址（十六进制，不带 0x）"));
    add("-d", ask_text("最大搜索深度", "4"));
    add("-o", ask_text("最大偏移量（十六进制，不带 0x）", "2000"));
    add("-l", ask_text("最多输出多少条结果（0 表示不限制）", "0"));
    std::string fmt = ask_text("输出格式（txt 文本 / bin 二进制）", "txt");
    add("--format", fmt);
    add("-f", ask_text("输出文件名（相对路径保存到程序所在目录）", fmt == "bin" ? "pointer_chains.bin" : "pointer_chains.txt"));
    if (ask_yes_no("是否使用 /proc/PID/mem 读取模式？", false))
      args.push_back("--io");
  } else if (choice == "2") {
    add("-p", ask_text("目标进程名称或 PID"));
    args.push_back("--path");
    add("--from", ask_text("起始地址（十六进制，不带 0x）"));
    add("--to", ask_text("目标地址（十六进制，不带 0x）"));
    add("-d", ask_text("最大搜索深度", "4"));
    add("-o", ask_text("最大偏移量（十六进制，不带 0x）", "2000"));
    add("-f", ask_text("输出文件名（相对路径保存到程序所在目录）", "pointer_paths.txt"));
  } else if (choice == "3" || choice == "4") {
    args.push_back(choice == "3" ? "--compare-txt" : "--compare-bin");
    add("--lhs", ask_text("旧版文件路径"));
    add("--rhs", ask_text("新版文件路径"));
    add("--report", ask_text("对比报告保存路径", "chain_compare.txt"));
  } else if (choice == "5" || choice == "6") {
    args.push_back(choice == "5" ? "--convert-txt-to-bin" : "--convert-bin-to-txt");
    add("--lhs", ask_text("输入文件路径"));
    add("--out", ask_text("输出文件路径", choice == "5" ? "converted.bin" : "converted.txt"));
  } else if (choice == "7") {
    args.push_back("--help");
  } else {
    std::cerr << "菜单选项无效。\n";
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
  parser.addOption({'p', "process", "目标进程名称或 PID", true, false});
  parser.addOption({'a', "address", "目标地址（十六进制，不带 0x 前缀）", true, false});
  parser.addOption({'d', "depth", "最大搜索深度", true, false, "10"});
  parser.addOption({'o', "offset", "最大偏移量（十六进制，不带 0x 前缀）", true, false, "500"});
  parser.addOption({'l', "limit", "结果限制数量", true, false, "0"});
  parser.addOption({'f', "file", "输出文件名", true, false, "pointer_chains.txt"});
  parser.addOption({0, "format", "扫描输出格式：txt（文本）或 bin（二进制）", true, false, "txt"});
  parser.addOption({0, "convert-txt-to-bin", "将文本链文件转换为紧凑链记录二进制", false, false});
  parser.addOption({0, "convert-bin-to-txt", "将二进制链文件转换为文本", false, false});
  parser.addOption({0, "out", "转换后的输出路径", true, false});
  parser.addOption({0, "compare-bin", "对比两份指针链二进制文件", false, false});
  parser.addOption({0, "compare-txt", "对比两份指针链文本文件", false, false});
  parser.addOption({0, "lhs", "旧版指针链文件路径", true, false});
  parser.addOption({0, "rhs", "新版指针链文件路径", true, false});
  parser.addOption({0, "report", "对比报告文件名", true, false,
                    "chain_compare.txt"});
  parser.addOption({'v', "verbose", "显示详细过程", false, false});
  parser.addOption({0, "io", "使用 /proc/PID/mem 方式读取内存", false, false});
  parser.addOption({0, "path", "路径扫描模式：查找两个地址之间的指针路径", false, false});
  parser.addOption({0, "from", "路径扫描的起始地址（十六进制）", true, false});
  parser.addOption({0, "to", "路径扫描的目标地址（十六进制）", true, false});
  parser.addOption({'h', "help", "显示命令行帮助", false, false});

  // 设置用法说明
  parser.setUsage("[扫描] -p <进程名/PID> -a <地址> | "
                  "[路径扫描] -p <进程名/PID> --path --from <起始地址> --to <目标地址> | "
                  "[文件对比] (--compare-bin|--compare-txt) --lhs <旧文件> --rhs <新文件> | "
                  "[格式转换] (--convert-txt-to-bin|--convert-bin-to-txt) --lhs <输入文件> --out <输出文件>");

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

  bool convert_txt_to_bin = parser.getBoolOption("convert-txt-to-bin", false);
  bool convert_bin_to_txt = parser.getBoolOption("convert-bin-to-txt", false);
  if (convert_txt_to_bin || convert_bin_to_txt) {
    if (convert_txt_to_bin && convert_bin_to_txt) {
      std::cerr << "错误：文本转二进制和二进制转文本只能选择一种。\n"; return 1;
    }
    if (!parser.hasOption("lhs") || !parser.hasOption("out")) {
      std::cerr << "错误：格式转换需要指定 --lhs 输入文件和 --out 输出文件。\n"; return 1;
    }
    std::string src = resolve_output_path(parser.getOptionValue("lhs"));
    std::string dst = resolve_output_path(parser.getOptionValue("out"));
    try {
      size_t count = 0;
      if (convert_txt_to_bin) count = chain_convert::text_to_bin(src, dst);
      else if (chain_convert::is_chain_list_bin(src)) count = chain_convert::bin_to_text(src, dst);
      else count = static_cast<size_t>(std::stoull(native_bin_to_text(src, dst)));
      std::printf("转换完成，共处理 %zu 条链：\n%s\n-> %s\n", count, src.c_str(), dst.c_str());
      return 0;
    } catch (const std::exception &ex) {
      std::cerr << "转换失败：" << ex.what() << "\n"; return 1;
    }
  }

  bool compare_bin_mode = parser.getBoolOption("compare-bin", false);
  bool compare_txt_mode = parser.getBoolOption("compare-txt", false);
  if (compare_bin_mode || compare_txt_mode) {
    if (!parser.hasOption("lhs") || !parser.hasOption("rhs")) {
      std::cerr << "错误: 对比模式需要提供 --lhs 与 --rhs 选项" << std::endl;
      return 1;
    }

    auto lhs_path = resolve_output_path(parser.getOptionValue("lhs"));
    auto rhs_path = resolve_output_path(parser.getOptionValue("rhs"));

    std::string report_path = resolve_output_path(
        parser.getOptionValue("report", "chain_compare.txt"));
    FILE *report = fopen(report_path.c_str(), "w");
    if (report == nullptr) {
      std::cerr << "警告: 无法创建报告文件: " << report_path << std::endl;
    }

    chainer::ccompare<size_t> comparer;
    chainer::bin_compare_result<size_t> compare_result;

    try {
      if (compare_bin_mode) {
        if (report != nullptr) fprintf(report, "=== 指针链二进制文件对比结果 ===\n\n");
        bool lhs_list = chain_convert::is_chain_list_bin(lhs_path);
        bool rhs_list = chain_convert::is_chain_list_bin(rhs_path);
        if (lhs_list || rhs_list) {
          std::string ltxt = resolve_output_path(".newscan_compare_lhs.tmp.txt");
          std::string rtxt = resolve_output_path(".newscan_compare_rhs.tmp.txt");
          if (lhs_list) chain_convert::bin_to_text(lhs_path, ltxt);
          else native_bin_to_text(lhs_path, ltxt);
          if (rhs_list) chain_convert::bin_to_text(rhs_path, rtxt);
          else native_bin_to_text(rhs_path, rtxt);
          compare_result = comparer.compare_txt_files(ltxt, rtxt);
          std::remove(ltxt.c_str()); std::remove(rtxt.c_str());
          compare_txt_mode = true; // custom chain-list binary uses text-signature comparison
        } else {
          compare_result = comparer.compare_bin_files(lhs_path, rhs_path, report);
        }
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
    printf("发现潜在指针：%zu 个\n", pointer_count);

    uint64_t from_addr = std::stoull(parser.getOptionValue("from"), nullptr, 16);
    uint64_t to_addr = std::stoull(parser.getOptionValue("to"), nullptr, 16);

    std::string output_file = resolve_output_path(parser.getOptionValue("file", "pointer_paths.txt"));
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
  printf("发现潜在指针：%zu 个\n", pointer_count);

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  printf("指针扫描耗时：%lld 毫秒\n", static_cast<long long>(duration.count()));

  // 第五步：构建指针链
  uint64_t target_addr = std::stoull(parser.getOptionValue("address"), nullptr, 16);
  std::vector<size_t> target_addrs;
  target_addrs.emplace_back(target_addr);

  std::string format = parser.getOptionValue("format", "txt");
  if (format != "txt" && format != "bin") {
    std::cerr << "错误：--format 只能填写 txt（文本）或 bin（二进制）。\n"; return 1;
  }
  std::string default_file = format == "bin" ? "pointer_chains.bin" : "pointer_chains.txt";
  std::string output_name = parser.hasOption("file") ? parser.getOptionValue("file") : default_file;
  std::string output_file = resolve_output_path(output_name);
  FILE *output = fopen(output_file.c_str(), format == "bin" ? "wb+" : "w+");
  if (output == nullptr) {
    std::cerr << "错误：无法创建输出文件：" << output_file << std::endl;
    return 1;
  }

  size_t chain_count = 0;
  if (format == "bin") {
    chain_count = scanner.scan_pointer_chain(target_addrs, max_depth, max_offset,
      parser.getIntOption("limit", 0) > 0,
      static_cast<size_t>(std::max(0, parser.getIntOption("limit", 0))), output);
  } else {
    chain_count = scanner.scan_pointer_chain_to_txt(target_addrs, max_depth, max_offset,
      parser.getIntOption("limit", 0) > 0,
      static_cast<size_t>(std::max(0, parser.getIntOption("limit", 0))), output);
  }
  printf("扫描完成，共找到 %zu 条基址链\n", chain_count);
  fclose(output);

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
  char exe_path[PATH_MAX + 1] = {0};
  ssize_t n = readlink("/proc/self/exe", exe_path, PATH_MAX);
  if (n > 0) {
    exe_path[n] = '\0';
    g_exe_dir = std::filesystem::path(exe_path).parent_path().string();
  } else if (argc > 0 && argv[0] != nullptr) {
    std::filesystem::path p(argv[0]);
    if (p.has_parent_path()) g_exe_dir = std::filesystem::absolute(p).parent_path().string();
    else g_exe_dir = std::filesystem::current_path().string();
  }
  if (argc == 1) return interactive_main();
  return run_app(argc, argv);
}
