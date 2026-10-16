#include <algorithm>
#include "memtool/membase.hpp"

#include "memtool/memextend.hpp"

#include "chainer/ccscan.hpp"  // IWYU pragma: keep
#include "chainer/ccompare.hpp"  // IWYU pragma: keep
#include "chainer/chain_locator.hpp"
#include "chainer/cformat.hpp"

#include "utils/cmd_parser.h"
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <fstream>
#include <unordered_map>
#include <ctime>
#include <limits.h>
#include <unistd.h>
#include <cstdlib>
#include <cctype>
#include <sys/stat.h>
#include <cstring>

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
  // Keep the prompt on its own line. On Android terminal emulators, backspace
  // can otherwise visually erase the prompt when the input line is empty.
  std::cout << "\n" << prompt;
  if (!default_value.empty()) std::cout << " [默认: " << default_value << "]";
  std::cout << "\n> " << std::flush;

  std::string value;
  if (!std::getline(std::cin, value)) {
    std::cin.clear();
    return default_value;
  }
  // Ignore a trailing carriage return if input comes from a CRLF terminal.
  if (!value.empty() && value.back() == '\r') value.pop_back();
  if (value.empty()) return default_value;
  return value;
}

template <typename T>
bool validate_binary_for_conversion(FILE *input, const std::string &path,
                                    std::string &error) {
  if (input == nullptr) {
    error = "无法打开输入文件: " + path;
    return false;
  }
  struct stat st {};
  if (fstat(fileno(input), &st) != 0 || st.st_size < 0) {
    error = "无法读取文件大小: " + path;
    return false;
  }
  const uint64_t file_size = static_cast<uint64_t>(st.st_size);
  if (file_size < sizeof(chainer::cprog_header)) {
    error = "文件太小，不是有效的指针链二进制文件: " + path;
    return false;
  }
  if (fseeko(input, 0, SEEK_SET) != 0) {
    error = "无法定位输入文件: " + path;
    return false;
  }

  chainer::cprog_header header{};
  if (fread(&header, sizeof(header), 1, input) != 1) {
    error = "无法读取二进制文件头: " + path;
    return false;
  }
  uint64_t offset = sizeof(header);
  constexpr char signature[] = ".bin from chainer";
  if (std::strncmp(header.sign, signature, sizeof(signature) - 1) != 0) {
    error = "文件签名不匹配，不是本工具支持的指针链二进制格式: " + path;
    return false;
  }
  if (header.size != static_cast<int>(sizeof(T))) {
    error = "指针宽度不匹配（文件为 " + std::to_string(header.size * 8) +
            " 位，当前解析器为 " + std::to_string(sizeof(T) * 8) + " 位）: " + path;
    return false;
  }
  if (header.module_count < 0 || header.level < 0 || header.level > 128) {
    error = "二进制文件头字段非法: " + path;
    return false;
  }

  auto has_bytes = [&](uint64_t bytes) {
    return offset <= file_size && bytes <= file_size - offset;
  };
  for (int i = 0; i < header.module_count; ++i) {
    if (!has_bytes(sizeof(chainer::cprog_sym<T>))) {
      error = "模块符号表不完整，二进制文件可能已损坏: " + path;
      return false;
    }
    chainer::cprog_sym<T> sym{};
    if (fread(&sym, sizeof(sym), 1, input) != 1) {
      error = "读取模块符号表失败: " + path;
      return false;
    }
    offset += sizeof(sym);
    if (sym.pointer_count < 0 || sym.level < 0 || sym.level > header.level ||
        std::memchr(sym.name, '\0', sizeof(sym.name)) == nullptr) {
      error = "模块符号表字段非法: " + path;
      return false;
    }
    const uint64_t bytes = static_cast<uint64_t>(sym.pointer_count) * sizeof(chainer::cprog_data<T>);
    if (!has_bytes(bytes) || fseeko(input, static_cast<off_t>(offset + bytes), SEEK_SET) != 0) {
      error = "模块指针数据不完整，二进制文件可能已损坏: " + path;
      return false;
    }
    offset += bytes;
  }

  for (int i = 0; i < header.level; ++i) {
    if (!has_bytes(sizeof(chainer::cprog_llen))) {
      error = "层级数据头不完整，二进制文件可能已损坏: " + path;
      return false;
    }
    chainer::cprog_llen level{};
    if (fread(&level, sizeof(level), 1, input) != 1) {
      error = "读取层级数据头失败: " + path;
      return false;
    }
    offset += sizeof(level);
    if (level.level < 0 || level.level >= header.level) {
      error = "层级编号非法，二进制文件可能已损坏: " + path;
      return false;
    }
    const uint64_t bytes = static_cast<uint64_t>(level.count) * sizeof(chainer::cprog_data<T>);
    if (!has_bytes(bytes) || fseeko(input, static_cast<off_t>(offset + bytes), SEEK_SET) != 0) {
      error = "层级指针数据不完整，二进制文件可能已损坏: " + path;
      return false;
    }
    offset += bytes;
  }
  if (offset != file_size) {
    error = "二进制文件长度与内部结构不一致，可能不是受支持的格式: " + path;
    return false;
  }
  return fseeko(input, 0, SEEK_SET) == 0;
}

bool terminal_color_enabled() {
  return ::isatty(STDOUT_FILENO) && std::getenv("NO_COLOR") == nullptr;
}

std::string paint(const std::string &text, const char *code) {
  if (!terminal_color_enabled()) return text;
  return std::string("\033[") + code + "m" + text + "\033[0m";
}

void print_module_map_table(pid_t pid, const std::string &filter) {
  std::vector<chainer::locator::Mapping> maps;
  std::string error;
  if (!chainer::locator::read_maps(pid, maps, error)) {
    std::cerr << paint("[失败] ", "31;1") << error << "\n";
    return;
  }
  if (maps.empty()) {
    std::cout << paint("没有读取到任何映射区域。\n", "33");
    return;
  }

  // Match the chain locator's indexing rule: module index is based on unique
  // load bases, while :bss indices are based on associated anonymous BSS maps.
  std::map<std::string, uint64_t> module_bases;
  std::map<std::string, std::set<uint64_t>> bss_bases;
  std::vector<std::string> labels(maps.size());
  for (size_t i = 0; i < maps.size(); ++i) {
    const auto &m = maps[i];
    if (!m.path.empty() && m.path[0] == '/' && m.basename.size()) {
      const uint64_t base = m.start >= m.file_offset ? m.start - m.file_offset : m.start;
      auto it = module_bases.find(m.basename);
      if (it == module_bases.end() || base < it->second) module_bases[m.basename] = base;
    }
  }
  for (size_t i = 0; i < maps.size(); ++i) {
    if (maps[i].path.find("[anon:.bss]") == std::string::npos) continue;
    for (size_t j = i; j-- > 0;) {
      if (maps[j].basename.size() && !maps[j].path.empty() && maps[j].path[0] == '/' ) {
        bss_bases[maps[j].basename].insert(maps[i].start);
        break;
      }
      if (!maps[j].path.empty() && maps[j].path[0] == '/') break;
    }
  }
  std::map<std::string, std::map<uint64_t, size_t>> module_index, bss_index;
  for (const auto &kv : module_bases) module_index[kv.first][kv.second] = 1;
  for (const auto &kv : bss_bases) {
    size_t idx = 1;
    for (uint64_t base : kv.second) bss_index[kv.first][base] = idx++;
  }

  size_t shown = 0;
  std::cout << "\n" << paint("模块映射查询", "36;1") << "  "
            << paint("PID " + std::to_string(pid), "1") << "\n";
  if (!filter.empty()) std::cout << "筛选关键字: " << filter << "\n";
  std::cout << paint("起始地址             - 结束地址           权限  文件偏移           模块标识 / 路径", "1;36") << "\n";
  std::cout << std::string(100, '-') << "\n";
  for (size_t i = 0; i < maps.size(); ++i) {
    const auto &m = maps[i];
    std::string label = m.path.empty() ? "[匿名映射]" : m.path;
    if (m.path.find("[anon:.bss]") != std::string::npos) {
      std::string owner;
      for (size_t j = i; j-- > 0;) {
        if (!maps[j].basename.empty() && !maps[j].path.empty() && maps[j].path[0] == '/') {
          owner = maps[j].basename; break;
        }
        if (!maps[j].path.empty() && maps[j].path[0] == '/') break;
      }
      if (!owner.empty() && bss_index[owner].count(m.start))
        label = owner + ":bss[" + std::to_string(bss_index[owner][m.start]) + "]  " + m.path;
    } else if (!m.basename.empty() && !m.path.empty() && m.path[0] == '/') {
      const uint64_t base = m.start >= m.file_offset ? m.start - m.file_offset : m.start;
      auto mi = module_index[m.basename].find(module_bases[m.basename]);
      if (mi != module_index[m.basename].end())
        label = m.basename + "[1]  " + m.path;
    }
    if (!filter.empty() && label.find(filter) == std::string::npos && m.path.find(filter) == std::string::npos)
      continue;
    std::ostringstream row;
    row << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << m.start
        << " - 0x" << std::setw(16) << m.end << std::dec << std::setfill(' ')
        << "  " << std::setw(4) << std::left << m.perms << std::right
        << "  0x" << std::hex << std::uppercase << std::setw(12) << m.file_offset << std::dec
        << "  " << label;
    std::cout << row.str() << "\n";
    ++shown;
  }
  std::cout << std::string(100, '-') << "\n"
            << "匹配映射区域: " << shown << " / " << maps.size() << "\n"
            << paint("提示：模块基址按当前定位器规则取同名文件映射的最低候选基址；:bss 为关联的匿名 BSS 映射。", "2") << "\n";
}

int interactive_menu(const char *argv0) {
  std::string last_process;
  for (;;) {
    std::cout << "\n"
              << paint("╭──────────────────────────────────────────────────────────────╮", "36;1") << "\n"
              << paint("│", "36;1") << "  " << paint("NEWSCAN", "36;1") << "  " << paint("指针链分析工具", "1;37")
              << "                         " << paint("ARM64 / C++17", "2") << " " << paint("│", "36;1") << "\n"
              << paint("├──────────────────────────────────────────────────────────────┤", "36;1") << "\n"
              << paint("│  01  指针链扫描       │  02  指针路径扫描                   │", "37") << "\n"
              << paint("│  03  按地址验证基址链 │  04  按数值定位基址链               │", "37") << "\n"
              << paint("│  05  对比文本链文件   │  06  对比二进制链文件               │", "37") << "\n"
              << paint("│  07  二进制转文本     │  08  模块映射查询                   │", "37") << "\n"
              << paint("│  09  命令行帮助       │  00  退出                           │", "37") << "\n"
              << paint("╰──────────────────────────────────────────────────────────────╯", "36;1") << "\n"
              << paint("选择功能编号 · 回车默认执行指针链扫描", "2") << "\n";
    std::string choice = ask_line("功能编号（0-9）", "1");
    if (choice == "0") {
      std::cout << paint("再见，祝你调试顺利！\n", "32;1");
      return 0;
    }
    if (choice == "9") {
      std::vector<std::string> storage{argv0 ? argv0 : "newscan", "--help"};
      std::vector<char *> args; for (auto &x : storage) args.push_back(x.data());
      int rc = main(static_cast<int>(args.size()), args.data());
      std::cout << "\n" << paint("操作结束", "32;1") << " · 返回代码：" << rc << "\n";
      continue;
    }

    std::vector<std::string> storage{argv0 ? argv0 : "newscan"};
    auto add = [&](const std::string &flag, const std::string &value) {
      storage.push_back(flag); storage.push_back(value);
    };
    auto add_flag = [&](const std::string &flag) { storage.push_back(flag); };
    auto ask_process = [&]() {
      std::string value = ask_line("目标进程名称或 PID", last_process);
      if (!value.empty()) last_process = value;
      return value;
    };
    if (choice == "1") {
      add("--process", ask_process());
      add("--address", ask_line("目标地址（十六进制，不带 0x）"));
      add("--depth", ask_line("最大搜索深度", "4"));
      add("--offset", ask_line("最大偏移量（十六进制，不带 0x）", "2000"));
      add("--limit", ask_line("结果数量限制（0 表示不限制）", "0"));
      std::string output_format = ask_line("输出格式（txt/bin）", "txt");
      add("--output-format", output_format);
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "2") {
      add("--process", ask_process());
      add_flag("--path");
      add("--from", ask_line("路径起始地址（十六进制）"));
      add("--to", ask_line("路径目标地址（十六进制）"));
      add("--depth", ask_line("最大搜索深度", "4"));
      add("--offset", ask_line("最大偏移量（十六进制）", "2000"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "3") {
      add("--process", ask_process()); add_flag("--locate-address");
      add("--chains", ask_line("基址链文件路径"));
      add("--target-address", ask_line("目标地址（十六进制，可带 0x）"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "4") {
      add("--process", ask_process()); add_flag("--locate-value");
      add("--chains", ask_line("基址链文件路径"));
      add("--value", ask_line("目标数值"));
      add("--value-type", ask_line("数值类型（i32/u32/i64/u64/f32/f64）", "i32"));
      if (ask_line("是否使用 /proc/PID/mem 读取模式？（y/N）", "N") == "y") add_flag("--io");
    } else if (choice == "5" || choice == "6") {
      add_flag(choice == "5" ? "--compare-txt" : "--compare-bin");
      add("--lhs", ask_line("旧版文件路径"));
      add("--rhs", ask_line("新版文件路径"));
    } else if (choice == "7") {
      add_flag("--convert-bin-to-txt");
      add("--input", ask_line("二进制指针链文件路径"));
      add("--report", ask_line("输出文本文件路径（留空则自动命名）"));
    } else if (choice == "8") {
      add_flag("--module-maps");
      add("--process", ask_process());
      add("--filter", ask_line("模块名/路径筛选（留空显示全部）", ""));
    } else {
      std::cout << paint("无效选项，请输入 0-9。\n", "31;1");
      continue;
    }
    std::vector<char *> args;
    for (auto &x : storage) args.push_back(x.data());
    int rc = main(static_cast<int>(args.size()), args.data());
    std::cout << "\n----------------------------------------------\n"
                << "操作结束，返回代码：" << rc << "\n";
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
  parser.addOption({0, "convert-bin-to-txt", "将本工具二进制指针链文件转换为文本", false, false});
  parser.addOption({0, "module-maps", "查询目标进程的模块映射地址、权限和文件偏移", false, false});
  parser.addOption({0, "filter", "模块映射查询筛选关键字（模块名或路径子串）", true, false});
  parser.addOption({0, "input", "二进制转文本的输入文件路径", true, false});
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
  parser.addOption({'h', "help", "显示帮助信息", false, false});

  // 设置用法说明
  parser.setUsage("[扫描] -p <进程名/PID> -a <地址> | "
                  "[路径] -p <进程名/PID> --path --from <源地址> --to <目标地址> | "
                  "[定位] (--locate-address|--locate-value) -p <进程> --chains <链文件> ... | "
                  "[对比] (--compare-bin|--compare-txt) --lhs <旧文件> --rhs <新文件> | "
                  "[转换] --convert-bin-to-txt --input <二进制文件> [--report <文本文件>] | "
                  "[模块映射] --module-maps -p <进程名/PID> [--filter <关键字>] | "
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

  if (parser.getBoolOption("module-maps", false)) {
    if (!parser.hasOption("process")) {
      std::cerr << "错误: 模块映射查询需要 -p/--process 指定进程名称或 PID\n";
      return 1;
    }
    const std::string proc = parser.getOptionValue("process");
    int pid = -1;
    try {
      size_t used = 0;
      int parsed = std::stoi(proc, &used);
      if (used == proc.size()) pid = parsed;
      else pid = memtool::base::get_pid(proc.c_str());
    } catch (...) {
      pid = memtool::base::get_pid(proc.c_str());
    }
    if (pid <= 0) {
      std::cerr << "错误: 无法找到目标进程: " << proc << "\n";
      return 1;
    }
    print_module_map_table(pid, parser.getOptionValue("filter", ""));
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

    std::string output_path = parser.getOptionValue("file", "");
    if (output_path.empty()) {
      output_path = default_output_path(argv[0], locate_value_mode ? "数值定位命中链" : "地址定位命中链");
    }
    std::ofstream output(output_path, std::ios::out | std::ios::trunc);
    if (!output) {
      std::cerr << "错误: 无法创建命中链文件: " << output_path << std::endl;
      return 1;
    }

    uint64_t total_lines = 0;
    uint64_t valid_chains = 0;
    uint64_t hits = 0;
    uint64_t invalid_format = 0;
    uint64_t module_not_found = 0;
    uint64_t dereference_failed = 0;
    uint64_t single_hit_address = 0;
    uint64_t single_hit_module_base = 0;
    std::string single_hit_value;

    std::string line;
    while (std::getline(input, line)) {
      ++total_lines;
      chainer::locator::ParsedChain chain;
      std::string error;
      if (!chainer::locator::parse_chain(line, chain, error)) {
        // Ignore blank lines and comments; count only malformed content.
        const std::string trimmed = chainer::locator::trim(line);
        if (!trimmed.empty() && trimmed[0] != '#') ++invalid_format;
        continue;
      }
      ++valid_chains;

      uint64_t module_base = 0;
      if (!chainer::locator::resolve_module_base(chain, maps, module_base, error)) {
        ++module_not_found;
        continue;
      }

      uint64_t final_address = 0;
      if (!chainer::locator::resolve_chain(chain, module_base, final_address, error)) {
        ++dereference_failed;
        continue;
      }

      bool hit = false;
      std::string actual_value;
      if (locate_address_mode) {
        hit = (final_address == target_address);
      } else {
        hit = chainer::locator::value_matches(final_address, value_type, wanted_value, actual_value);
        if (!hit) {
          // A readable value that differs from the target is a normal miss,
          // not a read/de-reference failure.
          std::string readable_value;
          if (!chainer::locator::read_typed_value(final_address, value_type, readable_value)) {
            ++dereference_failed;
          }
        }
      }

      if (hit) {
        output << chain.module;
        if (chain.bss) output << ":bss";
        if (chain.occurrence > 0) output << "[" << chain.occurrence << "]";
        if (!chain.offsets.empty()) {
          output << " + 0x" << std::hex << std::uppercase << chain.offsets[0] << std::dec;
          for (size_t i = 1; i < chain.offsets.size(); ++i) {
            output << " -> + 0x" << std::hex << std::uppercase << chain.offsets[i] << std::dec;
          }
        }
        output << '\n';
        ++hits;
        if (hits == 1) {
          single_hit_address = final_address;
          single_hit_module_base = module_base;
          single_hit_value = actual_value;
        }
      }
    }
    output.close();

    // Keep terminal output concise: only print the run summary, never each hit chain.
    std::cout << "=== 基址链文件定位报告 ===\n"
              << "目标 PID: " << pid << "\n"
              << "模式: " << (locate_value_mode ? "目标数值匹配" : "目标地址匹配") << "\n";
    if (locate_value_mode) {
      std::cout << "目标数值: " << wanted_value << "\n"
                << "数值类型: " << value_type << "\n";
    } else {
      std::cout << "目标地址: 0x" << std::hex << std::uppercase << target_address
                << std::dec << "\n";
    }
    if (hits == 1) {
      std::cout << "最终地址: 0x" << std::hex << std::uppercase << single_hit_address << std::dec << "\n";
      if (locate_value_mode) std::cout << "读取数值: " << single_hit_value << "\n";
      std::cout << "模块基址: 0x" << std::hex << std::uppercase << single_hit_module_base << std::dec << "\n";
    }
    std::cout << "命中链文件: " << output_path << "\n"
              << "\n--- 统计 ---\n"
              << "总行数: " << total_lines
              << " | 有效链: " << valid_chains
              << " | 命中: " << hits
              << " | 格式无效: " << invalid_format
              << " | 模块未找到: " << module_not_found
              << " | 解引用失败/数值不可读: " << dereference_failed
              << std::endl;
    return 0;
  }

  bool convert_bin_to_txt = parser.getBoolOption("convert-bin-to-txt", false);
  if (convert_bin_to_txt) {
    if (!parser.hasOption("input")) {
      std::cerr << "错误: 二进制转文本需要提供 --input 输入文件路径" << std::endl;
      return 1;
    }
    const std::string input_path = parser.getOptionValue("input");
    std::string output_path = parser.getOptionValue("report", "");
    if (output_path.empty()) output_path = default_output_path(argv[0], "二进制转文本结果", ".txt");
    if (input_path == output_path) {
      std::cerr << "错误: 输入文件与输出文件不能是同一路径" << std::endl;
      return 1;
    }

    FILE *input = fopen(input_path.c_str(), "rb");
    if (!input) {
      std::cerr << "错误: 无法打开二进制文件: " << input_path << std::endl;
      return 1;
    }
    chainer::cprog_header header{};
    if (fread(&header, sizeof(header), 1, input) != 1 ||
        std::strncmp(header.sign, ".bin from chainer", sizeof(".bin from chainer") - 1) != 0) {
      fclose(input);
      std::cerr << "错误: 输入文件不是本工具支持的指针链二进制文件" << std::endl;
      return 1;
    }
    if (fseeko(input, 0, SEEK_SET) != 0) {
      fclose(input);
      std::cerr << "错误: 无法重置二进制文件读取位置" << std::endl;
      return 1;
    }

    std::string validation_error;
    bool valid = false;
    if (header.size == 8) valid = validate_binary_for_conversion<size_t>(input, input_path, validation_error);
    else if (header.size == 4) valid = validate_binary_for_conversion<uint32_t>(input, input_path, validation_error);
    else validation_error = "不支持的指针宽度: " + std::to_string(header.size);
    if (!valid) {
      fclose(input);
      std::cerr << "错误: " << validation_error << std::endl;
      return 1;
    }

    FILE *output = fopen(output_path.c_str(), "w");
    if (!output) {
      fclose(input);
      std::cerr << "错误: 无法创建文本输出文件: " << output_path << std::endl;
      return 1;
    }
    size_t converted = 0;
    try {
      if (header.size == 8) {
        chainer::format<size_t> formatter;
        converted = formatter.format_bin_chain_data(input, output);
      } else {
        chainer::format<uint32_t> formatter;
        converted = formatter.format_bin_chain_data(input, output);
      }
    } catch (const std::exception &ex) {
      fclose(input);
      fclose(output);
      std::cerr << "错误: 二进制转文本失败: " << ex.what() << std::endl;
      return 1;
    }
    bool output_ok = (fflush(output) == 0 && ferror(output) == 0);
    fclose(input);
    if (fclose(output) != 0) output_ok = false;
    if (!output_ok) {
      std::cerr << "错误: 写入文本文件失败: " << output_path << std::endl;
      return 1;
    }
    std::cout << "二进制转文本完成\n"
              << "输入文件: " << input_path << "\n"
              << "输出文件: " << output_path << "\n"
              << "转换链数: " << converted << std::endl;
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
        compare_result = comparer.compare_bin_files(lhs_path, rhs_path, report);
      } else {
        compare_result = comparer.compare_txt_files(lhs_path, rhs_path, report);
      }
    } catch (const std::exception &ex) {
      if (report != nullptr) fclose(report);
      std::cerr << "错误: " << ex.what() << std::endl;
      return 1;
    }

    // 文本对比的匹配链已在比较过程中逐条写入报告，避免在内存中累计结果。
    if (report != nullptr) {
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