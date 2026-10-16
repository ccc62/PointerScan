#pragma once

// Streaming verifier for text pointer-chain files.
// Supported examples:
//   libunity.so:bss+0x72448+0x1508+0x1398+0x280+0x874
//   libunity.so:bss[1] + 0x72448 -> + 0x1508 -> + 0x1398 -> + 0x280 -> + 0x874
//   libunity.so[1] + 0x72448 -> + 0x1508 -> + 0x1398

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <sys/types.h>
#include <unistd.h>
#include "../memtool/membase.hpp"

namespace chainer::locator {

struct Mapping {
    uint64_t start = 0, end = 0, file_offset = 0;
    std::string perms, path, basename;
};

struct ParsedChain {
    std::string original;
    std::string module;
    bool bss = false;
    int occurrence = 0; // 0 means first matching mapping
    std::vector<uint64_t> offsets;
};

inline std::string trim(std::string s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

inline bool parse_hex(const std::string &s, uint64_t &out) {
    std::string v = trim(s);
    if (v.rfind("0x", 0) == 0 || v.rfind("0X", 0) == 0) v.erase(0, 2);
    if (v.empty()) return false;
    char *end = nullptr;
    errno = 0;
    unsigned long long n = std::strtoull(v.c_str(), &end, 16);
    if (errno || end == v.c_str() || *end != '\0') return false;
    out = static_cast<uint64_t>(n);
    return true;
}

inline bool parse_chain(const std::string &line, ParsedChain &out, std::string &error) {
    out = ParsedChain{};
    out.original = trim(line);
    if (out.original.empty() || out.original[0] == '#') return false;

    // Normalize the project's arrow-form output to plus-separated tokens.
    std::string normalized;
    normalized.reserve(out.original.size());
    for (size_t i = 0; i < out.original.size();) {
        if (i + 3 <= out.original.size() && out.original.compare(i, 3, "-> ") == 0) {
            normalized.push_back('+');
            i += 3;
        } else {
            normalized.push_back(out.original[i++]);
        }
    }
    // Also accept arrows without a trailing space.
    std::string s;
    for (size_t i = 0; i < normalized.size(); ++i) {
        if (i + 1 < normalized.size() && normalized[i] == '-' && normalized[i + 1] == '>') {
            s.push_back('+'); ++i;
        } else s.push_back(normalized[i]);
    }

    auto plus = s.find('+');
    if (plus == std::string::npos) { error = "未找到偏移序列"; return false; }
    std::string head = trim(s.substr(0, plus));
    // Head can be module:bss[1], module[1], or module:bss.
    auto lb = head.find('[');
    if (lb != std::string::npos) {
        auto rb = head.find(']', lb + 1);
        if (rb != std::string::npos) {
            std::string ix = head.substr(lb + 1, rb - lb - 1);
            if (!ix.empty()) {
                char *e = nullptr; long n = std::strtol(ix.c_str(), &e, 10);
                if (e && *e == '\0' && n > 0 && n <= 100000) out.occurrence = static_cast<int>(n);
            }
            head.erase(lb, rb - lb + 1);
        }
    }
    auto bss_pos = head.find(":bss");
    if (bss_pos != std::string::npos) {
        out.bss = true;
        out.module = trim(head.substr(0, bss_pos));
    } else {
        out.module = trim(head);
    }
    // Allow paths in module names, but match maps by basename.
    auto slash = out.module.find_last_of('/');
    if (slash != std::string::npos) out.module = out.module.substr(slash + 1);
    if (out.module.empty()) { error = "模块名为空"; return false; }

    // Extract explicit hexadecimal offset tokens. This tolerates both compact
    // '+0x...' chains and the project's '+ 0x... -> + 0x...' formatting.
    for (size_t i = plus; i + 2 < s.size();) {
        if (s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X') &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            size_t end = i + 2;
            while (end < s.size() && std::isxdigit(static_cast<unsigned char>(s[end]))) ++end;
            uint64_t off = 0;
            if (!parse_hex(s.substr(i, end - i), off)) {
                error = "偏移不是有效十六进制数: " + s.substr(i, end - i); return false;
            }
            out.offsets.push_back(off);
            i = end;
        } else {
            ++i;
        }
    }
    if (out.offsets.empty()) { error = "没有偏移"; return false; }
    if (out.offsets.size() > 128) { error = "偏移层数超过安全上限128"; return false; }
    return true;
}

inline std::string base_name(const std::string &path) {
    auto p = path.find_last_of('/');
    return p == std::string::npos ? path : path.substr(p + 1);
}

inline bool read_maps(pid_t pid, std::vector<Mapping> &maps, std::string &error) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
    if (!f) { error = "无法读取 /proc/" + std::to_string(pid) + "/maps"; return false; }
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream is(line);
        std::string range, perms, offset, dev, inode;
        if (!(is >> range >> perms >> offset >> dev >> inode)) continue;
        std::string path; std::getline(is, path); path = trim(path);
        auto dash = range.find('-');
        if (dash == std::string::npos) continue;
        Mapping m;
        uint64_t start = 0, end = 0, fileoff = 0;
        if (!parse_hex(range.substr(0, dash), start) || !parse_hex(range.substr(dash + 1), end) || !parse_hex(offset, fileoff)) continue;
        m.start = start; m.end = end; m.file_offset = fileoff; m.perms = perms; m.path = path; m.basename = base_name(path);
        maps.push_back(std::move(m));
    }
    return true;
}

inline bool resolve_module_base(const ParsedChain &c, const std::vector<Mapping> &maps,
                               uint64_t &base, std::string &error) {
    std::vector<uint64_t> candidates;
    if (c.bss) {
        // Android commonly names the BSS mapping [anon:.bss], directly after
        // a file-backed mapping of the same shared object. Find the closest
        // preceding mapping for this module and associate the anonymous BSS map.
        for (size_t i = 0; i < maps.size(); ++i) {
            if (maps[i].path.find("[anon:.bss]") == std::string::npos) continue;
            bool matched = false;
            for (size_t j = i; j-- > 0;) {
                if (maps[j].basename == c.module && maps[j].path.find('/') != std::string::npos) {
                    matched = true; break;
                }
                // Don't associate across another named shared object mapping.
                if (!maps[j].path.empty() && maps[j].path[0] == '/' && maps[j].basename != c.module) break;
            }
            if (matched) candidates.push_back(maps[i].start);
        }
    } else {
        uint64_t lowest = std::numeric_limits<uint64_t>::max();
        for (const auto &m : maps) {
            if (m.basename == c.module && !m.path.empty() && m.path[0] == '/') {
                uint64_t b = m.start >= m.file_offset ? m.start - m.file_offset : m.start;
                lowest = std::min(lowest, b);
            }
        }
        if (lowest != std::numeric_limits<uint64_t>::max()) candidates.push_back(lowest);
    }
    if (candidates.empty()) {
        error = std::string("找不到模块基址: ") + c.module + (c.bss ? ":bss" : "");
        return false;
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    size_t idx = c.occurrence > 0 ? static_cast<size_t>(c.occurrence - 1) : 0;
    if (idx >= candidates.size()) {
        error = "模块匹配编号超出范围: " + c.module;
        return false;
    }
    base = candidates[idx];
    return true;
}

inline bool read_exact(uint64_t address, void *out, size_t size) {
    // membase's readv returns byte count; unlike its value-returning overload,
    // this allows us to distinguish unreadable addresses from a legitimate zero.
    return memtool::base::readv(address, out, size) == static_cast<long>(size);
}

inline bool resolve_chain(const ParsedChain &c, uint64_t module_base, uint64_t &final_address,
                          std::string &error) {
    uint64_t current = 0;
    if (c.offsets[0] > std::numeric_limits<uint64_t>::max() - module_base) {
        error = "起始地址溢出"; return false;
    }
    current = module_base + c.offsets[0];
    for (size_t i = 1; i < c.offsets.size(); ++i) {
        uint64_t ptr = 0;
        if (!read_exact(current, &ptr, sizeof(ptr))) {
            std::ostringstream os; os << "第" << i << "级无法读取指针，地址=0x" << std::hex << current;
            error = os.str(); return false;
        }
        if (ptr == 0) { error = "第" + std::to_string(i) + "级指针为0"; return false; }
        if (c.offsets[i] > std::numeric_limits<uint64_t>::max() - ptr) { error = "指针加偏移溢出"; return false; }
        current = ptr + c.offsets[i];
    }
    final_address = current;
    return true;
}

inline bool read_typed_value(uint64_t address, const std::string &type, std::string &value) {
    std::ostringstream os;
    if (type == "i32" || type == "int32") {
        int32_t v; if (!read_exact(address, &v, sizeof(v))) return false; os << v;
    } else if (type == "u32" || type == "uint32") {
        uint32_t v; if (!read_exact(address, &v, sizeof(v))) return false; os << v;
    } else if (type == "i64" || type == "int64") {
        int64_t v; if (!read_exact(address, &v, sizeof(v))) return false; os << v;
    } else if (type == "u64" || type == "uint64") {
        uint64_t v; if (!read_exact(address, &v, sizeof(v))) return false; os << v;
    } else if (type == "f32" || type == "float") {
        float v; if (!read_exact(address, &v, sizeof(v))) return false; os << std::setprecision(9) << v;
    } else if (type == "f64" || type == "double") {
        double v; if (!read_exact(address, &v, sizeof(v))) return false; os << std::setprecision(17) << v;
    } else {
        return false;
    }
    value = os.str(); return true;
}

inline bool value_matches(uint64_t address, const std::string &type, const std::string &wanted,
                          std::string &actual) {
    if (!read_typed_value(address, type, actual)) return false;
    char *end = nullptr;
    if (type == "f32" || type == "float" || type == "f64" || type == "double") {
        errno = 0; double expected = std::strtod(wanted.c_str(), &end);
        if (errno || end == wanted.c_str() || *end != '\0') return false;
        double got = std::strtod(actual.c_str(), nullptr);
        double tol = std::max(1e-6, std::abs(expected) * 1e-6);
        return std::abs(got - expected) <= tol;
    }
    if (type == "u32" || type == "uint32" || type == "u64" || type == "uint64") {
        errno = 0; unsigned long long expected = std::strtoull(wanted.c_str(), &end, 0);
        if (errno || end == wanted.c_str() || *end != '\0') return false;
        errno = 0; unsigned long long got = std::strtoull(actual.c_str(), nullptr, 10);
        return !errno && got == expected;
    }
    errno = 0; long long expected = std::strtoll(wanted.c_str(), &end, 0);
    if (errno || end == wanted.c_str() || *end != '\0') return false;
    errno = 0; long long got = std::strtoll(actual.c_str(), nullptr, 10);
    return !errno && got == expected;
}

} // namespace chainer::locator
