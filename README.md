# PointerScan (newscan)

高性能 Android 进程内存指针链分析工具。通过扫描目标进程内存，找到指向目标地址的指针链（pointer chains），并支持在不同版本之间对比指针链的变化。

## 功能特性

- 多线程扫描目标进程内存，收集潜在指针
- DFS 反向构建指针链，支持自定义搜索深度和偏移量
- 基于 mmap 的文件后端队列，避免大规模扫描时 OOM
- 指针链对比：支持二进制和文本两种格式的对比
- 模板化设计，同时支持 64 位（ARM64）和 32 位进程

## 环境要求

- Android NDK r25c（默认使用 OLLVM 版本）
- CMake 3.10+
- C++17
- 目标平台：Android ARM64-v8a

## 构建

```bash
# 配置
cmake -B build -S .

# 编译
cmake --build build
```

输出二进制位于 `outputs/newscan`。

> NDK 路径硬编码在 `CMakeLists.txt` 第 13 行，默认为 `D:/ndkollvm/android-ndk-r25c.Ollvm/android-ndk-r25c`，如需修改请编辑该行。

## 使用方式

### 扫描模式

扫描目标进程内存，构建指向指定地址的指针链：

```bash
newscan -p <进程名|PID> -a <目标地址hex> [-d 深度] [-o 最大偏移] [-f 输出文件]
```

示例：

```bash
# 扫描进程 com.example.app 中指向地址 7A1B2C3D00 的指针链
newscan -p com.example.app -a 7A1B2C3D00 -d 8 -o 1000 -f result.txt
```

### 二进制文件对比

对比两份指针链二进制文件，找出保持不变的链：

```bash
newscan --compare-bin --lhs <旧文件> --rhs <新文件> [--report 输出文件]
```

### 文本文件对比

对比两份指针链文本文件：

```bash
newscan --compare-txt --lhs <旧文件> --rhs <新文件> [--report 输出文件]
```

## 命令行参数

| 参数 | 短选项 | 说明 | 默认值 |
|------|--------|------|--------|
| `--process` | `-p` | 目标进程名称或 PID | — |
| `--address` | `-a` | 目标地址（16 进制，不带 0x 前缀） | — |
| `--depth` | `-d` | 最大搜索深度 | 10 |
| `--offset` | `-o` | 最大偏移量（16 进制，不带 0x 前缀） | 500 |
| `--limit` | `-l` | 结果限制数量（0 为不限制） | 0 |
| `--file` | `-f` | 输出文件名 | `pointer_chains.txt` |
| `--compare-bin` | — | 比较两份指针链二进制文件 | — |
| `--compare-txt` | — | 比较两份指针链文本文件 | — |
| `--lhs` | — | 旧版指针链文件路径 | — |
| `--rhs` | — | 新版指针链文件路径 | — |
| `--report` | — | 对比输出文件名 | `chain_compare.txt` |
| `--verbose` | `-v` | 详细输出模式 | — |
| `--help` | `-h` | 显示帮助信息 | — |

## 项目架构

```
├── main.cpp              # 入口，命令行解析与流程控制
├── chainer/              # 指针链扫描与对比逻辑
│   ├── cbase.h/hpp       # 基础数据结构（pointer_data、二进制格式头等）
│   ├── cscan.h/hpp       # 高层扫描接口：收集指针 + DFS 构建指针链
│   ├── csearch.h/hpp     # 底层指针搜索：从内存区域中筛选有效指针
│   ├── ccompare.h/hpp    # 指针链对比：基于树的直接匹配算法
│   ├── ccscan.h/hpp      # 扫描操作封装层
│   └── cformat.hpp       # 二进制指针链数据的格式化输出
├── memtool/              # 进程内存访问
│   ├── membase.hpp       # process_vm_readv 系统调用封装
│   ├── memextend.hpp/cpp # 解析 /proc/[pid]/maps，过滤内存区域
│   └── memsetting.h      # 内存区域类型枚举
├── threadpool/           # 基于 std::future 的线程池
├── utils/                # 工具组件
│   ├── BufferPool.hpp    # 预分配缓冲池
│   ├── mapqueue.h/hpp    # mmap 文件后端队列
│   ├── varray.h/hpp      # 零拷贝 mmap 视图包装器
│   ├── cmd_parser.h/cpp  # 命令行参数解析
│   └── sutils.h/hpp      # 通用工具函数
└── CMakeLists.txt
```

### 数据流

1. `main.cpp` 解析命令行参数，初始化扫描器
2. `memtool::extend::get_target_mem()` 解析目标进程内存布局（`/proc/[pid]/maps`）
3. `cscan::get_pointers()` 多线程扫描内存区域，收集潜在指针存入 mapqueue
4. `cscan::scan_pointer_chain()` 用 DFS 从目标地址反向构建指针链
5. 结果输出为文本或二进制格式

### 模板设计

核心类（`cscan`、`csearch`、`ccompare` 等）均为模板类，模板参数 `T` 控制指针宽度：

- `size_t`（64 位）— 用于 ARM64 进程
- `uint32_t`（32 位）— 用于 32 位进程

## 输出格式

### 文本格式

每行一条指针链，格式为：

```
模块名[索引] + 0x偏移1 -> + 0x偏移2 -> + 0x偏移3
```

示例：

```
libunity.so[0] + 0x1A2B3C -> + 0x48 -> + 0x10
```

表示从 `libunity.so` 基址加偏移 `0x1A2B3C` 处读取指针，再加偏移 `0x48` 读取，再加偏移 `0x10` 即为目标地址。

### 二进制格式

二进制文件包含文件头（`cprog_header`）、模块符号表（`cprog_sym`）和各层级指针数据（`cprog_data`），适用于大规模数据存储和后续程序化对比。扫描器可直接输出此项目原生格式，不需要先生成临时文件再转换。

### 选择扫描输出格式

交互菜单选择“1. 指针链扫描”后，可输入 `txt` 或 `bin`；默认 `txt`，保持旧用法不变。未指定 `--file` 时，文件保存在可执行文件所在目录，文件名包含时间戳及对应扩展名。

```sh
# 默认文本格式
./newscan -p <游戏PID> -a <目标地址>

# 生成可供 --compare-bin 使用的原生二进制指针链文件
./newscan -p <游戏PID> -a <目标地址> --output-format bin

# 显式指定二进制输出路径
./newscan -p <游戏PID> -a <目标地址> --output-format bin -f ./chains.bin

# 对比两份二进制指针链文件
./newscan --compare-bin --lhs ./old.bin --rhs ./new.bin
```

`--output-format` 只接受 `txt` 或 `bin`；省略时默认 `txt`。`--file` 指定路径时会按该路径写入，不会自动改写扩展名，因此建议二进制文件使用 `.bin` 扩展名。

### 二进制对比冒烟测试

在已编译出 `newscan` 的主机环境中运行：

```sh
sh tests/test_binary_compare_empty.sh ./newscan
```

该测试检查比较器能否读取合法的空二进制文件。它不代替 Android NDK 编译或真实进程扫描测试。

## 基址链文件定位/验证（新增）

新增两个只读验证模式，逐行读取文本链文件，不会把整个文件载入内存。支持本项目的 `module[1] + 0x... -> + 0x...` 输出格式，也支持紧凑格式 `libunity.so:bss+0x...+0x...`。

### A. 按目标地址验证

```sh
./newscan -p <游戏PID> --locate-address \
  --chains /data/local/tmp/pointer_chains.txt \
  --target-address 740A64D874 \
  --locate-report /data/local/tmp/locate_report.txt
```

### B. 按目标数值定位

默认数值类型为有符号 32 位整数 `i32`：

```sh
./newscan -p <游戏PID> --locate-value \
  --chains /data/local/tmp/pointer_chains.txt \
  --value 100 --value-type i32 \
  --locate-report /data/local/tmp/value_report.txt
```

支持类型：`i32`、`u32`、`i64`、`u64`、`f32`、`f64`（也接受 `int32/uint32/int64/uint64/float/double` 别名）。浮点数使用相对/绝对容差约 `1e-6`。如果 `process_vm_readv` 读取受限，可以加 `--io` 尝试通过 `/proc/<pid>/mem` 读取（仍取决于系统权限）。

注意事项：

- `--target-address` 使用十六进制地址，可带或不带 `0x`。
- 链的首个偏移加到模块或 BSS 映射起点；之后每一级按“读取 64 位指针，再加下一级偏移”计算，最后一级偏移得到最终地址。
- 该模式只验证当前进程、当前运行状态下的链，不保证重启后稳定。
- 数值模式必须选对数据类型；同一地址按 `i32`、`float` 等解释可能得到完全不同的值。
- 输入文件按行流式处理，内存用量不会随总链数线性增长；但每条链本身最多接受 128 个偏移。

### 本地解析器测试

```sh
g++ -std=c++17 -I. -Imemtool -Iutils -Ithreadpool -Ichainer tests/test_chain_locator.cpp -o test_chain_locator
./test_chain_locator
```

## 中文交互菜单与自动命名输出（本次增强）

直接运行 `./newscan-arm64`（不带参数）会进入中文菜单，可选择：

1. 指针链扫描
2. 指针路径扫描
3. 按目标地址验证基址链
4. 按目标数值定位基址链
5. 对比文本指针链文件
6. 对比二进制指针链文件
7. 查看命令行帮助
0. 退出

未通过 `--file`、`--report` 或 `--locate-report` 手动指定输出路径时，结果自动保存到**可执行文件所在目录**，并带有本地时间戳，避免覆盖之前的结果。例如：

- `指针链扫描结果_20261016_123045.txt`
- `路径扫描结果_20261016_123045.txt`
- `文本对比报告_20261016_123045.txt`
- `地址定位报告_20261016_123045.txt`
- `数值定位报告_20261016_123045.txt`

如显式指定输出路径，则尊重指定路径。时间戳使用设备本地时间。
