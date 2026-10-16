# PointerScan (newscan)

高性能 Android 进程内存指针链分析工具。通过扫描目标进程内存，找到指向目标地址的指针链（pointer chains），并支持在不同版本之间对比指针链的变化。

## 功能特性

- 多线程扫描目标进程内存，收集潜在指针
- DFS 反向构建指针链，支持自定义搜索深度和偏移量
- 基于 mmap 的文件后端队列，避免大规模扫描时 OOM
- 指针链对比：支持二进制和文本两种格式的对比
- 支持将本工具生成的二进制指针链文件转换为文本链
- 查询目标进程的模块映射范围、读写执行权限、文件偏移及关联 BSS 映射
- 交互菜单分组展示，支持终端颜色（设置 `NO_COLOR` 可关闭）
- ARM64 工具自动读取目标进程 ELF 位数；扫描、路径扫描和基址链解引用分别按 32/64 位指针处理

## 环境要求

- Android NDK r25c（默认使用 OLLVM 版本）
- CMake 3.10+
- C++17
- 构建平台：Android `arm64-v8a`（64 位）和 `armeabi-v7a`（32 位）

## 构建

```bash
# 默认编译 ARM64（保持原有默认行为）
cmake -B build -S . -DCMAKE_ANDROID_NDK="$ANDROID_NDK_HOME" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-28
cmake --build build

# 编译 ARM32（建议使用独立 build 目录）
cmake -B build-arm32 -S . -DCMAKE_ANDROID_NDK="$ANDROID_NDK_HOME" -DANDROID_ABI=armeabi-v7a -DANDROID_PLATFORM=android-28
cmake --build build-arm32
```

每次构建的可执行文件位于 `outputs/newscan`。GitHub Actions 的 `android-build.yml` 和 `newbuild.yml` 都使用 ABI 矩阵，分别上传 `PointerScan-Android-arm64-v8a` 与 `PointerScan-Android-armeabi-v7a` 两个构建产物，并验证 ELF 位数、CPU 架构和动态链接器。

**选择建议：** ARM64 版本是首选，并且程序内的扫描入口会根据目标进程 ELF 位数选择 32/64 位指针类型。ARM32 版本主要用于 32 位目标；32 位程序自身的地址空间和系统兼容性存在限制，不能将它视为扫描 64 位游戏的替代品。若要扫描 32 位和 64 位游戏，优先使用 ARM64 版本。

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

扫描前会读取 `/proc/<PID>/exe` 的 ELF 标识自动判断目标进程是 32 位还是 64 位：32 位目标使用 `uint32_t` 指针节点，64 位目标使用 64 位指针节点。无需手动指定位数；如果系统权限阻止读取目标 ELF 信息，工具会明确报错而不是猜测。

### 二进制文件对比

对比两份指针链二进制文件，找出保持不变的链。工具会根据文件头自动选择 32 位或 64 位解析器；两份二进制文件必须具有相同指针宽度。若宽度不同，请先分别转成文本再使用文本对比：

```bash
newscan --compare-bin --lhs <旧文件> --rhs <新文件> [--report 输出文件]
```

### 文本文件对比

对比两份指针链文本文件：

```bash
newscan --compare-txt --lhs <旧文件> --rhs <新文件> [--report 输出文件]
```

### 二进制转文本

将本工具原生二进制指针链文件转换为逐行文本：

```bash
newscan --convert-bin-to-txt --input <指针链.bin> [--report 输出.txt]
```

省略 `--report` 时，会在程序所在目录自动生成带时间戳的文本文件。转换器会检查文件签名、指针宽度及内部数据长度；支持本工具的 32 位和 64 位指针链二进制格式。

### 模块映射查询

查看目标进程的 `/proc/<PID>/maps`，包含映射起止地址、权限、文件偏移、模块名及路径；可选关键字筛选：

```bash
# 列出目标进程的全部映射
newscan --module-maps -p <进程名|PID>

# 只查看 libil2cpp.so 相关映射
newscan --module-maps -p <进程名|PID> --filter libil2cpp.so
```

交互菜单中的“08 模块映射查询”也提供相同功能。该功能只读取进程映射表，不读取或修改目标进程内存；若系统权限不允许读取 `/proc/<PID>/maps`，请以有权限的身份运行。

## 命令行参数

| 参数 | 短选项 | 说明 | 默认值 |
|------|--------|------|--------|
| `--process` | `-p` | 目标进程名称或 PID | — |
| `--address` | `-a` | 目标地址（16 进制，不带 0x 前缀） | — |
| `--depth` | `-d` | 最大搜索深度；默认保留所有不超过该深度的链 | 10 |
| `--exact-depth` | — | 只输出指定层级的链；`0` 表示关闭。按输出链中的偏移项总数计数 | 0 |
| `--module` | — | 只输出指定模块名/关键字对应的基址链；匹配模块名也会包含其 BSS 区域 | 空（全部模块） |
| `--offset` | `-o` | 最大偏移量（16 进制，不带 0x 前缀） | 500 |
| `--limit` | `-l` | 结果限制数量（0 为不限制） | 0 |
| `--file` | `-f` | 输出文件名 | `pointer_chains.txt` |
| `--compare-bin` | — | 比较两份指针链二进制文件 | — |
| `--compare-txt` | — | 比较两份指针链文本文件 | — |
| `--module-maps` | — | 查询目标进程的模块映射 | — |
| `--filter` | — | 模块映射筛选关键字 | 空（显示全部） |
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

# 只扫描 libil2cpp.so 对应的基址模块（包含匹配的 BSS 区域）
./newscan -p <游戏PID> -a <目标地址> --module libil2cpp.so

# 最大深度设为 5，同时只输出精确 5 级的链
./newscan -p <游戏PID> -a <目标地址> --depth 5 --exact-depth 5

# 同时限定模块和精确层级
./newscan -p <游戏PID> -a <目标地址> --depth 5 --exact-depth 5 --module libil2cpp.so

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
- 链的首个偏移加到模块或 BSS 映射起点；之后每一级根据目标进程 ELF 位数读取 32 位或 64 位指针，再加下一级偏移，最后一级偏移得到最终地址。
- 该模式只验证当前进程、当前运行状态下的链，不保证重启后稳定。
- 数值模式必须选对数据类型；同一地址按 `i32`、`float` 等解释可能得到完全不同的值。
- 输入文件按行流式处理，内存用量不会随总链数线性增长；但每条链本身最多接受 128 个偏移。

### 本地解析器测试

```sh
g++ -std=c++17 -I. -Imemtool -Iutils -Ithreadpool -Ichainer tests/test_chain_locator.cpp -o test_chain_locator
./test_chain_locator
```

## 中文交互菜单与自动命名输出（本次增强）

直接运行 `./newscan-arm64`（不带参数）会进入中文菜单，并按“指针扫描”“基址链验证”“指针链文件处理”“其他工具”分组。菜单内会记住本次运行期间最近输入的进程名或 PID，下一次使用扫描/验证功能时可直接回车复用。工具会自动识别目标进程的 ELF 位数，无需手动选择 32/64 位。

01. 指针链扫描
02. 指针路径扫描
03. 按目标地址验证基址链
04. 按目标数值定位基址链
05. 对比文本指针链文件
06. 对比二进制指针链文件（要求两份文件位数相同）
07. 二进制指针链转文本
08. 模块映射查询
09. 命令行帮助
00. 退出（输入 `0` 也可以）

未通过 `--file`、`--report` 或 `--locate-report` 手动指定输出路径时，结果自动保存到**可执行文件所在目录**，并带有本地时间戳，避免覆盖之前的结果。例如：

- `指针链扫描结果_20261016_123045.txt`
- `路径扫描结果_20261016_123045.txt`
- `文本对比报告_20261016_123045.txt`
- `地址定位报告_20261016_123045.txt`
- `数值定位报告_20261016_123045.txt`

如显式指定输出路径，则尊重指定路径。时间戳使用设备本地时间。
