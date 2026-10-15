# PointerScan (newscan)

高性能 Android 进程内存指针链分析工具。通过扫描目标进程内存，找到指向目标地址的指针链（pointer chains），并支持在不同版本之间对比指针链的变化。

## 功能特性

- 多线程扫描目标进程内存，收集潜在指针
- DFS 反向构建指针链，支持自定义搜索深度和偏移量
- 基于 mmap 的文件后端队列，避免大规模扫描时 OOM
- 指针链对比：支持原生二进制和文本格式；另提供可复用的紧凑二进制缓存格式
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

NDK 路径可通过 `CMAKE_ANDROID_NDK`、`ANDROID_NDK_HOME` 或 `ANDROID_NDK_ROOT` 指定。GitHub Actions 示例请参考 `.github/workflows/android-build.yml`。

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

### 原生二进制文件对比

对比两份由 newscan 扫描器生成的树形指针链二进制文件，找出保持不变的链：

```bash
newscan --compare-bin --lhs <旧文件> --rhs <新文件> [--report 输出文件]
```


### 大文本文件的紧凑二进制缓存（可复用）

如果会反复比较同一份旧扫描结果，先把旧文本转换一次：

```bash
newscan --convert-keybin --lhs /data/local/tmp/pointer_chains.txt --out /data/local/tmp/pointer_chains.pskb --mem-limit 2048 --chunk-mib 128
```

新版文本也转换为同一种缓存格式，然后执行：

```bash
newscan --compare-keybin --lhs /data/local/tmp/pointer_chains.pskb --rhs /data/local/tmp/pointer_ch2.pskb --report /data/local/tmp/chain_compare.txt
```

交互菜单中新增 **5. 文本转紧凑二进制缓存** 和 **6. 对比紧凑二进制缓存**。缓存格式会将规范化后的完整链键分块排序、去重并以长度前缀记录写入磁盘；比较时直接双路归并，不再重新解析或排序缓存。旧缓存可以保留重复使用，因此适合反复对比场景。

**注意：`.pskb` 是 newscan 新增的专用缓存格式，不是原生树形 `.bin` 格式。** 不要把 `.pskb` 交给原来的功能 4，也不要只改扩展名来伪装格式。转换时 `--mem-limit` 是工作预算参考值而非内核硬限制，`--chunk-mib` 控制工作块目标大小；转换会用临时文件进行外部归并，磁盘空间也必须足够。内存压力检测会缩小后续工作块，但任何用户态程序都无法仅凭该预算保证绝不被 Android OOM 杀死。

### 文本文件对比

对比两份指针链文本文件：

```bash
newscan --compare-txt --lhs <旧文件> --rhs <新文件> [--report 输出文件] [--mem-limit MiB] [--chunk-mib MiB] [--sort-threads N] [--merge-fan-in N]
```

文本对比使用外部排序和多路归并，匹配链流式写入报告。可以分别设置 `--mem-limit`（内存工作预算参考值）、`--chunk-mib`（工作块大小）、`--sort-threads`（排序线程数）和 `--merge-fan-in`（归并扇入）。这些输入不设置人为上限，但仍受整数表示范围、实际内存、CPU、文件描述符和存储空间限制。排序线程数会用于并行排序工作块。检测到内存压力时会自动减小工作块、暂时切换为单线程并降低归并扇入；压力缓解后恢复用户设置。`--mem-limit` 是自适应参考值，不是进程 RSS 硬上限。

性能优化说明：文本链键的生成已改为直接字符串构造，避免每条链都创建 `ostringstream`；临时排序文件使用 64 KiB 缓冲读取；归并成功后立即删除已消费的旧临时块，以降低多轮归并时的临时磁盘峰值。对比时会显示分块、排序块和归并轮次进度，长任务可观察 RSS。

交互菜单选择“3. 对比文本指针链文件”后，可以分别设置内存工作预算、工作块大小、排序线程数和归并扇入；直接回车使用默认值（内存预算 2048 MiB、工作块 128 MiB、排序线程 4、归并扇入 32）。

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
| `--convert-keybin` | — | 将文本转换为排序去重的紧凑缓存，需配合 `--lhs` 和 `--out` | — |
| `--compare-keybin` | — | 比较两份 newscan 紧凑缓存，需配合 `--lhs` 和 `--rhs` | — |
| `--out` | — | 紧凑缓存输出路径（用于 `--convert-keybin`） | — |
| `--lhs` | — | 旧版指针链文件路径 | — |
| `--rhs` | — | 新版指针链文件路径 | — |
| `--report` | — | 对比输出文件名 | `chain_compare.txt` |
| `--mem-limit` | — | 文本对比内存工作预算参考值（MiB），用于内存压力判断；不是 RSS 硬上限 | 2048 |
| `--chunk-mib` | — | 工作块大小（MiB） | 8 |
| `--sort-threads` | — | 排序工作块时使用的线程数 | 2 |
| `--merge-fan-in` | — | 同时归并的输入文件数，至少为 2 | 16 |
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

二进制文件包含文件头（`cprog_header`）、模块符号表（`cprog_sym`）和各层级指针数据（`cprog_data`），适用于大规模数据存储和后续程序化对比。


## 文本指针链对比的低内存模式

文本对比使用外部排序和多路归并：默认工作块为 8 MiB、排序线程为 2、归并扇入为 16；中间结果写入临时文件，再分轮归并并流式输出共同链。这样不需要把两份文件的全部指针链和所有匹配结果同时保存在内存中；大文件会更多依赖临时存储空间，速度也取决于磁盘、解析成本和参数设置。

交互菜单选择“3. 对比文本指针链文件”后，可分别输入内存工作预算、工作块大小、排序线程数和归并扇入，直接回车使用默认值（内存预算 2048 MiB、工作块 128 MiB、排序线程 4、归并扇入 32）。命令行也支持 `--mem-limit 2048 --chunk-mib 128 --sort-threads 4 --merge-fan-in 32`。参数没有人为设定的最大值，但不能超出系统整数表示范围，过大的设置也可能导致内存不足、线程创建失败或文件描述符耗尽。内存保护会在压力出现时自动降档；它不是 Android 对进程 RSS 的系统级硬限制。临时文件默认写入 `$TMPDIR` 指定目录，否则尝试 `/data/local/tmp`，失败时回退到 `/tmp`；请确保临时目录有足够可用空间。

## 大文件文本指针链对比（性能调优版）

此版本保留外部排序，针对大文本文件优化热路径：读取每一行时直接生成规范化排序键，避免先填充 `chain_signature`/偏移 vector 再重新编码；使用分块排序和缓冲读取/归并；归并后立即删除旧轮次临时块。

文本对比参数：
- `--mem-limit <MiB>`：内存工作预算参考值，不是 RSS 硬限制，默认 2048。
- `--chunk-mib <MiB>`：排序工作块目标大小，默认 128。
- `--sort-threads <N>`：单块排序分段线程数，默认 4。
- `--merge-fan-in <N>`：每轮同时归并的输入块数量，默认 32。

注意：工作块的实际 RAM 占用可能高于其 MiB 数值（字符串对象、分配器、排序临时空间均有开销）；线程数不是并发工作块数量。归并扇入过大可能碰到 Android 文件描述符限制。参数接受正整数，但仍受 `size_t`、可用内存、文件描述符和存储空间等系统限制。

性能测试说明：本次在 Linux 主机上以 `g++ -std=c++17 -O3 -DNDEBUG -pthread` 编译，并用小型文本样例验证共同链数量、重复链去重和报告输出。尚未在 Android 手机上对数十 GB 文件进行实测；具体提速幅度需要使用实际数据验证。

## 扫描输出格式与原生二进制转换

基址链扫描支持两种输出格式：

- 默认文本：`--format txt -f pointer_chains.txt`
- 项目原生二进制：`--format bin -f pointer_chains.bin`

交互菜单的“1. 指针链扫描”会询问输出格式。原生 `.bin` 使用本项目现有的链目录格式，可用于本项目的二进制对比和格式化工具；它不是 `.pskb` 紧凑缓存。

把本项目原生二进制链文件转成文本：

```sh
newscan --convert-bin-to-txt --lhs pointer_chains.bin --out pointer_chains.txt
```

交互菜单“7. 原生二进制转文本”也提供该功能。转换器会检查文件头，并以只读私有映射读取原生二进制，避免为了读取文件而要求对输入文件有写权限。由于输出文本可能很大，转换前请确保目标存储空间足够。

注意：`--convert-keybin` 生成的是用于排序/去重和快速比较的自定义 `.pskb` 缓存；它与原生 `.bin` 是两种不同格式，不能互相冒充。当前版本提供原生 `.bin` → 文本、文本 → `.pskb`，没有把 `.pskb` 还原成原始链文本的功能。
