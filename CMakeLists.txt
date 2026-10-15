cmake_minimum_required(VERSION 3.10)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# Android NDK 路径
# 优先使用 CMake 参数传入的路径，
# 否则读取 ANDROID_NDK_HOME 或 ANDROID_NDK_ROOT。
# ============================================================
if(NOT CMAKE_ANDROID_NDK)
    if(DEFINED ENV{ANDROID_NDK_HOME}
       AND NOT "$ENV{ANDROID_NDK_HOME}" STREQUAL "")
        set(CMAKE_ANDROID_NDK "$ENV{ANDROID_NDK_HOME}")
    elseif(DEFINED ENV{ANDROID_NDK_ROOT}
           AND NOT "$ENV{ANDROID_NDK_ROOT}" STREQUAL "")
        set(CMAKE_ANDROID_NDK "$ENV{ANDROID_NDK_ROOT}")
    else()
        message(FATAL_ERROR
            "Android NDK not found. Please set "
            "CMAKE_ANDROID_NDK, ANDROID_NDK_HOME or ANDROID_NDK_ROOT."
        )
    endif()
endif()

# 检查 NDK 路径
if(NOT EXISTS "${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake")
    message(FATAL_ERROR
        "Android NDK toolchain file not found: "
        "${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake"
    )
endif()

# Android 交叉编译设置
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 28)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)

# 设置 Android NDK 工具链
set(CMAKE_TOOLCHAIN_FILE
    "${CMAKE_ANDROID_NDK}/build/cmake/android.toolchain.cmake"
    CACHE FILEPATH "Android NDK toolchain file"
)

# 项目信息
project(newscan VERSION 1.0.0 LANGUAGES CXX)

# Android ABI 和最低 API 级别
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM android-28)
set(ANDROID_NDK "${CMAKE_ANDROID_NDK}")

# 输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_SOURCE_DIR}/outputs"
)

# 包含目录
include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}/memtool"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils"
    "${CMAKE_CURRENT_SOURCE_DIR}/threadpool"
    "${CMAKE_CURRENT_SOURCE_DIR}/chainer"
)

# 源文件
file(GLOB_RECURSE SOURCES
    "memtool/memextend.cpp"
    "utils/*.cpp"
    "threadpool/threadpool.cpp"
)

# 构建可执行文件
add_executable(newscan
    ${SOURCES}
    main.cpp
)
