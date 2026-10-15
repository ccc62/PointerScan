#pragma once

#include "cbase.h"
#include <stdexcept>

#define PARSE_ADDR_DATA(a, b) \
    a = (decltype(a))b;       \
    b += sizeof(*a);

template <class T>
void chainer::base<T>::parse_cprog_bin_data(chainer::cprog_chain_info<T> &b_data)
{
    cprog_llen *llen;
    cprog_sym<T> *sym;
    cprog_header *header;
    cprog_data<T> *data;

    auto addr = b_data.addr;
    auto &syms = b_data.syms;
    auto &contents = b_data.contents;

    PARSE_ADDR_DATA(header, addr);

    syms.assign(header->module_count, {});
    for (auto i = 0; i < header->module_count; ++i) {
        PARSE_ADDR_DATA(sym, addr);

        syms[i].sym = sym;
        data = (decltype(data))addr;

        syms[i].data.set_data(data, sym->pointer_count);
        addr = (char *)(data + sym->pointer_count);
    }

    contents.assign(header->level, {});
    for (auto i = 0; i < header->level; ++i) {
        PARSE_ADDR_DATA(llen, addr);

        data = (decltype(data))addr;
        contents[llen->level].set_data(data, llen->count);
        addr = (char *)(data + llen->count);
    }
}

template <class T>
chainer::cprog_chain_info<T> chainer::base<T>::parse_cprog_bin_data(FILE *f)
{
    int fd;
    struct stat st;
    chainer::cprog_chain_info<T> data;

    fd = fileno(f);
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        throw std::runtime_error("无法获取指针链文件大小，或文件为空");
    }
    data.size = static_cast<size_t>(st.st_size);
    printf("data.size %zu fd %d\n", data.size, fd);

    // 对比过程只读取文件。输入以 "rb" 打开，因此必须使用只读映射，
    // 避免 PROT_WRITE + MAP_SHARED 在只读文件描述符上触发 EACCES。
    data.addr = static_cast<char *>(mmap(nullptr, data.size, PROT_READ, MAP_PRIVATE, fd, 0));
    if (data.addr == MAP_FAILED) {
        data.addr = nullptr;
        data.size = 0;
        throw std::runtime_error("指针链文件映射失败（只读映射失败）");
    }
    parse_cprog_bin_data(data);
    return data;
}

