#ifndef __MAPS_H
#define __MAPS_H

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[64]);
    __type(value, __u32); // 0=drop, 1=redirect, etc.
} rule_map SEC(".maps");

#endif

