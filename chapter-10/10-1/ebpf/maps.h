struct bpf_map_def SEC("maps") rule_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 64,
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

