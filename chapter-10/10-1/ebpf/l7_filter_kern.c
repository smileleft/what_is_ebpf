#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("xdp")
int xdp_l7_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void*)ip + ip->ihl * 4;
    if ((void*)tcp + sizeof(*tcp) > data_end) return XDP_PASS;
    if (ntohs(tcp->dest) != 80) return XDP_PASS;

    char *payload = (void *)tcp + tcp->doff * 4;
    if (payload + 4 > (char *)data_end) return XDP_PASS;

    // HTTP 요청인지 확인
    if (__builtin_memcmp(payload, "GET ", 4) == 0) {
        bpf_printk("HTTP GET received\n");
        // 추후 필터 룰 적용
        return XDP_DROP; // 또는 XDP_REDIRECT
    }

    return XDP_PASS;
}

