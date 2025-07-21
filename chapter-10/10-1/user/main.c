#include <bpf/libbpf.h>
#include <net/if.h>

int main() {
    struct bpf_object *obj;
    int prog_fd, map_fd;

    obj = bpf_object__open_file("build/l7_filter_kern.o", NULL);
    bpf_object__load(obj);
    prog_fd = bpf_program__fd(bpf_object__find_program_by_title(obj, "xdp_l7_filter"));

    int ifindex = if_nametoindex("eth0");
    bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);

    // map 업데이트 예시
    map_fd = bpf_object__find_map_fd_by_name(obj, "rule_map");
    const char *key = "/blocked-path";
    __u32 action = 0; // 0=drop
    bpf_map_update_elem(map_fd, key, &action, BPF_ANY);

    return 0;
}

