#include <bpf/libbpf.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj;
    int prog_fd;

    obj = bpf_object__open_file("build/l7_filter_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_l7_filter");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    int ifindex = if_nametoindex("eth0");

    if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0) {
        perror("bpf_set_link_xdp_fd");
        return 1;
    }

    printf("eBPF program successfully attached to eth0\n");
    return 0;
}

