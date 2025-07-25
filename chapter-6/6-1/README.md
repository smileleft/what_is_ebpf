# 6.1 XDP (Express Data Path) 이해 및 실습

# XDP(eXpress Data Path) 기본지식

XDP는 Linux 커널의 네트워크 데이터 경로를 가속화하기 이한 기술. 패킷이 네트워크 드라이버에 의해 수신되는 즉시, 

즉 일반적인 커널 네트워크 스택 처리 이전에 패킷을 처리할 수 있게 함.

이를 통해 매우 낮은 latency와 높은 처리량을 달성할 수 있슴(DPDK, Deep Plain Development Kit과 유사한 듯?)

## 1. XDP의 필요성

전통적인 Linux 네트워크 스택은 유연하고 강력하지만 고성능 네트워크 어플리케이션에서는 오버헤드 발생 가능성 있슴.

패킷이 커널스택을 통과하면서 여러 계층을 거치고 메모리 복사, 컨텍스트 스위치 등이 발생하여 성능저하의 원인이 됨.

XDP는 이러한 오버헤드를 줄여줌

## 2. XDP의 작동원리

XDP는 BPF(Berkeley Packet Filter)프로그램을 사용하여 동작. BPF는 커널 내에서 안전하게 실행될 수 있는 제한된 가상 머신.

XDP BPF 프로그램은 다음과 같은 특징이 있슴

- 네트워크 드라이버 레벨 실행 : XDP 프로그램은 네트워크 드라이버의 수신 큐(RX Queue) 에서 패킷이 도착하자마자 실행됨 → 패킷이 커널 스택으로 올라가기 전.
- eBPF(extended BPF) : XDP는 eBPF를 사용함.
- zero Copy : XDP 프로그램은 패킷 데이터를 복사하지 않고 직접 접근하여 처리함 → 메모리 복사 오버헤드를 크게 줄임
- 결정론적 동작 : XDP 프로그램은 네트워크 인터럽트 컨텍스트에서 실행되므로 지연시간을 최소화하기 위해 짧고 결정론적으로 동작해야 함

## 3. XDP 프로그램의 반환값(Action)

XDP는 패킷 처리 후 다음 중 하나의 동작을 반환.

- `XDP_PASS`: 패킷을 일반적인 커널 네트워크 스택으로 전달 (default)
- `XDP_DROP`: 패킷을 즉시 드롭 (for Firewall or DDoS protection)
- `XDP_TX`: 패킷을 동일한 인터페이스에서 다시 송신 (for Load Balancer or Mirroring)
- `XDP_REDIRECT`: 패킷을 다른 네트워크 인터페이스(NIC) 또는 사용자 공간 소켓(UMEM 사용 시)으로 리다이렉트
- `XDP_ABORTED`: 프로그램 내부 오류로 인해 패킷 처리가 중단되었음을 나타냄. 보통 드라이버가 패킷을 드롭함.

## 4. XDP의 장점

- 고성능 : 패킷 처리나 오버헤드를 최소화하여 높은 처리량과 낮은 지연시간(Latency)을 제공
- 프로그래밍 가능성 : BPF를 통해 커널에서 네트워크 로직을 직접 프로그래밍 할 수 있으므로 유연성이 높음
- 보안 : BPF verifier 는 커널에 로드되는 BPF 프로그램이 안전하고 무한 루프에 빠지지 않는지 검증함
- 다양한 활용 : 방화벽, 로드 밸런서, DDoS 방어, 모니터링, 패킷 포워딩 등 다양한 네트워크 어플리케이션에 활용 가능

## 5. XDP의 제약사항

- 드라이버 지원: XDP를 지원하는 드라이버는 한정되어 있슴(ixgbe, i40e, mlx5, virtio_net 등
- 프로그래밍 복잡성 : BPF 프로그래밍은 일반적인 사용자 공간 프로그래밍보다 Low Level 에서 이뤄지며, 특히 커널 환경을 잘 이해하고 있어야 함
- 디버깅의 어려움 : 커널 레벨에서 동작하므로 디버깅하기가 까다로움

# XDP 실습 프로젝트 - Simple XDP Firewall for Drop

- 목표 : 특정 포트로 들어오는 UDP 패킷을 드롭하는 간단한 XDP 방화벽 구현
    - XDP BPF 프로그램 개발 (.bpf.c)
    - User Space 헬퍼 프로그램 작성 (.c)
    - BPF 프로그램 컴파일 및 로드
    - XDP 프로그램 동작 확인

- 전제 조건
    - Ubuntu 20.04 LTS 이상의 배포판
    - kernel Header
    
    ```bash
    sudo apt update
    sudo apt install build-essential clang llvm libelf-dev libpcap-dev linux-headers-$(uname -r)
    sudo apt install binutils-dev
    ```
    
    - IProute2 : ip 명령어가 XDP 프로그램을 로그하는데 사용됨. 대부분의 리눅스 시스템에 기본으로 설치되어 있슴
    - 네트워크 인터페이스 : XDP 를 지원하는 네트워크 인터페이스 (가상머신의 경우 virtio_net 드라이버, 실제 NIC 사용하는 경우 해당 드라이버가 XDP를 지원하는지 확인해야 함)

- project

```bash
xdp_drop_example/
├── src/
│   ├── xdp_drop_kern.bpf.c  # XDP BPF 커널 프로그램
│   └── xdp_drop_user.c     # 사용자 공간 로더 프로그램
├── Makefile              # 컴파일 자동화
└── README.md             # 프로젝트 설명
```

### src/xdp_drop_kern.bpf.c

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h> // for BPF helper functions

// Define the UDP port to drop
#define DROP_UDP_PORT 7777

// BPF map definition (optional for this simple example, but good practice)
// This map could be used to pass configuration from userspace to BPF program
struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

SEC("xdp") // Section name for XDP programs
int xdp_drop_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Malformed packet, pass
    }

    // Check if it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not IPv4, pass
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS; // Malformed IP header, pass
    }

    // Check if it's a UDP packet
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS; // Not UDP, pass
    }

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        return XDP_PASS; // Malformed UDP header, pass
    }

    // Check if destination port matches our DROP_UDP_PORT
    if (bpf_htons(udp->dest) == DROP_UDP_PORT) {
        bpf_printk("XDP: Dropping UDP packet to port %d\n", DROP_UDP_PORT);
        return XDP_DROP; // Drop the packet
    }

    return XDP_PASS; // Otherwise, pass the packet
}

char _license[] SEC("license") = "GPL"; // Required license declaration
```

- `SEC("xdp")`: 이 함수가 XDP 프로그램임을 나타냄
- `struct xdp_md *ctx`: XDP 프로그램에 전달되는 컨텍스트 구조체로, 패킷 데이터의 시작(`data`)과 끝(`data_end`) 포인터를 포함
- `bpf_printk()`: 커널 로그(`dmesg`)에 메시지를 출력하는 헬퍼 함수
- `pf_htons()`: 호스트 바이트 오더를 네트워크 바이트 오더로 변환

### src/xdp_drop_user.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h> // for if_nametoindex

#include <bpf/libbpf.h> // for libbpf functions
#include <bpf/bpf.h>    // for BPF system calls

static int ifindex = -1;
static __u32 xdp_flags = 0;
static const char *ifname = NULL;
static const char *bpf_file_path = NULL;

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -i <ifname> -f <bpf_file.o>\n", prog_name);
    fprintf(stderr, "  -i <ifname>: Network interface name (e.g., eth0)\n");
    fprintf(stderr, "  -f <bpf_file.o>: Path to the compiled BPF object file\n");
    fprintf(stderr, "  -U (Optional): Unload XDP program\n");
}

static int xdp_set_link(int ifindex, __u32 flags, int fd) {
    int err;
    if (fd >= 0) { // Load XDP program
        err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    } else { // Unload XDP program
        err = bpf_set_link_xdp_fd(ifindex, -1, flags);
    }

    if (err) {
        fprintf(stderr, "ERROR: %s, code %d (%s)\n",
                fd >= 0 ? "attaching XDP program" : "detaching XDP program",
                err, strerror(abs(err)));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int opt;
    int err;
    int prog_fd = -1;
    int unload_only = 0;

    while ((opt = getopt(argc, argv, "i:f:U")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'f':
                bpf_file_path = optarg;
                break;
            case 'U':
                unload_only = 1;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (ifname == NULL) {
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: Invalid interface name: %s\n", ifname);
        return 1;
    }

    if (unload_only) {
        printf("Unloading XDP program from %s (ifindex: %d)...\n", ifname, ifindex);
        return xdp_set_link(ifindex, xdp_flags, -1);
    }

    if (bpf_file_path == NULL) {
        usage(argv[0]);
        return 1;
    }

    // Load BPF object file
    obj = bpf_object__open_file(bpf_file_path, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: bpf_object__open_file failed: %s\n", strerror(errno));
        return 1;
    }

    // Load BPF object into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: bpf_object__load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Get the XDP program from the object
    prog = bpf_object__find_program_by_name(obj, "xdp_drop_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: finding XDP program 'xdp_drop_prog' in %s\n", bpf_file_path);
        bpf_object__close(obj);
        return 1;
    }

    // Get the file descriptor of the program
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: bpf_program__fd failed\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach XDP program to the interface
    printf("Attaching XDP program to %s (ifindex: %d)...\n", ifname, ifindex);
    err = xdp_set_link(ifindex, xdp_flags, prog_fd);
    if (err) {
        bpf_object__close(obj);
        return 1;
    }

    printf("XDP program successfully loaded and attached.\n");
    printf("To detach, run: %s -i %s -U\n", argv[0], ifname);
    printf("To see kernel debug messages: sudo dmesg -w\n");
    printf("Press Ctrl+C to detach and exit.\n");

    // Keep program running until Ctrl+C
    while (1) {
        sleep(1);
    }

    // Detach XDP program on exit (Ctrl+C will trigger this)
    printf("\nDetaching XDP program from %s...\n", ifname);
    xdp_set_link(ifindex, xdp_flags, -1);
    bpf_object__close(obj);

    return 0;
}
```

- `libbpf.h`: BPF 프로그램을 로드하고 관리하는 데 사용되는 라이브러리
- `bpf_object__open_file()`: BPF 오브젝트 파일(.o)을 open
- `bpf_object__load()`: 오브젝트 파일을 커널에 로드
- `bpf_object__find_program_by_name()`: 로드된 오브젝트에서 특정 이름의 BPF 프로그램을 찾음
- `bpf_program__fd()`: BPF 프로그램의 파일 디스크립터를 얻음
- `bpf_set_link_xdp_fd()`: 네트워크 인터페이스에 XDP 프로그램을 연결하거나 해제

### Makefile

```c
# Makefile for XDP Drop Example

# Define source and build directories
SRC_DIR := src
BUILD_DIR := build

# Source files
XDP_KERN_SRC := $(SRC_DIR)/xdp_drop_kern.bpf.c
USER_APP_SRC := $(SRC_DIR)/xdp_drop_user.c

# Output files
XDP_KERN_OBJ := $(BUILD_DIR)/xdp_drop_kern.bpf.o
USER_APP_BIN := $(BUILD_DIR)/xdp_drop_user

# Compiler flags
CLANG_CFLAGS := -g -O2 -target bpf -I/usr/include/bpf
LIBCBPF_CFLAGS := -g -Wall
LIBCBPF_LIBS := -lbfd -lelf -lz # Required for libbpf
LIBS := $(LIBCBPF_LIBS)

# Phony targets
.PHONY: all clean

all: $(BUILD_DIR) $(XDP_KERN_OBJ) $(USER_APP_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(XDP_KERN_OBJ): $(XDP_KERN_SRC)
	clang $(CLANG_CFLAGS) -c $< -o $@

$(USER_APP_BIN): $(USER_APP_SRC)
	$(CC) $(LIBCBPF_CFLAGS) $< -o $@ -lbpf $(LIBS)

clean:
	rm -rf $(BUILD_DIR)
```

## 실행

1. 디렉터리 및 파일 생성
2. compile and execute
    1. 
    
    ```bash
    make
    # xdp_drop_kern.bpf.o 파일 생성 확인
    # xdp_drop_user 파일 생성 확인
    
    sudo ./build/xdp_drop_user -i {your nic name} -f ./build/xdp_drop_kern.bpf.o
    ```
    
3. packet 전송 & drop 확인
    1. 새로운 터미널에서 특정 포트(여기서는 7777) 로 UDP 패킷 전송
    2. 
    
    ```bash
    # Localhost로 전송 (loopback interface는 XDP가 안붙을 수 있으니 실제 IP로)
    # 자신의 IP 주소를 확인 (예: 192.168.1.100)
    # XDP 프로그램이 로드된 인터페이스의 IP 주소로 전송
    echo "Test packet" | nc -u -w1 192.168.1.100 7777
    echo "Another packet" | nc -u -w1 192.168.1.100 8888 # This should PASS
    ```
    
    c. XDP 로더 터미널
    
    ```bash
    sudo dmesg -w # 실행 후 XDP: Dropping UDP packet to port 7777 과 같은 메시지 확인
    ```
    
    d. XDP 프로그램 unload
    
    ```bash
    Crtl + C 또는 sudo ./build/xdp_drop_user -i {your nic name} -U
    ```

