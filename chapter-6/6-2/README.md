# 6.2 TC (Traffic Control) Hook 활용법

# TC(Traffic Control) Hook 개념

XDP(eXpress Data Path)가 네트워크 드라이버의 가장 빠른 경로(Early path)에서 패킷을 처리한다면, 
TC Hook은 리눅스 커널 네트워크 스택 내의 다른 지점에서 패킷을 처리하게 함.

TC는 본래 트래픽 shaping, policing, scheduling 등 다양한 트래픽 관리를 위해 설계한 프레임워크.

BPF(Berkeley Packet Filter) 프로그램은 TC 프레임워크에 ‘Hook’ 되어 패킷 필터링, 수정, 리다이렉션 등 더 복잡한 로직을 구현함.

1. TC Hook vs XDP

| 특징 | XDP (eXpress Data Path) | TC Hook (Traffic Control) |
| --- | --- | --- |
| 위치 | 네트워크 드라이버의 수신 큐 (RX queue) 직후. | 커널 네트워크 스택 내의 다양한 지점 (주로 ingress 및 egress). |
| 성능 | 가장 빠름. 제로 카피(zero-copy) 처리 가능. | XDP보다는 느리지만, 커널 스택의 다른 정보(소켓 정보 등) 접근 가능. |
| 제약 | 드라이버 지원 필수. 커널 스택 정보 접근 제한. | 드라이버 독립적. 커널 스택의 더 많은 정보 접근 가능. |
| 용도 | DDoS 방어, 로드 밸런서, 빠른 패킷 드롭/포워딩. | 방화벽, QoS, 패킷 통계, 복잡한 정책 기반 라우팅, 터널링. |
| 패킷 상태 | xdp_md 컨텍스트 (raw packet data). | sk_buff 컨텍스트 (Fully formed packet with metadata). |
1. TC Hook 작동원리
    1. **`qdisc` (Queuing Discipline)**: 패킷이 큐에 쌓여 처리되는 방식(정렬, 스케줄링, 드롭 등)을 정의
    2. **`ingress` Qdisc**: 인터페이스로 **들어오는(수신) 패킷**에 적용
    3. **`egress` Qdisc**: 인터페이스에서 **나가는(송신) 패킷**에 적용
    4. **`tc filter`**: `qdisc`에 필터를 연결하여 특정 조건에 맞는 패킷에 BPF 프로그램을 적용
    5. BPF 프로그램 실행 흐름
        1. 패킷이 네트워크 인터페이스에 도착하면 `ingress` Qdisc에 연결된 BPF 프로그램이 패킷을 처리
        2. BPF 프로그램은 패킷을 수정하거나, 드롭하거나, 통과시키거나, 다른 큐로 리다이렉트할 수 있슴
        3. 패킷이 커널 스택을 거쳐 나갈 때, `egress` Qdisc에 연결된 BPF 프로그램이 다시 패킷을 처리할 수 있슴
2. TC BPF 프로그램의 주요 반환값 (패킷 처리 후 반환)
    1. `TC_ACT_OK`: 패킷을 커널 스택으로 계속 전달(기본 동작)
    2. `TC_ACT_SHOT`: 패킷을 즉시 드롭
    3. `TC_ACT_UNSPEC`: 동작을 지정하지 않음
    4. `TC_ACT_PIPE`: 다음 필터로 체이닝
    5. `TC_ACT_RECLASSIFY`: 큐 디스크 내에서 패킷을 재분류
    6. `TC_ACT_REDIRECT`: 패킷을 다른 인터페이스로 리다이렉트
3. TC Hook의 장점
    1. **더 많은 정보 접근**: `sk_buff` 컨텍스트를 통해 TCP/UDP 포트, 시퀀스 번호, 소켓 정보 등 더 많은 패킷 메타데이터에 접근할 수 있슴
    2. **드라이버 독립적**: XDP와 달리 대부분의 네트워크 인터페이스에서 TC Hook BPF 프로그램을 사용할 수 있슴
    3. **유연성**: `ingress`와 `egress` 양쪽에서 패킷을 제어할 수 있어 인바운드/아웃바운드 트래픽에 대한 미세한 제어 가능
4. TC Hook의 제약사항
    1. **XDP보다 느림**: 패킷이 `sk_buff`로 변환되고 커널 스택의 더 깊은 곳에서 처리되므로 XDP만큼 빠르게 처리할 수 없슴
    2. **BPF 프로그래밍 복잡성**: BPF 프로그래밍은 여전히 낮은 수준의 커널 프로그래밍이며, `sk_buff` 구조를 이해해야 개발 가능

# TC Hook 실습 프로젝트 (특정 TCP 포트 차단)

- 목표 : TC ingress Hook을 사용하여 특정 TCP port로 들어오는 패킷을 차단하는 간단한 BPF 방화벽 구현
    - TC BPF 프로그램 작성(.bpf.c)
    - User space 헬퍼 프로그램  없이 tc 명령으로 BPF 프로그램 로드 및 attach
    - TC 프로그램 동작 확인

1. 전제 조건
    1. Linux system (Ubuntu 22.04 또는 24.04 사용)
    2. 커널 헤더, clang, llvm 등
    3. iproute2: tc 명령어를 포함
2. 프로젝트 구조

```bash
tc_block_example/
├── src/
│   └── tc_block_tcp_kern.bpf.c  # TC BPF 커널 프로그램
└── Makefile                   # 컴파일 자동화
```

1. 소스코드
    1. `src/tc_block_tcp_kern.bpf.c` (TC BPF 커널 프로그램)

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h> // For struct tcphdr and TCP_FLAG_SYN
#include <bpf/bpf_helpers.h> // For BPF helper functions
#include <bpf/bpf_endian.h>    // For bpf_htons, bpf_ntohs
#include <linux/in.h>          // For IPPROTO_TCP definition
#include <linux/pkt_cls.h>

#define BLOCK_TCP_PORT 80 // Block TCP traffic to port 80 (HTTP)

char _license[] SEC("license") = "GPL"; // Required license declaration

// TC ingress hook
//SEC("tc") // Section name for TC programs
__attribute__((section("classifier"), used))
int tc_block_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Start of Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        // Malformed packet or insufficient data, pass
        return TC_ACT_OK;
    }

    // Check if it's an IPv4 packet
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        // Not IPv4, pass
        return TC_ACT_OK;
    }

    // Start of IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)ip + sizeof(*ip) > data_end) {
        // Malformed IP header or insufficient data, pass
        return TC_ACT_OK;
    }

    if ((void *)ip + (ip->ihl * 4) > data_end) {
    	return TC_ACT_OK;
    }

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP) {
        // Not TCP, pass
        return TC_ACT_OK;
    }

    // Start of TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        // Malformed TCP header or insufficient data, pass
        return TC_ACT_OK;
    }

    if ((void *)tcp + (tcp->doff * 4) > data_end) {
        //bpf_printk("TC: TCP Hdr var length too short\n");
        return TC_ACT_OK;
    }

    // Check if destination port matches our BLOCK_TCP_PORT
    if (bpf_ntohs(tcp->dest) == BLOCK_TCP_PORT) {
        bpf_printk("TC: Blocking TCP packet to port %d\n", BLOCK_TCP_PORT);
        return TC_ACT_SHOT; // Drop the packet
    }

    return TC_ACT_OK; // Otherwise, pass the packet
}
```

- `struct __sk_buff *skb`: TC BPF 프로그램은 `sk_buff` 구조체를 컨텍스트로 받음. XDP의 `xdp_md`와 달리 `sk_buff`는 패킷에 대한 더 많은 커널 메타데이터를 포함
- `bpf_ntohs()`: 네트워크 바이트 오더를 호스트 바이트 오더로 변환. `tcp->dest` (목적지 포트)는 네트워크 바이트 오더로 되어 있습
- `SEC("tc")`: 이 함수가 TC BPF 프로그램임을 나타냄
- `TC_ACT_OK`, `TC_ACT_SHOT`: TC 프로그램의 반환값. `TC_ACT_SHOT`은 패킷을 드롭

b. Makefile

```makefile
# Makefile for TC Block Example

# Define source and build directories
SRC_DIR := src
BUILD_DIR := build

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

ARCH_INCLUDE_PATH := /usr/include/$(shell dpkg-architecture -qDEB_HOST_MULTIARCH)

# Source files
TC_KERN_SRC := $(SRC_DIR)/tc_block_tcp_kern.bpf.c

# Output files
TC_KERN_OBJ := $(BUILD_DIR)/tc_block_tcp_kern.bpf.o

# Compiler flags
CLANG_CFLAGS := -g -O2 -target bpf -I/usr/include/bpf -I$(ARCH_INCLUDE_PATH)
LIBS := # TC 예제는 사용자 공간 앱이 없으므로 라이브러리 필요 없음

# Phony targets
.PHONY: all clean

all: $(BUILD_DIR) $(TC_KERN_OBJ)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TC_KERN_OBJ): $(TC_KERN_SRC)
	clang $(CLANG_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
```

1. 실행
    1. 파일 생성
    2. 컴파일 : make
    3. 네트워크 인터페이스 확인
    4. **TC `qdisc` 및 `filter` 설정 (루트 권한 필요)**
    
    ```bash
    sudo tc qdisc add dev enp1s0 ingress
    ```
    
    e. BPF filter attach
    
    ```bash
    # sudo tc filter add dev enp1s0 ingress pref 1 handle 1 bpf obj build/tc_block_tcp_kern.bpf.o section classifier flowid 1:1
    sudo tc filter add dev enp1s0 ingress pref 1 handle 1 bpf obj build/tc_block_tcp_kern.bpf.o section classifier direct-action flowid 1:1
    ```
    
2. TC 동작확인
    1. **커널 로그 모니터링 (새 터미널)**
    
    ```bash
    sudo dmesg -w
    ```
    
    b. 패킷 전송(다른 머신에서 `ens33`의 IP로)
    
    ```bash
    # 웹 서버가 실행 중인 경우
    curl http://<IP_주소>/
    
    # 또는 netcat을 사용하여 연결 시도 (응답이 없거나 바로 연결 끊김)
    nc -v -w 3 <IP_주소> 80
    ```
    
    c. **허용될 다른 TCP 포트로 연결 시도 (예: 22번 SSH 포트)**
    
    ```bash
    nc -v -w 3 <ens33의_IP_주소> 22
    ```
    
3. TC 프로그램 제거 (필수!!!, 반드시 순서대로 진행해야 함)
    1. 필터 제거
    
    ```bash
    sudo tc filter del dev enp1s0 ingress pref 1 handle 1 bpf
    ```
    
    b. `ingress` Qdisc 제거
    
    ```bash
    sudo tc qdisc del dev enp1s0 ingress
    ```
