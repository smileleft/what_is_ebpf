# 5.1 CPU/Memory/File IO 추적 예제

- 프로젝트 구조

```bash
.
├── Makefile
├── multi_monitor.bpf.c
└── multi_monitor_user.c
```

- 필수 패키지
    - `clang`, `llvm`, `libelf-dev` (또는 `libelf-devel`), `libbpf-dev` (또는 `libbpf-devel`), `bpftool`

## multi_monitor.bpf.c 파일

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* multi_monitor.bpf.c */

#include "vmlinux.h" // bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 명령으로 생성
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <linux/sched.h>   // TASK_COMM_LEN을 위해 필요

#define TASK_COMM_LEN 16

// 이벤트를 사용자 공간으로 보내기 위한 perf event array 맵 정의
// CPU당 하나의 버퍼를 관리하며, bpf_perf_event_output 헬퍼를 사용합니다.
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// 이벤트 유형 정의
// 사용자 공간에서 어떤 종류의 이벤트인지 구분하는 데 사용됩니다.
enum event_type {
    EVENT_CPU_EXEC = 1,
    EVENT_CPU_FORK,
    EVENT_MEM_MMAP,
    EVENT_MEM_MUNMAP,
    EVENT_MEM_BRK,
    EVENT_FILE_OPEN,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CLOSE,
};

// 사용자 공간으로 보낼 이벤트 데이터 구조체
// 모든 이벤트 타입에 필요한 필드를 포함하며, union을 사용하여 메모리를 최적화할 수도 있지만,
// 예제에서는 단순함을 위해 모든 필드를 포함합니다.
struct event {
    __u32 pid;          // 프로세스 ID
    char comm[TASK_COMM_LEN]; // 프로세스 이름 (보통 16바이트)
    enum event_type type; // 이벤트 유형

    // CPU 관련 필드
    char filename[256]; // execve, openat 등에 사용

    // 메모리 관련 필드
    __u64 mem_addr;     // mmap, munmap, brk 등에 사용되는 주소
    __u64 mem_len;      // mmap, munmap 등에 사용되는 길이
    __u64 mem_brk_val;  // brk 시스템 호출의 새 break 값

    // 파일 I/O 관련 필드
    int fd;             // 파일 디스크립터 (read, write, close 등에 사용)
    __s64 bytes_rw;     // 읽거나 쓴 바이트 수 (read, write의 retval)
};

// ========================
// CPU 모니터링 (프로세스 실행/생성)
// ========================

// sys_execve 시스템 호출 진입점 Kprobe (프로세스 실행)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep execve` 로 확인하세요.
SEC("kprobe/__x64_sys_execve")
//int BPF_KPROBE(sys_execve_entry, const char *filename, const char *const argv[], const char *const envp[])
int sys_execve_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    const char *filename;

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_CPU_EXEC;

    filename = (const char *)PT_REGS_PARM1(ctx);

    bpf_probe_read_user_str(&event_data.filename, sizeof(event_data.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_fork 시스템 호출 반환점 Kretprobe (프로세스 생성)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep fork` 로 확인하세요.
SEC("kretprobe/__x64_sys_fork")
//int BPF_KRETPROBE(sys_fork_exit, long retval)
int sys_fork_exit(struct pt_regs *ctx)
{
    // retval은 새로 생성된 자식 프로세스의 PID입니다.
    long retval = PT_REGS_RC(ctx);
    if (retval < 0) return 0; // fork 실패 시 무시

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_CPU_FORK;
    event_data.pid = retval; // 새로 생성된 자식 PID

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// ========================
// 메모리 모니터링
// ========================

// sys_mmap 시스템 호출 진입점 Kprobe (메모리 매핑)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep mmap` 로 확인하세요.
SEC("kprobe/__x64_sys_mmap")
//int BPF_KPROBE(sys_mmap_entry, unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long offset)
int sys_mmap_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long addr = PT_REGS_PARM1(ctx);
    unsigned long len = PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_MMAP;
    event_data.mem_addr = addr;
    event_data.mem_len = len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_munmap 시스템 호출 진입점 Kprobe (메모리 매핑 해제)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep munmap` 로 확인하세요.
SEC("kprobe/__x64_sys_munmap")
//int BPF_KPROBE(sys_munmap_entry, unsigned long addr, unsigned long len)
int sys_munmap_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long addr = PT_REGS_PARM1(ctx);
    unsigned long len = PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_MUNMAP;
    event_data.mem_addr = addr;
    event_data.mem_len = len;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_brk 시스템 호출 진입점 Kprobe (프로그램 break 조정)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep brk` 로 확인하세요.
SEC("kprobe/__x64_sys_brk")
//int BPF_KPROBE(sys_brk_entry, unsigned long brk)
int sys_brk_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    unsigned long brk = PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_MEM_BRK;
    event_data.mem_brk_val = brk; // 새로운 break 주소

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// ========================
// 파일 I/O 모니터링
// ========================

// sys_openat 시스템 호출 진입점 Kprobe (파일 열기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep openat` 로 확인하세요.
SEC("kprobe/__x64_sys_openat")
//int BPF_KPROBE(sys_openat_entry, int dfd, const char __user *filename, int flags, umode_t mode)
int sys_openat_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    // sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
    // x86_64 시스템 호출 인자: RDI, RSI, RDX, RCX, R8, R9
    // dfd: RDI (PT_REGS_PARM1)
    // filename: RSI (PT_REGS_PARM2)
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_OPEN;
    bpf_probe_read_user_str(&event_data.filename, sizeof(event_data.filename), filename);
    // fd는 kretprobe에서 얻을 수 있습니다.

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_read 시스템 호출 반환점 Kretprobe (파일 읽기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep read` 로 확인하세요.
SEC("kretprobe/__x64_sys_read")
//int BPF_KRETPROBE(sys_read_exit, int fd, char __user *buf, size_t count, long retval)
int sys_read_exit(struct pt_regs *ctx)
{

    long retval = PT_REGS_RC(ctx);
    if (retval <= 0) return 0;

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_READ;
    event_data.fd = fd;
    event_data.bytes_rw = retval;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_write 시스템 호출 반환점 Kretprobe (파일 쓰기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep write` 로 확인하세요.
SEC("kretprobe/__x64_sys_write")
//int BPF_KRETPROBE(sys_write_exit, int fd, const char __user *buf, size_t count, long retval)
int sys_write_exit(struct pt_regs *ctx)
{
    long retval = PT_REGS_RC(ctx);
    if (retval <= 0) return 0; // 쓰기 실패 또는 0바이트 쓴 경우 무시

    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_WRITE;
    event_data.fd = fd;
    event_data.bytes_rw = retval;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

// sys_close 시스템 호출 진입점 Kprobe (파일 닫기)
// 정확한 심볼 이름은 `sudo cat /proc/kallsyms | grep close` 로 확인하세요.
SEC("kprobe/__x64_sys_close")
//int BPF_KPROBE(sys_close_entry, int fd)
int sys_close_entry(struct pt_regs *ctx)
{
    struct event event_data = {};
    __u64 id = bpf_get_current_pid_tgid();
    int fd = (int)PT_REGS_PARM1(ctx);

    event_data.pid = id >> 32;
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));
    event_data.type = EVENT_FILE_CLOSE;
    event_data.fd = fd;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; // BPF 프로그램 라이선스
```

## 주의사항

1. 다음 심볼은 시스템 실행환경에 따라 이름이 상이할 수 있슴. 본인의 시스템에서 /proc/kallsyms 내용을 확인하여 시스템 환경에 맞게 수정해야 함
    1. `sys_execve`, `sys_fork`, `sys_mmap`, `sys_munmap`, `sys_brk`, `sys_openat`, `sys_read`, `sys_write`, `sys_close`
    2. 아래 명령으로 각 심볼명 확인
    
    ```bash
    sudo cat /proc/kallsyms | grep execve
    sudo cat /proc/kallsyms | grep fork
    sudo cat /proc/kallsyms | grep mmap
    sudo cat /proc/kallsyms | grep munmap
    sudo cat /proc/kallsyms | grep brk
    sudo cat /proc/kallsyms | grep openat
    sudo cat /proc/kallsyms | grep read
    sudo cat /proc/kallsyms | grep write
    sudo cat /proc/kallsyms | grep close
    ```
    

## multi_monitor_user.c 파일

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* multi_monitor_user.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h> // libbpf 라이브러리 헤더
#include <linux/types.h> // __u32, __u64 등을 위해 필요

// bpftool gen skeleton 명령으로 생성될 스켈레톤 헤더 파일
// BPF 프로그램 (multi_monitor.bpf.c)과 사용자 공간 프로그램 간의 인터페이스를 제공합니다.
#include "multi_monitor.bpf.skel.h"

// 이벤트 유형 정의 (BPF 코드의 enum event_type과 동일해야 함)
enum event_type {
    EVENT_CPU_EXEC = 1,
    EVENT_CPU_FORK,
    EVENT_MEM_MMAP,
    EVENT_MEM_MUNMAP,
    EVENT_MEM_BRK,
    EVENT_FILE_OPEN,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_CLOSE,
};

// 이벤트 데이터 구조체 (BPF 코드의 'struct event'와 동일해야 함)
struct event {
    __u32 pid;
    char comm[16]; // TASK_COMM_LEN은 보통 16
    enum event_type type;

    char filename[256];

    __u64 mem_addr;
    __u64 mem_len;
    __u64 mem_brk_val;

    int fd;
    __s64 bytes_rw;
};

static struct multi_monitor_bpf *skel; // BPF 스켈레톤 구조체 포인터
static volatile bool exiting = false;  // 프로그램 종료 플래그
static __u32 my_pid;

// Perf buffer에서 이벤트를 수신할 때 호출되는 콜백 함수
static void handle_event(void *ctx, int cpu, void *data, __u32 data_len)
{
    // 수신된 데이터를 'struct event' 타입으로 캐스팅
    const struct event *e = (const struct event *)data;

    // 데이터 길이 유효성 검사 (안전성 강화)
    if (data_len < sizeof(*e)) {
        fprintf(stderr, "Received truncated event data (expected %zu, got %u)\n",
                sizeof(*e), data_len);
        return;
    }

    //if (e->pid != my_pid) return;
    if (strncmp(e->comm, "vim", sizeof(e->comm)) != 0) return;

    // 이벤트 유형에 따라 출력 포맷 변경
    switch (e->type) {
        case EVENT_CPU_EXEC:
            //printf("[CPU_EXEC] PID: %-6d | COMM: %-16s | FILENAME: %s\n", e->pid, e->comm, e->filename);
            break;
        case EVENT_CPU_FORK:
            //printf("[CPU_FORK] PID: %-6d | COMM: %-16s | CHILD_PID: %u\n", e->pid, e->comm, e->pid);
            break;
        case EVENT_MEM_MMAP:
            //printf("[MEM_MMAP] PID: %-6d | COMM: %-16s | ADDR: 0x%-16llx | LEN: %lld\n", e->pid, e->comm, e->mem_addr, e->mem_len);
            break;
        case EVENT_MEM_MUNMAP:
            //printf("[MEM_UNMAP]PID: %-6d | COMM: %-16s | ADDR: 0x%-16llx | LEN: %lld\n", e->pid, e->comm, e->mem_addr, e->mem_len);
            break;
        case EVENT_MEM_BRK:
            //printf("[MEM_BRK]  PID: %-6d | COMM: %-16s | NEW_BRK: 0x%-16llx\n", e->pid, e->comm, e->mem_brk_val);
            break;
        case EVENT_FILE_OPEN:
            //printf("[FILE_OPEN]PID: %-6d | COMM: %-16s | FILENAME: %s\n", e->pid, e->comm, e->filename);
            break;
        case EVENT_FILE_READ:
            printf("[FILE_READ]PID: %-6d | COMM: %-16s | FD: %-4d | BYTES: %lld\n", e->pid, e->comm, e->fd, e->bytes_rw);
            break;
        case EVENT_FILE_WRITE:
            //printf("[FILE_WRITE]PID: %-6d | COMM: %-16s | FD: %-4d | BYTES: %lld\n", e->pid, e->comm, e->fd, e->bytes_rw);
            break;
        case EVENT_FILE_CLOSE:
            //printf("[FILE_CLOSE]PID: %-6d | COMM: %-16s | FD: %-4d\n", e->pid, e->comm, e->fd);
            break;
        default:
            printf("[UNKNOWN]  PID: %-6d | COMM: %-16s | TYPE: %d\n", e->pid, e->comm, e->type);
            break;
    }
}

// 시그널 핸들러 (Ctrl+C 또는 kill 시그널 처리)
static void sig_handler(int sig)
{
    printf("\nExiting...\n");
    exiting = true; // 종료 플래그 설정
}

int main(int argc, char **argv)
{
    int err;
    struct perf_buffer *pb = NULL; // Perf buffer 구조체 포인터

    my_pid = getpid();

    // SIGINT (Ctrl+C)와 SIGTERM 시그널에 대한 핸들러 등록
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. BPF 스켈레톤 열기:
    skel = multi_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 2. BPF program load:
    err = multi_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s (errno: %d)\n", strerror(errno), errno);
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    // 3. BPF progarm attach:
    err = multi_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s (errno: %d)\n", strerror(errno), errno);
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    // 4. Perf buffer init:
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        multi_monitor_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully started! Tracing CPU, Memory, File I/O system calls. Press Ctrl+C to stop.\n");

    // 5. 이벤트 폴링 루프:
    while (!exiting) {
        err = perf_buffer__poll(pb, 100); // 100ms 타임아웃
        if (err == -EINTR) {
            err = 0; // 시그널 수신 시 루프 종료
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(errno));
            break;
        }
    }

    // 6. 자원 해제:
    perf_buffer__free(pb);
    multi_monitor_bpf__destroy(skel);
    return 0;
}
```

## Makefile

```c
# Makefile for eBPF Multi-System Call Monitor
CLANG_BUILTIN_INCLUDE := /usr/lib/llvm-18/lib/clang/18/include

# CLANG/LLVM 경로 설정 (시스템에 따라 다를 수 있음)
CLANG ?= /usr/bin/clang
LLVM_STRIP ?= /usr/bin/llc
BPFTOOL ?= /usr/sbin/bpftool

LIBBPF_SYSTEM_INCLUDE ?= /usr/include/bpf

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

# BPF 소스 및 출력 파일 경로
BPF_SRC = multi_monitor.bpf.c
BPF_OBJ = $(BPF_SRC:.c=.o)
BPF_SKEL_H = $(BPF_SRC:.c=.skel.h)

# 사용자 공간 소스 및 출력 파일 경로
USER_SRC = multi_monitor_user.c
USER_BIN = multi_monitor_user

# libbpf 설치 경로 (시스템에 따라 다름)
# libbpf는 /usr/lib/x86_64-linux-gnu/libbpf.a 나 /usr/local/lib/libbpf.a 등에 위치할 수 있습니다.
# 헤더 파일은 /usr/include/bpf 에 있습니다.
LIBBPF_DIR ?= /usr/lib/x86_64-linux-gnu/include # Ubuntu/Debian 기준
# LIBBPF_DIR ?= /usr/local # 직접 설치한 경우

KERNEL_HEADERS_DIR ?= /usr/src/linux-headers-$(shell uname -r)

# 컴파일러 플래그
BPF_CFLAGS := -g -O2 -target bpf -Wall $(ARCH_HDR_DEFINE) \
	      -I$(CLANG_BUILTIN_INCLUDE) \
	      -I$(LIBBPF_SYSTEM_INCLUDE) \
	      -I$(KERNEL_HEADERS_DIR)/arch/x86/include \
              -I$(KERNEL_HEADERS_DIR)/include

# libbpf 라이브러리와 헤더 경로 포함
USER_CFLAGS := -g -Wall -I. -I$(LIBBPF_SYSTEM_INCLUDE) -L$(LIBBPF_DIR)
USER_LDFLAGS := -lbpf -lelf

# 모든 타겟
.PHONY: all clean

all: $(USER_BIN)

# BPF 프로그램 컴파일 및 스켈레톤 헤더 생성
$(BPF_SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# 사용자 공간 프로그램 컴파일
$(USER_BIN): $(USER_SRC) $(BPF_SKEL_H)
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

# 클린 (모든 생성 파일 삭제)
clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL_H) $(USER_BIN)
```

## 실행 순서

1. 위 파일들 모두 저장
2. 아래 명령으로 vmlinux.h 파일 생성

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

1. 컴파일 및 실행

```bash
make # 실행 후 multi_monitor_user 바이너리 파일 생성 혹인
sudo ./multi_monitor_user

# 이후 다른 터미널에서 'vi new_file.txt' 등으로 파일 생성 명령 실행
# 다시 multi_monitor_user 가 실행되고 있는 터미널에서 출력 결과 확인
```
