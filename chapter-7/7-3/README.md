# 7.3 시스템호출 기반 파일접근제어 실습

## 프로젝트 개요: eBPF 기반 파일 접근제어

구성요소

- **eBPF 프로그램(C)**: 커널에 로드되어 openat 시스템 호출을 후킹. 접근하려는 파일 경로를 확인하고 정책에 따라 허용 또는 거부함
- **userspace 어플리케이션 (Go)** : eBPF 프로그램을 컴파일하고 커널에 로드하며, eBPF 맵을 통해 커널 프로그램과 통신. 또한 접근제어 정첵을 정의하고 관리함
- **eBPF 맵** : 접근제어 정책 목록을 저장

## 개발환경 설정

```bash
# Ubuntu/Debian 기준
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) golang-go

# libbpf 설치 (최신 버전 사용 권장)
# https://github.com/libbpf/libbpf/releases 에서 최신 버전 확인
# 예시: v1.3.0
wget https://github.com/libbpf/libbpf/archive/refs/tags/v1.3.0.tar.gz
tar -xvzf v1.3.0.tar.gz
cd libbpf-1.3.0/src
make
sudo make install
sudo ldconfig

# go-libbpf 라이브러리 설치 (Go에서 eBPF 사용을 위함)
go install github.com/cilium/ebpf/cmd/bpf2go@latest # bpf2go 도구 설치
```

## 프로젝트 구조 생성

```bash
file-access-control/
├── bpf/
│   └── file_acl.c
├── main.go
├── go.mod
├── go.sum
└── Makefile
```

## eBPF 프로그램 (bpf/file_acl.c)  작성

이 코드는 openat  시스템 호출을 후킹하고 특정 파일(/tmp/secret.txt) 에 대한 접근을 거부하게 함

```c
// bpf/file_acl.c
#include "vmlinux.h" // 커널 타입 정의 (bpf2go를 통해 자동 생성될 수 있음)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>
#include <linux/limits.h> // PATH_MAX

// 특정 파일 경로를 매치하기 위한 맵
// 이 맵은 사용자 공간에서 제어될 수 있습니다.
// 여기서는 간단화를 위해 eBPF 프로그램 내부에 하드코딩합니다.
// 실제 프로젝트에서는 BPF_MAP_TYPE_HASH 등을 사용합니다.

// 파일 접근을 거부할 경로
const char *target_file = "/tmp/secret.txt";

SEC("tp/syscalls/sys_enter_openat")
int BPF_PROG(file_access_control, int dfd, const char *filename, int flags, umode_t mode) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 파일 경로를 커널 공간에서 사용자 공간으로 복사 (filename은 사용자 공간 주소)
    char path[PATH_MAX];
    bpf_probe_read_user(&path, sizeof(path), filename);

    // 로그 출력 (디버깅용)
    bpf_printk("openat called by %s for file %s\n", comm, path);

    // 접근 제어 로직
    // "/tmp/secret.txt" 파일에 대한 접근을 거부
    if (bpf_strncmp(path, sizeof(target_file), target_file) == 0) {
        bpf_printk("Blocking access to %s\n", path);
        // -EACCES (Permission denied) 반환하여 접근 거부
        return -EACCES;
    }

    // 다른 파일은 허용
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

## userspace 어플리케이션 (main.go) 작성

```go
// main.go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf_file_acl bpf/file_acl.c -- -I./bpf/

func main() {
	// rlimit 설정: eBPF 맵 및 프로그램에 필요한 메모리 제한 해제
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	// bpf2go를 통해 생성된 bpf_file_acl 객체 로드
	// 이는 bpf_file_acl.go 파일에 정의되어 있습니다.
	objs := bpf_file_aclObjects{}
	if err := loadBpf_file_aclObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close() // 프로그램 종료 시 eBPF 객체 정리

	// sys_enter_openat 트레이스포인트에 eBPF 프로그램 연결
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.FileAccessControl)
	if err != nil {
		log.Fatalf("Linking tracepoint failed: %v", err)
	}
	defer tp.Close() // 프로그램 종료 시 링크 해제

	log.Println("eBPF program loaded and attached to sys_enter_openat tracepoint.")
	log.Printf("Attempt to access '/tmp/secret.txt' now. It should be blocked.")
	log.Println("Press Ctrl+C to exit and unload the eBPF program.")

	// CTRL+C 신호를 기다림
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Unloading eBPF program.")
}
```

## GO 모듈 및 Makefile 설정

- go.mod 파일 생성

```bash
go mod init file-access-control
go get github.com/cilium/ebpf/cmd/bpf2go
go get github.com/cilium/ebpf
go mod tidy
```

- Makefile 생성

```makefile
# Makefile
.PHONY: all build clean run

C_SOURCES := bpf/file_acl.c
GO_SOURCES := main.go

all: build

build: bpf_file_acl.go
go build -o file-access-control ${GO_SOURCES}

bpf_file_acl.go: ${C_SOURCES}
go generate ./...

clean:
rm -f file-access-control bpf_file_acl.go bpf_file_acl_bpfel.o bpf_file_acl_bpfel_xgo.o
rm -rf bpf/
rm -rf go.sum go.mod

run: build
sudo ./file-access-control
```

프로젝트 빌드 및 실행

- 빌드

```bash
make build
```

go generate 가 bpf_file_acl.go 파일을 생성하고 go build가 실행 파일을 생성함.

제대로 빌드되면 file-access-control 이라는 바이너리 파일이 생성됨

- 실행

```bash
sudo ./file-access-control
```

프로그램이 실행되면 “eBPF program loaded and attached…” 메시지가 출력됨

- 동작테스트
    - 새로운 터미널을 열고 다음 명령어를 실행하여 /tmp/secret.txt 파일에 접근을 시도
    - (사전에) 비밀 파일 생성(루트 권한)
    
    ```bash
    sudo touch /tmp/secret.txt
    ```
    
    - 파일 읽기 시도(eBPF 가 로드된 상태에서)
    
    ```bash
    cat /tmp/secret.txt
    ```
    
    이 명령은 Permission Denied 에러와 함께 실패해야 함
    
    ```bash
    echo "test" > /tmp/secret.txt
    ```
    
    이 명령도 Premission Denied 에러와 함께 실패해야 함
    
- eBPF 로그확인
    
    ```bash
    sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "Blocking access"
    # or
    sudo bpftool prog tracelog
    ```
    
- eBPF 프로그램 종료
    
    sudo ./file-access-control 을 실행한 터미널에서 Ctrl+C 로 종료
    
- 파일 읽기 다시 시도(eBPF가 언로드된 상태에서)
    
    ```bash
    cat /tmp/secret.txt
    ```
    
    파일이 정상적으로 읽혀야 함
    

[7.3.1 python userprogram](https://www.notion.so/7-3-1-python-userprogram-22a2c18e27da80bf8a17ff3dc2a61d0f?pvs=21)
