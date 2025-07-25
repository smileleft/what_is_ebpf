# 5.2.1 bcc-tools(BCC, BPF compiler collection)

- 목표
    - bcc tool을 설치한다
    - bcc 를 활용하여 커널 네트워크 함수에 Kprobe 를 attach하고 데이터를 수집한다
        - 각 프로세스 정보(PID 및 프로세스 이름) 별로 전송 및 수신된 네트워크 바이트를 측정한다
        - 실시간으로 데이터를 출력하고, 종료 시 데이터를 집계하여 총계(Total) 값을 요약하여 보여준다

# BCC install (Ubuntu)

패키지 설치

```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# 설치가 안될 경우 직접 패키지 정보를 업데이트 한 후 아래와 같이 설치
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)
```

소스코드 빌드

- 아래 dependency 설치 필요

```bash
LLVM 3.7.1 or newer, compiled with BPF support (default=on)
Clang, built from the same tree as LLVM
cmake (>=3.1), gcc (>=4.7), flex, bison
LuaJIT, if you want Lua support
Optional tools used in some examples: arping, netperf, and iperf
```

- build tool chain install

```bash
# For Jammy (22.04)
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
  
# For Noble Numbat (24.04)
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm18 llvm-18-dev libclang-18-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf libpolly-18-dev
```

- source code clone, compile and install

 

```bash
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd
```

# BPF C code

```c
// net_monitor.c

#include <uapi/linux/ptrace.h> // PT_REGS_PARM* 매크로를 위해 필요
#include <linux/sched.h>     // TASK_COMM_LEN을 위해 필요

// BPF 맵 정의: 프로세스 이름(comm)을 키로, 전송/수신 바이트를 값으로 하는 해시 맵
// 이 맵은 파이썬 사용자 공간에서 읽어옴
BPF_HASH(sent_bytes, char[TASK_COMM_LEN]); // 전송 바이트
BPF_HASH(recv_bytes, char[TASK_COMM_LEN]); // 수신 바이트

// BPF_HASH는 BCC에서 제공하는 래퍼 매크로.
// 실제로는 BPF_MAP_TYPE_HASH 맵을 생성.
// 키는 `char[TASK_COMM_LEN]` (프로세스 이름), 값은 `u64` (바이트 수)

// Kprobe: tcp_sendmsg (패킷 전송)
// 이 함수는 소켓을 통해 데이터를 전송할 때 호출됨.
// 인자: struct sock *sk, struct msghdr *msg, size_t len
// len (세 번째 인자)은 전송된 바이트 수입니다.
// 사용하는 커널 버전에 따라 함수 시그니처나 인자 순서가 다를 수 있슴.
// `sudo cat /proc/kallsyms | grep tcp_sendmsg` 로 확인.
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    char comm[TASK_COMM_LEN];
    u64 *value;
    u64 bytes = len; // 전송된 바이트 수

    // 현재 프로세스 이름 가져오기
    bpf_get_current_comm(&comm, sizeof(comm));

    // sent_bytes 맵에 현재 프로세스(comm)의 전송 바이트를 누적.
    value = sent_bytes.lookup(&comm);
    if (value) {
        // 이미 맵에 항목이 있으면 값을 업데이트.
        (*value) += bytes;
    } else {
        // 맵에 항목이 없으면 새로 추가.
        sent_bytes.update(&comm, &bytes);
    }

    return 0;
}

// Kprobe: tcp_recvmsg (패킷 수신)
// 이 함수는 소켓을 통해 데이터를 수신할 때 호출됨.
// 인자: struct sock *sk, struct msghdr *msg, size_t len, int flags
// `sudo cat /proc/kallsyms | grep tcp_recvmsg` 로 확인.
// 참고: tcp_recvmsg의 kprobe에서는 '수신될' 바이트 수를 알 수 있지만,
// 실제 '수신된' 바이트 수는 kretprobe에서 retval을 통해 알 수 있슴.
// 여기서는 kprobe에서 len을 사용하고, 더 정확하게는 kretprobe에서 retval을 사용하는 것이 좋음.
// 하지만 예제의 단순함을 위해 kprobe에서 len을 사용.
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int flags) {
    char comm[TASK_COMM_LEN];
    u64 *value;
    u64 bytes = len; // 수신될 (또는 수신된 예상) 바이트 수

    bpf_get_current_comm(&comm, sizeof(comm));

    // recv_bytes 맵에 현재 프로세스(comm)의 수신 바이트를 누적.
    value = recv_bytes.lookup(&comm);
    if (value) {
        (*value) += bytes;
    } else {
        recv_bytes.update(&comm, &bytes);
    }

    return 0;
}

// 라이선스 정보 (BCC에서는 필요하지 않지만 BPF 프로그램의 표준 관례)
// char LICENSE[] SEC("license") = "GPL";
```

# Python frontend code

```python
# !/usr/bin/python3
from bcc import BPF
from ctypes import c_char_p
import time
import sys
import signal

# BPF C 코드 (raw 문자열)
# 이 코드는 BCC에 의해 컴파일되어 커널에 로드됩니다.
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> // TASK_COMM_LEN을 위해 필요 (보통 16)
#include <linux/fs.h> // struct file, struct path 등을 위해 필요.
#include <linux/socket.h> // struct sock 등을 위해 필요.
#include <net/sock.h> // sock_common 등을 위해 필요.
#include <linux/tcp.h> // tcp_sendmsg, tcp_recvmsg 등의 함수 원형을 위해 필요.

// BPF 맵 정의: 프로세스 이름(comm)을 키로, 전송/수신 바이트를 값으로 하는 해시 맵
// 이 맵은 파이썬 사용자 공간에서 읽어옴.
BPF_HASH(sent_bytes, char[TASK_COMM_LEN]); // 전송 바이트
BPF_HASH(recv_bytes, char[TASK_COMM_LEN]); // 수신 바이트

// Kprobe: tcp_sendmsg (패킷 전송)
// tcp_sendmsg 함수는 다양한 커널 버전에 따라 시그니처가 상이함.
// PT_REGS_PARM3(ctx)를 사용하여 세 번째 인자(size_t len)를 추출.
// 커널 버전에 따라 매개변수의 레지스터 위치가 다를 수 있으니,
// `sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_sendto/format`
// 또는 `sudo bpftool prog dump kprobe/tcp_sendmsg` 등을 참조하여 확인.
// 여기서는 일반적인 x86-64 규칙을 따름: RDI, RSI, RDX, RCX, R8, R9
// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
// arg1: sk (RDI)
// arg2: msg (RSI)
// arg3: len (RDX)
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    u64 *value;
    u64 bytes = PT_REGS_PARM3(ctx); // 세 번째 인자(len) 추출

    // 현재 프로세스 이름 가져오기
    bpf_get_current_comm(&comm, sizeof(comm));

    // sent_bytes 맵에 현재 프로세스(comm)의 전송 바이트를 누적.
    value = sent_bytes.lookup(&comm);
    if (value) {
        // 이미 맵에 항목이 있으면 값을 업데이트.
        (*value) += bytes;
    } else {
        // 맵에 항목이 없으면 새로 추가.
        sent_bytes.update(&comm, &bytes);
    }

    return 0;
}

// Kprobe: tcp_recvmsg (패킷 수신)
// tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags)
// arg1: sk (RDI)
// arg2: msg (RSI)
// arg3: len (RDX)
// arg4: flags (RCX)
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    u64 *value;
    u64 bytes = PT_REGS_PARM3(ctx); // 세 번째 인자(len) 추출

    bpf_get_current_comm(&comm, sizeof(comm));

    // recv_bytes 맵에 현재 프로세스(comm)의 수신 바이트를 누적.
    value = recv_bytes.lookup(&comm);
    if (value) {
        (*value) += bytes;
    } else {
        recv_bytes.update(&comm, &bytes);
    }

    return 0;
}
"""

# BPF 프로그램 로드
b = BPF(text=bpf_text)

# Kprobe 어태치
try:
    # tcp_sendmsg 함수에 kprobe attach
    # 함수 이름이 커널 버전에 따라 다를 수 있으니, 필요시 `tcp_sendmsg`를 수정.
    b.attach_kprobe(event="tcp_sendmsg", fn_name="kprobe__tcp_sendmsg")
    # tcp_recvmsg 함수에 kprobe attach
    b.attach_kprobe(event="tcp_recvmsg", fn_name="kprobe__tcp_recvmsg")
except Exception as e:
    print(f"Failed to attach kprobe: {e}")
    print("Please check if the kernel function names (tcp_sendmsg, tcp_recvmsg) are correct for your kernel version.")
    print("You can verify with `sudo cat /proc/kallsyms | grep tcp_sendmsg` and `sudo cat /proc/kallsyms | grep tcp_recvmsg`")
    sys.exit(1)

print("네트워크 트래픽 모니터링 시작... Ctrl-C를 눌러 종료하세요.")
print(f"{'PID':<6} {'프로세스':<16} {'SENT (KB)':>12} {'RECV (KB)':>12}")

# Ctrl-C 시그널 핸들러
def signal_handler(sig, frame):
    print("\n모니터링 종료 중...")
    print("\n--- 최종 네트워크 트래픽 요약 ---")

    # 최종 집계 데이터 출력
    sent_map = b.get_table("sent_bytes")
    recv_map = b.get_table("recv_bytes")

    all_comms = set(sent_map.keys()) | set(recv_map.keys())

    for comm_bytes in all_comms:
        comm = comm_bytes.decode('utf-8').strip('\x00') # byte string을 utf-8로 디코딩하고 널 문자 제거
        sent = sent_map.get(comm_bytes, 0) / 1024 # 바이트를 KB로 변환
        recv = recv_map.get(comm_bytes, 0) / 1024 # 바이트를 KB로 변환
        print(f"{'':<6} {comm:<16} {sent:>12.2f} {recv:>12.2f}") # PID는 총계에서 빈 칸

    print("\n모니터링이 종료되었습니다.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# 주기적으로 맵에서 데이터를 읽어와 출력
try:
    while True:
        time.sleep(1) # 1초마다 업데이트

        # 맵에서 데이터 읽기
        sent_map = b.get_table("sent_bytes")
        recv_map = b.get_table("recv_bytes")

        # 각 프로세스별로 전송/수신 바이트 출력
        # 맵은 {b'comm': value} 형태이므로, 키를 디코딩해야 함.
        # 주의: BPF 맵에서 키를 직접 삭제하는 기능은 BCC에서 제공하지 않음.
        # 여기서는 주기적으로 모든 데이터를 다시 읽고 출력.
        # 실시간 변경 사항을 보려면, 이전 값을 추적하고 차이를 계산하는 로직이 필요.
        # 이 예제에서는 단순함을 위해 현재 누적된 값을 출력.

        # 전체 프로세스 목록을 가져오기 위해 두 맵의 키를 합침.
        all_comms = set(sent_map.keys()) | set(recv_map.keys())

        # 각 comm별로 출력
        for comm_bytes in all_comms:
            comm = comm_bytes.decode('utf-8').strip('\x00') # byte string을 utf-8로 디코딩하고 널 문자 제거
            sent = sent_map.get(comm_bytes, 0) / 1024 # 바이트를 KB로 변환
            recv = recv_map.get(comm_bytes, 0) / 1024 # 바이트를 KB로 변환
            # PID는 실시간으로 얻기 어려우므로 생략하거나, BPF에서 직접 PID를 맵 키로 추가해야 함.
            # 여기서는 PID 대신 공백으로 채움.
            print(f"{'':<6} {comm:<16} {sent:>12.2f} {recv:>12.2f}")

except KeyboardInterrupt:
    pass # Ctrl-C는 signal_handler가 처리.
except Exception as e:
    print(f"오류 발생: {e}")
finally:
    # 프로그램 종료 시 BPF 자원 자동 해제
    pass
```

# 실행

```bash
chmod 744 net_monitor.py
sudo python3 ./net_monitor.py

# 실행 후 다른 터미넡에서 네트워크 활동 생성
# ping google.com
# curl naver.com
# wget https://www.google.com/index.html
# 웹 브라우저로 웹 서핑
# Ctrl + C 로 종료 후 최종 요약 보고서 확인
```

# Flow

1. BPF C 코드 실행 → tcp_sendmsg, tcp_recvmsg 커널 함수에 Kprobe/Kretprobe attach
2. 데이터 추출 → 커널 함수 호출 시 현재 process PID, name, 전송/수신 바이트 수 추출
3. BPF map → 추출된 데이터를 BPF 맵에 저장하여 프로세스별로 바이트 수를 누적 계산
4. Python frontend → BPF C 코드를 로딩, BPF 맵에서 주기적으로 데이터를 읽어와 정의된 포맷에 따라 출력

# 참고.

- 이 외에도 [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc) 의 examples 디렉터리에 많은 예제들이 있으므로 추가 학습 가능
