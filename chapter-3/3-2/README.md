# 3.2 개발 툴(clang, llvm, libbpf, bpftool) 설치

- 이 문서에서는 Ubuntu 22.04 버전을 사용한다
- Ubuntu 22.04 의 커널버전은 6.8.0-60-generic 임

### 1. 시스템 업데이트

시스템 패키지 목록을 업데이트하고, 기존 패키지들을 업그레이드하여 최신 상태를 유지한다

```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Clang & LLVM 설치

Clang 과 LLVM은 eBPF 프로그램을 컴파일하는데 필수 도구. Ubuntu 22.04의 기본 저장소에 비교적 최신 버전이 포함되어 있다.

```bash
sudo apt install -y clang llvm
```

설치 확인

```bash
clang --version
```

참고 : llvm 은 단일 실행파일이 없으며 clang —vesion 이 제대로 동작하면 llvm 의 실행환경에는 문제가 없슴. 아래는 clang 버전 체크 결과.

![스크린샷 2025-05-31 16-33-33.png](resource/%EC%8A%A4%ED%81%AC%EB%A6%B0%EC%83%B7_2025-05-31_16-33-33.png)

- Ubuntu clang version 14.0.0-1ubuntu1.1 → Ubuntu 22.04 의 기본 저장소에 있는 Clang 14.0.0 버전이 성공적으로 설치됨(eBPF 개발에 충분한 최신 버전)
- Target: x86_64-pc-linux-gnu → Clang 이 64비트 리눅스 시스템을 대상으로 컴파일 하도록 설정되어 있슴
- Thread model: posix → POSIX 스레드 모델을 사용하고 있슴
- InstallDir: /usr/bin → Clang 실행 파일이 /usr/bin 경로에 설치되어 있슴

### 3. libbpf 설치

libbpf 는 eBPF 프로그램을 로드하고 맵과 상호 작용하기 위한 저수준 라이브러리. libbpf-dev 패키지를 설치하면 개발에 필요한 헤더 파일과 라이브러리를 사용할 수 있슴

```bash
sudo apt install -y libbpf-dev
```

설치 확인

libbpf는 실행파일이 아니므로, 설치된 라이브러리 파일의 위치를 확인함

(x86 CPU 기준)

```bash
ls /usr/lib/x86_64-linux-gnu/libbpf.so
ls /usr/include/bpf/libbpf.h
```

참고: libbpf 공식 github → [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)

### 4. bpftool 설치

bpftool은 커널 내의 eBPF 프로그램 및 맵과 상호작용하고 디버깅하는 데 유용한 도구

```bash
sudo apt install linux-tools-common linux-tools-$(uname -r)
```

→ 이미 linux-tools-common 패키지가 최신으로 설치되어, 따로 설치하지 않아도 된다는 메시지가 출력될 수 있슴

![스크린샷 2025-05-31 16-51-56.png](resource/%EC%8A%A4%ED%81%AC%EB%A6%B0%EC%83%B7_2025-05-31_16-51-56.png)

```bash
# 아래 명령의 결과가 정상 출력되면 OK (결과는 /usr/sbin/bpftool)
which bpftool
```

참고: bpf tool 공식 블로그 → [https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/](https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/)

### 5. Linux 커널 헤더 설치

```bash
sudo apt install -y linux-headers-$(uname -r)
```

→ 이미 최신 헤더가 설치되어 있다는 메시지가 출력될 수 있슴

![스크린샷 2025-05-31 17-03-40.png](resource/%EC%8A%A4%ED%81%AC%EB%A6%B0%EC%83%B7_2025-05-31_17-03-40.png)

### 6. BCC(BPF Compiler Collection) 설치

```bash
sudo apt install -y bpfcc-tools linux-headers-$(uname -r)
```

설치 확인

```bash
sudo opensnoop-bpfcc # 실행 후 Ctrl + C 로 중지
```

ubtuntu 이외의 플랫폼에 설치하는 법 - 공식문서
[https://github.com/iovisor/bcc/blob/master/INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

