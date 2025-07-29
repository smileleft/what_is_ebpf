# 9.1 BTF, CO-RE (Compile Once – Run Everywhere)

# eBPF의 이식성(portability)

eBPF 프로그램은 커널 내부 구조에 의존하는 경우가 많음. 

예를 들어 특정 커널 구조체(struct task_struct 등)의 필드에 접근하거나, 특정 syscall 또는 hook 지점에 붙는 등의 동작을 함. 이 때,

- 커널 버전이 바뀔 때 구조체의 레이아웃이 바뀌거나
- 디버깅 심볼이 바뀌거나
- 커널 기능이 달라져 프로그램이 동작하지 않을 수도 있슴

즉, 하나의 시스템에서 빌드한 eBPF 프로그램이 다른 커널에서는 제대로 실행되지 않을 수도 있슴

# CO-RE(Compile Once, Run Everywhere)

CO-RE는 이런 문제를 해결하기 위한 기술로, eBPF 프로그램을 한번 컴파일하면 다양한 커널 버전에서 다시 컴파일 없이 그대로 실행할 수 있게 함

## 핵심 아이디어

1. eBPF 프로그램을 BTF(BPF Type Format) 정보를 바탕으로 작성
2. 컴파일 시 커널의 구조체 정의에 고정적으로 의존하지 않고, 런타임 시 실제 커널의 구조체 정보를 참조하여 동적으로 주소와 오프셋을 계산함
3. 이를 위해 libbpf의 CO-RE Relocation(리로케이션) 기능이 사용됨 ([https://libbpf.readthedocs.io/en/latest/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere](https://libbpf.readthedocs.io/en/latest/libbpf_overview.html#bpf-co-re-compile-once-run-everywhere))

## CO-RE를 가능하게 하는 주요 기술

1. **BTF (BPF Type Format)**
- 커널이 자신이 사용하는 타입 정보를 **.BTF** 섹션에 담아서 노출
- 구조체 필드, 타입 이름, 크기, 오프셋 등을 담고 있슴
- CO-RE는 이 BTF 정보를 활용해서 프로그램이 커널 구조체와 정확히 맞도록 동작하게 함
1. **BPF Skeleton ( bpftool gen skeleton )**
- 최신 방식에서는 **bpftool** 을 통해 eBPF 프로그램에서 사용할 수 있는 skeleton code 를 생성
- 이 skeleton 은 CO-RE에 필요한 BTF 정보를 포함하고, 런타임에 커널에 맞춰 자동 Relocation을 수행함
1. **libbpf** 의 CO-RE relocation
- eBPF 프로그램 내에서 **bpf_core_read()** 또는 **BPF_CORE_READ()** 매크로를 사용하면
- 컴파일된 시점과는 다른 커널 구조체에서도 유연하게 필드에 접근할 수 있슴

예

```c
// task_struct에서 comm 필드를 안전하게 읽기
char comm[16];
BPF_CORE_READ_STR(&comm, task, comm);
```

## CO-RE 적용 전 vs 후 비교

| 항목 | CO-RE 이전 | CO-RE 이후 |
| --- | --- | --- |
| 커널 버전에 대한 의존성 | 매우 높음 | 매우 낮음 |
| eBPF 프로그램 유지보수 | 복잡함 (커널 버전마다 빌드 필요) | 단순 (한번 빌드하면 다양한 커널에서 실행 가능) |
| 런타임 안정성 | 커널 변경 시 깨질 수 있음 | 구조체 변경에도 자동 적응 |
| 요구사항 | 특정 커널 디버그 헤더 필요 | BTF 지원만 있으면 됨 |

## CO-RE 기반 eBPF 개발 과정

1. BTF 지원 커널(5.4+ 이상)을 대상으로 eBPF 프로그램 작성
2. **clang -target bpf …** 로 컴파일
3. **bpftool gen skeleton** 또는 **bpftool get object** 사용하여 BTF 포함된 바이너리 생성
4. target 시스템에서 **libbpf** 를 이용해 로드 → libbpf 가 구조체 오프엣 등을 자동 계산

## CO-RE 지원 플랫폼 (BTF, BPF Type Format 사용 가능한 OS)

- Ubuntu 20.10+
- Debian 11 (amd64/arm64)
- Fedora 31+
- RHEL 8.2+
- OpenSUSE Tumbleweed (in the next release, as of 2020-06-04)
- Arch Linux (from kernel 5.7.1.arch1-1)
- Manjaro (from kernel 5.4 if compiled after 2021-06-18)

## 참고

- vmlinux.h → 전체 커널 타입 정의를 담은 헤더 파일. **`bpftool btf dump file /sys/kernel/btf/vmlinux format c`**로 생성 가능
- skeleton 구조체 자동 생성 : **bpftool gen skeleton prog.bpf.o > prog.skel.h**
- CO-RE 테스트 환경: Ubuntu 20.04 이상이면 대부분 지원함, BTF 가 /sys/kernel/btf/vmlinux 경로에 있어야 함
- [https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)
