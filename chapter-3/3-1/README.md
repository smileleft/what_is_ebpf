# 3.1 필수 커널 버전과 조건 확인

# 필수 커널 버전

eBPF는 리눅스 커널에 기반한 기술이며, 사용 가능한 기능과 안정성은 커널 버전에 따라 크게 달라짐.

- 최소 요구 사항 : eBPF가 도입된 리눅스 커널 버전은 3.18임. 이 버전에선 가장 기본적인 기능만 제공하며, 실제 개발에 필요한 다양한 기능(Map, Helper Function. Verifier) 들은 이후 버전에서 추가되었슴
- 권장 커널 버전
    - 리눅스 커널 4.14 이상 : 이 버전부터 eBPF의 핵심 기능들이 많이 안정화되고 새로운 기능들이 추가되기 시작함.
    - 리눅스 커널 5.7 이상 : 최신 eBPF 기능(CO-RE, BPF ring buffer, BPF LSM hook)을 활용하려면 5.7 이후의 버전을 권장함. 특히 CO-RE(Compile Once Run Everywhere) 기능을 사용하려면 커널이 BTF(BPF Type Format) 정보를 노출하도록 컴파일되어야 함. 이는 최신 배포판에 기본 활성화되어 있슴
- 참고
    - 특정 eBPF 기반 도구(Falco, Cilium 등) 는 자체적으로 최소 커널 버전을 명시하고 있슴. 따라서 사용하고자 하는 도구의 문서를 확인해야 함

# 커널 조건 및 설정

eBPF 개발을 위해 커널에 특정 설정이 활성화되어야 함. 일반적으로 make menuconfig 등을 통해 커널을 직접 컴파일 하거나, 사용 중인 리눅스 배포판의 커널 패키지가 이러한 옵션들을 포함하고 있는지 체크해야 함

### 주요커널 설정

- **`CONFIG_BPF=y`**: eBPF 자체를 활성화
- **`CONFIG_BPF_SYSCALL=y`**: `bpf()` 시스템 호출을 활성화하여 사용자 공간에서 eBPF 프로그램과 상호 작용
- **`CONFIG_DEBUG_INFO=y` 및 `CONFIG_DEBUG_INFO_BTF=y`**: BPF CO-RE (Compile Once Run Everywhere) 기능을 위해 필요함. 이는 BPF 프로그램이 커널 버전이나 특정 커널 구조체에 의존하지 않고 동작하게 함. BTF 정보는 프로그램이 로드될 때 커널의 데이터 구조와 일치하는지 확인하는 데 사용됨
- **`CONFIG_BPF_JIT=y`**: eBPF 프로그램을 JIT (Just-In-Time) 컴파일하여 성능을 향상시킴
- **`CONFIG_PERF_EVENTS=y`**: eBPF 프로그램이 성능 이벤트를 통해 커널 함수에 연결될 수 있도록 함
- **`CONFIG_KPROBES=y`, `CONFIG_UPROBES=y`, `CONFIG_TRACEPOINTS=y`**: eBPF 프로그램이 각각 커널 함수, 사용자 공간 함수, 트레이스포인트에 연결될 수 있도록 하는 기능
- **`CONFIG_BPF_LSM=y` (커널 5.7 이상 권장)**: Linux Security Modules (LSM) hook을 eBPF 프로그램으로 확장할 수 있게 함. 보안 관련 eBPF 프로그램을 개발할 때 유용.

### 권한

eBPF 프로그램을 커널에 로드하려면 일반적으로 루트(root) 권한이 필요하거나, `CAP_SYS_BPF`, `CAP_SYS_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_PTRACE`와 같은 특정 리눅스 **역량(capabilities)**이 필요함.

### 개발 도구

eBPF 프로그램을 개발하려면 아래와 같은 도구들이 필요함

- CLang/LLVM : C 언어로 작성된 eBPF 프로그램을 eBPF 바이트 코드로 컴파일하는데 사용됨
- BPF Compiler Collection(BCC) : eBPF 개발을 위한 프레임워크 및 도구 모음. 파이썬 바인등을 제공하여 eBPF 프로그램을 더 쉽게 작성하고 관리할 수 있슴
- libbpf : BPF 시스템 호출을 래핑하고 BPF 프로그램 로딩, 맵 관리 등을 위한 저수준 라이브러리. C/C++ 기반의 eBPF 개발에 주요 사용됨. CO-RE를 지원.
- bpftrace : eBPF 기반의 고수준 트레이싱 언어. 간단한 스크립트로 커널 및 사용자 공간 이벤트를 추적하고 분석할 수 있슴.
- Linux Kernel Headers : 개발 중인 커널 버전과 일치하는 커널 헤더 파일이 필요함. 이는 eBPF 프로그램이 커널의 데이터 구조와 상호작용하는 데 사용됨.

⇒ 사용 중인  리눅스 배포판의 문서나 eBPF 공식 웹사이트(ebpf.io) 에서 본인의 환경에 맞는 가이드를 찾아볼 것을 권장.
