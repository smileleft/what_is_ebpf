# 3.3 주요 프레임워크 소개

## BCC(BPF Compiler Collection)

eBPF는 강력하지만, 직접 eBPF 프로그램을 작성하고 커널과 상호작용하는 것은 복잡한 작업. C 언어로 커널 코드를 작성하고 이를 eBPF 바이트 코드로 컴파일 한 후, bpf( ) 시스템 콜을 통해 커널과 통신하는 과정이 필요하기 때문.

BCC는 이러한 복잡성을 추상화하고, eBPF 프로그램을 쉽게 만들고 사용할 수 있도록 돕는 툴킷.

### BCC 주요 기능과 특징

- 런타임 컴파일 : BCC는 사용자가 작성한 제한된 C언어 코드를 내부적으로 LLVM/Clang 을 사용하여 eBPF 바이트 코드로 컴파일(런타임에 이루어짐). 이는 타겟 시스템의 커널 헤더와 정확히 일치하는 메모리 레이아웃을 보장하여 호환성 문제를 줄임
- 다양한 프런트엔드 언어 지원: BCC는 주로 Python을 통한 사용자 인터페이스를 제공하며, Lua도 지원함. 이를 통해 C언어로 작성된 eBPF 프로그램(백엔드)와 상호작용하고 데이터 수집 등의 User Space 프로그램(프런트엔드)을 쉽게 작성할 수 있슴
- 내장된 도구 컬렉션 : BCC는 이미 80개 이상의 유용한 eBPF 기반 도구를 포함하고 있슴. 이 도구들은 시스템의 다양한 측면(파일 IO, 디스크 IO, 네트워크, CPU 사용량, 프로세스 실행 등)을 추적하고 분석하는데 사용될 수 있슴. 유명한 성능 분석가인 Brendan Gregg 이 개발한 많은 도구들이 포함되어 있슴
- 커널 계측 용이성: kprobe, uprobe, tracepoint, USDT(Userland Statically Defined Tracing) 등 다양한 커널 계측 지점에 eBPF 프로그램 연결 가능.
- 안정한 프로덕션 사용 : eBPF가 안정성을 보장하므로 시스템 불안정 없이 사용 가능

### BCC 활용 사례

- biolatency : 디스크 I/O 지연 시간을 히스토그램으로 시각화하여 보여줌(디스크 병목현상 진단)
- execsnoop : 어떤 프로세스가 어떤 파일을 열고 있는지 추적
- tcplife : TCP 연결의 수명 주기와 송수신 바이트 분석(네트워크 어플리케이션 분석)
- profile : CPU 사용량 프로파일링, 어떤 함수가 CPU 시간을 많이 사용하는지 스택 트레이스를 통해 분석(CPU 병목 현상 진단)
- syscount : 특정 시스템 콜 호출 횟수 집계
- ext4slower : ext4 파일시스템에서 느린 파일 시스템 작업(read, write 등)을 추적

## libbpf

libbpf는 리눅스 커널과 함께 배포되는 eBPF 어플리케이션 개발을  위한 C/C++ 라이브러리. eBPF 프로그램을 커널에 로드/관리, User Space 어플리케이션과 상호 작용하는데 필요한 저수준(low-level) API를 제공.

### 주요 특징

- AOT(Ahead-Of-Time) 컴파일 : libbpf는 BCC와 달리 eBPF 프로그램을 미리 컴파일함. 개발자는 eBPF C 코드를 작성한 후, LLVM/Clang을 사용하여 .o(ELF) 파일로 컴파일. 컴파일된 .o 파일은 libbpf를 사용하는 User Space 어플리케이션에 배포됨.
    - 장점
        - 종속성 감소 : 런타임에 LLVM/Clang이 필요없기에 배포 환경에 대한 종속성이 줄어듬. 컨테이너 또는 경량 배포 환경에 유리.
        - 안정적인 배포 : 미리 컴파일됨 → 배포 시점의 컴파일 오류 X
        - 최적화된 코드 : 컴파일러 최적화를 통해 더 효율적인 eBPF 바이트 코드 생성
- BTF(BPF Type Format) 지원 : libbpf의 가장 중요한 특징으로서, BTF는 eBPF 프로그램이 참조하는 커널 데이커 구조와 함수의 타입 정보를 포함하는 메타 데이터 형식
    - libbpf는 로드 시점에 BTF 정보를 활용하여, 컴파일된 eBPF 프로그램이 로드될 커널의 실제 데이터 구조 오프셋과 타입에 맞게 자동으로 재배치(relocate) 하고 적응(adopt) 시킴.
    - 이점 : 커널 버전마다 데이터 구조의 레이아웃이 미묘하게 다를 수 있슴. BTF 를 사용하면 하나의 컴파일된 eBPF 프로그램이 다양한 커널 버전에서 호환되도록 실행될 수 있슴. (Write once, run everywhere → 이식성 향상)
- 콜드 스타트(Cold Start) 시간 단축 : 런타임 컴파일이 필요 없으므로, eBPF 프로그램이 커널에 로드되고 실행되기까지의 시간이 단축됨.
- 커널에 내장 : libbpf 자체가 커널 소스 트리에 포함되어 개발되고 유지보수됨 → 커널의 최신 eBPF 기능과 API 변경 사항에 빠르게 대응할 수 있슴
- Idiomatic C API : C/C++ 개발자에게 익숙한 방식으로 eBPF 프로그램을 제어할 수 있는 API 제공.

## libbpf-bootstrap

libbpf-bootstrap 은 libbpf를 사용하여 새로운 eBPF 프로젝트를 시작하기 위한 boilerplate 저장소이자 템플릿. eBPF 개발의 초기 설정을 간소화하고, libbpf의 기능을 효과적으로 활용할 수 있도록 미리 구성된 프로젝트 구조를 제공함.

### libbpf-boostrap의 주요 특징 및 역할

- 프로젝트 템플릿 : eBPF 프로그램(C code)과 User Sapce 어플리케이션(C/C++ code)을 위한 기본 구조를 제공
- Makefile 지원 : libbpf 기반 프로젝트를 빌드하는데 필요한 Makefile 이 구성되어 있슴. LLVM/Clang 을 사용하여 eBPF C 코드를 .o 파일로 컴파일하고 libbpf 라이브러리를 사용하여 User Space 바이너티를 링크하는 과정이 포함됨
- 자동 BTF 처리 : libbpf-bootstrap 템플릿은 빌드 시스템이 BTF 정보를 자동으로 처리하고, eBPF 프로그램이 CO-RE를 지원하도록 설정하는 방법을 보여줌
- 예제 코드 : 기본적인 예시 코드 제공
- CMake 통합 : Make 외에 CMake 를 이용한 빌드 시스템 지원.

| 특징 | libbpf (및 libbpf-bootstrap) | BCC (BPF Compiler Collection) |
| --- | --- | --- |
| 컴파일 방식 | AOT (Ahead-Of-Time) 컴파일 | 런타임(Runtime) 컴파일 |
| 개발 언어 | C/C++ (eBPF), C/C++ (사용자 공간) | C (eBPF), Python/Lua (사용자 공간) |
| 종속성 | 배포 시 LLVM/Clang 필요 없음 (커널 헤더 필요) | 런타임에 LLVM/Clang 필요 |
| 이식성 (CO-RE) | BTF를 통한 높은 이식성 (Compile Once – Run Everywhere) | 런타임 컴파일로 인한 높은 호환성 (하지만 종속성 증가) |
| 배포 용이성 | 단일 바이너리 또는 경량 패키지 형태로 배포 용이 | LLVM/Clang 종속성으로 인한 배포 복잡성 |
| 주요 사용처 | 프로덕션 환경에서의 안정적인 eBPF 애플리케이션 | 빠른 프로토타이핑, 개발, 시스템 진단 도구 |
| 디버깅 | 정적 분석 및 컴파일 타임 오류 검출 용이 | 런타임 컴파일 특성상 디버깅이 다소 까다로울 수 있음 |
| 도구 제공 | 템플릿 제공, 직접 도구 개발 필요 | 다양한 기성 eBPF 도구 내장 (예: execsnoop) |

## eBPF for Windows

[https://github.com/microsoft/ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows)

eBPF는 리눅스 커널의 기술이지만, 그 기능과 활용성은 다른 운영체제에서도 도입 필요성이 제기되어 옴. 마이크로스프트는 이러한 요구에 부응하여 “eBPF for Windows” 프로젝트를 추진하고 있슴. 이는 eBPF 툴체인과 API를 Windows 에서도 사용할 수 있도록 하는 것을 목표로 함

![image.png](resource/image.png)

                Architectural Overview of eBPF for Windows

### eBPF for Windows 의 아키텍처 및 구현 세부 사항

1. eBPF Shim (Windows-specific Hosting Environment)
    1. eBPF 프로그램을 Windows 커널의 public API를 래핑하여 eBPF Helper function 과 Hook point를 노출함
    2. Linux의 bpf( ) 시스템 콜과 유사한 기능을 ebpfapi.dll 이라는 공유 라이브러리를 통해 제공, User Space 어플리케이션이 eBPF 프로그램과 상호작용할 수 있게 함
2. eBPF Runtime (Interpreter & JIT)
    1. Linux eBPF 와 유사하게, eBPF for Windows 도 인터프리터 모드와 JIT(Just-In-Time) 컴파일 모드를 지원함
    2. JIT 컴파일러는 eBPF 바이트 코드를 wIndows CPU 아키텍처에 맞는 네이티브 머신 코드로 변환하여 고성능 실행을 가능하게 함
3. eBPF Verifier (PREVAIL)
    1. eBPF 프로그램의 안정성을 보장하는 핵심 구성 요소
    2. Linux 의 verifier 와 유사하게 eBPF 프로그램이 커널에 로드되기 전, 무한로프/유효하지 않은 메모리접근/타입 불일치 등을 검사
    3. eBPF for Windows는 PREVAIL 이라는 정적 verifier 를 user-mode protected process 내에서 호스팅함 → Windows의 보안모델을 따름
4. eBPF 프로그램 형식
    1. linux와 마찬가지로 eBPF for Windows에서도 LLVM/Clang 을 사용하여 C 소스코드를 eBPF 바이트 코드(ELF) 로 컴파일.
    2. libbpf API를 지원하여 Linux에서 사용하는 libbpf 기반의 AOT(Ahead-Of-Time) 컴파일 및 CO-RE(Compile once, Run Everywhere) 개념을 Windows 에서도 구현할 수 있게 함.
5. Hook Points & Helper Function
    1. eBPF 프로그램이 커널의 특정 이벤트에 연결될 수 있는 다양한 후크 지점을 제공. 
    2. eBPF 프로그램 내에서 사용할 수 있는 Helper 함수들을 제공
6. 네이티브 드라이버 컴파일
    1. eBPF for Windows 의 독특한 기능 : eBPF 프로그램을 네이티브 Windows 드라이버로 컴파일 할 수 있는 모드를 지원함
    2. 이렇게 컴파일된 드라이버는 표준 Windows 드라이버 서명 메커니즘을 사용하여 서명 가능. 이는 프로덕션 환경에서 엄격한 보안 요구사항을 충족하는데 중요함.

## Aya : Rust 기반 eBPF 개발 프레임워크

Aya는 러스트 언어를 사용하여 eBPF 를 개발할 있게 하는 오픈소스 프레임워크. 

[https://github.com/aya-rs/aya](https://github.com/aya-rs/aya)

### Why Rust for eBPF?

- eBPF의 특성 : 커널 패닉을 일으키지 않도록 안정성을 엄격하게 검증하는 것이 중요
- Rust 의 강점
    - 메모리 안정성 : Rust 는 컴파일 시점에 메모리 오류(널 포인터 역참조 등)를 방지하는 강력한 타입 시스템과 소유권(Ownership) 및 빌림(Borrowing) 규칙을 가짐.
    - 성능 : C/C++ 과 동등한 수준의 성능을 제공하며 런타임 오버헤드가 거의 없슴.
    - 강력한 타입 시스템 : 버그 방지
- BCC 및 libbpf 의 한계 보완
    - BCC : 런타임에 LLVM/Clang 이 필요, python 기반으로 인해 프로덕션 배포에 다소 제약이 있슴
    - libbpf (C) : C/C++ 언어 고유의 특성으로 인해 메모리 안정성 문제로부터 자유롭지 못함

### Aya의 구성요소

1. Kernel Space 크레이트
    1. Rust 로 eBPF 프로그램을 작성하는데 필요한 매크로와 헬퍼함수 제공
    2. eBPF 맵(Maps)과의 상호작용, `kprobe`, `tracepoint` 등 다양한 후크 지점에 대한 인터페이스를 정의
    3. `no_std` 환경을 지원하여, Rust 표준 라이브러리 없이 커널에서 실행될 수 있는 최소한의 코드를 생성
    4. `aya-bpf`라는 이름의 크레이트(crate)로 배포
2. User Space 크레이트
    1. Rust 로 작성된 eBPF 프로그램을 로드
    2. `libbpf`와 유사하게, 컴파일된 eBPF ELF 파일을 파싱하고, 프로그램을 커널에 로드하며, 후크 지점에 연결하는 기능을 제공
    3. eBPF 맵을 통해 커널 공간의 eBPF 프로그램과 사용자 공간 애플리케이션 간에 데이터를 주고받을 수 있도록 함
    4. `perf_events` 버퍼를 통한 이벤트 스트리밍도 지원
    5. `aya`라는 이름의 크레이트(crate)로 배포

### Aya의 핵심 특징

- **Rust native:** eBPF 프로그램과 사용자 공간 코드를 모두 Rust로 작성 가능
- **안전성:** Rust의 메모리 안전성 보장을 통해 eBPF 프로그램 개발 중 발생할 수 있는 잠재적인 버그를 컴파일 타임에 미리 방지
- **성능:** Rust는 C/C++에 필적하는 성능을 제공하며, eBPF 프로그램은 커널에서 효율적으로 실행
- **BTF 및 CO-RE 지원:** `libbpf`와 유사하게 BTF(BPF Type Format)를 활용하여 `Compile Once – Run Everywhere (CO-RE)`를 지원합니다. 이는 하나의 eBPF 프로그램이 여러 다른 리눅스 커널 버전에서 작동하도록 하여 이식성을 크게 향상
- **빌드 시스템 통합:** `cargo` (Rust의 빌드 도구)를 통해 eBPF 프로그램과 사용자 공간 코드를 쉽게 빌드할 수 있도록 통합
- **개발자 경험:** Rust의 강력한 타입 추론, 매크로, 모듈 시스템 등을 활용하여 eBPF 개발자 경험을 향상
- **Aya CLI:** `aya` CLI 도구를 제공하여 프로젝트 스캐폴딩, 빌드, 로드 등 eBPF 개발 워크플로우를 간소화
- 공식 Docs : [https://aya-rs.dev/book/](https://aya-rs.dev/book/)
