# 2.3 eBPF Program, Map, Event Hook

eBPF의 핵심 구성요소 3가지

1. eBPF Program
2. eBPF Map
3. Event Hook

# eBPF Program

eBPF 프로그램은 커널 내부에서 실행되는 사용자 정의 코드. C 언어로 작성된 후, LLVM/Clang 컴파일러를 통해 eBPF 바이트코드(bytecode)로 컴파일된다.

이 바이트코드는 커널로 로드되기 전에 eBPF 검증기(verifier) 에 의해 안정성과 보안성 검사를 받는다.

### 주요 특징 및 역할

- 안정성 : eBPF 검증기는 프로그램이 무한 루프에 빠지지 않는지, 유효하지 않은 메모리 접근을 하지 않는지 또는 시스템 충돌을 일으키는지 여부를 체크한다. →커널의 안정성 보장
- 격리성: eBPF 프로그램은 커널 내부에서 실행되지만, 제한된 컨텍스트(Context) 내에서 동작하며, 모든 커널 메모리에 직접 접근할 수 없슴. 이는 보안 취약점 발생 가능성을 줄임.
- 이벤트 기반 실행: eBPF 프로그램은 특정 커널 이벤트(이벤트 훅)가 발생할 때 실행됨
- 다양한 종류: eBPF 프로그램은 목적에 따라 다양한 타입(Type)을 가진다. 각 타입은 특정 이벤트 훅에 연결되며 접슨할 수 있는 헬퍼 함수(Helper Function)와 컨텍스트 데이터에 차이가 있슴
    - BPF_PROG_TYPE_KPROBE : 커널 함수 진입/종료 시점에 실행(트레이싱)
    - BPF_PROG_TYPE_TRACEPOINT : 커널 정의 트레이스 프인트에서 실행(미리 정의된 커널 이벤트 트레이싱)
    - BPF_PROG_TYPE_XDP : 네트워크 패킷이 NIC 드라이버에 도달했을 때 실행(초고속 네트워크 처리)
    - BPF_PROG_TYPE_SCHED_CLS : 트래픽 제어(TC) 큐에 패킷이 들어올 때 처리(네트워크 패킷 분류 및 조작)
    - BPF_PROG_TYPE_SOCK_FILTER : 소켓에서 패킷을 필터링(네트워크 보안)
    - BPF_PROG_TYPE_CGROUP_SKB : cgroup에 속한 소켓의 패킷 처리(컨테이너 네트워킹)
    - BPF_PROG_TYPE_LSM : Linux Security Module 훅에서 실행(보안 정책 강화)
    - BPF_PROG_TYPE_PERF_EVENT : 성능 이벤트 발생 시 실행(성능 프로파일링)
    - Etc…

# eBPF Map

eBPF 맵은 eBPF 프로그램과 사용자 공간 애플리케이션 간, 또는 eBPF 프로그램 들 간에 데이터를 공유하고 저장하는데 사용되는 효율적인 키-값 저장소.

맵은 커널 공간에 상주하며, eBPF 프로그램이 직접 접근하고 수정할 수 있다.

### 주요 특징 및 역할

- 데이터 공유 : eBPF 프로그램은 직접적으로 전역 변수를 가질 수 없기 때문에, eBPF 맵을 통해 상태를 저장하고 공유함
    - eBPF Program ←→ eBPF Program : 한 eBPF 프로그램이 맵에 데이터를 쓰고, 다른 eBPF 프로그램이 그 데이터를 읽는다.
    - eBPF Program ←→ User Space : eBPF 프로그램이 맵에 데이터를 기록하면, User Space의 어플리케이션이 bpf() 시스템 콜을 통해 해당 맵을 읽어 데이터를 가져올 수 있다. 반대로 User Spacee 에서 맵에 데이터를 미리 저장해 두고 eBPF 프로그램이 이를 활용할 수도 있다.
- 맵 타입
    - BPF_MAP_TYPE_HASH : 일반적인 해시 테이블. 키-값 저장
    - BPF_MAP_TYPE_ARRAY : 인덱스를 키로 사용하는 배열. 고정 크기
    - BPF_MAP_TYPE_PROG_ARRAY : eBPF 프로그램들의 배열. 프로그램 간 점프(Tail Call) 구현에 사용됨.
    - BPF_MAP_TYPE_PERCPU_HASH / _ARRAY : CPU마다 독립적인 해시/배열. 경합을 줄여 성능 향상.
    - BPF_MAP_TYPE_RINGBUF : 순환 버퍼. eBPF 프로그램에서 사용자 공간으로 이벤트 데이터를 효율적으로 전달한다
    - BPF_MAP_TYPE_LPM_TRIE : 최장 접두사 매치(Longest Prefix Match)을 위한 트라이. IP 라우팅 등 네트워크 처리
    - BPF_MAP_TYPE_STACK_TRACE : 스택 트레이스 저장을 위한 맵. 성능 프로파일링
    - Etc…
- bpf( ) 시스템 콜 : User Space 어플리케이션은 bpf( ) 시스템 콜을 사용하여 맵을 생성/삭제/조회/업데이트 함. eBPF 프로그램은 맵 헬퍼 함수(bpf_map_lookup_elem(), bpf_map_update_elem(), bpf_map_delete_elem()) 을 사용하여 맵에 접근한다.

## Event Hook

이벤트 훅은 eBPF 프로그램이 커널 내부의 특정 지점에서 실행되도록 연결되는 ‘지점’ 또는 ‘이벤트’를 의미함.

eBPF 프로그램은 이러한 훅에 연결되어 해당 이벤트가 발생할 때마다 자동으로 실행됨.

### 주요 특징 및 역할

- 실행 지점 지정 : eBPF 프로그램이 언제 어디서 실행될지를 정의한다
- 컨텍스트 제공 : 각 훅은 프로그램에 특정 컨텍스트 데이터(예: 네트워크 패킷 정보, 함수 인자, 시스템 콜 인자 등)를 제공하여 프로그램이 필요한 정보를 얻고 작업을 실행할 수 있도록 한다
- 커널 기능 확장 : 기존 커널 코드를 수정하지 않고도 커널의 동작을 모니터링, 필터링, 조작 가능.

### 주요 이벤트 훅 종류

- Kprobe/Kretprobe:
    - Kprobe : 커널 함수의 시작 지점에 연결됨. 함수의 인자를 검사하거나 함수 호출 횟수를 세는 등 함수 호출 시점을 모니터링 할 때 사용됨.
    - Kretprobe : 커널 함수의 반환 지점에 연결. 함수의 반환 값이나 실행 시간을 측정할 때 사용.
    - 용도 : 동적 트레이싱, 성능 모니터링, 디버깅
- Tracepoints:
    - 커널 개발자가 미리 커널 코드 내에 명시적으로 정의해 둔 정적(Static) 이벤트 지점
    - Kprobe 보다 오버헤드가 적고, 인터페이스가 안정적.
    - 용도 : 시스템 콜, 스케줄링 이벤트, 파일 시스템 이벤트 등 미리 정의된 커널 이벤트 모니터링
- XDP (eXpress Data Path)
    - 네트워크 드라이버 수준에서 가장 빠르게 네트워크 패킷을 처리할 수 있는 훅. 패킷에 네트워크 카드(NIC)에 도달하자 마자 커널 네트워크 스택으로 진입하기 전에 실행됨
    - 용도 : DDoS 방어, 로드 밸런싱, 고성능 방화벽 등 초고속 네트워크 처리.
- Traffic Control (TC) / BPF_PROG_TYPE_SCHED_CLS
    - 네트워크 패킷이 리눅스 트래픽 제어(Traffic Control) 큐에 들어가거나 나갈 때 실행. XDP 보다는 늦은 단계이지만, 더 많은 네트워크 스택 정보에 접근 가능.
    - 용도 : 패킷 분류, 라우팅, 혼잡 제어, 대역폭 관리
- Socket Filters (BPF_PROG_TYPE_SOCK_FILTER)
    - 사용자 공간으로 전달될 패킷을 필터링하거나, 소켓에 도달하는 데이터를 조작하는 데 사용됨.
    - 용도 : 네트워크 보안(특정 IP나 포트의 패킷만 허용), 로깅
- cgroup 훅
    - cgroup(컨트롤 그룹)과 관련된 네트워크 이벤트나 시스템 콜에 연결됨
    - 용도 : 컨테이너 환경에서 네트워크 정책 적용, 자원 제어
- LSM (Linux Security Module) 훅
    - Linux Security Module 프레임워크의 특정 보안 작업 지점에 연결
    - 용도 : 사용자 정의 보안 정책 강화, 접근 제어
- Perf Events (BPF_PROG_TYPE_PERF_EVENT)
    - CPU 카운터, 하드웨어 이벤트, 소프트웨어 이벤트 등 Perf 이벤트가 발생할 때 실행됨
    - 용도 : 시스템 성능 프로파일링, CPU 사용량 분석