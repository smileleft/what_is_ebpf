# 2.2 eBPF의 주요 기능: 관찰성, 보안, 네트워킹

eBPF는 Linux 커널의 핵심 부분에서 직접 코드를 실행할 수 있는 독특한 능력을 바탕으로, 크게 관찰성(Observability), 보안(Security), **네트워킹(Networking)**의 세 가지 주요 영역에서 혁신적인 기능을 제공. 이 세 가지 영역은 현대 시스템에서 매우 중요한 요소이며, eBPF는 이들을 효과적으로 강화하고 확장하는 도구로 자리매김하고 있슴

# 관찰성(Observability)

관찰성은 시스템의 내부 상태를 이해하고 문제를 진단하기 위해 시스템에서 발생하는 이벤트를 수집, 분석하고 시각화하는 능력. 

eBPF는 커널 내부의 거의 모든 지점에서 데이터를 수집할 수 있는 강력한 기능을 제공하며, 기존의 모니터링 도구로는 얻기 어려웠던 심층적인 관찰성을 제공합니다.

- 시스템 전체 가시성
    - 커널 함수 호출 추적 (Kprobes/Tracepoints): read(), write(), open() 등 시스템 콜의 호출 횟수, 인자, 반환 값, 실행 시간 등을 정확하게 추적하여 어떤 애플리케이션이 어떤 파일에 얼마나 접근하는지, 어떤 시스템 콜이 병목 현상을 일으키는지 등을 파악
    - 네트워크 스택 모니터링: 패킷의 송수신 경로, 드롭된 패킷, TCP/UDP 연결 상태, 소켓 통계 등을 커널 네트워크 스택의 각 계층에서 모니터링하여 네트워크 문제를 진단하고 성능을 최적화
    - 스케줄러 동작 분석: 프로세스 스케줄링 이벤트(컨텍스트 스위치, CPU 대기 시간 등)를 추적하여 CPU 사용량 불균형이나 프로세스 병목 현상을 파악
    - 메모리/파일 시스템 I/O 추적
    - 동적 계측 (Dynamic Instrumentation): 시스템을 재부팅하거나 애플리케이션 코드를 수정하지 않고도 동적으로 원하는 지점에 eBPF 프로그램을 부착하여 데이터를 수집
    - 컨텍스트 정보 제공: eBPF 프로그램은 실행되는 커널 컨텍스트(예: 현재 프로세스 ID, 스택 트레이스, 레지스터 값 등)에 접근할 수 있어, 수집된 데이터에 대한 풍부한 컨텍스트 정보를 제공
    - 사례: bpftrace, bcc 툴킷의 다양한 도구들 (예: execsnoop, opensnoop, tcpsnoop, biosnoop, profile)

# 보안(Security)

eBPF는 커널 수준에서 시스템 호출, 네트워크 트래픽, 프로세스 동작 등을 모니터링하고 제어할 수 있는 능력을 제공하여 보안 기능을 강화하는 데 사용됨. 

이는 악의적인 활동을 감지하고 차단하며, 시스템의 공격 표면을 줄이는 데 기여

- 런타임 보안 정책
    - 시스템 콜 필터링 : 특정 프로세스나 컨테이너가 실행할 수 있는 시스템 콜을 세분화하여 제한. 웹 서버 프로세스가 execve() 시스템 콜을 호출하는 것을 방지하여 쉘 실행을 통한 공격을 막음 (seccomp-bpf가 대표적인 예시)
    - 네트워크 접근 제어 : 특정 IP 주소나 포트, 프로토콜에 대한 네트워크 통신을 허용하거나 차단하는 방화벽 기능을 커널 내부에서 효율적으로 구현할 수 있습니다. 이는 기존 iptables 보다 더 유연하고 성능이 뛰어남
- 침입 탐지 및 방지 (IDS/IPS)
    - 비정상 행위 탐지: eBPF를 사용하여 파일 접근 패턴, 네트워크 연결 시도, 프로세스 생성 등 시스템의 모든 활동을 실시간으로 모니터링하고, 미리 정의된 보안 규칙이나 머신러닝 기반의 비정상 행위 탐지 모델과 비교하여 의심스러운 활동을 탐지
    - 커널 우회 공격 방어: 커널 내부에서 실행되므로, 사용자 공간에서 작동하는 보안 솔루션이 우회될 수 있는 커널 수준의 공격(예: 루트킷)에 대해서도 방어 메커니즘을 제공
- 데이터 흐름 모니터링
    - 중요한 데이터(예: 민감 정보)가 어떻게 시스템 내에서 이동하고 외부로 유출되는지 추적하여 데이터 유출 방지(DLP)에 기여
- LSM (Linux Security Module) 통합
    - Linux Security Module의 훅에 연결되어 SELinux나 AppArmor와 같은 기존 보안 모듈의 기능을 확장하거나, 완전히 새로운 보안 정책을 구현(사례: Cilium Tetragon)

# 네트워킹(Networking)

Linux 네트워크 스택의 다양한 지점에 연결되어 패킷 처리 방식을 개선하고, 고성능 네트워킹 솔루션을 구현할 수 있게 함. 

서비스 메시, 로드 밸런싱, 방화벽 등 다양한 네트워크 기능에 활용됨

eBPF를 통한 네트워킹 기능

- 고성능 패킷 처리 (XDP - eXpress Data Path)
- Linux 트래픽 제어(TC) 프레임워크와 결합하여 패킷 분류, 포워딩, 마킹 등을 세밀하게 제어
- 소켓 필터링 및 조작
- 네트워크 정책 강제