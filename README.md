# what_is_ebpf
eBPF self-study guide for Beginners

### 1. **기초 지식 정리**

- 1.1 Linux 커널 구조와 역할 이해
- 1.2 시스템 호출(System Call)과 커널 이벤트 개념
- 1.3 커널 모듈과 커널 공간 vs 유저 공간 차이

### 2. **eBPF 개요 및 철학**

- 2.1 eBPF란? (BPF의 역사와 확장판으로서의 의미)
- 2.2 eBPF의 주요 기능: 관찰성, 보안, 네트워킹
- 2.3 eBPF의 구성 요소: 프로그램, 맵(Map), 이벤트 훅(Hook)

### 3. **eBPF 개발 환경 구성**

- 3.1 필수 커널 버전과 조건 확인 (`uname -r`)
- 3.2 개발 툴 설치 (clang, llvm, libbpf, bpftool 등)
- 3.3 주요 프레임워크 소개
    - BCC (BPF Compiler Collection)
    - libbpf/libbpf-bootstrap
    - eBPF for Windows
    - Aya (Rust 기반 eBPF)

### 4. **간단한 예제 실습**

- 4.1 `hello_world` eBPF 프로그램 작성
- 4.2 tracepoint / kprobe / uprobes 사용법
- 4.3 bpftrace를 활용한 고수준 스크립팅

### 5. **관찰성(Observability)**

- 5.1 CPU, 메모리, IO 추적 예제
- 5.2 퍼포먼스 튜닝을 위한 eBPF 툴킷 (bcc-tools, perf-tools)
    - 5.2.1 bcc-tools(BPF compiler collection)
    - 5.2.2 perf-tools

### 6. **네트워크 트래픽 분석**

- 6.1 XDP (Express Data Path) 이해 및 실습
- 6.2 TC (Traffic Control) Hook 활용법
- 6.3 eBPF 기반 패킷 필터링, 로드밸런싱, 방화벽

### 7. **보안과 런타임 분석**

- 7.1 LSM (Linux Security Module)과 eBPF
- 7.2 Falco / Tetragon 기반 이상 탐지
- 7.3 시스템 호출 기반 파일 접근 제어 실습

### 8. **eBPF와 Kubernetes**

- 8.1 Cilium: eBPF 기반 CNI 네트워킹
- 8.2 eBPF를 활용한 서비스 메시 대체
- 8.3 클러스터 수준 트래픽/보안/리소스 관찰

### 9. **고급 주제 및 확장**

- 9.1 BTF, CO-RE (Compile Once – Run Everywhere)
- 9.2 eBPF 성능 최적화 전략
- 9.3 eBPF를 활용한 실시간 모니터링 대시보드 구축 (ex: Grafana, Prometheus 연동)

### 10. **프로젝트 실습 및 포트폴리오**

- 10.1 커널 이벤트 기반 실시간 로그 추적기 만들기
- 10.2 XDP를 활용한 간단한 방화벽/로드밸런서 구현
- 10.3 에너지 측정 또는 보안 탐지 에이전트 구축

---

### 📚 참고 자료

- [https://ebpf.io](https://ebpf.io/) — 공식 문서
- "Learning eBPF" (O'Reilly)
- [BCC Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)
- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
- 유튜브 강의: “BPF Performance Tools by Brendan Gregg”
