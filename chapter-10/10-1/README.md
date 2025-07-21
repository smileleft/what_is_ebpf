## 1. 프로젝트 개요

### 목표

HTTP 패킷의 헤더나 URI를 분석하여 특정 조건을 만족하는 요청을 **차단하거나 다른 백엔드로 라우팅**하는 eBPF 기반 **L7 패킷 필터링 로드밸런서** 구현

---

## 2. 구현 계획

| 항목             | 내용                                             |
| -------------- | ---------------------------------------------- |
| **Hook Point** | XDP (fast path), TC (slow path) 병렬 실험          |
| **분석 대상**      | L3 \~ L7: Ethernet/IP/TCP + HTTP 헤더            |
| **라우팅 룰**      | `Host`, `User-Agent`, `Path` 필터 기반             |
| **제어 동작**      | drop, redirect, pass                           |
| **컨트롤 채널**     | user space에서 bpf map 업데이트 (Netlink or CLI)     |
| **관찰성**        | `bpf_trace_printk` → perf event로 수집, stats map |
| **추가 기능**      | pcap capture or prometheus exporter 가능         |

---

## 3. 디렉터리 구조

```
ebpf-l7-loadbalancer/
├── README.md
├── Makefile
├── common/
│   └── http_parser.h         # minimal HTTP parser
├── ebpf/
│   ├── l7_filter_kern.c      # eBPF XDP/TC 프로그램
│   └── maps.h                # shared BPF map definitions
├── user/
│   ├── main.c                # user space controller
│   └── config.json           # 필터 룰 정의
├── scripts/
│   ├── setup.sh              # iptables/XDP 환경 설정
│   └── load_bpf.sh           # BPF 프로그램 로드
└── build/
    └── ...                   # 컴파일된 객체 파일
```

---
