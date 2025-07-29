# 9.3 eBPF를 활용한 실시간 모니터링 대시보드 구축

## 환경

- Cilium Load Balancer
- Prometheus
- Grafana

## 개요

eBPF 기반 로드밸런서 Cilium은 커널 내에서 패킷 처리, 서비스 매칭, 로드 밸런싱을 수행함.

Prometheus는 이러한 시스템에서 발생하는 메트릭을 수집하는데 사용되며, Grafana는 수집된 메트릭을 시각화하는 대시보드를 제공.

- **Cilium Agent 메트릭**
    - Cilium Agent 는 eBPF 프로그램의 로드, 트래픽 처리 통계, 정책 적용 상태 등 다양한 내부 메트릭을 Prometheus 포맷으로 노출
- **eBPF 맵 통계**
    - eBPF 프로그램 내부에서 사용되는 맵(서비스 매칭, 벡엔드 정봅 등)의 상태나 조회 수 등을 직접 메트릭으로 노출할 수 있슴
- 커널 레벨 네트워크 통계
    - eBPF는 XDP 나 TC(Traffic Control) 계층에서 패킷을 직접 처리하므로 여기서 발생하는 드롭 비율, 지연 시간, 처리량 등을 더욱 정확하게 측정할 수 있슴

## Grafana/Prometheus 대시보드 구성

### Prometheus 설정

- Cilium Prometheus Exporter 활성화

Cilium의 경우, Helm 차트를 사용하여 설치할 때 Prometheus 메트릭 노출을 활성화할 수 있슴

```bash
helm upgrade --install cilium cilium/cilium --namespace kube-system \
    --set prometheus.enabled=true \
    --set operator.prometheus.enabled=true \
    --set hubble.enabled=true \
    --set hubble.metrics.enabled="{dns,drop,tcp,flow,port_distribution,http}" # Hubble 추가 메트릭 활성화 (선택 사항)
```

- prometheus ConfigMap 설정

Prometheus가 Cilium 메트릭 엔드포인트를 찾아서 스크랩하도록 `prometheus.yml` (또는 Kubernetes `ServiceMonitor` / `PodMonitor` 리소스)을 구성

Kubernetes ServiceMonitor 사용

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cilium-agent
  namespace: kube-system
  labels:
    release: prometheus-stack # Prometheus Operator의 label selection에 맞게 조정
spec:
  selector:
    matchLabels:
      k8s-app: cilium # Cilium Agent Pod의 레이블
  namespaceSelector:
    matchNames:
    - kube-system
  endpoints:
  - port: prometheus
    interval: 10s # 스크랩 주기
    path: /metrics
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cilium-operator
  namespace: kube-system
  labels:
    release: prometheus-stack
spec:
  selector:
    matchLabels:
      io.cilium/app: operator
  namespaceSelector:
    matchNames:
    - kube-system
  endpoints:
  - port: prometheus
    interval: 10s
    path: /metrics
```

위 ServiceMonitor 를 배포하면 Promethues Operator 가 자동으로 Prometheus의 스크랩 설정을 업데이트함.

- Prometheus UI에서 메트릭 확인

Prometheus UI (http://<prometheus-ip>:9090) 에 접속하여 "Status" -> "Targets" 메뉴에서 Cilium 에이전트와 Operator가 `UP` 상태인지 확인하고, "Graph" 메뉴에서 `cilium_`으로 시작하는 메트릭들을 검색하여 데이터가 잘 수집되는지 확인

### Grafana 설치 및 설정

- Grafana 설치

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm install grafana grafana/grafana --namespace monitoring --create-namespace
```

- Grafana 접속 및 초기 비밀번호 얻기

```bash
kubectl get secret --namespace monitoring grafana -o jsonpath="{.data.admin-password}" | base64 --decode ; echo
```

이후 `kubectl port-forward svc/grafana 3000:80 -n monitoring` 으로 로컬에서 접속 가능

- Prometheus 데이터 소스 추가
    - Grafana UI에 로그인한 후, "Configuration" (톱니바퀴 아이콘) -> "Data sources" -> "Add data source" -> "Prometheus"를 선택
        - Name 설정
        - URL : [http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090](http://prometheus-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090/) (Prometheus가 Kubernetes 클러스터에 배포된 Service 이름으로 변경)
        - Access : Server
        - Save & Test 클릭하여 연결 여부 확인
- Grafana 대시보드 구성
    - 미리 만들어진 대시보드 Import (아래 대시보드 ID 중 선택)
        - **Cilium Overview:**  (ID: `13563`)
        - **Cilium Cluster Mesh:** (ID: `16049`)
        - **Hubble Overview:** (ID: `13010`)
- Alerting 구성
    - `alert.rules.yml` 파일을 생성하고 Prometheus 설정에 포함시킵
    
    ```yaml
    # alert.rules.yml 예시
    groups:
    - name: cilium-lb-alerts
      rules:
      - alert: HighLoadBalancingDrops
        expr: sum(rate(cilium_drop_count_total{reason="NoEndpoint"}[5m])) > 100
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Load Balancing drops due to no endpoint detected on {{ $labels.instance }}"
          description: "Over 100 packets/sec are being dropped because of no healthy load balancing backend endpoints."
    
      - alert: TooManyActiveConnections
        expr: sum(cilium_lb_active_connections) > 10000
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High number of active load balancing connections on {{ $labels.instance }}"
          description: "Active load balancing connections exceeded 10000. This might indicate an overload."
    ```
