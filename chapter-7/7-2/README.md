# 7.2 Falco / Tetragon 기반 이상 탐지

# CIlium Tetragon + Falco 를 이용한 이상탐지 시스템 구축(Step-by-Step Guide)

이 가이드는 Kubernetes 환경 기반임

## 사전 준비 사항

1. **Kubernetes cluster** : 동작하는 Kubernetes 클러스터 (Minikube, Kind, k3s, EKS, GKE, AKS 등)
2. **kubectl** : kubernetes 클러스터에 접근하려면 kubectl 설치 필요
3. **Helm** : Kubernetes 패키지 관리 도구 (Falco 및 Tetragon 배포에 사용)
4. **Cilium** (선택 사항이지만 권장) : 만약 네트워크 플러그인으로 Cilium을 사용하고 있다면, Tetragon과의 통합이 더욱 원활. (Cilium 미사용 시에도 Tetragon은 독립적으로 작동 가능)
5. **기본적인 Linux 및 보안 개념 이해** : eBPF, 시스템 call, Kubernetes 네트워킹에 대한 이해

### step 1 : Falco 설치

Falco는 런타임 보안 이벤트를 감지하고 경고하는 데 사용됨. 

Falco는 `kubectl` 또는 Helm을 통해 설치할 수 있지만, Helm을 사용하는 것이 일반적.

**Falco Helm Chart Repository 추가**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
```

**Falco Install**

Falco는 커널 모듈, eBPF 또는 KMOD와 eBPF 모두를 통해 동작 가능. 여기서는 eBPF 드라이버를 사용

```bash
helm install falco falcosecurity/falco \
    --namespace falco --create-namespace \
    --set driver.kind=ebpf \
    --set tty=true
```

- `--set driver.kind=ebpf`: Falco가 eBPF 드라이버를 사용하도록 설정
- `--namespace falco --create-namespace`: `falco`라는 네임스페이스를 생성하고 그 안에 Falco를 설치

**Falco 설치 확인**

```bash
kubectl get pods -n falco
# falco-xxxx 형태의 Pod가 Running 상태인지 확인
```

**Falco 로그 확인**

```bash
kubectl logs -f -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
```

### step 2 : Tetragon 설치

Tetragon은 Cilium 프로젝트의 일부로, eBPF 기반으로 시스템 호출 및 네트워크 이벤트를 세밀하게 가시화하고 제어하는 데 중점을 둠

### Tetragon Helm Chart Repository 추가

```bash
helm repo add cilium https://helm.cilium.io/
helm repo update
```

Tetragon 설치

```bash
helm install tetragon cilium/tetragon \
    --namespace kube-system \
    --set agent.collector.host=localhost \
    --set agent.collector.port=8090 # Falco와 연동을 위한 gRPC 서버 설정
```

- `--set agent.collector.host=localhost`: Tetragon 에이전트가 이벤트를 전송할 Collector의 호스트 주소.
- `--set agent.collector.port=8090`: Collector의 포트. 이 포트로 Falco가 Tetragon의 이벤트를 수신함

Tetragon 설치 확인

```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
# tetragon-agent-xxxx 형태의 Pod가 각 노드에 Running 상태로 배포되었는지 확인

kubectl get tetragoninfo
# tetragoninfo CRD가 생성되고 클러스터 정보가 표시되는지 확인
```

### Step 3 : Falco와 Tetragon 연동(gRPC 출력 설정)

Falco가 Tetragon 이벤트를 수신하려면, Falcon 설정에 Tetragon gRPC 출력을 추가해야 함

1. Tetragon 이벤트 수신을 위한 Falco ConfigMap 수정
    1. 기존 Falco 배포의 `values.yaml`을 수정하여 재설치하거나, `kubectl edit configmap falco-rules -n falco` 명령으로 직접 ConfigMap을 수정. 본 가이드에서는 Helm upgrade 를 사용함
    2. `falco-values-tetragon.yaml` 파일을 생성하고 다음 내용을 추가
    
    ```yaml
    falco:
      outputs:
        json_output: true
        syscall_event_drops: true
      # ... 다른 설정들 ...
      grpc:
        enabled: true
        bind_address: "0.0.0.0:5060" # Falco가 gRPC 서버를 노출할 주소 (선택 사항, 다른 서비스에서 Falco 이벤트를 소비할 경우)
    
      # Tetragon Collector (gRPC Client) 설정
      grpc_output:
        enabled: true
        address: "tetragon-agent.<your-node-ip>" # Tetragon 에이전트가 실행 중인 노드의 IP (Falco Pod가 Tetragon 에이전트에 직접 연결)
        port: 8090
        check_connection: true
        connect_timeout_seconds: 5
        output_type: json
        keepalive_timeout_seconds: 10
        # ... 추가적인 TLS 설정 (필요시) ...
    ```
    
    c. group > address 섹션은 구성하고자 하는 환경에 맞게 설정해 주어야 함
    
    옵션 1 - 아래와 같이 falco Pod 가 hostNetwork: true 를 사용하도록 설정 (보안상 취약)한 뒤 helm upgrade 로 Falco를 재설치
    
    ```yaml
    falco:
      hostNetwork: true
      outputs:
        json_output: true
      grpc_output:
        enabled: true
        address: "127.0.0.1" # Falco Pod가 로컬호스트의 Tetragon 에이전트에 연결
        port: 8090
        # ... (위의 다른 설정들) ...
    ```
    
    옵션 2 - Tetragon Collector Service 노출 (Tetragon Daemonset 의 각 Pod가 hostPort : 8090 을 사용하도록 설정하고, 이 포트를 통해 Falco가 접근하게 함)
    
    ```yaml
    # tetragon-values.yaml 파일 생성
    agent:
      collector:
        host: "0.0.0.0" # 모든 인터페이스에서 수신
        port: 8090
      extraHostPathMounts:
        - name: "tetragon-sock"
          mountPath: "/var/run/cilium/tetragon"
    ```
    
    ```bash
    helm upgrade tetragon cilium/tetragon \
        --namespace kube-system -f tetragon-values.yaml
    ```
    

이후 falco-values-tetragon.yaml 수정 후 Helm Upgrade

```yaml
falco:
  outputs:
    json_output: true
    syscall_event_drops: true
  grpc:
    enabled: true
    bind_address: "0.0.0.0:5060"

  grpc_output:
    enabled: true
    address: "localhost" # Tetragon 에이전트가 동일 노드에 있다면 localhost로 연결
    port: 8090
    check_connection: true
    connect_timeout_seconds: 5
    output_type: json
    keepalive_timeout_seconds: 10
```

```bash
helm upgrade falco falcosecurity/falco \
    --namespace falco -f falco-values-tetragon.yaml
```

### Step 4 - 이상 탐지를 위한 Falco 규칙 정의

- 사용자 정의 falco rule (my_falco_rules.yaml)

```bash
# my_falco_rules.yaml
- rule: Unexpected Executable in Web Server
  desc: Detects an executable being run from a common web server directory.
  condition: >
    evt.type=execve and fd.directory=/var/www/html and not proc.name in (apache, nginx)
  output: >
    Executable %proc.name (%proc.cmdline) run in web server directory %fd.directory (user=%user.name clientip=%client.ip).
  priority: ERROR
  tags: [filesystem, host, web, anomaly]

- rule: Suspicious Outbound Connection from Internal Service
  desc: Detects outbound network connections from internal services to external IPs, which might indicate C2 activity.
  condition: >
    evt.type=connect and not proc.name in (kube-proxy, cilium-agent) and fd.sip.is_private=false and not fd.port=443
  output: >
    Suspicious outbound connection from %proc.name to %fd.saddr:%fd.sport (user=%user.name)
  priority: WARNING
  tags: [network, host, anomaly, C2]

- rule: Write to Sensitive Path by Non-Admin User
  desc: Detects non-administrative users writing to sensitive system paths.
  condition: >
    evt.type=write and fd.name in (/etc/passwd, /etc/shadow, /bin/, /usr/bin/, /sbin/, /usr/sbin/) and user.uid > 0 and user.name not in (root, admin)
  output: >
    Non-admin user %user.name (%user.uid) wrote to sensitive path %fd.name (command=%proc.cmdline)
  priority: CRITICAL
  tags: [filesystem, privilege, host]
```

- Falco ConfigMap 에 사용자 정의 규칙 추가

`falco-values-custom-rules.yaml` 파일을 생성하고 `falco-values-tetragon.yaml` 내용을 포함한 후, `falco.rules` 섹션에 사용자 정의 규칙을 추가

```yaml
# falco-values-custom-rules.yaml
falco:
  outputs:
    json_output: true
    syscall_event_drops: true
  grpc:
    enabled: true
    bind_address: "0.0.0.0:5060"

  grpc_output:
    enabled: true
    address: "localhost" # 혹은 적절한 IP 주소
    port: 8090
    check_connection: true
    connect_timeout_seconds: 5
    output_type: json
    keepalive_timeout_seconds: 10

  rules:
    # 여기에 my_falco_rules.yaml 내용 직접 붙여넣기
    - rule: Unexpected Executable in Web Server
      desc: Detects an executable being run from a common web server directory.
      condition: >
        evt.type=execve and fd.directory=/var/www/html and not proc.name in (apache, nginx)
      output: >
        Executable %proc.name (%proc.cmdline) run in web server directory %fd.directory (user=%user.name clientip=%client.ip).
      priority: ERROR
      tags: [filesystem, host, web, anomaly]

    - rule: Suspicious Outbound Connection from Internal Service
      desc: Detects outbound network connections from internal services to external IPs, which might indicate C2 activity.
      condition: >
        evt.type=connect and not proc.name in (kube-proxy, cilium-agent) and fd.sip.is_private=false and not fd.port=443
      output: >
        Suspicious outbound connection from %proc.name to %fd.saddr:%fd.sport (user=%user.name)
      priority: WARNING
      tags: [network, host, anomaly, C2]

    - rule: Write to Sensitive Path by Non-Admin User
      desc: Detects non-administrative users writing to sensitive system paths.
      condition: >
        evt.type=write and fd.name in (/etc/passwd, /etc/shadow, /bin/, /usr/bin/, /sbin/, /usr/sbin/) and user.uid > 0 and user.name not in (root, admin)
      output: >
        Non-admin user %user.name (%user.uid) wrote to sensitive path %fd.name (command=%proc.cmdline)
      priority: CRITICAL
      tags: [filesystem, privilege, host]
```

또는 `falco.rulesFile` 옵션을 사용하여 외부 파일을 참조하도록 설정

```yaml
# falco-values-custom-rules.yaml
falco:
  # ... 다른 설정들 ...
  rulesFiles:
    - /etc/falco/falco_rules.yaml # 기본 규칙
    - /etc/falco/my_falco_rules.yaml # 사용자 정의 규칙 (ConfigMap으로 마운트)

  extraVolumes:
    - name: my-falco-rules
      configMap:
        name: my-falco-rules-configmap # 아래에서 생성할 ConfigMap 이름

  extraVolumeMounts:
    - name: my-falco-rules
      mountPath: /etc/falco/my_falco_rules.yaml
      subPath: my_falco_rules.yaml # ConfigMap의 특정 키를 파일로 마운트
```

이어서 `my_falco_rules.yaml` 파일을 ConfigMap으로 생성

```bash
kubectl create configmap my-falco-rules-configmap -n falco --from-file=my_falco_rules.yaml
```

마지막으로 Falco 업그레이드

```bash
helm upgrade falco falcosecurity/falco \
    --namespace falco -f falco-values-custom-rules.yaml
```

### Step 5 - 이상 행위 시뮬레이션 및 탐지 확인

Falco와 Tetragon이 동작하는지 확인하기 위해 의도적으로 이상 행위를 발생시킴

1. 테스트 Pod 생성

```bash
kubectl run test-pod --image=ubuntu --restart=Never -- sleep infinity
```

1. 테스트 Pod 접속

```bash
kubectl exec -it test-pod -- bash
```

1. 이상 행위 시뮬레이션
- 웹 서버 디렉터리에서 실행 파일 생성 및 실행 시도 (Falco 규칙 1  트리거)

```bash
# Pod 내부에서 실행
mkdir -p /var/www/html
echo '#!/bin/bash' > /var/www/html/malicious_script.sh
echo 'echo "Hello from malicious script!"' >> /var/www/html/malicious_script.sh
chmod +x /var/www/html/malicious_script.sh
/var/www/html/malicious_script.sh
```

- 외부 IP로 의심스러운 네트워크 연결 시도 (Falco 규칙 2 트리거)

```bash
# Pod 내부에서 실행
apt update && apt install -y curl
curl http://example.com:12345 # 443이 아닌 포트로 외부 연결 시도
```

위 명령은 비표준 포트로 외부 연결을 시도하므로 두 번째 Falco  규칙을 트리거함. 실제 연결여부와 관계없이 connect syscall 발생을 탐지하기 때문.

- 비관리자 계정으로 민감한 경로에 쓰기 시도 (Falco 규칙 3 트리거)

```bash
# Pod 내부에서 실행
echo "malicious content" >> /etc/passwd
```

1. Falco 로그 확인
    1. 새로운 터미널에서 Falco Pod의 로그를 확인
    
    ```bash
    kubectl logs -f -n falco $(kubectl get pod -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
    ```
    
    위에서 정의한 규칙에 따라 Falco 경고 메시지가 출력되는지 확인
    
    아래는 예상 출력 (실제 상황에 따라 상이함)
    
    ```json
    {"output":"Executable bash (/var/www/html/malicious_script.sh) run in web server directory /var/www/html (user=root clientip=).","priority":"Error", ...}
    {"output":"Suspicious outbound connection from curl to 93.184.216.34:12345 (user=root)","priority":"Warning", ...}
    {"output":"Non-admin user root (0) wrote to sensitive path /etc/passwd (command=bash)","priority":"Critical", ...}
    ```
    

### Step 6 - 추가 고려 사항 및 고급설정

- Tetragon 정책(Policy)
    - Tetragon은 단순히 이벤트를 수집하는 것을 넘어, `TracingPolicy` CRD를 사용하여 특정 프로세스, 시스템 호출, 네트워크 연결 등에 대한 상세한 정책을 정의할 수 있슴.
    - 예를 들어 특정 Pod에서 execve 호출이 일어날 때만 이벤트를 발생시키거나, 특정 파일 접근만 감시하도록 설정할 수 있슴
    
    ```yaml
    apiVersion: cilium.io/v1alpha1
    kind: TracingPolicy
    metadata:
      name: monitor-execve
    spec:
      kprobes:
      - call: "sys_execve"
        selectors:
        - matchPIDs:
          - operator: In
            followRuns: true
            values:
            - pod:
                namespace: default
                labelSelector: "app=test-pod" # test-pod에서만 execve 감시
        action: Follow
    ```
    
    이러한 정책을 배포하면 Tetragon은 훨씬 더 효율적으로 필요한 이벤트를 수집하고 Falco에 전달할 수 있슴
    
- Falco 경고 처리
    - Falco는 경고를 STDOUD으로 출력하는 것 외에도 다양한 출력 옵션(gRPC, HTTP webhook, Slack, PagerDuty 등)을 제공함.
    - 실제 운영 환경에서는 SIEM (Security Information and Event Management) 시스템이나 경고 시스템과 연동하여 통합적인 관리를 해야 함
- Falco 규칙 최적화
    - 기본 Falco 규칙은 매우 많고 읿반적인 경우에 해당하므로 오탐(False Positive)이 발생함.
    - 실제 환경에 맞게 규칙을 조정하고 불필요한 규칙을 비활성화, 중요한 규칙에 집중하는 것이 중요
- 성능 고려
    - eBPF는 성능 오버헤드가 매우 낮지만, Falco 규칙이 너무 복잡하거나 너무 많은 이벤트를 처리하면 CPU 및 메모리 사용량이 증가함.
    - 모니터링 시스템을 통해 Falco와 Tetragon 리소스 사용량을 지속적으로 모니터링 해야 함
- 지속적인 업데이트
    - Falco와 Tetragon 은 활발하게 개발되고 있으므로 최신 버전으로 유지하고 변경 사항을 주기적으로 확인하는 것이 좋음
- 시각화 도구 연동
    - Falco의 이벤트를 Elastisearch, Grafana, Kibana 등과 연동하여 시각화하고 대시보드를 구축

## 참고자료

- Falco
    - [https://falco.org/docs/](https://falco.org/docs/)
- Tetragon
    - [https://tetragon.io/](https://tetragon.io/)
    - [https://github.com/cilium/tetragon](https://github.com/cilium/tetragon)
