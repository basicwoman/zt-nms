# Исходный код диаграмм ZT-NMS

## 1. Дорожная карта тестирования (Mermaid Gantt)

```mermaid
gantt
    title Testing Roadmap ZT-NMS
    dateFormat  YYYY-MM-DD
    section Phase 1: Unit Testing
    Model testing           :a1, 2024-01-01, 7d
    Crypto testing          :a2, after a1, 4d
    Service testing         :a3, after a2, 3d
    
    section Phase 2: Integration Testing
    API testing             :b1, after a3, 5d
    Database testing        :b2, after b1, 4d
    Protocol testing        :b3, after b2, 5d
    
    section Phase 3: System Testing
    E2E scenarios           :c1, after b3, 5d
    Failover testing        :c2, after c1, 4d
    Load testing            :c3, after c2, 5d
    
    section Phase 4: Security Testing
    Penetration testing     :d1, after c3, 7d
    Vulnerability analysis  :d2, after d1, 7d
    
    section Phase 5: UAT
    User scenarios          :e1, after d2, 7d
    Final validation        :e2, after e1, 7d
```

## 2. Архитектура системы (Mermaid Flowchart)

```mermaid
flowchart TB
    subgraph Operators["Operator Layer"]
        WebUI[Web UI]
        CLI[CLI]
        API[API Client]
    end
    
    subgraph ControlPlane["Control Plane"]
        Gateway[API Gateway]
        Identity[Identity Service]
        Policy[Policy Engine]
        Capability[Capability Issuer]
        Config[Config Manager]
        Audit[Audit Service]
    end
    
    subgraph DataPlane["Data Plane"]
        Proxy[Device Proxy Pool]
        SSH[SSH Adapter]
        NETCONF[NETCONF Adapter]
    end
    
    subgraph Devices["Device Layer"]
        Router[Routers]
        Switch[Switches]
        Firewall[Firewalls]
    end
    
    subgraph Storage["Storage Layer"]
        PostgreSQL[(PostgreSQL)]
        Redis[(Redis)]
        etcd[(etcd)]
    end
    
    WebUI --> Gateway
    CLI --> Gateway
    API --> Gateway
    
    Gateway --> Identity
    Gateway --> Policy
    Gateway --> Capability
    
    Identity --> PostgreSQL
    Policy --> etcd
    Capability --> Redis
    
    Config --> Proxy
    Proxy --> SSH
    Proxy --> NETCONF
    
    SSH --> Router
    SSH --> Switch
    NETCONF --> Firewall
```

## 3. Поток аутентификации (Mermaid Sequence)

```mermaid
sequenceDiagram
    participant O as Operator
    participant G as API Gateway
    participant I as Identity Service
    participant P as PostgreSQL
    
    O->>G: POST /auth/challenge
    G->>I: Generate Challenge
    I-->>G: Challenge (32 bytes)
    G-->>O: Challenge Response
    
    O->>O: Sign(Challenge, PrivateKey)
    O->>G: POST /auth/authenticate
    
    G->>I: Verify Authentication
    I->>P: Get Identity by PublicKey
    P-->>I: Identity Record
    I->>I: Verify Signature
    I-->>G: Auth Result + Token
    G-->>O: Access Token
```

## 4. 4-фазный протокол (Mermaid State)

```mermaid
stateDiagram-v2
    [*] --> Validating
    
    Validating --> Preparing: Passed
    Validating --> Failed: Error
    
    Preparing --> Committing: Confirmed
    Preparing --> Rollback: Error
    
    Committing --> Verifying: Applied
    Committing --> Rollback: Error
    
    Verifying --> Success: Verified
    Verifying --> Rollback: Mismatch
    
    Success --> [*]
    Failed --> [*]
    Rollback --> [*]
```

## 5. Сравнение архитектур (PlantUML)

```plantuml
@startuml
!theme plain

skinparam backgroundColor #FFFFFF
skinparam componentStyle rectangle

title Traditional NMS vs Zero Trust NMS

rectangle "Traditional NMS" as trad {
    actor Operator as op1
    component "Central Server" as cs {
        component "Auth" as auth1
        component "Config" as cfg1
        component "Device Manager" as dm1
    }
    database "Credentials DB" as cdb
    
    op1 --> auth1 : Username/Password
    auth1 --> cdb : Stored Secrets
    auth1 --> cfg1 : Session
    cfg1 --> dm1 : Internal Trust
}

rectangle "Zero Trust NMS" as zt {
    actor Operator as op2
    component "Identity Service" as id
    component "Policy Engine" as pe
    component "Capability Issuer" as ci
    component "Device Proxy" as dp
    component "Device Agent" as da
    
    op2 --> id : Signed Request
    id --> pe : Policy Check
    pe --> ci : Issue Token
    ci --> dp : Capability Token
    dp --> da : Signed Command
}

note right of trad
  Vulnerabilities:
  * Single point of failure
  * Stored credentials
  * Implicit trust
  * No per-op auth
end note

note right of zt
  Protection:
  * Distributed trust
  * No stored secrets
  * Continuous verification
  * Per-operation auth
end note

@enduml
```

## 6. Поток Capability Token (PlantUML)

```plantuml
@startuml
title Capability Token Flow

actor Operator
participant "API Gateway" as GW
participant "Capability Issuer" as CI
participant "Policy Engine" as PE
database Redis

Operator -> GW: Request Capability
activate GW

GW -> CI: Evaluate Request
activate CI

CI -> PE: Check Policy
activate PE
PE -> PE: Match Rules
PE -> PE: Evaluate Conditions
PE --> CI: Decision
deactivate PE

alt Allowed
    CI -> CI: Create Token
    CI -> CI: Sign Token
    CI -> Redis: Cache Token
    CI --> GW: Capability Token
    GW --> Operator: Token Response
else Denied
    CI --> GW: Access Denied
    GW --> Operator: Error
end

deactivate CI
deactivate GW

@enduml
```

## 7. Диаграмма развертывания (PlantUML)

```plantuml
@startuml
!theme plain

title ZT-NMS Deployment Architecture

node "Kubernetes Cluster" {
    node "API Gateway Pod (x3)" as api {
        component "API Gateway" as gw
        component "Rate Limiter" as rl
    }
    
    node "Identity Pod (x2)" as idpod {
        component "Identity Service" as id
    }
    
    node "Policy Pod (x2)" as ppod {
        component "Policy Engine" as pe
        component "Policy Cache" as pc
    }
    
    node "Capability Pod (x2)" as cpod {
        component "Capability Issuer" as ci
    }
    
    node "Proxy Pod (x3)" as prpod {
        component "Device Proxy" as dp
        component "Connection Pool" as cp
    }
}

database "PostgreSQL\n(HA Cluster)" as pg
database "Redis\n(Cluster)" as redis
database "etcd\n(3 nodes)" as etcd
queue "NATS\n(JetStream)" as nats

cloud "Network Devices" as devices {
    node "Routers"
    node "Switches"
    node "Firewalls"
}

api --> idpod
api --> ppod
api --> cpod
idpod --> pg
ppod --> etcd
cpod --> redis
prpod --> devices
api --> nats
idpod --> nats
ppod --> nats

@enduml
```

## 8. Диаграмма классов моделей (PlantUML)

```plantuml
@startuml
title ZT-NMS Core Models

class Identity {
    +ID: UUID
    +Type: IdentityType
    +Attributes: JSON
    +PublicKey: []byte
    +Certificate: []byte
    +Status: IdentityStatus
    +CreatedAt: Time
    +Verify(sig, msg): bool
}

class CapabilityToken {
    +TokenID: UUID
    +Version: int
    +Issuer: string
    +SubjectID: UUID
    +Grants: []Grant
    +Validity: Validity
    +IssuerSignature: []byte
    +Sign(key): void
    +Verify(key): bool
    +IsValid(): bool
    +Allows(action, resource): bool
}

class Grant {
    +Resource: ResourceSelector
    +Actions: []ActionType
    +Constraints: Constraints
}

class Policy {
    +ID: UUID
    +Name: string
    +Type: PolicyType
    +Definition: PolicyDefinition
    +Status: PolicyStatus
    +Evaluate(request): Decision
}

class ConfigBlock {
    +ID: UUID
    +DeviceID: UUID
    +Sequence: int64
    +PrevHash: []byte
    +MerkleRoot: []byte
    +BlockHash: []byte
    +Configuration: JSON
    +AuthorSignature: []byte
    +Sign(key): void
    +Verify(key): bool
    +VerifyChain(prev): bool
}

class AuditEvent {
    +ID: UUID
    +Sequence: int64
    +PrevHash: []byte
    +EventHash: []byte
    +EventType: AuditEventType
    +ActorID: UUID
    +Action: string
    +Result: AuditResult
    +ComputeHash(): void
    +Verify(): bool
}

Identity "1" -- "*" CapabilityToken : subject
CapabilityToken "1" -- "*" Grant : contains
Policy "1" -- "*" CapabilityToken : authorizes
ConfigBlock "1" -- "1" ConfigBlock : prev_hash
AuditEvent "1" -- "1" AuditEvent : prev_hash

@enduml
```

## 9. Диаграмма тестового покрытия (Mermaid Pie)

```mermaid
pie showData
    title Test Coverage by Module
    "pkg/models" : 87
    "pkg/crypto" : 95
    "internal/identity" : 83
    "internal/policy" : 81
    "internal/capability" : 86
    "internal/config" : 79
    "internal/proxy" : 77
    "internal/api" : 82
```

## 10. Диаграмма метрик производительности (Mermaid)

```mermaid
xychart-beta
    title "Performance Metrics"
    x-axis [Auth, Policy, Cap, Config, Audit]
    y-axis "Latency (ms)" 0 --> 100
    bar [23, 15, 8, 45, 12]
    line [50, 50, 50, 50, 50]
```

## 11. Сетевая топология тестового стенда (PlantUML)

```plantuml
@startuml
title Test Environment Network Topology

nwdiag {
    network management {
        address = "10.0.0.0/24"
        
        zt-nms [address = "10.0.0.10"]
        prometheus [address = "10.0.0.20"]
        grafana [address = "10.0.0.21"]
    }
    
    network devices {
        address = "10.0.1.0/24"
        
        router-01 [address = "10.0.1.1"]
        router-02 [address = "10.0.1.2"]
        switch-01 [address = "10.0.1.10"]
        switch-02 [address = "10.0.1.11"]
        firewall-01 [address = "10.0.1.100"]
    }
    
    network database {
        address = "10.0.2.0/24"
        
        postgresql [address = "10.0.2.10"]
        redis [address = "10.0.2.20"]
        etcd [address = "10.0.2.30"]
    }
}
@enduml
```

## 12. Матрица тестирования (ASCII)

```
+------------------+--------+--------+--------+--------+--------+
|                  | Unit   | Integ  | System | Secur  | Perf   |
+------------------+--------+--------+--------+--------+--------+
| Identity Service | 25     | 5      | 3      | 5      | 2      |
| Policy Engine    | 18     | 4      | 2      | 4      | 3      |
| Capability Issuer| 22     | 4      | 3      | 6      | 2      |
| Config Manager   | 16     | 5      | 4      | 3      | 2      |
| Device Proxy     | 14     | 4      | 3      | 2      | 3      |
| API Handlers     | 28     | 6      | 5      | 5      | 4      |
| Crypto Module    | 20     | 2      | 1      | 8      | 2      |
| Models           | 88     | -      | -      | -      | -      |
+------------------+--------+--------+--------+--------+--------+
| TOTAL            | 231    | 30     | 21     | 33     | 18     |
+------------------+--------+--------+--------+--------+--------+
```
