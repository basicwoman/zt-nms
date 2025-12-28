# Zero Trust Network Management System (ZT-NMS)

A comprehensive network management system built on Zero Trust principles, designed to eliminate implicit trust from network device management operations.

## Overview

ZT-NMS addresses critical security vulnerabilities in traditional network management systems (like those exploited in the SolarWinds attack and FortiManager CVE-2024-47575) by implementing:

- **Per-Operation Authentication**: Every operation cryptographically signed
- **Capability-Based Access Control**: Fine-grained, time-limited permissions
- **Configuration Integrity**: Merkle tree-based configuration chains
- **Continuous Attestation**: Runtime device verification
- **Distributed Trust**: No single point of compromise
- **Immutable Audit Trail**: Cryptographic audit chain

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Operator Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │   Web UI    │  │    CLI      │  │   API       │                  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                  │
└─────────┼────────────────┼────────────────┼─────────────────────────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────────┐
│                    Control Plane                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  Identity   │  │   Policy    │  │ Capability  │  │   Config    │ │
│  │  Service    │  │   Engine    │  │   Issuer    │  │   Manager   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Crypto    │  │ Attestation │  │    Audit    │  │   Device    │ │
│  │   Service   │  │  Verifier   │  │   Service   │  │    Proxy    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────────────────┐
│                      Data Plane                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                       Device Proxy Pool                          │ │
│  │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │ │
│  │   │ Proxy 1 │  │ Proxy 2 │  │ Proxy 3 │  │ Proxy N │           │ │
│  │   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘           │ │
│  └────────┼────────────┼────────────┼────────────┼─────────────────┘ │
└───────────┼────────────┼────────────┼────────────┼──────────────────┘
            │            │            │            │
┌───────────┼────────────┼────────────┼────────────┼──────────────────┐
│           │     Device Layer        │            │                   │
│  ┌────────▼───┐ ┌──────▼────┐ ┌─────▼─────┐ ┌───▼───────┐          │
│  │  Router    │ │  Switch   │ │ Firewall  │ │    ...    │          │
│  │  + Agent   │ │  + Agent  │ │  + Agent  │ │  + Agent  │          │
│  └────────────┘ └───────────┘ └───────────┘ └───────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Components

### Identity Service
- Manages operator, device, and service identities
- Ed25519-based cryptographic identity
- Certificate issuance and revocation
- MFA integration

### Policy Engine
- Attribute-based access control (ABAC)
- Real-time policy evaluation
- Emergency access support
- Policy versioning and audit

### Capability Issuer
- Time-limited capability tokens
- Fine-grained permissions
- Delegation support
- Multi-party approval

### Configuration Manager
- Intent-based configuration
- Merkle tree integrity
- 4-phase deployment (Validate→Prepare→Commit→Verify)
- Automatic rollback

### Device Proxy
- Protocol adaptation (SSH, NETCONF, RESTCONF, gNMI)
- Command filtering and sanitization
- Session recording
- Rate limiting

### Attestation Verifier
- TPM-based and software attestation
- Continuous device verification
- Measurement validation
- Quarantine enforcement

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Go 1.22+
- PostgreSQL 16+
- Redis 7+

### Installation

1. Clone the repository:
```bash
git clone https://github.com/zt-nms/zt-nms.git
cd zt-nms
```

2. Start with Docker Compose:
```bash
cd deployments/docker
docker-compose up -d
```

3. Initialize the database:
```bash
docker exec -i zt-nms-postgres psql -U ztnms ztnms < database/schema.sql
```

4. Access the API:
```bash
curl https://localhost:8080/health
```

### Generate Keys
```bash
./zt-nms-cli keygen operator
./zt-nms-cli keygen device
```

### Register an Operator
```bash
./zt-nms-cli identity create \
  --type operator \
  --name admin \
  --email admin@example.com \
  --public-key operator.pub
```

### Authenticate
```bash
./zt-nms-cli auth login --key operator.key
```

## API Reference

### Authentication

```http
POST /api/v1/auth/challenge
POST /api/v1/auth/authenticate
```

### Identities

```http
GET    /api/v1/identities
POST   /api/v1/identities
GET    /api/v1/identities/{id}
PUT    /api/v1/identities/{id}
DELETE /api/v1/identities/{id}
POST   /api/v1/identities/{id}/suspend
POST   /api/v1/identities/{id}/activate
```

### Capabilities

```http
POST   /api/v1/capabilities/request
GET    /api/v1/capabilities/{id}
DELETE /api/v1/capabilities/{id}
POST   /api/v1/capabilities/{id}/approve
```

### Policies

```http
GET    /api/v1/policies
POST   /api/v1/policies
GET    /api/v1/policies/{id}
PUT    /api/v1/policies/{id}
POST   /api/v1/policies/evaluate
```

### Devices

```http
GET    /api/v1/devices
POST   /api/v1/devices
GET    /api/v1/devices/{id}
GET    /api/v1/devices/{id}/config
POST   /api/v1/devices/{id}/operations
GET    /api/v1/devices/{id}/attestation
```

### Configurations

```http
POST   /api/v1/configs/validate
POST   /api/v1/configs/deploy
GET    /api/v1/configs/deployments/{id}
POST   /api/v1/configs/deployments/{id}/rollback
```

## Security Model

### Zero Trust Principles

1. **Never Trust, Always Verify**
   - Every operation requires authentication
   - Cryptographic signatures on all requests
   - Continuous validation of trust

2. **Least Privilege**
   - Capability tokens with minimal permissions
   - Time-limited access
   - Action-specific grants

3. **Assume Breach**
   - Immutable audit trail
   - Configuration integrity verification
   - Device attestation

### Cryptographic Primitives

| Algorithm | Usage |
|-----------|-------|
| Ed25519 | Signatures, identity keys |
| X25519 | Key exchange |
| AES-256-GCM | Symmetric encryption |
| SHA-256 | Hashing, Merkle trees |
| HKDF | Key derivation |

### Protocol Security

- TLS 1.3 required for all communications
- Mutual TLS (mTLS) for service-to-service
- Replay protection with nonces
- Rate limiting per identity

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| ZTNMS_SERVER_PORT | API server port | 8080 |
| ZTNMS_DATABASE_HOST | PostgreSQL host | localhost |
| ZTNMS_DATABASE_PASSWORD | Database password | - |
| ZTNMS_REDIS_HOST | Redis host | localhost |
| ZTNMS_NATS_URL | NATS URL | nats://localhost:4222 |

### Configuration File

See `configs/config.yaml` for full configuration options.

## Deployment

### Kubernetes

```bash
kubectl apply -f deployments/kubernetes/
```

### Helm

```bash
helm install zt-nms deployments/helm/zt-nms
```

## Monitoring

### Metrics

Prometheus metrics available at `/metrics`:
- `ztnms_operations_total`
- `ztnms_authentications_total`
- `ztnms_policy_evaluations_total`
- `ztnms_attestations_total`

### Tracing

Jaeger tracing enabled for distributed request tracing.

### Dashboards

Grafana dashboards available in `deployments/docker/monitoring/grafana/dashboards/`.

## Development

### Building

```bash
go build -o bin/api-gateway ./cmd/api-gateway
go build -o bin/zt-nms-cli ./cmd/zt-nms-cli
go build -o bin/zt-nms-agent ./cmd/zt-nms-agent
```

### Testing

```bash
go test ./...
go test -bench ./...
```

### Code Structure

```
zt-nms/
├── cmd/                    # Entry points
│   ├── api-gateway/
│   ├── zt-nms-cli/
│   └── zt-nms-agent/
├── internal/               # Private packages
│   ├── identity/
│   ├── policy/
│   ├── capability/
│   ├── config/
│   ├── proxy/
│   └── api/
├── pkg/                    # Public packages
│   ├── models/
│   └── crypto/
├── deployments/
│   ├── docker/
│   └── kubernetes/
├── configs/
└── docs/
```

## License

MIT License - see LICENSE file for details.

## Contributing

See CONTRIBUTING.md for guidelines.

## References

- [NIST SP 800-207: Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
- [RFC 8235: Schnorr Non-interactive Zero-Knowledge Proof](https://tools.ietf.org/html/rfc8235)
