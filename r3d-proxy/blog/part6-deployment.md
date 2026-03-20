# Part 6: From `docker-compose up` to Production -- Deploying R3D

*This is Part 6 of a 6-part series on building R3D. [Start from Part 1](part1-architecture.md) for the full architecture overview.*

---

## The Development Stack

Running R3D locally requires four services: MongoDB, LocalStack KMS, a KMS initialization sidecar, and the proxy itself. All of this is orchestrated in a single `docker-compose.yml`.

```mermaid
flowchart LR
    subgraph compose [docker-compose.yml]
        MongoDB["MongoDB Atlas Local 8.0<br/>(r3d database)"]
        LocalStack["LocalStack<br/>(KMS service)"]
        KMSInit["kms-init sidecar<br/>(aws-cli)"]
        Proxy["R3D Proxy<br/>(FastAPI + CSFLE)"]
    end

    KMSInit -->|"create CMK, write ARN"| KMSConfig[(kms_config volume)]
    LocalStack -->|"KMS API"| KMSInit
    KMSConfig -->|"read ARN"| Proxy
    MongoDB -->|"CSFLE auto-encrypt"| Proxy
    LocalStack -->|"HTTPS :4566<br/>(DEK encrypt/decrypt)"| Proxy
```

### MongoDB Atlas Local

```yaml
mongodb:
  image: mongodb/mongodb-atlas-local:8.0
  hostname: mongodb
  environment:
    - MONGODB_INITDB_ROOT_USERNAME=r3d
    - MONGODB_INITDB_ROOT_PASSWORD=r3d
  healthcheck:
    test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
    interval: 5s
    start_period: 30s
```

Atlas Local bundles `mongot` for Atlas Search, which extends the cold-start time. The 30-second `start_period` accommodates this. The healthcheck ensures dependent services don't start until MongoDB is accepting connections.

### LocalStack KMS

```yaml
localstack:
  image: localstack/localstack:latest
  hostname: localstack
  environment:
    - SERVICES=kms
    - AWS_DEFAULT_REGION=us-east-1
  healthcheck:
    test: ["CMD", "awslocal", "kms", "list-keys"]
```

LocalStack emulates the AWS KMS API locally -- zero AWS costs during development. It provides full `CreateKey`, `Encrypt`, `Decrypt`, and `GenerateDataKey` API compatibility. The critical detail: LocalStack serves both HTTP (port 4566) and HTTPS on the same port. `libmongocrypt` (the C library that handles CSFLE) always connects via HTTPS, so the kms-init script verifies HTTPS readiness before declaring success.

### The KMS Init Sidecar

The `kms-init` service is a one-shot sidecar that creates the KMS Customer Master Key and writes the ARN to a shared volume:

```bash
#!/bin/sh
set -e

# Idempotency: if key already exists and is valid, skip creation
if [ -f /kms-config/arn.txt ]; then
  EXISTING_ARN=$(cat /kms-config/arn.txt)
  if aws kms describe-key --key-id "$EXISTING_ARN" >/dev/null 2>&1; then
    echo "Key is still valid in LocalStack — skipping creation."
    verify_https
    exit $?
  fi
fi

# Create new KMS key
KEY_ID=$(aws kms create-key \
  --description "R3D CSFLE Master Key (LocalStack)" \
  --query 'KeyMetadata.KeyId' \
  --output text)

aws kms create-alias --alias-name "alias/r3d-csfle" --target-key-id "$KEY_ID"

KEY_ARN=$(aws kms describe-key --key-id "$KEY_ID" --query 'KeyMetadata.Arn' --output text)
echo "$KEY_ARN" > /kms-config/arn.txt
```

Idempotency is important: on container restart, the `kms_config` volume retains the ARN file. If the key still exists in LocalStack (the `localstack_data` volume persists it), no new key is created. This prevents orphaning existing Data Encryption Keys in MongoDB's key vault, which would make previously encrypted data unreadable.

The HTTPS verification gate at the end ensures `libmongocrypt` can connect before the proxy starts:

```bash
verify_https() {
  for i in $(seq 1 10); do
    if aws kms list-keys --endpoint-url https://localstack:4566 --no-verify-ssl >/dev/null 2>&1; then
      echo "HTTPS verification passed."
      return 0
    fi
    sleep 2
  done
  echo "ERROR: LocalStack HTTPS not responding on port 4566."
  return 1
}
```

### The Proxy Service

```yaml
proxy:
  build: .
  ports:
    - "4000:4000"
  environment:
    MDB_URI: mongodb://r3d:r3d@mongodb:27017/r3d?authSource=admin
    KMS_PROVIDER: aws
    AWS_ACCESS_KEY_ID: test
    AWS_SECRET_ACCESS_KEY: test
    AWS_DEFAULT_REGION: us-east-1
    AWS_KMS_ENDPOINT: "localstack:4566"
    R3D_ALLOWED_EXTENSION_IDS: "*"
    OPSEC_STEALTH_MODE: "true"
  volumes:
    - phish_cache:/app/phish_cache
    - kms_config:/kms-config:ro
  read_only: true
  cap_drop: [ALL]
  cap_add: [NET_BIND_SERVICE]
  tmpfs:
    - /tmp:mode=1777,size=100M
  mem_limit: 2g
  pids_limit: 512
  depends_on:
    mongodb:
      condition: service_healthy
    kms-init:
      condition: service_completed_successfully
```

The `depends_on` chain is critical: the proxy waits for MongoDB to be healthy AND for kms-init to complete successfully. This guarantees the KMS key exists and HTTPS is verified before CSFLE bootstrap runs.

### The Entrypoint

```bash
#!/usr/bin/env bash
set -e

if [ -z "$R3D_API_KEY" ]; then
  R3D_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  export R3D_API_KEY
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  R3D Proxy — starting                                      ║"
echo "║  Dashboard:  http://localhost:4000                          ║"
echo "║  CSFLE:      $CSFLE_LINE"
echo "║  Extension auto-connects — no config needed.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"

exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-4000}"
```

If `R3D_API_KEY` isn't set, the entrypoint auto-generates a cryptographically secure one. This means `docker-compose up` works immediately without any manual configuration. The generated key is printed in the startup banner so the operator can find it.

### Bringing It Up

```bash
docker-compose up -d
```

The startup sequence:

1. MongoDB Atlas Local starts, `mongot` initializes
2. LocalStack starts, KMS service becomes healthy
3. kms-init creates the CMK, writes ARN, verifies HTTPS
4. Proxy starts, reads ARN from `/kms-config/arn.txt`, bootstraps CSFLE
5. Startup banner prints with `CSFLE: ✓ AWS KMS verified`

The extension auto-discovers the proxy at `localhost:4000` and performs the handshake. No manual configuration needed.

---

## Testing Infrastructure

### Unit and API Tests

The `conftest.py` provides `FakeCollection` -- an in-memory mock of Motor's async collection interface that supports `find_one`, `insert_one`, `update_one`, `delete_many`, and cursor operations:

```python
class FakeCollection:
    """In-memory stand-in for a Motor async collection."""
    def __init__(self, docs=None):
        self._docs = {}
        for d in docs or []:
            self._docs[d["_id"]] = d

    async def find_one(self, filter=None, projection=None):
        # ... in-memory matching logic ...
```

The test app is built with a no-op lifespan (skipping real MongoDB/CSFLE bootstrap) and all collections replaced with `FakeCollection` instances:

```python
def _build_test_app():
    from app import app
    from core.vault import CredentialVault

    @asynccontextmanager
    async def _noop_lifespan(a):
        yield

    app.router.lifespan_context = _noop_lifespan
    app.state.sessions_col = FakeCollection()
    app.state.credential_vault = CredentialVault(FakeCollection())
    return app
```

API tests use `httpx.AsyncClient` with `ASGITransport` to make requests directly against the ASGI app without starting a real server:

```python
@pytest.fixture()
async def client(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
```

This makes tests fast (sub-second) and dependency-free.

### CSFLE Integration Tests

Tests that exercise the full encryption chain are marked with `@pytest.mark.csfle` and run against real Docker services:

```yaml
# docker-compose.test.yml
test:
  build: .
  entrypoint: ["python", "-m", "pytest"]
  command: ["-m", "csfle", "-v", "--tb=short"]
  environment:
    MDB_URI: mongodb://r3d:r3d@mongodb:27017/r3d_test?authSource=admin
    LOCAL_MASTER_KEY: AAECAwQF...  # 96-byte test key
  depends_on:
    mongodb:
      condition: service_healthy
```

```bash
docker-compose -f docker-compose.test.yml run test
```

These tests verify:

- KMS key creation and DEK generation
- Encrypted collection creation with the correct schema
- Document insertion with CSFLE auto-encryption
- Round-trip read with auto-decryption
- Equality queries on encrypted `origin` field
- Smoke test (encrypt + decrypt a sentinel value)

The test compose file uses `LOCAL_MASTER_KEY` by default for simplicity, but can be switched to the AWS KMS path (`KMS_PROVIDER=aws` + `AWS_KMS_ENDPOINT=localstack:4566`) to test the full KMS code path.

### Test Matrix

| Test Type | Speed | Dependencies | What It Covers |
|-----------|-------|-------------|----------------|
| Unit tests | <1s | None | Business logic, data transformations |
| API tests (mocked) | <3s | None | Route handlers, auth, request validation |
| CSFLE integration | ~30s | Docker (MongoDB + LocalStack) | Full encryption chain, KMS bootstrap |

---

## Terraform for Production

The `terraform/` directory contains two files that set up production KMS and IAM infrastructure.

### `kms.tf` -- Customer Master Key

```hcl
resource "aws_kms_key" "r3d_csfle" {
  description              = "R3D CSFLE Master Key - ${var.environment}"
  enable_key_rotation      = true
  deletion_window_in_days  = 30

  policy = jsonencode({
    Statement = [
      {
        Sid    = "Allow R3D Service to Use Key"
        Effect = "Allow"
        Principal = { AWS = var.service_role_arn }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      // ... root account access, CloudWatch logs encryption ...
    ]
  })

  tags = {
    Purpose    = "MongoDB CSFLE credential encryption"
    Compliance = "SOC2,PCI-DSS"
  }
}
```

Key properties:

- **Automatic annual rotation** via `enable_key_rotation`
- **30-day deletion window** preventing accidental key destruction
- **Least-privilege key policy** -- only the service role ARN can use the key
- **CloudWatch Logs encryption** permission for audit log protection

The module also provisions:

- **CloudTrail** for KMS API auditing -- every `Encrypt`, `Decrypt`, `GenerateDataKey` call is logged
- **S3 bucket** for CloudTrail storage with versioning, server-side encryption, and public access blocking
- **CloudWatch log group** with 90-day retention

### `iam.tf` -- Least-Privilege Roles

Three deployment patterns, each with its own IAM role:

**EC2 Instance Profile:**
```hcl
resource "aws_iam_role" "r3d_ec2" {
  name = "r3d-proxy-ec2-${var.environment}"
  assume_role_policy = jsonencode({
    Statement = [{
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}
```

**ECS Task Role:**
```hcl
resource "aws_iam_role" "r3d_ecs_task" {
  name = "r3d-proxy-ecs-task-${var.environment}"
  assume_role_policy = jsonencode({
    Statement = [{
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}
```

**EKS IRSA (IAM Roles for Service Accounts):**
```hcl
resource "aws_iam_role" "r3d_eks_irsa" {
  name = "r3d-proxy-eks-${var.environment}"
  assume_role_policy = jsonencode({
    Statement = [{
      Principal = { Federated = var.eks_oidc_provider_arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${oidc_provider}:sub" = "system:serviceaccount:${var.eks_namespace}:r3d-proxy"
        }
      }
    }]
  })
}
```

Each role gets the same two policies attached:

- **KMS CSFLE policy** -- `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` scoped to the specific key ARN
- **CloudWatch Logs policy** -- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` scoped to `/aws/r3d/*`

### Deploying

```bash
cd terraform
terraform init
terraform plan -var="service_role_arn=arn:aws:iam::ACCOUNT:role/YourServiceRole"
terraform apply
terraform output kms_key_arn  # Use this in AWS_KMS_KEY_ARN
```

---

## Deployment Patterns

### EC2 with Instance Profile

```bash
aws ec2 run-instances \
  --iam-instance-profile Name=r3d-proxy-ec2-production \
  --user-data file://cloud-init.sh
```

Environment variables on the instance:

```bash
KMS_PROVIDER=aws
AWS_KMS_KEY_ARN=arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID
AWS_DEFAULT_REGION=us-east-1
R3D_ALLOWED_EXTENSION_IDS=chrome-extension://abc123...
# NO AWS_ACCESS_KEY_ID — uses instance profile
```

### ECS Fargate

```json
{
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/r3d-proxy-ecs-task-production",
  "containerDefinitions": [{
    "name": "proxy",
    "image": "your-registry/r3d-proxy:latest",
    "environment": [
      {"name": "KMS_PROVIDER", "value": "aws"},
      {"name": "AWS_KMS_KEY_ARN", "value": "arn:aws:kms:..."},
      {"name": "AWS_DEFAULT_REGION", "value": "us-east-1"},
      {"name": "R3D_ALLOWED_EXTENSION_IDS", "value": "chrome-extension://abc123..."}
    ],
    "readonlyRootFilesystem": true
  }]
}
```

### EKS with IRSA

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: r3d-proxy
  namespace: r3d
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/r3d-proxy-eks-production
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      serviceAccountName: r3d-proxy
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        readOnlyRootFilesystem: true
      containers:
      - name: proxy
        env:
        - name: KMS_PROVIDER
          value: "aws"
        - name: AWS_KMS_KEY_ARN
          value: "arn:aws:kms:..."
```

In all three patterns, no AWS access keys appear in environment variables. The service authenticates to KMS through its IAM role.

---

## Migrating from Local Keys to AWS KMS

For teams already running R3D with `LOCAL_MASTER_KEY`, the migration path:

1. **Export existing credentials** -- decrypt with old key and dump to JSON
2. **Deploy KMS infrastructure** -- `terraform apply`
3. **Drop old encrypted collections** -- data encrypted with the old key is incompatible
4. **Update environment** -- set `KMS_PROVIDER=aws`, `AWS_KMS_KEY_ARN`, remove `LOCAL_MASTER_KEY`
5. **Restart** -- CSFLE bootstraps with KMS
6. **Re-import credentials** -- POST each credential through the API (re-encrypted with KMS)
7. **Verify** -- check `curl localhost:4000/health` shows `"provider": "aws"`

Total downtime: ~10 minutes. Detailed steps are in the `MIGRATION.md` guide.

---

## Production Checklist

### Before Launch

- [ ] Deploy KMS with Terraform
- [ ] Set `R3D_ALLOWED_EXTENSION_IDS` to the published Chrome extension ID
- [ ] Enable CloudTrail for KMS audit trail
- [ ] Configure CloudWatch log retention (90+ days for compliance)
- [ ] Test JWT rotation (force rotate, verify grace period works)
- [ ] Load test with stealth mode enabled
- [ ] Review `/r3d/security/metrics` for anomalies
- [ ] Verify container runs as non-root: `docker exec r3d-proxy whoami` returns `r3d`

### Operational Monitoring

- [ ] Monitor `kms_decrypt_error` events (should be zero in steady state)
- [ ] Review `handshake_denied` patterns (legitimate traffic vs. probing)
- [ ] Verify JWT rotation occurs on schedule
- [ ] Check CloudTrail for unexpected KMS API calls
- [ ] Audit credential access patterns for anomalies
- [ ] Verify container resource usage stays within limits

### Incident Response

| Scenario | Response |
|----------|----------|
| JWT compromise | Clear `/tmp/r3d/*.key` and restart -- all tokens invalidated |
| KMS key compromise | Terraform re-apply with new key, re-import credentials |
| Rogue extension | Update `R3D_ALLOWED_EXTENSION_IDS` and restart |
| Rate limit false positives | Adjust `_HANDSHAKE_RATE_LIMIT` in `routers/dashboard.py` |
| Emergency rollback | Set `KMS_PROVIDER=local` + `LOCAL_MASTER_KEY` and restart |

---

## Compliance Coverage

The infrastructure choices map directly to compliance requirements:

| Framework | Requirement | How R3D Addresses It |
|-----------|-------------|---------------------|
| SOC 2 CC6.1 | Logical access controls | IAM roles + JWT RBAC |
| SOC 2 CC6.6 | Encryption | CSFLE + KMS |
| SOC 2 CC7.2 | Monitoring | security_monitor + anomaly detection |
| SOC 2 CC7.3 | Audit logging | CloudTrail + r3d_audit_log |
| PCI DSS 3.4 | Key management | KMS annual rotation |
| PCI DSS 3.5 | Key storage | AWS HSM (FIPS 140-2 Level 3) |
| PCI DSS 8.2 | Unique credentials | JWT per session, no shared keys |
| PCI DSS 10.2 | Audit trail | CloudTrail + MongoDB audit log |
| NIST SC-12 | Cryptographic key establishment | KMS CMK + DEK hierarchy |
| NIST SI-4 | System monitoring | Anomaly detection thresholds |

---

## Series Recap

Over six posts, we've covered the complete R3D platform:

1. **[Architecture](part1-architecture.md)** -- the vision, design decisions, and end-to-end engagement workflow
2. **[Chrome Extension](part2-extension.md)** -- service worker capture, MAIN world hooks, CSP relay, and side panel UI
3. **[Server-Side Infrastructure](part3-proxy.md)** -- 18 FastAPI routers for attacks, scans, AI planning, phishing, and proofs
4. **[CSFLE + KMS](part4-csfle.md)** -- field-level encryption, the CredentialVault pattern, and on-demand decryption
5. **[Operational Security](part5-opsec.md)** -- TLS stealth, JWT rotation, handshake hardening, and container lockdown
6. **[Deployment](part6-deployment.md)** -- Docker Compose for dev, Terraform for production, and three deployment patterns

The core thesis: **red team tools should be hardened to the same standard as the systems they test.** CSFLE ensures a database compromise yields nothing. The vault pattern ensures a memory dump yields nothing. KMS ensures the master key never leaves an HSM. And the stealth stack ensures blue teams see browser traffic, not automated tooling.

If your red team proxy can't survive a memory dump, you're not ready for enterprise engagements. Build for the threat model you'd apply to your own targets.

---

*This concludes the R3D blog series. [Start from Part 1](part1-architecture.md) if you haven't read the full series.*
