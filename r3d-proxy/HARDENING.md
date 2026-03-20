# Advanced Security Hardening - 

## Blue Team Evasion

### TLS Fingerprint Randomization
**Problem**: JA3/JA4 fingerprinting identifies Python/httpx as non-browser traffic.

**Solution** (`core/stealth.py`):
- Randomizes TLS cipher suite ordering per request
- Rotates between Chrome/Firefox/Safari patterns
- HTTP/2 SETTINGS frame normalization
- Header ordering matches browser behavior

```python
from core.stealth import create_stealth_client

# Automatically randomizes TLS fingerprint
client = create_stealth_client(profile="random")
resp = await client.get("https://target.com")
# Appears as legitimate browser to blue team tools
```

### Request Normalization
- Header ordering (insertion order preserved in Python 3.7+)
- Case normalization (matches browser canonical casing)
- Connection pooling limits (avoid "too many connections" patterns)
- Human-like timing jitter

### Detection Evasion Metrics
- No Prometheus/external metrics endpoints
- Internal monitoring only (`/r3d/security/metrics` - auth required)
- Silent anomaly detection (no external alerts)
- Stealth mode configurable: `OPSEC_STEALTH_MODE=true`

## Container Security

### Non-Root Execution
```dockerfile
USER r3d:r3d  # UID/GID 1000
```

### Read-Only Root Filesystem
```yaml
read_only: true
tmpfs:
  - /tmp:mode=1777,size=100M
```

### Capability Dropping
```yaml
cap_drop: [ALL]
cap_add: [NET_BIND_SERVICE]  # Port 4000 only
security_opt:
  - no-new-privileges:true
```

### Resource Limits
```yaml
mem_limit: 2g
cpus: 2.0
pids_limit: 512  # Prevent fork bombs
```

## Secret Rotation

### Automatic JWT Key Rotation
**Zero-downtime rotation** with grace period:

```python
# core/rotation.py
# Rotates every 7 days (configurable)
JWT_ROTATION_HOURS=168

# Verifies with current + previous secret
# Tokens signed before rotation still work
```

**Benefits**:
- Limits blast radius of compromised tokens
- Automatic without manual intervention
- Backwards compatible during rotation window

### KMS Key Rotation
Terraform-managed automatic rotation:
```hcl
enable_key_rotation = true  # Annual rotation
```

## Infrastructure as Code

### Terraform Modules
**Production-ready KMS setup**:
- `terraform/kms.tf` - CMK with key policy
- `terraform/iam.tf` - Least-privilege roles (EC2/ECS/EKS)
- CloudTrail + CloudWatch logging
- S3 versioning + encryption

**Deploy**:
```bash
cd terraform
terraform init
terraform plan -var="service_role_arn=arn:aws:iam::ACCOUNT:role/R3DService"
terraform apply
```

**Outputs**:
```bash
kms_key_arn = "arn:aws:kms:us-east-1:ACCOUNT:key/..."
ec2_instance_profile_name = "r3d-proxy-ec2-production"
ecs_task_role_arn = "arn:aws:iam::ACCOUNT:role/r3d-proxy-ecs-task-production"
```

## Security Monitoring

### Event Tracking (Internal Only)
```python
from core.security_monitor import track_event

track_event("credential_access", ip=client_ip, user=username)
```

**Monitored Events**:
- `credential_access` - Vault decrypt operations
- `handshake_attempt` / `handshake_denied`
- `rate_limit_hit` - Rate limiter triggered
- `jwt_verification_failed` - Invalid/expired tokens
- `kms_decrypt_error` - KMS API failures

### Anomaly Detection Thresholds
```python
THRESHOLDS = {
    "credential_access": {"window_minutes": 5, "max_count": 50},
    "handshake_denied": {"window_minutes": 5, "max_count": 10},
    "kms_decrypt_error": {"window_minutes": 10, "max_count": 3},
}
```

**Alerting**:
- Internal logging only (no external webhooks)
- Silent anomaly detection
- Integration-ready for SIEM (Splunk, ELK, Datadog)

### Metrics Endpoint
```bash
# Authenticated only, not exposed externally
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:4000/r3d/security/metrics

{
  "rates": {
    "credential_access": {"1m": 5, "5m": 23, "1h": 142},
    "handshake_denied": {"1m": 0, "5m": 2, "1h": 8}
  },
  "anomalies_detected": 0
}
```

## Deployment Patterns

### EC2 with Instance Profile
```bash
# Attach IAM role (from Terraform output)
aws ec2 run-instances \
  --iam-instance-profile Name=r3d-proxy-ec2-production \
  --user-data file://ec2-userdata.sh

# Environment variables (no hardcoded credentials)
KMS_PROVIDER=aws
AWS_KMS_KEY_ARN=arn:aws:kms:...
AWS_DEFAULT_REGION=us-east-1
R3D_ALLOWED_EXTENSION_IDS=<extension-id>
```

### ECS Fargate Task
```json
{
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/r3d-proxy-ecs-task-production",
  "containerDefinitions": [{
    "environment": [
      {"name": "KMS_PROVIDER", "value": "aws"},
      {"name": "AWS_KMS_KEY_ARN", "value": "arn:aws:kms:..."},
      {"name": "OPSEC_STEALTH_MODE", "value": "true"}
    ],
    "readonlyRootFilesystem": true
  }]
}
```

### EKS with IRSA
```yaml
# ServiceAccount with IAM role annotation
apiVersion: v1
kind: ServiceAccount
metadata:
  name: r3d-proxy
  namespace: r3d
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/r3d-proxy-eks-production

---
# Deployment
spec:
  template:
    spec:
      serviceAccountName: r3d-proxy
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        readOnlyRootFilesystem: true
```

## Attack Surface Reduction Summary

| Vector | Mitigation | Layer |
|--------|-----------|-------|
| Memory dump | On-demand decrypt only | Application |
| Config file leak | KMS with IAM (no hardcoded keys) | Infrastructure |
| API key theft | JWT minting (master key server-side) | Application |
| Rogue extension | ID pinning + rate limiting | Application |
| JA3/JA4 fingerprint | TLS randomization | Network |
| Container escape | Non-root + read-only FS + cap drop | Container |
| Fork bomb | PID limits | Container |
| Memory exhaustion | Memory limits + reservation | Container |
| Blue team detection | Stealth mode + header normalization | Network |
| Secret compromise | Automatic rotation (7d default) | Application |
| Insider threat | Audit logging + CloudTrail | Observability |

## Performance Impact

| Feature | Overhead | Mitigation |
|---------|----------|------------|
| KMS decrypt | ~30-50ms/req | Data key caching (automatic) |
| On-demand vault | ~5ms/req | MongoDB connection pooling |
| TLS randomization | ~2ms/req | Async SSL context creation |
| JWT rotation | 0ms | Passive (grace period) |
| Security monitoring | <1ms/event | In-memory counters |

## Compliance Mapping

### SOC 2 Type II
✅ Encryption at rest (KMS)
✅ Encryption in transit (TLS 1.2+)
✅ Access control (IAM + RBAC)
✅ Audit logging (CloudTrail + app logs)
✅ Secure configuration (IaC)
✅ Incident response (anomaly detection)

### PCI DSS 3.2.1
✅ Req 3.4 - Cryptographic key management (KMS rotation)
✅ Req 3.5 - Key storage (HSM via AWS KMS)
✅ Req 8.2 - Unique credentials (JWT per session)
✅ Req 10.2 - Audit trail (CloudTrail + app audit_log)
✅ Req 10.7 - Log retention (90 days CloudWatch)

### NIST 800-53
✅ AC-2 - Account management (IAM roles)
✅ AU-2 - Audit events (security_monitor)
✅ SC-12 - Cryptographic key establishment (KMS)
✅ SC-13 - Cryptographic protection (AES-256-GCM)
✅ SI-4 - System monitoring (anomaly detection)

## Production Checklist

### Before Launch
- [ ] Deploy KMS with Terraform (`terraform apply`)
- [ ] Set `R3D_ALLOWED_EXTENSION_IDS` to published extension ID
- [ ] Enable CloudTrail for KMS audit trail
- [ ] Configure CloudWatch log retention (90+ days)
- [ ] Test secret rotation (force rotate, verify grace period)
- [ ] Load test with stealth mode enabled
- [ ] Review security metrics endpoint for anomalies
- [ ] Set up SIEM integration (optional)

### Operational
- [ ] Monitor `kms_decrypt_error` events (should be zero)
- [ ] Review `handshake_denied` patterns (legitimate traffic?)
- [ ] Verify JWT rotation occurs every 7 days
- [ ] Check CloudTrail for unexpected KMS API calls
- [ ] Audit credential access patterns (anomalies?)
- [ ] Container resource usage within limits

### Incident Response
- [ ] Rotate JWT secrets: `kubectl rollout restart deployment/r3d-proxy`
- [ ] Rotate KMS key: Terraform re-apply with new key
- [ ] Revoke tokens: Clear `/tmp/r3d/*.key` and restart
- [ ] Block extension: Update `R3D_ALLOWED_EXTENSION_IDS` and restart
- [ ] Review audit logs: Query CloudWatch + MongoDB `r3d_audit_log`
