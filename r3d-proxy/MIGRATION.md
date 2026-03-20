# Migration Guide: Local → Enterprise Security

## Pre-Migration Checklist

- [ ] Backup existing MongoDB data: `mongodump --uri=$MDB_URI --out=backup/`
- [ ] Export credentials (will need re-import): See step 1 below
- [ ] Test rollback plan in non-production
- [ ] Schedule maintenance window (10-15 minutes downtime)
- [ ] Review Terraform plan: `terraform plan`

## Step 1: Export Existing Credentials

```bash
# Before migration, export decrypted credentials
docker exec -it r3d-proxy-proxy-1 python3 << 'EOF'
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
import json

async def export():
    client = AsyncIOMotorClient("mongodb://r3d:r3d@mongodb:27017/r3d?authSource=admin")
    col = client.r3d.r3d_credentials
    creds = []
    async for doc in col.find():
        doc["_id"] = str(doc["_id"])
        creds.append(doc)
    print(json.dumps(creds, indent=2, default=str))

asyncio.run(export())
EOF
```

Save output to `credentials_backup.json`.

## Step 2: Deploy KMS Infrastructure

```bash
cd terraform

# Initialize Terraform
terraform init

# Review planned changes
terraform plan \
  -var="environment=production" \
  -var="service_role_arn=arn:aws:iam::ACCOUNT:role/YourServiceRole"

# Apply (creates KMS key + IAM roles)
terraform apply
# Approve when prompted

# Save outputs
terraform output kms_key_arn > ../kms_key_arn.txt
terraform output ec2_instance_profile_name > ../instance_profile.txt
```

## Step 3: Update Environment Variables

```bash
# OLD docker-compose.yml
environment:
  LOCAL_MASTER_KEY: AAECAwQFBgcICQ...

# NEW docker-compose.yml (or .env file)
environment:
  KMS_PROVIDER: aws
  AWS_KMS_KEY_ARN: arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID  # From terraform output
  AWS_DEFAULT_REGION: us-east-1
  # For EC2: No AWS_ACCESS_KEY_ID (uses instance profile)
  # For local dev: Keep AWS_KMS_ENDPOINT=localstack:4566
  R3D_ALLOWED_EXTENSION_IDS: "*"  # Change to real extension ID in prod
  OPSEC_STEALTH_MODE: "true"
```

## Step 4: Update Application Code (Git Pull)

```bash
# Pull latest hardening changes
git pull origin main

# Rebuild container
docker-compose build proxy

# Verify new files exist
ls -la core/vault.py core/stealth.py core/rotation.py terraform/
```

## Step 5: Drop Old Encrypted Collections

```bash
# OLD encryption used different keys - data is incompatible
docker exec -it r3d-proxy-mongodb-1 mongosh r3d --eval "
  db.r3d_credentials.drop();
  db.encryption.__r3dKeyVault.drop();
"
```

## Step 6: Restart with New KMS

```bash
# Stop services
docker-compose down

# Start with new configuration
docker-compose up -d

# Wait for startup
sleep 10

# Verify KMS bootstrap
curl http://localhost:4000/health | jq '.csfle'
# Should show:
# {
#   "status": "enabled",
#   "provider": "aws",
#   "region": "us-east-1",
#   "keyArn": "arn:aws:kms:..."
# }
```

## Step 7: Re-Import Credentials

```bash
# Read backup file
cat credentials_backup.json | jq -c '.[]' | while read -r line; do
  ORIGIN=$(echo "$line" | jq -r '.origin')
  COOKIES=$(echo "$line" | jq -r '.cookies')
  HEADERS=$(echo "$line" | jq -r '.headers_json')
  UA=$(echo "$line" | jq -r '.userAgent')

  # Re-import via API (will re-encrypt with new KMS key)
  curl -X POST http://localhost:4000/r3d/auth-context \
    -H "Authorization: Bearer $R3D_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"origin\": \"$ORIGIN\",
      \"cookies\": \"$COOKIES\",
      \"headers\": $HEADERS,
      \"userAgent\": \"$UA\"
    }"

  echo "Re-encrypted: $ORIGIN"
done
```

## Step 8: Verify New Encryption

```bash
# Check MongoDB - should see Binary encrypted data
docker exec r3d-proxy-mongodb-1 mongosh r3d --eval "
  db.r3d_credentials.findOne()
"
# cookies: Binary(6, "...") ← encrypted with KMS

# Verify on-demand decryption works
curl -X POST http://localhost:4000/r3d/attack/fetch \
  -H "Authorization: Bearer $R3D_API_KEY" \
  -d '{"url":"https://httpbin.org/get","useAuthContext":false}'
# Should succeed
```

## Step 9: Test Handshake (Extensions)

```bash
# Old handshake (GET) should fail
curl http://localhost:4000/r3d/handshake
# 405 Method Not Allowed

# New handshake (POST) should return JWT
curl -X POST http://localhost:4000/r3d/handshake \
  -d '{"extensionId":"test-extension-id"}'
# {"ok": true, "token": "eyJ...", ...}
```

**Extension update required**: Extensions must call `POST /r3d/handshake` with `extensionId` parameter.

## Step 10: Production Deployment

### EC2 Deployment

```bash
# 1. Create launch template with IAM instance profile
aws ec2 create-launch-template \
  --launch-template-name r3d-proxy-production \
  --version-description "KMS hardened" \
  --launch-template-data '{
    "IamInstanceProfile": {
      "Name": "r3d-proxy-ec2-production"
    },
    "ImageId": "ami-xxxxx",
    "InstanceType": "t3.medium",
    "UserData": "<base64-encoded-cloud-init>"
  }'

# 2. Launch instance
aws ec2 run-instances \
  --launch-template LaunchTemplateName=r3d-proxy-production

# 3. SSH and verify
ssh ec2-user@<instance-ip>
sudo docker logs r3d-proxy
# Should see: "CSFLE: Created encrypted collection with AWS KMS key arn:..."
```

### ECS Fargate Deployment

```json
{
  "family": "r3d-proxy",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
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
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/r3d-proxy",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "proxy"
      }
    }
  }]
}
```

### EKS Deployment

```yaml
# ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: r3d-proxy
  namespace: r3d
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/r3d-proxy-eks-production

---
# Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: r3d-proxy
  namespace: r3d
spec:
  replicas: 2
  selector:
    matchLabels:
      app: r3d-proxy
  template:
    metadata:
      labels:
        app: r3d-proxy
    spec:
      serviceAccountName: r3d-proxy
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: proxy
        image: your-registry/r3d-proxy:latest
        env:
        - name: KMS_PROVIDER
          value: "aws"
        - name: AWS_KMS_KEY_ARN
          value: "arn:aws:kms:us-east-1:ACCOUNT:key/..."
        - name: AWS_DEFAULT_REGION
          value: "us-east-1"
        - name: R3D_ALLOWED_EXTENSION_IDS
          value: "chrome-extension://abc123..."
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
            add: [NET_BIND_SERVICE]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
```

## Step 11: Monitoring & Validation

```bash
# Check CloudTrail for KMS API calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<kms-key-id> \
  --max-results 10

# Check security metrics
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:4000/r3d/security/metrics | jq

# Check audit log
mongosh r3d --eval "
  db.r3d_audit_log.find({action: /handshake/}).sort({ts: -1}).limit(5)
"
```

## Rollback Procedure

If migration fails:

```bash
# 1. Stop new services
docker-compose down

# 2. Revert docker-compose.yml
git checkout HEAD~1 docker-compose.yml

# 3. Restore backup
mongorestore --uri=$MDB_URI --drop backup/

# 4. Restart with old config
docker-compose up -d

# 5. Verify old credentials work
curl -X POST http://localhost:4000/r3d/attack/fetch \
  -H "Authorization: Bearer $R3D_API_KEY" \
  -d '{"url":"https://httpbin.org/get","useAuthContext":false}'
```

## Common Issues

### Issue: "KMS key not found"
**Cause**: IAM role doesn't have KMS permissions or wrong key ARN.
**Fix**:
```bash
# Verify IAM policy
aws iam get-role-policy \
  --role-name r3d-proxy-ecs-task-production \
  --policy-name r3d-kms-csfle-production

# Verify key ARN
echo $AWS_KMS_KEY_ARN
terraform output kms_key_arn
```

### Issue: "AccessDeniedException" in CloudWatch
**Cause**: Task role missing KMS permissions.
**Fix**: Re-run `terraform apply` or manually attach KMS policy to IAM role.

### Issue: Credentials not decrypting
**Cause**: Data encrypted with old key, but new KMS key is active.
**Fix**: Re-import credentials (Step 7).

### Issue: Handshake returns 403
**Cause**: Extension ID not in allowlist.
**Fix**: Update `R3D_ALLOWED_EXTENSION_IDS` or set to `*` for testing.

### Issue: Rate limit false positives
**Cause**: Aggressive thresholds or NAT IP causing multiple hits.
**Fix**: Adjust thresholds in `routers/dashboard.py`:
```python
_HANDSHAKE_RATE_LIMIT = 10  # Increase from 5
_HANDSHAKE_WINDOW = 60      # Keep at 60 seconds
```

## Post-Migration Cleanup

```bash
# Remove old backup files
rm credentials_backup.json kms_key_arn.txt

# Remove LocalStack volumes (if migrating to real AWS)
docker-compose down -v

# Update documentation
git add docker-compose.yml terraform/ core/
git commit -m "chore: migrate to AWS KMS with enterprise security hardening"
git push origin main
```

## Timeline

| Phase | Duration | Downtime |
|-------|----------|----------|
| Export credentials | 2 min | No |
| Deploy Terraform | 3 min | No |
| Restart services | 2 min | **Yes** (downtime starts) |
| Re-import credentials | 5 min | **Yes** |
| Validation | 3 min | **Yes** |
| **Total** | **15 min** | **10 min downtime** |

## Success Criteria

- [ ] `/health` shows `"csfle": {"status": "enabled", "provider": "aws"}`
- [ ] All credentials re-imported and decrypting correctly
- [ ] Handshake returns JWT tokens (not raw API key)
- [ ] CloudTrail shows KMS API calls (Decrypt, GenerateDataKey)
- [ ] Security metrics accessible via `/r3d/security/metrics`
- [ ] Container running as non-root (`docker exec r3d-proxy whoami` → `r3d`)
- [ ] No errors in CloudWatch Logs

## Support

Questions? File an issue or contact security team.
