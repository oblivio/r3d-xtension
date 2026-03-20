#!/bin/sh
# KMS Initialization Script for LocalStack (Development)
#
# This script creates a Customer Master Key (CMK) in LocalStack's KMS service
# and writes the key ARN to a shared volume for the proxy to read at startup.
#
# IDEMPOTENT: If /kms-config/arn.txt already exists and the key is still valid
# in LocalStack, no new key is created. This prevents orphaning existing DEKs
# in MongoDB's key vault on container restart.
#
# HTTPS GATE: Before exiting, verifies LocalStack serves HTTPS on port 4566
# (libmongocrypt always connects via TLS). If HTTPS fails, this script exits
# non-zero, preventing the proxy from starting.
#
# PRODUCTION SETUP:
#   1. Create a real CMK in AWS KMS via Terraform/CloudFormation:
#      aws kms create-key --description "R3D CSFLE Master Key"
#   2. Enable automatic key rotation:
#      aws kms enable-key-rotation --key-id <key-id>
#   3. Restrict key policy to your service's IAM role ARN only
#   4. Grant kms:Encrypt, kms:Decrypt, kms:GenerateDataKey to the role
#   5. Use EC2 instance profile / ECS task role / EKS IRSA — NEVER hardcoded credentials

set -e

echo "Waiting for LocalStack KMS to be ready..."
sleep 5

# ── HTTPS verification ────────────────────────────────────────────────
# libmongocrypt always connects to KMS via HTTPS. Verify LocalStack
# actually serves TLS before letting the proxy start.
verify_https() {
  echo "Verifying LocalStack HTTPS (libmongocrypt requires TLS)..."
  for i in $(seq 1 10); do
    if aws kms list-keys \
         --endpoint-url https://localstack:4566 \
         --no-verify-ssl >/dev/null 2>&1; then
      echo "HTTPS verification passed."
      return 0
    fi
    echo "  HTTPS not ready (attempt $i/10), waiting 2s..."
    sleep 2
  done
  echo "ERROR: LocalStack HTTPS not responding on port 4566."
  echo "       libmongocrypt requires HTTPS — CSFLE will fail."
  return 1
}

# ── Idempotency check ────────────────────────────────────────────────
if [ -f /kms-config/arn.txt ]; then
  EXISTING_ARN=$(cat /kms-config/arn.txt)
  if [ -n "$EXISTING_ARN" ]; then
    echo "Found existing key ARN: $EXISTING_ARN"
    if aws kms describe-key --key-id "$EXISTING_ARN" >/dev/null 2>&1; then
      echo "Key is still valid in LocalStack — skipping creation."
      verify_https
      exit $?
    else
      echo "Key no longer exists in LocalStack (volume was reset?) — recreating."
    fi
  fi
fi

# ── Create new KMS key ───────────────────────────────────────────────
echo "Creating KMS Customer Master Key..."
KEY_ID=$(aws kms create-key \
  --description "R3D CSFLE Master Key (LocalStack)" \
  --query 'KeyMetadata.KeyId' \
  --output text)

echo "Creating key alias..."
aws kms create-alias \
  --alias-name "alias/r3d-csfle" \
  --target-key-id "$KEY_ID" 2>/dev/null || true

echo "Retrieving key ARN..."
KEY_ARN=$(aws kms describe-key \
  --key-id "$KEY_ID" \
  --query 'KeyMetadata.Arn' \
  --output text)

echo "Writing key ARN to shared volume..."
echo "$KEY_ARN" > /kms-config/arn.txt

echo "KMS key ready:"
echo "  Key ID:  $KEY_ID"
echo "  Key ARN: $KEY_ARN"

verify_https
exit $?
