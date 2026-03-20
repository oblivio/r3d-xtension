#!/usr/bin/env bash
set -e

if [ -z "$R3D_API_KEY" ]; then
  R3D_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  export R3D_API_KEY
fi

if [ "$KMS_PROVIDER" = "aws" ]; then
  CSFLE_LINE="AWS KMS (verifying on startup…)"
elif [ -n "$LOCAL_MASTER_KEY" ]; then
  CSFLE_LINE="local key (verifying on startup…)"
else
  CSFLE_LINE="disabled"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  R3D Proxy — starting                                      ║"
echo "║  Dashboard:  http://localhost:4000                          ║"
echo "║  CSFLE:      $CSFLE_LINE"
echo "║  Extension auto-connects — no config needed.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Look for 'CSFLE: ✓' in the logs below to confirm encryption is live."
echo ""

exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-4000}"
