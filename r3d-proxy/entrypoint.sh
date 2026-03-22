#!/usr/bin/env bash
set -e

if [ -z "$R3D_API_KEY" ]; then
  R3D_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  export R3D_API_KEY
fi

if [ "$KMS_PROVIDER" = "aws" ]; then
  QE_LINE="AWS KMS (verifying on startup…)"
elif [ -n "$LOCAL_MASTER_KEY" ]; then
  QE_LINE="local key (verifying on startup…)"
else
  QE_LINE="disabled"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  R3D Proxy — starting                                      ║"
echo "║  Dashboard:  http://localhost:4000                          ║"
echo "║  QE:         $QE_LINE"
echo "║  Extension auto-connects — no config needed.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Look for 'QE: ✓' in the logs below to confirm encryption is live."
echo ""

exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-4000}"
