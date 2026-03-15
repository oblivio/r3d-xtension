#!/usr/bin/env bash
set -e

if [ -z "$R3D_API_KEY" ]; then
  R3D_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
  export R3D_API_KEY
fi

if [ -n "$LOCAL_MASTER_KEY" ]; then
  CSFLE_LINE="ENABLED  (local dev key)"
else
  CSFLE_LINE="disabled (set LOCAL_MASTER_KEY to enable)"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  R3D Proxy — ready                                         ║"
echo "║  Dashboard:  http://localhost:4000                          ║"
echo "║  CSFLE:      $CSFLE_LINE  ║"
echo "║  Extension auto-connects — no config needed.               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

exec uvicorn app:app --host 0.0.0.0 --port "${PORT:-4000}"
