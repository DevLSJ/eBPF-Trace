#!/usr/bin/env bash
# 로컬 Webhook 수신용 ngrok 터널 (docs/11 §1). 고정 도메인으로 gateway(:4000) 노출.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v ngrok >/dev/null 2>&1; then
  echo "ngrok 미설치. 설치: brew install ngrok"; exit 1
fi
# shellcheck disable=SC1091
set -a; [ -f .env ] && . ./.env; set +a

if [ -n "${NGROK_AUTHTOKEN:-}" ]; then ngrok config add-authtoken "$NGROK_AUTHTOKEN" >/dev/null 2>&1 || true; fi

if [ -n "${NGROK_DOMAIN:-}" ]; then
  echo "▶ ngrok → https://${NGROK_DOMAIN}  (gateway :4000)"
  echo "  Webhook Payload URL: https://${NGROK_DOMAIN}/webhooks/github"
  exec ngrok http 4000 --domain "$NGROK_DOMAIN"
else
  echo "▶ ngrok(임시 도메인) → gateway :4000. 고정 도메인은 .env NGROK_DOMAIN 설정"
  exec ngrok http 4000
fi
