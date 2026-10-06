#!/usr/bin/env bash
# CKYCRR connectivity probe -- run this from a WHITELISTED server (no Netskope in the path).
#
#   ./server_probe.sh                 stage 1: NO credentials. Which hosts accept which client cert?
#   ./server_probe.sh token <URL>     stage 2: request an OAuth token from ONE host, e.g.
#                                     ./server_probe.sh token https://secureapi-testbed.ckycindia.dev:9443
#
# Copy these next to the script on the server:
#   mtls.crt  mtls.key                      your client certificate and key
#   secureapi.ckycregistry.co.in.cer        CERSAI's server chain (private root; needed for *.ckycregistry.co.in)
#   .env                                    CLIENT_ID=...  CLIENT_SECRET=...   (stage 2 only; chmod 600)
# Override paths with MTLS_CRT, MTLS_KEY, CHAIN. Set SHOW_TOKEN=1 to print the full token in stage 2.
set -u
cd "$(dirname "$0")"

MTLS_CRT=${MTLS_CRT:-mtls.crt}
MTLS_KEY=${MTLS_KEY:-mtls.key}
CHAIN=${CHAIN:-secureapi.ckycregistry.co.in.cer}
TOKEN_PATH=/api/ckyc/v1/generate-token

HOSTS=(
  https://testbed.secureapi.ckycregistry.co.in
  https://secureapi.ckycregistry.co.in
  https://secureapi-uat.ckycindia.dev:9443
  https://secureapi-testbed.ckycindia.dev:9443
  https://secureapi-dev.ckycindia.dev:9443
  https://sandbox.ckycindia.dev
  https://uat.ckycindia.dev
)

need() { [ -f "$1" ] || { echo "missing file: $1" >&2; exit 1; }; }
need "$MTLS_CRT"; need "$MTLS_KEY"

set_ca() {  # CERSAI's chain ends at a non-public root, so *.ckycregistry.co.in needs it explicitly
  CA=()
  case "$1" in *ckycregistry.co.in*) need "$CHAIN"; CA=(--cacert "$CHAIN");; esac
}

summarize() {  # <html-or-json file> -> one short line
  local f=$1
  if grep -qi '<title>' "$f"; then sed -n 's/.*<title>\(.*\)<\/title>.*/\1/Ip' "$f" | head -1
  else tr '\n' ' ' < "$f" | sed -E 's/"accessToken" *: *"[^"]+"/"accessToken":"<redacted>"/' | cut -c1-150; fi
}

issuer() {  # who signed the certificate this server presents TO YOU -- 'goskope' means a proxy is intercepting
  local hp=${1#https://}; local host=${hp%%:*}; local port=443
  [[ "$hp" == *:* ]] && port=${hp##*:}
  echo | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null \
    | openssl x509 -noout -issuer 2>/dev/null | sed 's/^issuer= *//'
}

stage1() {
  echo "client IP as seen from outside: $(curl -s -m 5 https://checkip.amazonaws.com 2>/dev/null || echo unknown)   <- this must be on CERSAI's whitelist"
  echo
  local tmp; tmp=$(mktemp)
  for h in "${HOSTS[@]}"; do
    echo "## $h"
    local iss; iss=$(issuer "$h")
    echo "   server cert issuer: $(printf %s "${iss:-<no TLS answer>}" | sed -E 's#.*/CN=#CN=#')"
    case "$iss" in *goskope*|*netskope*|*Netskope*|*zscaler*|*Zscaler*) echo "   !! INTERCEPTED by a TLS-inspection proxy -- results for this host are NOT trustworthy";; esac
    set_ca "$h"
    for mode in "no client cert" "mtls pair"; do
      local certargs=(); [ "$mode" = "mtls pair" ] && certargs=(--cert "$MTLS_CRT" --key "$MTLS_KEY")
      local code; code=$(curl -sS -m 15 --connect-timeout 5 ${CA[@]+"${CA[@]}"} ${certargs[@]+"${certargs[@]}"} -X POST \
        -H 'Content-Type: application/x-www-form-urlencoded' -d '' -o "$tmp" -w '%{http_code}' "$h$TOKEN_PATH" 2>"$tmp.err") \
        || { printf '   %-15s curl failed: %s\n' "$mode" "$(head -c 110 "$tmp.err" | tr '\n' ' ')"; continue; }
      printf '   %-15s HTTP %s  %s\n' "$mode" "$code" "$(summarize "$tmp")"
    done
    echo
  done
  rm -f "$tmp" "$tmp.err"
  cat <<'LEGEND'
How to read it
  "No required SSL certificate was sent"   server demands mTLS; you sent none            (expected for 'no client cert')
  "The SSL certificate error"              server rejected your client cert              (cert not signed by a CA it trusts)
  "Unable to identify proxy ..."           TLS fine, but no API is deployed on that host/path
  HTTP 401 / 400 with a JSON body          mTLS PASSED and the token endpoint answered   -> run stage 2 on that host
LEGEND
}

stage2() {
  local base=${1:?usage: $0 token <base-url>}
  [ -f .env ] && { set -a; . ./.env; set +a; }
  : "${CLIENT_ID:?CLIENT_ID not set (put it in .env)}"; : "${CLIENT_SECRET:?CLIENT_SECRET not set}"
  set_ca "$base"
  local out; out=$(mktemp)
  # Credentials go to curl on STDIN as a config file, so they never appear in `ps` / shell history.
  local code
  code=$(curl -sS -m 20 --connect-timeout 5 ${CA[@]+"${CA[@]}"} --cert "$MTLS_CRT" --key "$MTLS_KEY" -K - -o "$out" -w '%{http_code}' "$base$TOKEN_PATH" <<EOF
header = "Content-Type: application/x-www-form-urlencoded"
data-urlencode = "grant_type=client_credentials"
data-urlencode = "client_id=$CLIENT_ID"
data-urlencode = "client_secret=$CLIENT_SECRET"
EOF
  ) || { echo "curl failed"; rm -f "$out"; exit 1; }
  echo "HTTP $code"
  if [ "${SHOW_TOKEN:-0}" = 1 ]; then cat "$out"; else sed -E 's/("accessToken" *: *")[^"]+/\1<redacted>/' "$out"; fi
  echo; rm -f "$out"
}

case "${1:-}" in
  token) stage2 "${2:-}" ;;
  "")    stage1 ;;
  *)     echo "usage: $0 | $0 token <base-url>" >&2; exit 2 ;;
esac
