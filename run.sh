#!/bin/sh
# streamflare — Cloudflare Tunnel smoke test.
#
# Answers one question before the fleet is moved off Tailscale: can a tunnel
# be started from this container without sudo, and does traffic actually
# arrive through the public hostname?
#
# Runs on Streamlit Cloud and on a bare host alike. Deliberately no Python:
# the target image may not ship one, so the throwaway origin is a small
# `sh` + nc loop or a busybox httpd when available, and the test still
# reports usefully when no origin can be started.
#
# Usage:
#   TUNNEL_TOKEN=eyJh... ./streamflare/run.sh
#
# Optional:
#   LOCAL_PORT   port the tunnel should reach (default 7932)
#   ORIGIN_URL   explicit origin (default http://127.0.0.1:$LOCAL_PORT)
#   BINDIR       where cloudflared is cached (default /tmp/bin)
#   SELF_TEST    1 = start a throwaway origin (default), 0 = use a real one
set -eu

APP_ROOT="$(cd "$(dirname "$0")" && pwd)"
BINDIR="${BINDIR:-/tmp/bin}"
CLOUDFLARED="$BINDIR/cloudflared"
BASE_URL="https://github.com/cloudflare/cloudflared/releases/latest/download"
LOCAL_PORT="${LOCAL_PORT:-7932}"
ORIGIN_URL="${ORIGIN_URL:-http://127.0.0.1:$LOCAL_PORT}"
LOG="$APP_ROOT/tunnel.log"
tmp="$(mktemp -d)"

say()  { printf '\033[36m→\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✘ %s\033[0m\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"; }

cleanup() {
  [ -n "${CF_PID:-}" ]  && kill "$CF_PID"  2>/dev/null || true
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# ── preflight ─────────────────────────────────────────────────────────
printf '\033[1mstreamflare\033[0m — Cloudflare Tunnel smoke test\n\n'
[ "$(id -u)" -eq 0 ] && warn "running as root; the Streamlit target is a non-root uid"
need curl

if [ -z "${TUNNEL_TOKEN:-}" ]; then
  die "TUNNEL_TOKEN is not set.
  Create a tunnel in the Cloudflare Zero Trust dashboard, copy its run
  command, and export TUNNEL_TOKEN before running this."
fi
# The token is a credential: report its presence, never its value.
ok "TUNNEL_TOKEN present ($(printf '%s' "$TUNNEL_TOKEN" | wc -c | tr -d ' ') chars, not shown)"

# ── fetch cloudflared ────────────────────────────────────────────────
# No sudo, no package manager: the official release asset, downloaded into a
# user-writable dir. Same path the worker would use, so a pass here means that
# fetch path works there too.
#
# The asset is a RAW ELF BINARY, not a tarball — `tar -xzf` on it fails with
# "gzip: invalid magic". Verified: content-type application/octet-stream, the
# first bytes are \x7fELF.
if [ -x "$CLOUDFLARED" ]; then
  ok "cloudflared present: $($CLOUDFLARED --version 2>&1 | head -1)"
else
  case "$(uname -m)" in
    x86_64|amd64) asset="cloudflared-linux-amd64" ;;
    aarch64|arm64) asset="cloudflared-linux-arm64" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  say "downloading $asset → $CLOUDFLARED"
  if ! curl -fsSL --retry 3 --retry-delay 2 -o "$tmp/cf.bin" "$BASE_URL/$asset"; then
    die "download failed: $BASE_URL/$asset
Egress to GitHub releases is blocked from here. That alone answers the
question: a tunnel client could not be fetched in this environment either."
  fi
  # Guard against a captive portal or an error page saved as a binary: a real
  # ELF starts with \x7fELF, and that is the difference between a 403 HTML page
  # and a working client.
  if ! head -c 4 "$tmp/cf.bin" | grep -q 'ELF' 2>/dev/null; then
    printf 'downloaded file is not an ELF binary; first bytes were:\n' >&2
    head -c 200 "$tmp/cf.bin" | tr -d '\0' >&2
    printf '\n' >&2
    die "egress to GitHub releases returned an error page, not the asset"
  fi
  mv "$tmp/cf.bin" "$CLOUDFLARED"
  chmod +x "$CLOUDFLARED"
  ok "installed: $($CLOUDFLARED --version 2>&1 | head -1)"
fi

# ── origin ───────────────────────────────────────────────────────────
# cloudflared starts and registers with nothing listening, but every request
# then 502s — which proves the handshake and nothing else. When the real
# origin already answers, use it; otherwise start a throwaway one so the test
# measures the whole path instead of just the registration.
origin_up() {
  curl -fsS --max-time 3 "$ORIGIN_URL" >/dev/null 2>&1
}

# Pick an implementation that exists in this image. Order matters: the
# Streamlit image has python3 but no busybox and no nc, and an earlier
# version of this script dropped python from the list — which is why the
# origin never came up there and every request 502'd.
start_throwaway() {
  if command -v python3 >/dev/null 2>&1; then
    say "starting python http.server origin on 127.0.0.1:$LOCAL_PORT"
    printf 'streamflare-origin-ok\n' > "$tmp/index.html"
    ( cd "$tmp" && exec python3 -m http.server "$LOCAL_PORT" --bind 127.0.0.1 ) >/dev/null 2>&1 &
    return 0
  fi
  if command -v busybox >/dev/null 2>&1 && busybox httpd -h >/dev/null 2>&1; then
    say "starting busybox httpd origin on 127.0.0.1:$LOCAL_PORT"
    printf 'streamflare-origin-ok\n' > "$tmp/index.html"
    busybox httpd -f -p "127.0.0.1:$LOCAL_PORT" -h "$tmp" >/dev/null 2>&1 &
    return 0
  fi
  if command -v nc >/dev/null 2>&1; then
    say "starting nc origin on 127.0.0.1:$LOCAL_PORT (minimal, 200 only)"
    while true; do
      printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 22\r\nConnection: close\r\n\r\nstreamflare-origin-ok\n' \
        | nc -l -p "$LOCAL_PORT" -s 127.0.0.1 >/dev/null 2>&1 || true
    done &
    return 0
  fi
  return 1
}

if origin_up; then
  ok "origin already answers at $ORIGIN_URL"
elif [ "${SELF_TEST:-1}" = "1" ]; then
  if start_throwaway; then
    sleep 2
    if origin_up; then
      ok "throwaway origin answers at $ORIGIN_URL"
    else
      die "started an origin but $ORIGIN_URL still does not answer.
This container may lack every http server (python3, busybox httpd, nc).
Set SELF_TEST=0 and point ORIGIN_URL at a service you start yourself."
    fi
  else
    die "no python3, busybox httpd or nc to start a test origin.
Set SELF_TEST=0 and point ORIGIN_URL at a real service."
  fi
else
  die "nothing is listening at $ORIGIN_URL and SELF_TEST=0."
fi

# ── tunnel ───────────────────────────────────────────────────────────
# The token goes through --token, NOT as the positional TUNNEL argument:
# `tunnel run` treats a positional value as a tunnel name/UUID and then
# demands cert.pem ("error parsing tunnel ID: Error locating origin cert").
# --token takes precedence over credentials and needs no login, which is what
# makes it viable in a container with no home directory.
say "starting tunnel → $LOG"
: > "$LOG"

"$CLOUDFLARED" tunnel --no-autoupdate --loglevel info \
  run --token "$TUNNEL_TOKEN" >>"$LOG" 2>&1 &
CF_PID=$!

# ── watch the log ────────────────────────────────────────────────────
# The public hostname is only known after registration, so it is read back out
# of cloudflared's own output rather than assumed. Registration is the
# signal that egress to Cloudflare works at all.
host=""
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if ! kill -0 "$CF_PID" 2>/dev/null; then
    warn "cloudflared exited early; log tail:"
    tail -25 "$LOG" >&2
    exit 1
  fi
  if grep -q "Registered tunnel connection" "$LOG" 2>/dev/null; then
    host=$(sed -n 's/.*hostname=\([A-Za-z0-9._-]*\).*/\1/p' "$LOG" | head -1)
    [ -z "$host" ] && host=$(grep -oE 'https://[A-Za-z0-9.-]+' "$LOG" | head -1 | sed 's|https://||' || true)
    break
  fi
  sleep 1
done

printf '\n'
if ! grep -q "Registered tunnel connection" "$LOG" 2>/dev/null; then
  warn "tunnel did not register within 60s. Log tail:"
  tail -30 "$LOG" >&2
  cat <<'GUIDE'

How to read that log:
  401 / 403            the token is wrong, or belongs to another account
  i/o timeout / dial    egress to Cloudflare is blocked from this network
  "no route" / no cert  the tunnel exists but has no public hostname bound
  "Registered..." but
  every request 502s    the path works; the local origin is the problem
GUIDE
  exit 1
fi

ok "tunnel registered"
n=$(grep -c "Registered tunnel connection" "$LOG" || true)
ok "connections registered: $n"

# ── end-to-end ───────────────────────────────────────────────────────
# A 502 is never a tunnel problem: cloudflared reached the edge and the edge
# could not reach us. The reason is already in the log, so surface it instead
# of printing a bare code that sends people hunting in the wrong place.
origin_detail() {
  sed -n 's/.*dial tcp \([^"]*\)[:;].*/\1/p' "$LOG" 2>/dev/null | tail -1
}

if [ -n "$host" ]; then
  ok "public host: $host"
  say "requesting through the tunnel — this is the actual test"
  code=$(curl -s -o "$tmp/body" -w '%{http_code}' --max-time 25 "https://$host/" 2>/dev/null || echo 000)
  case "$code" in
    200)
      ok "HTTP 200 through the tunnel"
      printf '     body: %s\n' "$(head -c 200 "$tmp/body" 2>/dev/null || true)"
      printf '\n\033[32;1mPASS\033[0m — cloudflared starts without sudo and traffic flows.\n'
      printf '       Egress to Cloudflare works from this container.\n'
      ;;
    502|503)
      detail=$(origin_detail)
      warn "HTTP $code — the tunnel is up, the origin is not answering"
      printf '     cloudflared said: %s\n' "${detail:-no dial error found in the log}"
      printf '     Start the service on %s, or set ORIGIN_URL to where it listens.\n' "$ORIGIN_URL"
      printf '\n\033[33;1mPARTIAL\033[0m — tunnel usable, origin missing.\n'
      ;;
    *)
      warn "HTTP $code"
      printf '\n\033[33;1mPARTIAL\033[0m — read %s for the reason.\n' "$LOG"
      ;;
  esac
else
  warn "registered, but the hostname could not be parsed from the log"
  printf '\n\033[33;1mPARTIAL\033[0m — read %s\n' "$LOG"
fi

printf '\n\033[1mLog:\033[0m %s\n' "$LOG"
printf '\033[1mMetrics:\033[0m http://127.0.0.1:2000/metrics (if the tunnel exposes them)\n\n'
