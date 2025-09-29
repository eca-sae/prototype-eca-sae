#!/usr/bin/env bash
set -euo pipefail
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) ROOT="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --self-signed) SELF="yes"; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
: "${ROOT:?--root required}"; : "${PORT:=443}"
mkdir -p "$ROOT"
CERT=/tmp/self.crt; KEY=/tmp/self.key
if [[ -n "${SELF:-}" ]]; then
  if [[ ! -s "$CERT" || ! -s "$KEY" ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
      -subj "/CN=localhost" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1
  fi
  ROOT="$ROOT" PORT="$PORT" CERT="$CERT" KEY="$KEY" python3 - <<'PY'
import http.server, ssl, os
root = os.environ["ROOT"]
port = int(os.environ["PORT"])
cert = os.environ["CERT"]
key  = os.environ["KEY"]
os.chdir(root)
httpd = http.server.HTTPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f"[tools] https static on :{port} serving {root} (self-signed)", flush=True)
httpd.serve_forever()
PY
else
  python3 -m http.server -d "$ROOT" "$PORT"
fi
