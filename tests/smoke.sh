#!/usr/bin/env bash
set -euo pipefail

binary="$(cd "$(dirname "$0")/.." && pwd)/server"
fixture=$(mktemp -d)
server_pid=
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$fixture"
}
trap cleanup EXIT
# Refuse to send test credentials to another process on the fixed server port.
if curl --silent --max-time 1 http://127.0.0.1:8080/health >/dev/null; then
    echo 'Port 8080 is occupied; stop that server before running tests.' >&2
    exit 1
fi
mkdir "$fixture/files_root"
touch "$fixture/files_root/smoke-fixture"
(cd "$fixture" && exec "$binary") >"$fixture/server.log" 2>&1 &
server_pid=$!
ready=false
for _ in {1..30}; do
    kill -0 "$server_pid" 2>/dev/null || { cat "$fixture/server.log"; exit 1; }
    if curl --silent --fail --max-time 1 http://127.0.0.1:8080/health >/dev/null; then
        ready=true
        break
    fi
    sleep 0.1
done
[[ "$ready" == true ]] || { echo 'Server did not become ready' >&2; exit 1; }
request() {
    local expected=$1 path=$2 actual
    shift 2
    echo "Checking $path (expected $expected)"
    actual=$(curl --silent --show-error --max-time 3 -D "$fixture/headers"         -o "$fixture/body" -w '%{http_code}' "http://127.0.0.1:8080$path" "$@")
    [[ "$actual" == "$expected" ]] || {
        echo "$path: expected $expected, got $actual" >&2
        cat "$fixture/headers" "$fixture/body"
        exit 1
    }
}
request 200 /health
request 404 /missing
request 405 /login
request 401 /files
request 201 /register --data 'username=smoke&password=secret'
request 409 /register --data 'username=smoke&password=secret'
request 401 /login --data 'username=smoke&password=wrong'
request 200 /login --data 'username=smoke&password=secret'
cookie=$(sed -n 's/^Set-Cookie: \(session=[0-9a-f]*\).*/\1/p' "$fixture/headers" | tr -d '\r')
[[ "$cookie" =~ ^session=[0-9a-f]{32}$ ]]
request 200 /files -H "Cookie: $cookie"
grep -q smoke-fixture "$fixture/body"
length=$(sed -n 's/^Content-Length: //p' "$fixture/headers" | tr -d '\r')
[[ "$length" -eq $(wc -c < "$fixture/body") ]]
request 200 /logout -X POST -H "Cookie: $cookie"
request 401 /files -H "Cookie: $cookie"
echo 'HTTP, registration, login, file listing and logout smoke tests passed.'
