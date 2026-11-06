#!/usr/bin/env bash
set -euo pipefail
umask 077
tmp=$(mktemp -d)
server=
cleanup() {
  if [[ -n $server ]]; then kill "$server" 2>/dev/null || true; fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
scripts/make-certs.sh "$tmp/good" > "$tmp/cert.log" 2>&1 || { cat "$tmp/cert.log"; exit 1; }
scripts/make-certs.sh "$tmp/bad" >> "$tmp/cert.log" 2>&1 || { cat "$tmp/cert.log"; exit 1; }

run_pair() {
  local attempt=$1 server_cert=$2 client_ca=$3 client_cert=$4 expect=$5 port
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
  ./build/test-session 2 "$port" "$tmp/good/ca.pem" "$server_cert" "$tmp/$attempt.server" 2>"$tmp/server.log" &
  server=$!
  for _ in {1..100}; do
    if grep -q listening "$tmp/server.log"; then break; fi
    sleep 0.02
  done
  local client_status=0 server_status=0
  ./build/test-session 1 "$port" "$client_ca" "$client_cert" "$tmp/$attempt.client" 2>"$tmp/client.log" || client_status=$?
  wait "$server" || server_status=$?
  server=
  if [[ $expect == success && $client_status == 0 && $server_status == 0 ]]; then
    cmp "$tmp/$attempt.client" "$tmp/$attempt.server"
  elif [[ $expect == failure && $client_status == 1 && $server_status == 1 &&
          ! -e "$tmp/$attempt.client" && ! -e "$tmp/$attempt.server" ]]; then
    return 0
  else
    cat "$tmp/server.log" "$tmp/client.log" >&2
    return 1
  fi
}
run_pair first "$tmp/good/device2.pem" "$tmp/good/ca.pem" "$tmp/good/device1.pem" success
run_pair second "$tmp/good/device2.pem" "$tmp/good/ca.pem" "$tmp/good/device1.pem" success
if cmp -s "$tmp/first.client" "$tmp/second.client"; then
  echo 'Session keys unexpectedly repeated' >&2
  exit 1
fi
run_pair untrusted "$tmp/good/device2.pem" "$tmp/good/ca.pem" "$tmp/bad/device1.pem" failure
run_pair wrong-role "$tmp/good/device1.pem" "$tmp/good/ca.pem" "$tmp/good/device1.pem" failure
echo 'PASS TLS 1.3 mutual authentication, matching directional keys and fresh session keys'
