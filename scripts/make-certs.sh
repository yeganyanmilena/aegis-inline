#!/usr/bin/env bash
set -euo pipefail
umask 077
out=${1:-certs}
mkdir -- "$out"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
openssl req -x509 -newkey ed25519 -nodes -days 30 -subj '/CN=Aegis local demo CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$tmp/ca.key" -out "$out/ca.pem"
for role in device1 device2; do
  usage=clientAuth
  [[ $role != device2 ]] || usage=serverAuth
  openssl req -new -newkey ed25519 -nodes -subj "/CN=$role.aegis" \
    -keyout "$tmp/$role.key" -out "$tmp/$role.csr"
  printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' \
    "extendedKeyUsage=$usage" "subjectAltName=DNS:$role.aegis" > "$tmp/extensions"
  openssl x509 -req -days 30 -in "$tmp/$role.csr" -CA "$out/ca.pem" \
    -CAkey "$tmp/ca.key" -CAserial "$tmp/ca.srl" -CAcreateserial \
    -extfile "$tmp/extensions" -out "$tmp/$role.crt"
  cat "$tmp/$role.crt" "$tmp/$role.key" > "$out/$role.pem"
done
