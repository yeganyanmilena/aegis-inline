#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID == 0 ]] || { echo 'Run with sudo make integration on a Linux host or VM.' >&2; exit 1; }
for cmd in ip ethtool python3 openssl tcpdump; do
  command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 1; }
done

tmp=$(mktemp -d)
pc1="aegis-pc1-$$"
d1="aegis-d1-$$"
d2="aegis-d2-$$"
pc2="aegis-pc2-$$"
namespaces=()
pids=()
cleanup() {
  local status=$?
  trap - EXIT
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  if (( status != 0 )); then
    for log in "$tmp"/*.log; do
      [[ ! -f $log ]] || { echo "---- $log" >&2; cat "$log" >&2; }
    done
  fi
  rm -rf -- "$tmp"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for ns in "$pc1" "$d1" "$d2" "$pc2"; do
  ip netns add "$ns"
  namespaces+=("$ns")
  ip -n "$ns" link set lo up
done

connect_pair() {
  local ns1=$1 if1=$2 ns2=$3 if2=$4 mtu=$5
  ip -n "$ns1" link add "$if1" type veth peer name "$if2" netns "$ns2"
  ip -n "$ns1" link set "$if1" mtu "$mtu" up
  ip -n "$ns2" link set "$if2" mtu "$mtu" up
  ip netns exec "$ns1" ethtool -K "$if1" tx off tso off gso off gro off
  ip netns exec "$ns2" ethtool -K "$if2" tx off tso off gso off gro off
}
connect_pair "$pc1" eth0 "$d1" lan0 1484
connect_pair "$d1" wan0 "$d2" wan0 1500
connect_pair "$d2" lan0 "$pc2" eth0 1484
ip -n "$pc1" addr add 10.42.0.1/24 dev eth0
ip -n "$pc2" addr add 10.42.0.2/24 dev eth0
ip -n "$d1" addr add 172.30.0.1/30 dev wan0
ip -n "$d2" addr add 172.30.0.2/30 dev wan0

await_log() {
  local pattern=$1 log=$2
  for _ in {1..200}; do
    if grep -q "$pattern" "$log"; then return; fi
    sleep 0.025
  done
  echo "Timed out waiting for '$pattern'" >&2
  return 1
}

scripts/make-certs.sh "$tmp/certs" > "$tmp/certs.log" 2>&1
ip netns exec "$pc2" python3 tests/traffic.py server > "$tmp/traffic.log" 2>&1 &
pids+=("$!")
await_log listening "$tmp/traffic.log"
ip netns exec "$pc1" python3 tests/traffic.py blocked 8080

for point in lan wan; do
  ip netns exec "$d1" tcpdump -i "${point}0" -s 0 -U -w "$tmp/$point.pcap" \
    'tcp and host 10.42.0.1 and host 10.42.0.2 and port 8080' > "$tmp/$point.log" 2>&1 &
  pids+=("$!")
  if [[ $point == lan ]]; then lan_capture=$!; else wan_capture=$!; fi
  await_log 'listening on' "$tmp/$point.log"
done

ip netns exec "$d2" ./build/aegis-inline 2 lan0 wan0 172.30.0.2 172.30.0.1 \
  7443 10.42.0.1 10.42.0.2 8080 "$tmp/certs/ca.pem" "$tmp/certs/device2.pem" > "$tmp/d2.log" 2>&1 &
pids+=("$!")
await_log 'listening' "$tmp/d2.log"
ip netns exec "$d1" ./build/aegis-inline 1 lan0 wan0 172.30.0.1 172.30.0.2 \
  7443 10.42.0.1 10.42.0.2 8080 "$tmp/certs/ca.pem" "$tmp/certs/device1.pem" > "$tmp/d1.log" 2>&1 &
pids+=("$!")
await_log 'Device1 ready' "$tmp/d1.log"
await_log 'Device2 ready' "$tmp/d2.log"

ip netns exec "$pc1" python3 tests/traffic.py client
ip netns exec "$pc1" python3 tests/traffic.py blocked 8081

kill -INT "$lan_capture" "$wan_capture"
wait "$lan_capture"
wait "$wan_capture"
python3 tests/traffic.py captures "$tmp/lan.pcap" "$tmp/wan.pcap"
echo 'PASS four namespaces, fail-closed startup, TCP round trip and selected port filter'
