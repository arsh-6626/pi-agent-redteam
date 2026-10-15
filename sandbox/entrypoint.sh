#!/usr/bin/env bash
# Runs as root: install a default-deny egress firewall, then drop to the unprivileged
# `redteam` user to run the agent. Enforced by the kernel — it holds no matter what the
# agent, the offense backend, or the HIJACKED VICTIM tries to do. The only allowed egress
# is HTTPS to the DeepSeek API (the brain); any exfil the victim attempts is dropped here.
set -euo pipefail

RESOLVERS="1.1.1.1 8.8.8.8"
ALLOWLIST="/etc/allowlist.txt"

hosts_list() { sed 's/#.*//' "$ALLOWLIST" | tr -s ' \t' '\n' | grep -v '^$' | sort -u; }

setup_dns() {
  local conf=/etc/dnsmasq.d/allow.conf ipset_domains=""
  mkdir -p /etc/dnsmasq.d
  {
    echo "no-resolv"; echo "no-hosts"; echo "user=root"
    echo "listen-address=127.0.0.1"; echo "bind-interfaces"
    for h in $(hosts_list); do
      for r in $RESOLVERS; do echo "server=/$h/$r"; done
      ipset_domains="${ipset_domains}/$h"
    done
    echo "ipset=${ipset_domains}/allowed"
    echo "address=/#/0.0.0.0"
  } > "$conf"
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
  ipset create allowed hash:ip timeout 3600 -exist
  dnsmasq --keep-in-foreground --log-facility=/tmp/dnsmasq.log --conf-file="$conf" &
  sleep 1
  echo "[dns] local resolver up; allowlisted: $(hosts_list | tr '\n' ' ')"
}

setup_firewall() {
  update-alternatives --set iptables /usr/sbin/iptables-nft >/dev/null 2>&1 || true
  iptables -F OUTPUT
  iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  for r in $RESOLVERS; do
    iptables -A OUTPUT -p udp -d "$r" --dport 53 -m owner --uid-owner 0 -j ACCEPT
    iptables -A OUTPUT -p tcp -d "$r" --dport 53 -m owner --uid-owner 0 -j ACCEPT
  done
  iptables -A OUTPUT -p tcp -m set --match-set allowed dst --dport 443 -j ACCEPT
  echo "[firewall] default-deny egress active (dynamic allowlist)"
}

setup_dns
setup_firewall

if [ "${1:-}" = "--verify" ]; then
  echo "== containment checks =="
  ok=0; fail=0
  chk() { if eval "$2"; then echo "PASS: $1"; ok=$((ok+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }
  chk "DeepSeek API reachable" \
    'code=$(gosu redteam curl -s -o /dev/null -w "%{http_code}" --max-time 12 https://api.deepseek.com/ || true); [ "$code" != "000" ]'
  chk "blocked host unreachable (example.com)" \
    '! gosu redteam curl -s -o /dev/null --max-time 8 https://example.com'
  chk "no host ssh keys present" '! ls /root/.ssh 2>/dev/null && ! ls /home/redteam/.ssh 2>/dev/null'
  echo "== $ok passed, $fail failed =="
  [ "$fail" -eq 0 ]; exit $?
fi

TASK="${1:-}"
export FINDINGS_PATH="${FINDINGS_PATH:-/out/findings.json}"
echo "[run] red-teaming the reference victim as unprivileged user; findings -> $FINDINGS_PATH"
if [ -n "$TASK" ]; then
  exec gosu redteam node --experimental-strip-types --no-warnings /app/src/run.ts "$TASK"
else
  exec gosu redteam node --experimental-strip-types --no-warnings /app/src/run.ts
fi
