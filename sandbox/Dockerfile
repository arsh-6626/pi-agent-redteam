# Sandbox image for agentic red teaming. The red-team agent, the offense backend, AND the
# reference victim (which executes attacker-chosen shell) all run INSIDE this container,
# never on the host. Build context is the project root (see run-sandboxed.sh).
FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables ipset dnsmasq dnsutils curl ca-certificates gosu python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY src ./src
COPY rtbackend ./rtbackend

# The agent's findings dir (also holds session state last_craft/last_episode).
RUN mkdir -p /app/findings

RUN useradd -m -u 10001 redteam
COPY sandbox/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY sandbox/allowlist.txt /etc/allowlist.txt
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R redteam:redteam /app/findings

# Root only long enough to install the egress firewall, then drops to `redteam`.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
