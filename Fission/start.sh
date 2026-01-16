#!/bin/sh
set -eu

# Accept flag from various CTF platform environment variables
FLAG_VALUE="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG_VALUE" ]; then
    echo "Warning: No flag provided, using placeholder" >&2
    FLAG_VALUE="flag{placeholder}"
fi

# Write flag to a protected location
umask 077
printf "%s\n" "$FLAG_VALUE" >/home/ctf/flag
chown root:ctf /home/ctf/flag
chmod 640 /home/ctf/flag

# Unset flag environment variables for security
unset FLAG
unset GZCTF_FLAG
unset DASFLAG
unset FLAG_VALUE
unset flag

# Resource limits (best-effort)
ulimit -c 0
ulimit -v 1048576 2>/dev/null || true # 1GB virtual memory
ulimit -u 1024 2>/dev/null || true     # max user processes

# Drop to user and start service via socat on 0.0.0.0:9999
cd /home/ctf
exec socat TCP-LISTEN:9999,reuseaddr,fork,su=ctf \
    EXEC:"/home/ctf/vuln"
