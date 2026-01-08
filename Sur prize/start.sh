#!/bin/sh
set -eu

# Accept flag from various CTF platform environment variables
FLAG_VALUE="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG_VALUE" ]; then
    echo "Warning: No flag provided, using placeholder" >&2
    FLAG_VALUE="flag{placeholder}"
fi

# Calculate MD5 hash of flag content
HASH=$(printf "%s" "$FLAG_VALUE" | md5sum | cut -d' ' -f1)
FLAG_FILE="/home/ctf/flag_${HASH}"

# Write flag to a protected location
umask 077
printf "%s\n" "$FLAG_VALUE" >"${FLAG_FILE}"
chown root:ctf "${FLAG_FILE}"
chmod 640 "${FLAG_FILE}"

# Unset flag environment variables for security
for var in FLAG GZCTF_FLAG DASFLAG FLAG_VALUE flag HASH FLAG_FILE; do
    unset "$var" 2>/dev/null || true
done

# Resource limits (best-effort)
ulimit -c 0
ulimit -v 1048576 2>/dev/null || true
ulimit -u 256 2>/dev/null || true

# Drop to user and start service via socat on 0.0.0.0:9999
cd /home/ctf
exec socat TCP-LISTEN:9999,reuseaddr,fork,su=ctf \
    EXEC:"/home/ctf/vuln"
