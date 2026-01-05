#!/bin/sh
set -eu

# Accept flag from various CTF platform environment variables
export FLAG="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG" ]; then
    echo "Warning: No flag provided, using placeholder" >&2
    export FLAG="flag{placeholder}"
fi

# Resource limits (best-effort)
ulimit -c 0
ulimit -v 1048576 2>/dev/null || true
ulimit -u 256 2>/dev/null || true

# Drop to user and start service via socat on 0.0.0.0:9999
cd /home/ctf
exec socat -T60 -t60 TCP-LISTEN:9999,reuseaddr,fork,su=ctf \
    EXEC:"python3 app.py",stderr
