# syntax=docker/dockerfile:1

FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /usr/sbin/nologin ctf \
    && mkdir -p /home/ctf \
    && chown -R root:ctf /home/ctf \
    && chmod 750 /home/ctf

WORKDIR /home/ctf

# Copy files
COPY app.py .
COPY start.sh /start.sh

# Set permissions
RUN chmod 755 /start.sh \
    && chmod 750 /home/ctf/app.py \
    && chown root:ctf /home/ctf/app.py

# Expose service port
EXPOSE 9999

# Use tini as init system to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
