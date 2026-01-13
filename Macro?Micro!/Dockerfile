# syntax=docker/dockerfile:1

# Build stage
FROM ubuntu:25.10 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang lld make ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile vuln.cpp ./
RUN make

# Runtime stage
FROM ubuntu:25.10
ENV DEBIAN_FRONTEND=noninteractive

# Install socat for TCP service and tini as init
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# Create user and directories
RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /usr/sbin/nologin ctf \
    && mkdir -p /home/ctf \
    && chown -R root:ctf /home/ctf

# Copy binary
COPY --from=build /src/vuln /home/ctf/vuln

# Add entrypoint script
COPY start.sh /start.sh
RUN chmod 755 /start.sh \
    && chmod 750 /home/ctf/vuln \
    && chown root:ctf /home/ctf/vuln

# Expose service port
EXPOSE 9999

# Use tini as init system to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
