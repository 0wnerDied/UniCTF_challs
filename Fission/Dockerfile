# syntax=docker/dockerfile:1

# Build stage
FROM archlinux:latest AS build
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    clang lld make ca-certificates \
    && pacman -Scc --noconfirm && \
    rm -rf /var/cache/pacman/pkg/*
WORKDIR /src
COPY Makefile vuln.c ./
RUN make

# Runtime stage
FROM archlinux:latest

# Install socat for TCP service
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
    socat ca-certificates \
    && pacman -Scc --noconfirm && \
    rm -rf /var/cache/pacman/pkg/*

ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini-static /usr/bin/tini
RUN chmod +x /usr/bin/tini

# Create user and directories
RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /usr/sbin/nologin ctf \
    && mkdir -p /home/ctf \
    && chown -R root:ctf /home/ctf \
    && chmod 750 /home/ctf

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
