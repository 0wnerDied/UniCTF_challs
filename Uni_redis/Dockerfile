# syntax=docker/dockerfile:1

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 安装基础工具，不再需要 build-essential 和 socat
# tini 用于作为 init 进程，防止僵尸进程
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# 创建用户 ctf
RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /usr/sbin/nologin ctf \
    && mkdir -p /home/ctf \
    && chown -R root:ctf /home/ctf

# 直接将同目录下的 redis-server 复制进去
COPY redis-server /home/ctf/redis-server

# 复制启动脚本
COPY start.sh /start.sh

# 设置权限
# start.sh 可执行
# redis-server 可执行且属主为 root，属组为 ctf
# /flag 这里预留位置，具体写入在 start.sh
RUN chmod 755 /start.sh \
    && chmod 750 /home/ctf/redis-server \
    && chown root:ctf /home/ctf/redis-server

# 暴露端口 (假设你的 redis-server 监听默认的 6379，如果不是请自行修改)
EXPOSE 6379

# 使用 tini 作为 init 进程
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]

