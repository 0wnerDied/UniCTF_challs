# syntax=docker/dockerfile:1

FROM kalilinux/kali-rolling

# 基础环境设置
ENV DEBIAN_FRONTEND=noninteractive

# 安装基础工具
# (注意：sid 更新频繁，apt-get update 是必须的)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 创建用户
RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /bin/bash ctf \
    && mkdir -p /home/ctf

# 复制二进制文件
COPY forum /home/ctf/forum
COPY libc.so.6 /home/ctf/libc.so.6
COPY ld-linux-x86-64.so.2 /home/ctf/ld-linux-x86-64.so.2
COPY start.sh /start.sh

# 权限设置
RUN chown -R ctf:ctf /home/ctf \
    && chmod 755 /home/ctf/* \
    && chmod +x /start.sh
WORKDIR /home/ctf

# 暴露端口
EXPOSE 8888

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
