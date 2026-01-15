# syntax=docker/dockerfile:1

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive


RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/*

# 1. 创建用户
RUN userdel -r $(getent passwd 1000 | cut -d: -f1) 2>/dev/null || true \
    && useradd -m -u 1000 -s /bin/bash ctf
# 2. 【核心修改】部署文件
# 解释：将本地当前目录下的 webapp 文件夹，复制到容器的 /home/ctf/webapp 路径中
# Docker 会自动创建 webapp 这个目录
COPY webapp /home/ctf/webapp
# 3. 部署启动脚本
COPY start.sh /start.sh
RUN chmod +x /start.sh
# 4. 设置权限
RUN chown -R ctf:ctf /home/ctf/ \
    && chown root:root /home/ctf/webapp/check.py \
    && chown root:root /home/ctf/webapp/Uni_check \
    && chmod 555 /home/ctf/webapp/check.py \
    && chmod 555 /home/ctf/webapp/Uni_check
# 5. 暴露端口 
EXPOSE 8888
# 6. 启动
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]

