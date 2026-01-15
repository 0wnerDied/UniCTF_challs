#!/bin/sh
set -u

# 1. 处理 Flag
# 兼容各种平台的 Flag 环境变量
FLAG_VALUE="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG_VALUE" ]; then
    echo "Warning: No flag provided, using placeholder" >&2
    FLAG_VALUE="flag{test_flag_placeholder}"
fi

# 固定 Flag 路径为 /flag
FLAG_FILE="/flag"

# 写入 Flag
# 注意：这里赋予了 644 权限，如果是 root 权限运行的 daemon 读取，600 也可以
# 如果是 setuid 或者 ctf 用户运行，要确保 ctf 用户能读到
echo "$FLAG_VALUE" > "${FLAG_FILE}"
chown root:root "${FLAG_FILE}"
chmod 644 "${FLAG_FILE}"

# 为了安全，清空环境变量
export FLAG=""
export GZCTF_FLAG=""
export DASFLAG=""
export FLAG_VALUE=""

# 2. 设置资源限制 (防止 fork 炸弹或内存耗尽)
ulimit -c 0           # 禁止核心转储
ulimit -n 65535       # 文件描述符限制
ulimit -u 1024        # 进程数限制

# 3. 启动服务 (看门狗模式)
echo "[+] Starting redis-server watchdog..."

# 切换到 ctf 用户主目录
cd /home/ctf

# 死循环，确保服务崩了自动拉起
while true; do
    echo "[*] Starting service instance..."
    
    # 使用 su 切换到 ctf 用户运行，提升安全性
    # 如果你的 redis-server 必须以 root 运行（不推荐），去掉 su -s /bin/sh ctf -c
    su -s /bin/sh ctf -c "/home/ctf/redis-server --protected-mode no"
    
    RET=$?
    echo "[-] Service crashed with exit code $RET. Restarting in 1 second..."
    sleep 1
done

