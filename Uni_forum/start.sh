#!/bin/bash
set -eu

# --- 1. Flag 处理部分 ---
FLAG_VALUE="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG_VALUE" ]; then
    echo "Warning: No flag provided, using placeholder"
    FLAG_VALUE="flag{test_flag_placeholder}"
fi

# 固定 flag 位置为 /flag
echo "$FLAG_VALUE" > /flag
chmod 644 /flag
chown root:root /flag

# 清理环境变量
unset FLAG GZCTF_FLAG DASFLAG FLAG_VALUE flag

# --- 2. 启动服务循环 (崩溃自动重启) ---
echo "Starting forum service loop..."

# 切换到 ctf 用户运行，避免 root 运行带来的风险
# 使用 su - ctf -c "命令" 来切换用户
cd /home/ctf/
while true; do
    echo "[+] Starting forum binary..."
    
    # 关键点：
    # 1. 使用 su 切换到 ctf 用户运行
    # 2. 如果程序崩了，这个命令会结束，脚本会继续执行
    # 3. || true 确保即使程序报错退出，脚本也不会因为 set -e 而退出
    su ctf -c "./forum" || true
    
    echo "[-] Service crashed or stopped. Restarting in 1 second..."
    sleep 1
done
