#!/bin/sh
set -eu

# ----------------------------------------------------------------
# 1. Flag 配置
# ----------------------------------------------------------------
FLAG_VALUE="${FLAG:-${GZCTF_FLAG:-${DASFLAG:-${flag:-}}}}"
if [ -z "$FLAG_VALUE" ]; then
    FLAG_VALUE="flag{test_flag_please_change_env}"
fi

# 写入 Flag
echo "$FLAG_VALUE" > /flag

# 权限设置：
# root:ctf 所有
# 440: root和ctf可读，其他人无权限，任何人(包括ctf)不可写
chown root:ctf /flag
chmod 440 /flag

# 清理变量
export FLAG=""
export GZCTF_FLAG=""
export DASFLAG=""
export flag=""

# ----------------------------------------------------------------
# 2. 启动服务
# ----------------------------------------------------------------
cd /home/ctf/webapp

echo "[*] Service starting..."

# 守护进程循环
while true; do
    # 以 ctf 用户身份运行
    # 由于 Dockerfile 里的设置，ctf 用户对当前目录只有只读/执行权限
    # 如果 Uni_check 尝试修改 check.py，会被系统拒绝 (Permission denied)
    su ctf -s /bin/bash -c "./Uni_check" || echo "[!] Process crashed with code $?"
    
    echo "[*] Restarting in 1 second..."
    sleep 1
done

