## Lua 5.1 底层数据结构

## 核心类型定义

### 1. 通用值结构 (TValue)

```c
/*
** Union of all Lua values
*/
typedef union {
  GCObject *gc;    // 可垃圾回收对象（string, table, function, userdata, thread）
  void *p;         // light userdata
  lua_Number n;    // 数字 (默认是 double)
  int b;           // 布尔值
} Value;

/*
** Tagged Values
*/
typedef struct lua_TValue {
  Value value;     // 实际值
  int tt;          // 类型标记 (type tag)
} TValue;
```

### 2. 类型标记常量

```c
#define LUA_TNIL           0
#define LUA_TBOOLEAN       1
#define LUA_TLIGHTUSERDATA 2
#define LUA_TNUMBER        3
#define LUA_TSTRING        4
#define LUA_TTABLE         5
#define LUA_TFUNCTION      6
#define LUA_TUSERDATA      7
#define LUA_TTHREAD        8
```

---

## 各类型详细结构

### 3. GC 对象通用头部

```c
/*
** Common Header for all collectable objects
*/
typedef struct GCheader {
  CommonHeader;
} GCheader;

#define CommonHeader \
  GCObject *next;      /* 链表指向下一个 GC 对象 */ \
  lu_byte tt;          /* 对象类型 */ \
  lu_byte marked       /* GC 标记 */
```

---

### 4. 字符串 (TString)

```c
/*
** String headers for string table
*/
typedef union TString {
  L_Umaxalign dummy;  // 内存对齐
  struct {
    CommonHeader;
    lu_byte reserved;  // 是否为保留字（关键字）
    unsigned int hash; // 哈希值（用于字符串驻留）
    size_t len;        // 字符串长度
  } tsv;
} TString;

// 获取实际字符串内容的宏（紧跟在结构体后面）
#define getstr(ts)  cast(const char *, (ts) + 1)
```

**内存布局：**
```
+----------------+-------------------+
|  TString 头部  |  实际字符串内容\0  |
+----------------+-------------------+
```

---

### 5. 表/字典 (Table)

```c
/*
** Tables
*/
typedef struct Table {
  CommonHeader;
  lu_byte flags;           // 元方法缓存标记（1=该元方法不存在）
  lu_byte lsizenode;       // 哈希部分大小 log2(size)
  struct Table *metatable; // 元表指针
  TValue *array;           // 数组部分
  Node *node;              // 哈希表部分
  Node *lastfree;          // 哈希表空闲位置指针
  GCObject *gclist;        // GC 列表
  int sizearray;           // 数组部分大小
} Table;

/*
** Node for Hash part
*/
typedef struct Node {
  TValue i_val;   // 值
  TKey i_key;     // 键
} Node;

typedef union TKey {
  struct {
    Value value;    // 键的值
    int tt;         // 键的类型
    struct Node *next;  // 哈希冲突链表
  } nk;
  TValue tvk;
} TKey;
```

**表的结构图：**
```
Table
├── array[] (数组部分，整数索引 1,2,3...)
│   ├── [1] -> TValue
│   ├── [2] -> TValue
│   └── ...
│
└── node[] (哈希部分，处理非连续整数和其他类型键)
    ├── Node[0]: {key, value, next}
    ├── Node[1]: {key, value, next}
    └── ...
```

---

### 6. 函数 (Closure)

```c
/*
** Closures
*/

// 闭包通用头部
#define ClosureHeader \
  CommonHeader; \
  lu_byte isC;        /* 是否是 C 函数 */ \
  lu_byte nupvalues;  /* upvalue 数量 */ \
  GCObject *gclist; \
  struct Table *env   /* 环境表 */

// C 闭包
typedef struct CClosure {
  ClosureHeader;
  lua_CFunction f;           // C 函数指针
  TValue upvalue[1];         // upvalues（柔性数组）
} CClosure;

// Lua 闭包
typedef struct LClosure {
  ClosureHeader;
  struct Proto *p;           // 函数原型
  UpVal *upvals[1];          // upvalue 指针数组（柔性数组）
} LClosure;

// 统一闭包类型
typedef union Closure {
  CClosure c;
  LClosure l;
} Closure;
```

---

### 7. 函数原型 (Proto)

```c
/*
** Function Prototypes
*/
typedef struct Proto {
  CommonHeader;
  TValue *k;              // 常量表
  Instruction *code;      // 字节码指令数组
  struct Proto **p;       // 内嵌函数原型
  int *lineinfo;          // 行号信息（调试用）
  struct LocVar *locvars; // 局部变量信息（调试用）
  TString **upvalues;     // upvalue 名称（调试用）
  TString *source;        // 源文件名
  int sizeupvalues;       // upvalue 数量
  int sizek;              // 常量数量
  int sizecode;           // 字节码数量
  int sizelineinfo;
  int sizep;              // 内嵌函数数量
  int sizelocvars;
  int linedefined;        // 函数定义起始行
  int lastlinedefined;    // 函数定义结束行
  GCObject *gclist;
  lu_byte nups;           // upvalue 数量
  lu_byte numparams;      // 参数数量
  lu_byte is_vararg;      // 是否有可变参数
  lu_byte maxstacksize;   // 最大栈空间
} Proto;
```

---

### 8. UpValue

```c
/*
** Upvalues
*/
typedef struct UpVal {
  CommonHeader;
  TValue *v;  // 指向栈上的值（open）或下面的 u.value（closed）
  union {
    TValue value;       // upvalue 关闭后的存储位置
    struct {
      struct UpVal *prev;  // 双向链表
      struct UpVal *next;
    } l;
  } u;
} UpVal;
```

**UpValue 状态图：**
```
Open (函数还在执行):
  UpVal.v -> 指向栈上的变量

Closed (函数返回后):
  UpVal.v -> 指向 UpVal.u.value (值被复制到这里)
```

---

### 9. Userdata

```c
/*
** Userdata
*/
typedef union Udata {
  L_Umaxalign dummy;  // 内存对齐
  struct {
    CommonHeader;
    struct Table *metatable;  // 元表
    struct Table *env;        // 环境表
    size_t len;               // 数据长度
  } uv;
} Udata;

// 实际数据紧跟在 Udata 结构后面
#define getudatamem(u)  cast(char *, (u) + 1)
```

---

### 10. 线程/协程 (lua_State)

```c
/*
** `per thread' state
*/
struct lua_State {
  CommonHeader;
  lu_byte status;              // 协程状态
  StkId top;                   // 栈顶指针
  StkId base;                  // 当前函数的栈基址
  global_State *l_G;           // 全局状态（所有线程共享）
  CallInfo *ci;                // 当前调用信息
  const Instruction *savedpc;  // 保存的 PC 指针
  StkId stack_last;            // 栈末端
  StkId stack;                 // 栈数组
  CallInfo *end_ci;            // 调用信息数组末端
  CallInfo *base_ci;           // 调用信息数组
  int stacksize;               // 栈大小
  int size_ci;                 // 调用信息数组大小
  unsigned short nCcalls;      // C 调用嵌套深度
  unsigned short baseCcalls;   // 
  lu_byte hookmask;            // 钩子掩码
  lu_byte allowhook;           // 是否允许钩子
  int basehookcount;
  int hookcount;
  lua_Hook hook;               // 钩子函数
  TValue l_gt;                 // 全局表
  TValue env;                  // 环境
  GCObject *openupval;         // open upvalue 链表
  GCObject *gclist;
  struct lua_longjmp *errorJmp; // 错误跳转点
  ptrdiff_t errfunc;           // 错误处理函数
};
```

---

## 类型结构总览图

```
                        TValue
                    ┌─────┴─────┐
                    │  value    │  (Value union)
                    │  tt       │  (type tag)
                    └───────────┘
                          │
        ┌─────┬─────┬─────┼─────┬─────┬─────┬─────┐
        ▼     ▼     ▼     ▼     ▼     ▼     ▼     ▼
       nil  bool  number  light  GCObject
                         udata      │
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
          TString               Table               Closure
       ┌─────────┐          ┌─────────┐          ┌────┴────┐
       │CommonHdr│          │CommonHdr│          │         │
       │reserved │          │flags    │       CClosure  LClosure
       │hash     │          │metatable│          │         │
       │len      │          │array[]  │          │      Proto
       │[chars]  │          │node[]   │          │
       └─────────┘          └─────────┘          │
                                              UpVal
              ┌─────────────────────┐
              ▼                     ▼
           Udata              lua_State
       ┌─────────┐          ┌─────────┐
       │CommonHdr│          │CommonHdr│
       │metatable│          │stack    │
       │env      │          │ci       │
       │len      │          │l_G      │
       │[data]   │          │...      │
       └─────────┘          └─────────┘
```

---

## 关键设计要点

| 特性 | 实现方式 |
|------|---------|
| **类型判断** | TValue.tt 标记 |
| **字符串驻留** | 全局哈希表 + TString.hash |
| **表的混合结构** | array（数组部分）+ node（哈希部分）|
| **闭包** | LClosure + UpVal 链表 |
| **GC 管理** | CommonHeader 链表 + 标记清除 |
| **协程** | 每个协程独立 lua_State，共享 global_State |
