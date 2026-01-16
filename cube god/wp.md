# UniCTF - cube god

这道题是一个 2x2 魔方交互题，服务端每轮随机打乱魔方，只展示 6 个面中的 5 个面贴纸，要求在 1 秒内输入不超过 11 手的复原步骤，连续通过 100 轮才能拿到 flag。

---

## 分析

阅读 `app.py` 可以得到题目流程：

1. 每轮新建 `RubiksCube2x2`，并执行 `scramble(randint(114, 514))` 打乱。
2. 随机隐藏一个面，仅输出其余 5 个面的 2x2 贴纸。
3. 1 秒内输入一行 moves，必须在 `VALID` 集合中，且最多 11 步。
4. 验证方式：新建 `check_cube`，应用相同 scramble，再应用提交的 moves，要求最后状态 `is_solved()`。

因此，本题不是还原 scramble，而是从“打乱后的 5 面投影”直接恢复 solved。

**关键限制来自源码**：

- `ROUNDS = 100`，失败即退出。
- `MAX_MOVES = 11`，超过直接判错。
- `VALID` 的 move 集合与 2x2 face-turn metric 一致。
- `signal.alarm(1)` 强制 1 秒交互。

---

## 本地调试

在本地调试时显然可以绕过 1 秒时限。最简单的方式是在本地把 `signal.alarm(1)` 注释。随后先从数据结构入手：`RubiksCube2x2` 用 6 个 2x2 矩阵表示贴纸，`display()` 固定打印顺序并给出行列顺序。只要把“哪个角块贴在哪些面、哪个坐标”对齐，就能把 5 面投影还原成角块状态。此时先用 Python 写出可用解，再把逻辑迁移到 C++ 提速。

---

## 建模

2x2 没有棱块，只包含 8 个角块。一个状态可表示为：

- `cp`（corner permutation）：8 个角块在 8 个位置上的排列，状态数 $8!=40320$。
- `co`（corner orientation）：每个角块 3 种朝向，但有整体约束，状态数 $3^7=2187$。

因此角块朝向不变量为：

$$
\sum_{i=0}^{7} co[i] \equiv 0 \pmod 3
$$

2x2 的 God’s number 为 11，因此题目设定 `MAX_MOVES = 11` 正好要求“必须写完整求解器”。

---

## 从 `display()` 与 move 推断贴纸坐标与角块映射

`display()` 输出每个面的格式如下：

```
Face U:
+-----+
| a b |
| c d |
+-----+
```

因此面内坐标为：

- `(0,0)` 对应 a
- `(0,1)` 对应 b
- `(1,0)` 对应 c
- `(1,1)` 对应 d

接下来要把 8 个角块位置与三张贴纸的 `(面, r, c)` 对齐。基于 `move_U/move_D/...` 的旋转逻辑可得到如下映射：

| 角块位置 | 三面顺序（定义朝向） | U/D 面坐标 | 其他两面坐标 |
|---|---|---|---|
| URF | (U,R,F) | U(1,1) | R(0,0), F(0,1) |
| UFL | (U,F,L) | U(1,0) | F(0,0), L(0,1) |
| ULB | (U,L,B) | U(0,0) | L(0,0), B(0,1) |
| UBR | (U,B,R) | U(0,1) | B(0,0), R(0,1) |
| DFR | (D,F,R) | D(0,1) | F(1,1), R(1,0) |
| DLF | (D,L,F) | D(0,0) | L(1,1), F(1,0) |
| DBL | (D,B,L) | D(1,0) | B(1,1), L(1,0) |
| DRB | (D,R,B) | D(1,1) | R(1,1), B(1,0) |

---

## 从 5 面重建 `cp/co`

### 角块 ID 约定

角块颜色集合为：

```
0: (U,R,F)
1: (U,F,L)
2: (U,L,B)
3: (U,B,R)
4: (D,F,R)
5: (D,L,F)
6: (D,B,L)
7: (D,R,B)
```

### 局部约束

每个位置有 3 张贴纸，对应三面顺序 `CORNER_FACES[pos]`。如果某个面被隐藏，则对应贴纸未知。把已知颜色集合记作 `seen`，候选角块必须满足“颜色集合包含 `seen`”。这样能大幅缩小候选集合。

### 全局 DFS 回溯

仅用局部集合还不够，需要全局约束：

- 8 个角块不能重复。
- 每个候选角块需要尝试 3 种朝向。

为了提速，按“候选数少优先、未知数少优先”排序后回溯。深度只有 8，分支非常小。

### 朝向定义与匹配

`co[pos]` 定义为：按 `CORNER_FACES[pos]` 顺序，U/D 贴纸落在第几个槽位（0/1/2）。

设角块基准顺序为 `base=(x0,x1,x2)`，其中第 0 个必为 U 或 D。要让 U/D 贴纸出现在 `twist` 位置，可以做循环移位：

$$
cols[i] = base[(i - twist)\bmod 3]
$$

然后逐槽位匹配已知颜色即可。

### 朝向和的约束

DFS 结束时必须满足：

$$
\sum co[i] \equiv 0 \pmod 3
$$

或者直接让第 8 个角块朝向由前 7 个决定，保证合法性。

---

## Move Table：从贴纸置换推导角块转移

为了连续解 100 轮，每轮在 1 秒内完成，必须预计算表。

### 24 贴纸编号

按面顺序 U/D/F/B/L/R，每个面 2x2 展平成 4 个编号，总计 24 个贴纸：

- U: 0..3
- D: 4..7
- F: 8..11
- B: 12..15
- L: 16..19
- R: 20..23

定义：

$$
facelet\_idx(face,r,c)=base(face)+r\cdot2+c
$$

### 计算 `perm24`

构造一个贴纸级魔方，初始化每个贴纸为自己的编号。对每个 move 执行一次，得到置换 `perm24`，并约定：

> `new[i] = old[perm24[i]]`

方向必须要统一，否则后续推导会反。

### 推导 corner 置换与朝向变化

固定每个角块位置的 3 个贴纸索引（按 `CORNER_FACES` 顺序）。对每个 move：

1. `moved24 = apply_perm24(solved24, perm24)`。
2. 取 `new_pos` 的 3 个贴纸组成 `triple`，其集合必对应某个 `old_pos`。
3. 用三贴纸集合的 bitmask 快速定位 `old_pos`。
4. `twist_of_corner(triple)` 通过“U/D 贴纸落在 triple 中的位置”给出朝向增量。

这样得到 `MOVE_CP` 和 `MOVE_CO` 转移表。

---

## Pruning Table：单空间最短距离

对 `cp` 空间（40320）与 `co` 空间（2187）分别 BFS，得到：

- `DIST_CP[cp_idx]`
- `DIST_CO[co_idx]`

它们是完整状态的下界，用于启发式剪枝。第一次生成耗时较长，所以写入缓存文件方便调用（这里我选择 `cube2x2_tables.bin`），后续直接加载即可。

---

## IDA*：深度不超过 11 的搜索

状态为 `(cp_idx, co_idx)`。启发式使用：

$$
h=\max\left(d_{cp}, d_{co}, \left\lfloor\frac{d_{cp}+d_{co}}{2}\right\rfloor\right)
$$

迭代加深 DFS，直到深度 ≤ 11。剪枝策略：

- 不连续转同一面。
- 不走上一手的逆操作。

这样搜索节点数就能大幅下降。

---

## 先写 Python 解，再迁移 C++

### Python 版本

Python 版本用于验证思路：

1. 解析 5 个面贴纸。
2. 用 DFS 重建 `cp/co`。
3. 利用预计算的 move/pruning 表进行 IDA* 求解。

该版本重点在正确性与可读性，保证每一轮都能给出 ≤ 11 的解即可，耗时在十几秒内都可以接受。

### C++ 版本

将 Python 逻辑等价迁移到 C++，保持相同的状态定义与启发式：

- 仍然构造 `perm24`，推导 `MOVE_CP/MOVE_CO`。
- 仍然 BFS 构建 `DIST_CP/DIST_CO`。
- 仍然用 IDA* 深度 ≤ 11 搜索。

为减少启动开销，C++ 版本将表缓存到二进制文件，并实现一个轻量协议：`BEGIN ... END` 输入 5 面，输出一行解。这样在交互脚本中可以常驻调用，避免每轮重启。

---

## exp

Python 交互脚本：

```python
#!/usr/bin/env python3
from pwn import *
import time

context.log_level = "info"


# ---------- parse server output: 5 face blocks ----------
def recv_face_block(io):
    line = io.recvline().decode()
    if not line.startswith("Face "):
        raise EOFError("Unexpected output: " + line)
    face = line.split()[1].strip(":")
    io.recvline()  # +-----+
    row1 = io.recvline().decode().strip()
    row2 = io.recvline().decode().strip()
    io.recvline()  # +-----+

    def parse_row(s):
        return s.strip("|").strip().split()

    mat = [parse_row(row1), parse_row(row2)]  # 2x2 strings
    return face, mat


def mat_to_tokens(mat):
    # mat: [[a,b],[c,d]]
    return mat[0][0], mat[0][1], mat[1][0], mat[1][1]


# ---------- bridge to C++ solver ----------
class SolverBridge:
    def __init__(self, path="./solver"):
        self.p = process([path])

    def solve_from_partial(self, partial):
        """
        partial: dict face(str)-> mat([[..],[..]])
        """
        self.p.sendline(b"BEGIN")
        for face, mat in partial.items():
            a, b, c, d = mat_to_tokens(mat)
            line = f"{face} {a} {b} {c} {d}"
            self.p.sendline(line.encode())
        self.p.sendline(b"END")
        sol = self.p.recvline().decode().strip()
        return sol


# ---------- per round ----------
def solve_round(io, bridge):
    partial = {}
    for _ in range(5):
        f, mat = recv_face_block(io)
        partial[f] = mat

    io.recvuntil(b"Enter your solution:\n")
    sol = bridge.solve_from_partial(partial)
    if not sol:
        sol = "U"
    return sol


io = remote("localhost", 9999)
# io = process(["python3", "app.py"])

bridge = SolverBridge("./solver")

io.recvuntil(b"get the flag!\n")

t_all = time.time()
for rnd in range(100):
    io.recvuntil(b"=== Round ")
    io.recvline()
    io.recvline()

    t0 = time.time()
    sol = solve_round(io, bridge)
    dt = (time.time() - t0) * 1000.0
    log.info(f"Round {rnd+1}/100 sol_len={len(sol.split())} time={dt:.2f}ms")

    io.sendline(sol.encode())

    line = io.recvline().decode(errors="ignore")
    if "[-]" in line:
        log.error("Rejected: " + line)
        log.error(io.recvall().decode(errors="ignore"))
        exit(1)
    io.recvline()

log.success(f"Done in {time.time()-t_all:.2f}s")
io.interactive()
```

C++ 求解器：

```cpp
#include <bits/stdc++.h>

using namespace std;

// ============================================================================
// 2x2 solver core (corner-only) + simple stdin/stdout protocol
//
// Protocol (one case):
//   BEGIN
//   U a b c d
//   F a b c d
//   ... (5 faces total, order arbitrary)
//   END
// Outputs one line: "U R2 F' ..." (or "U" fallback)
//
// This build is mac/arm64 safe:
// - NO unordered_map<string,int> (avoids std::hash<string> -> __hash_memory link issues)
// - clang-friendly array init
// ============================================================================

static const char *CACHE_FILE = "cube2x2_tables.bin";

enum CornerPos {
	URF = 0,
	UFL = 1,
	ULB = 2,
	UBR = 3,
	DFR = 4,
	DLF = 5,
	DBL = 6,
	DRB = 7
};

struct RC {
	int r, c;
};

// Corner cubies by color set
static const array<array<char, 3>, 8> CUBIES = { { { { 'U', 'R', 'F' } },
						   { { 'U', 'F', 'L' } },
						   { { 'U', 'L', 'B' } },
						   { { 'U', 'B', 'R' } },
						   { { 'D', 'F', 'R' } },
						   { { 'D', 'L', 'F' } },
						   { { 'D', 'B', 'L' } },
						   { { 'D', 'R', 'B' } } } };

// For each position, the faces order we use for orientation definition
static const array<array<char, 3>, 8> CORNER_FACES = CUBIES;

// MUST match server printed facelet layout (r,c).
static const array<unordered_map<char, RC>, 8> CORNER_FACELETS = [] {
	array<unordered_map<char, RC>, 8> m;
	m[URF] = { { { 'U', { 1, 1 } }, { 'R', { 0, 0 } }, { 'F', { 0, 1 } } } };
	m[UFL] = { { { 'U', { 1, 0 } }, { 'F', { 0, 0 } }, { 'L', { 0, 1 } } } };
	m[ULB] = { { { 'U', { 0, 0 } }, { 'L', { 0, 0 } }, { 'B', { 0, 1 } } } };
	m[UBR] = { { { 'U', { 0, 1 } }, { 'B', { 0, 0 } }, { 'R', { 0, 1 } } } };
	m[DFR] = { { { 'D', { 0, 1 } }, { 'F', { 1, 1 } }, { 'R', { 1, 0 } } } };
	m[DLF] = { { { 'D', { 0, 0 } }, { 'L', { 1, 1 } }, { 'F', { 1, 0 } } } };
	m[DBL] = { { { 'D', { 1, 0 } }, { 'B', { 1, 1 } }, { 'L', { 1, 0 } } } };
	m[DRB] = { { { 'D', { 1, 1 } }, { 'R', { 1, 1 } }, { 'B', { 1, 0 } } } };
	return m;
}();

// Move list MUST match indices used later
static const vector<string> MOVES = { "U", "U'", "U2", "D", "D'", "D2",
				      "F", "F'", "F2", "B", "B'", "B2",
				      "L", "L'", "L2", "R", "R'", "R2" };

// Move indices by face
static const array<array<int, 3>, 6> MOVES_BY_FACE_IDX = {
	{ /* U */ { 0, 2, 1 },
	  /* D */ { 3, 5, 4 },
	  /* F */ { 6, 8, 7 },
	  /* B */ { 9, 11, 10 },
	  /* L */ { 12, 14, 13 },
	  /* R */ { 15, 17, 16 } }
};

static inline string inv_move(const string &m)
{
	if (!m.empty() && m.back() == '2')
		return m;
	if (!m.empty() && m.back() == '\'')
		return m.substr(0, m.size() - 1);
	return m + "'";
}
static inline bool is_inverse(const string &a, const string &b)
{
	return inv_move(a) == b;
}

// Factorials for perm index
static const int FACT[9] = { 1, 1, 2, 6, 24, 120, 720, 5040, 40320 };

// perm <-> idx (Lehmer code)
static inline int perm_to_idx(const array<int, 8> &p)
{
	int idx = 0;
	for (int i = 0; i < 8; i++) {
		int smaller = 0;
		for (int j = i + 1; j < 8; j++)
			if (p[j] < p[i])
				smaller++;
		idx += smaller * FACT[7 - i];
	}
	return idx;
}
static inline array<int, 8> idx_to_perm(int idx)
{
	array<int, 8> p{};
	array<int, 8> elems{};
	for (int i = 0; i < 8; i++)
		elems[i] = i;
	int n = 8;
	for (int i = 0; i < 8; i++) {
		int f = FACT[7 - i];
		int q = idx / f;
		idx %= f;
		p[i] = elems[q];
		for (int k = q; k < n - 1; k++)
			elems[k] = elems[k + 1];
		n--;
	}
	return p;
}

// orientation <-> idx (base-3, last determined)
static inline int ori_to_idx(const array<int, 8> &co)
{
	int idx = 0;
	for (int i = 0; i < 7; i++)
		idx = idx * 3 + co[i];
	return idx;
}
static inline array<int, 8> idx_to_ori(int idx)
{
	array<int, 8> co{};
	int s = 0;
	for (int i = 6; i >= 0; i--) {
		co[i] = idx % 3;
		idx /= 3;
		s += co[i];
	}
	co[7] = (3 - (s % 3)) % 3;
	return co;
}

// ---------------------------------------------------------------------------
// Sticker-level cube (for generating perm24 of each move)
// ---------------------------------------------------------------------------
struct StickerCube2x2 {
	array<array<array<int, 2>, 2>, 6> f;

	static int fid(char c)
	{
		return (int)string("UDFBLR").find(c);
	}
	StickerCube2x2()
	{
		for (int k = 0; k < 6; k++)
			for (int r = 0; r < 2; r++)
				for (int c = 0; c < 2; c++)
					f[k][r][c] = k;
	}

	// clang-friendly (no nested brace init that clang dislikes)
	static array<array<int, 2>, 2> rot_cw(const array<array<int, 2>, 2> &a)
	{
		array<array<int, 2>, 2> o{};
		o[0][0] = a[1][0];
		o[0][1] = a[0][0];
		o[1][0] = a[1][1];
		o[1][1] = a[0][1];
		return o;
	}
	static array<array<int, 2>, 2> rot_ccw(const array<array<int, 2>, 2> &a)
	{
		array<array<int, 2>, 2> o{};
		o[0][0] = a[0][1];
		o[0][1] = a[1][1];
		o[1][0] = a[0][0];
		o[1][1] = a[1][0];
		return o;
	}

	array<int, 2> get_row(int id, int r) const
	{
		return { f[id][r][0], f[id][r][1] };
	}
	void set_row(int id, int r, const array<int, 2> &v)
	{
		f[id][r][0] = v[0];
		f[id][r][1] = v[1];
	}
	array<int, 2> get_col(int id, int c) const
	{
		return { f[id][0][c], f[id][1][c] };
	}
	void set_col(int id, int c, const array<int, 2> &v)
	{
		f[id][0][c] = v[0];
		f[id][1][c] = v[1];
	}

	void move_U(bool p)
	{
		int U = 0, F = 2, B = 3, L = 4, R = 5;
		if (p) {
			f[U] = rot_ccw(f[U]);
			auto t = get_row(F, 0);
			set_row(F, 0, get_row(L, 0));
			set_row(L, 0, get_row(B, 0));
			set_row(B, 0, get_row(R, 0));
			set_row(R, 0, t);
		} else {
			f[U] = rot_cw(f[U]);
			auto t = get_row(F, 0);
			set_row(F, 0, get_row(R, 0));
			set_row(R, 0, get_row(B, 0));
			set_row(B, 0, get_row(L, 0));
			set_row(L, 0, t);
		}
	}
	void move_D(bool p)
	{
		int D = 1, F = 2, B = 3, L = 4, R = 5;
		if (p) {
			f[D] = rot_ccw(f[D]);
			auto t = get_row(F, 1);
			set_row(F, 1, get_row(R, 1));
			set_row(R, 1, get_row(B, 1));
			set_row(B, 1, get_row(L, 1));
			set_row(L, 1, t);
		} else {
			f[D] = rot_cw(f[D]);
			auto t = get_row(F, 1);
			set_row(F, 1, get_row(L, 1));
			set_row(L, 1, get_row(B, 1));
			set_row(B, 1, get_row(R, 1));
			set_row(R, 1, t);
		}
	}
	void move_F(bool p)
	{
		int U = 0, D = 1, F = 2, L = 4, R = 5;
		if (p) {
			f[F] = rot_ccw(f[F]);
			auto t = get_row(U, 1);
			set_row(U, 1, get_col(R, 0));
			auto d0 = get_row(D, 0);
			set_col(R, 0, { d0[1], d0[0] });
			set_row(D, 0, get_col(L, 1));
			set_col(L, 1, { t[1], t[0] });
		} else {
			f[F] = rot_cw(f[F]);
			auto t = get_row(U, 1);
			auto lc = get_col(L, 1);
			set_row(U, 1, { lc[1], lc[0] });
			set_col(L, 1, get_row(D, 0));
			auto rc = get_col(R, 0);
			set_row(D, 0, { rc[1], rc[0] });
			set_col(R, 0, t);
		}
	}
	void move_B(bool p)
	{
		int U = 0, D = 1, B = 3, L = 4, R = 5;
		if (p) {
			f[B] = rot_ccw(f[B]);
			auto t = get_row(U, 0);
			auto lc = get_col(L, 0);
			set_row(U, 0, { lc[1], lc[0] });
			set_col(L, 0, get_row(D, 1));
			auto rc = get_col(R, 1);
			set_row(D, 1, { rc[1], rc[0] });
			set_col(R, 1, t);
		} else {
			f[B] = rot_cw(f[B]);
			auto t = get_row(U, 0);
			set_row(U, 0, get_col(R, 1));
			auto d1 = get_row(D, 1);
			set_col(R, 1, { d1[1], d1[0] });
			set_row(D, 1, get_col(L, 0));
			set_col(L, 0, { t[1], t[0] });
		}
	}
	void move_L(bool p)
	{
		int U = 0, D = 1, F = 2, B = 3, L = 4;
		if (p) {
			f[L] = rot_ccw(f[L]);
			auto t = get_col(U, 0);
			set_col(U, 0, get_col(F, 0));
			set_col(F, 0, get_col(D, 0));
			auto bc = get_col(B, 1);
			set_col(D, 0, { bc[1], bc[0] });
			set_col(B, 1, { t[1], t[0] });
		} else {
			f[L] = rot_cw(f[L]);
			auto t = get_col(U, 0);
			auto bc = get_col(B, 1);
			set_col(U, 0, { bc[1], bc[0] });
			auto dc = get_col(D, 0);
			set_col(B, 1, { dc[1], dc[0] });
			set_col(D, 0, get_col(F, 0));
			set_col(F, 0, t);
		}
	}
	void move_R(bool p)
	{
		int U = 0, D = 1, F = 2, B = 3, R = 5;
		if (p) {
			f[R] = rot_ccw(f[R]);
			auto t = get_col(U, 1);
			auto bc = get_col(B, 0);
			set_col(U, 1, { bc[1], bc[0] });
			auto dc = get_col(D, 1);
			set_col(B, 0, { dc[1], dc[0] });
			set_col(D, 1, get_col(F, 1));
			set_col(F, 1, t);
		} else {
			f[R] = rot_cw(f[R]);
			auto t = get_col(U, 1);
			set_col(U, 1, get_col(F, 1));
			set_col(F, 1, get_col(D, 1));
			auto bc = get_col(B, 0);
			set_col(D, 1, { bc[1], bc[0] });
			set_col(B, 0, { t[1], t[0] });
		}
	}

	void apply_move(const string &m)
	{
		if (!m.empty() && m.back() == '2') {
			string b = m.substr(0, m.size() - 1);
			apply_move(b);
			apply_move(b);
			return;
		}
		bool prime = (!m.empty() && m.back() == '\'');
		char face = m[0];
		switch (face) {
		case 'U':
			move_U(prime);
			break;
		case 'D':
			move_D(prime);
			break;
		case 'F':
			move_F(prime);
			break;
		case 'B':
			move_B(prime);
			break;
		case 'L':
			move_L(prime);
			break;
		case 'R':
			move_R(prime);
			break;
		default:
			break;
		}
	}
};

// facelet indexing for 24 stickers (U D F B L R each 2x2)
static inline int facelet_idx(char face, int r, int c)
{
	int base = 0;
	switch (face) {
	case 'U':
		base = 0;
		break;
	case 'D':
		base = 4;
		break;
	case 'F':
		base = 8;
		break;
	case 'B':
		base = 12;
		break;
	case 'L':
		base = 16;
		break;
	case 'R':
		base = 20;
		break;
	default:
		base = 0;
		break;
	}
	return base + (r * 2 + c);
}

// which 3 stickers form each corner position (in CORNER_FACES order)
static const array<array<int, 3>, 8> CORNER_FACELETS_IDX = {
	{ { { facelet_idx('U', 1, 1), facelet_idx('R', 0, 0),
	      facelet_idx('F', 0, 1) } },
	  { { facelet_idx('U', 1, 0), facelet_idx('F', 0, 0),
	      facelet_idx('L', 0, 1) } },
	  { { facelet_idx('U', 0, 0), facelet_idx('L', 0, 0),
	      facelet_idx('B', 0, 1) } },
	  { { facelet_idx('U', 0, 1), facelet_idx('B', 0, 0),
	      facelet_idx('R', 0, 1) } },
	  { { facelet_idx('D', 0, 1), facelet_idx('F', 1, 1),
	      facelet_idx('R', 1, 0) } },
	  { { facelet_idx('D', 0, 0), facelet_idx('L', 1, 1),
	      facelet_idx('F', 1, 0) } },
	  { { facelet_idx('D', 1, 0), facelet_idx('B', 1, 1),
	      facelet_idx('L', 1, 0) } },
	  { { facelet_idx('D', 1, 1), facelet_idx('R', 1, 1),
	      facelet_idx('B', 1, 0) } } }
};

// orientation delta: where the U/D sticker ends up (0/1/2)
static inline int twist_of_corner(const array<int, 3> &triple)
{
	for (int i = 0; i < 3; i++)
		if (0 <= triple[i] && triple[i] <= 7)
			return i;
	throw runtime_error("invalid corner triple");
}
static inline uint32_t mask3(const array<int, 3> &a)
{
	return (1u << a[0]) | (1u << a[1]) | (1u << a[2]);
}

// Move/pruning tables
static vector<array<uint16_t, 40320> > MOVE_CP; // [18][40320]
static vector<array<uint16_t, 2187> > MOVE_CO; // [18][2187]
static vector<uint8_t> DIST_CP; // [40320]
static vector<uint8_t> DIST_CO; // [2187]

// Build perm24 for a move: new[i] = old[perm[i]]
static vector<int> build_perm24_for_move(const string &m)
{
	StickerCube2x2 c;
	int idx = 0;
	for (char fc : string("UDFBLR")) {
		int id = StickerCube2x2::fid(fc);
		for (int r = 0; r < 2; r++)
			for (int col = 0; col < 2; col++)
				c.f[id][r][col] = idx++;
	}
	c.apply_move(m);
	vector<int> perm;
	perm.reserve(24);
	for (char fc : string("UDFBLR")) {
		int id = StickerCube2x2::fid(fc);
		for (int r = 0; r < 2; r++)
			for (int col = 0; col < 2; col++)
				perm.push_back(c.f[id][r][col]);
	}
	return perm;
}
static inline array<int, 24> apply_perm24(const array<int, 24> &st,
					  const vector<int> &perm)
{
	array<int, 24> out{};
	for (int i = 0; i < 24; i++)
		out[i] = st[perm[i]];
	return out;
}

static void build_corner_move_tables()
{
	MOVE_CP.assign(MOVES.size(), {});
	MOVE_CO.assign(MOVES.size(), {});

	array<uint32_t, 8> corner_masks{};
	for (int pos = 0; pos < 8; pos++)
		corner_masks[pos] = mask3(CORNER_FACELETS_IDX[pos]);

	vector<vector<int> > perm24_list;
	perm24_list.reserve(MOVES.size());
	for (auto &m : MOVES)
		perm24_list.push_back(build_perm24_for_move(m));

	array<int, 24> solved24{};
	for (int i = 0; i < 24; i++)
		solved24[i] = i;

	for (int mi = 0; mi < (int)MOVES.size(); mi++) {
		auto moved24 = apply_perm24(solved24, perm24_list[mi]);

		array<int, 8> newpos_to_oldpos{};
		array<int, 8> twist_delta_by_oldpos{};
		twist_delta_by_oldpos.fill(0);

		// Determine how corners permute + how orientation changes
		for (int new_pos = 0; new_pos < 8; new_pos++) {
			auto idxs = CORNER_FACELETS_IDX[new_pos];
			array<int, 3> triple = { moved24[idxs[0]],
						 moved24[idxs[1]],
						 moved24[idxs[2]] };
			uint32_t msk = mask3(triple);

			int old_pos = -1;
			for (int p = 0; p < 8; p++)
				if (corner_masks[p] == msk) {
					old_pos = p;
					break;
				}
			if (old_pos < 0)
				throw runtime_error("corner mask not found");

			newpos_to_oldpos[new_pos] = old_pos;
			twist_delta_by_oldpos[old_pos] =
				twist_of_corner(triple);
		}

		// cp transition table
		for (int pidx = 0; pidx < 40320; pidx++) {
			auto cp_state = idx_to_perm(pidx);
			array<int, 8> new_cp{};
			for (int new_pos = 0; new_pos < 8; new_pos++) {
				int old_pos = newpos_to_oldpos[new_pos];
				new_cp[new_pos] = cp_state[old_pos];
			}
			MOVE_CP[mi][pidx] = (uint16_t)perm_to_idx(new_cp);
		}

		// co transition table
		for (int oidx = 0; oidx < 2187; oidx++) {
			auto co_state = idx_to_ori(oidx);
			array<int, 8> new_co{};
			for (int new_pos = 0; new_pos < 8; new_pos++) {
				int old_pos = newpos_to_oldpos[new_pos];
				new_co[new_pos] =
					(co_state[old_pos] +
					 twist_delta_by_oldpos[old_pos]) %
					3;
			}
			// fix last corner orientation
			int s = 0;
			for (int i = 0; i < 7; i++)
				s += new_co[i];
			new_co[7] = (3 - (s % 3)) % 3;

			MOVE_CO[mi][oidx] = (uint16_t)ori_to_idx(new_co);
		}
	}
}

template <typename TMoveTable>
static vector<uint8_t> build_pruning(const TMoveTable &move_table, int size)
{
	vector<int16_t> dist(size, -1);
	deque<int> q;
	dist[0] = 0;
	q.push_back(0);

	while (!q.empty()) {
		int x = q.front();
		q.pop_front();
		int d = dist[x];
		for (int mi = 0; mi < (int)MOVES.size(); mi++) {
			int y = move_table[mi][x];
			if (dist[y] == -1) {
				dist[y] = d + 1;
				q.push_back(y);
			}
		}
	}

	vector<uint8_t> out(size);
	for (int i = 0; i < size; i++)
		out[i] = (dist[i] < 0) ? 255 : (uint8_t)dist[i];
	return out;
}

static bool load_cache()
{
	ifstream in(CACHE_FILE, ios::binary);
	if (!in)
		return false;

	uint32_t magic = 0, ver = 0;
	in.read((char *)&magic, 4);
	in.read((char *)&ver, 4);
	if (magic != 0x32583232u || ver != 1)
		return false;

	MOVE_CP.assign(MOVES.size(), {});
	MOVE_CO.assign(MOVES.size(), {});
	DIST_CP.resize(40320);
	DIST_CO.resize(2187);

	for (int mi = 0; mi < (int)MOVES.size(); mi++)
		in.read((char *)MOVE_CP[mi].data(), 40320 * sizeof(uint16_t));
	for (int mi = 0; mi < (int)MOVES.size(); mi++)
		in.read((char *)MOVE_CO[mi].data(), 2187 * sizeof(uint16_t));
	in.read((char *)DIST_CP.data(), 40320 * sizeof(uint8_t));
	in.read((char *)DIST_CO.data(), 2187 * sizeof(uint8_t));

	return (bool)in;
}

static void save_cache()
{
	ofstream out(CACHE_FILE, ios::binary);
	uint32_t magic = 0x32583232u, ver = 1;
	out.write((char *)&magic, 4);
	out.write((char *)&ver, 4);

	for (int mi = 0; mi < (int)MOVES.size(); mi++)
		out.write((char *)MOVE_CP[mi].data(), 40320 * sizeof(uint16_t));
	for (int mi = 0; mi < (int)MOVES.size(); mi++)
		out.write((char *)MOVE_CO[mi].data(), 2187 * sizeof(uint16_t));
	out.write((char *)DIST_CP.data(), 40320 * sizeof(uint8_t));
	out.write((char *)DIST_CO.data(), 2187 * sizeof(uint8_t));
}

static inline bool is_in_cubie(int cubie_id, char v)
{
	auto &b = CUBIES[cubie_id];
	return b[0] == v || b[1] == v || b[2] == v;
}

// Reconstruct cp/co from 5 faces (unknown facelets are missing)
static pair<array<int, 8>, array<int, 8> > reconstruct_from_5faces(
	const unordered_map<char, array<array<char, 2>, 2> > &partial)
{
	auto get_facelet = [&](char face, RC rc) -> optional<char> {
		auto it = partial.find(face);
		if (it == partial.end())
			return nullopt;
		return it->second[rc.r][rc.c];
	};

	array<bool, 8> used{};
	used.fill(false);
	array<int, 8> cp{};
	cp.fill(-1);
	array<int, 8> co{};
	co.fill(0);

	array<array<optional<char>, 3>, 8> need;
	array<vector<int>, 8> cands;

	// Build candidate cubies for each position
	for (int pos = 0; pos < 8; pos++) {
		array<char, 3> seen{};
		int sc = 0;
		for (int i = 0; i < 3; i++) {
			char face = CORNER_FACES[pos][i];
			RC rc = CORNER_FACELETS[pos].at(face);
			auto v = get_facelet(face, rc);
			need[pos][i] = v;
			if (v.has_value())
				seen[sc++] = *v;
		}

		vector<int> possible;
		for (int cub = 0; cub < 8; cub++) {
			bool ok = true;
			for (int k = 0; k < sc; k++) {
				if (!is_in_cubie(cub, seen[k])) {
					ok = false;
					break;
				}
			}
			if (ok)
				possible.push_back(cub);
		}
		cands[pos] = std::move(possible);
	}

	// Most constrained first
	vector<int> order(8);
	iota(order.begin(), order.end(), 0);
	sort(order.begin(), order.end(), [&](int a, int b) {
		int ca = (int)cands[a].size(), cb = (int)cands[b].size();
		int na = 0, nb = 0;
		for (int i = 0; i < 3; i++) {
			if (!need[a][i].has_value())
				na++;
			if (!need[b][i].has_value())
				nb++;
		}
		if (ca != cb)
			return ca < cb;
		return na < nb;
	});

	// twist definition matches Python:
	// twist = index in (U/R/F) order where U/D color sits
	auto colors_with_twist = [&](int cub, int twist) -> array<char, 3> {
		auto base = CUBIES[cub];
		int k = (3 - (twist % 3)) % 3;
		return { base[k], base[(k + 1) % 3], base[(k + 2) % 3] };
	};

	auto fits = [&](int pos, int cub, int twist) -> bool {
		auto cols = colors_with_twist(cub, twist);
		for (int i = 0; i < 3; i++) {
			if (need[pos][i].has_value() &&
			    *need[pos][i] != cols[i])
				return false;
		}
		return true;
	};

	function<bool(int)> dfs = [&](int i) -> bool {
		if (i == 8) {
			int s = 0;
			for (int k = 0; k < 8; k++)
				s += co[k];
			return (s % 3) == 0;
		}
		int pos = order[i];
		for (int cub : cands[pos]) {
			if (used[cub])
				continue;
			for (int twist = 0; twist < 3; twist++) {
				if (!fits(pos, cub, twist))
					continue;
				used[cub] = true;
				cp[pos] = cub;
				co[pos] = twist;
				if (dfs(i + 1))
					return true;
				used[cub] = false;
				cp[pos] = -1;
				co[pos] = 0;
			}
		}
		return false;
	};

	if (!dfs(0))
		throw runtime_error("reconstruct failed (mapping mismatch?)");

	// Fix last twist parity
	int s = 0;
	for (int i = 0; i < 7; i++)
		s += co[i];
	co[7] = (3 - (s % 3)) % 3;
	return { cp, co };
}

// IDA* with pruning tables (max depth 11)
static string ida_solve(const array<int, 8> &cp, const array<int, 8> &co,
			int max_depth = 11)
{
	int cp_idx = perm_to_idx(cp);
	int co_idx = ori_to_idx(co);

	auto h = [&](int cpi, int coi) -> int {
		int dcp = (DIST_CP[cpi] == 255) ? 99 : DIST_CP[cpi];
		int dco = (DIST_CO[coi] == 255) ? 99 : DIST_CO[coi];
		return max({ dcp, dco, (dcp + dco) / 2 });
	};

	int bound = h(cp_idx, co_idx);
	vector<string> path;
	path.reserve(max_depth);

	function<int(int, int, int, int, int, string *)> dfs =
		[&](int cpi, int coi, int g, int bound, int last_face_idx,
		    string *last_move) -> int {
		int f = g + h(cpi, coi);
		if (f > bound)
			return f;
		if (cpi == 0 && coi == 0)
			return -1; // solved
		if (g == bound)
			return INT_MAX;

		int min_next = INT_MAX;
		for (int fi = 0; fi < 6; fi++) {
			if (last_face_idx != -1 && fi == last_face_idx)
				continue;
			for (int k = 0; k < 3; k++) {
				int mi = MOVES_BY_FACE_IDX[fi][k];
				const string &m = MOVES[mi];
				if (last_move && is_inverse(*last_move, m))
					continue;

				int ncpi = MOVE_CP[mi][cpi];
				int ncoi = MOVE_CO[mi][coi];

				path.push_back(m);
				string cur = m;
				int res =
					dfs(ncpi, ncoi, g + 1, bound, fi, &cur);
				if (res == -1)
					return -1;
				path.pop_back();
				if (res < min_next)
					min_next = res;
			}
		}
		return min_next;
	};

	while (bound <= max_depth) {
		int res = dfs(cp_idx, co_idx, 0, bound, -1, nullptr);
		if (res == -1) {
			string out;
			for (size_t i = 0; i < path.size(); i++) {
				if (i)
					out.push_back(' ');
				out += path[i];
			}
			return out;
		}
		if (res == INT_MAX)
			break;
		bound++;
	}
	return "";
}

// main: load/build tables once, then serve queries using BEGIN/END protocol
int main()
{
	ios::sync_with_stdio(false);
	cin.tie(nullptr);

	if (!load_cache()) {
		build_corner_move_tables();
		DIST_CP = build_pruning(MOVE_CP, 40320);
		DIST_CO = build_pruning(MOVE_CO, 2187);
		save_cache();
	}

	string tok;
	while (cin >> tok) {
		if (tok != "BEGIN") {
			// ignore any garbage (robust for piping)
			continue;
		}

		unordered_map<char, array<array<char, 2>, 2> > partial;

		// read face lines until END
		while (cin >> tok) {
			if (tok == "END")
				break;
			if (tok.size() != 1)
				throw runtime_error("bad face token");
			char face = tok[0];

			string a, b, c, d;
			cin >> a >> b >> c >> d;

			array<array<char, 2>, 2> mat{};
			mat[0][0] = a[0];
			mat[0][1] = b[0];
			mat[1][0] = c[0];
			mat[1][1] = d[0];
			partial[face] = mat;
		}

		auto [cp, co] = reconstruct_from_5faces(partial);
		string sol = ida_solve(cp, co, 11);
		if (sol.empty())
			sol = "U";
		cout << sol << "\n" << flush;
	}
	return 0;
}
```

可能偶尔运气差还是会超时，多试几次即可，出题人设备为 MacBookAir M3 和拯救者R9000P 2023，测试均能通过远程。
