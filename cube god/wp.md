# UniCTF - cube god

这题本质是一个 **2x2 口袋魔方交互题**：服务端每轮随机打乱一个 2x2 魔方（114~514 手），只给出 **6 个面中随机隐藏 1 个面**后的其余 **5 个面贴纸**，要求你在 **1 秒内**输入一串转动，使得打乱后的魔方复原。

关键限制：

- 总共 **100 轮**，全部通过才给 flag。
- 每轮输入至多 **11 手**（`MAX_MOVES = 11`）。
- move 语法仅允许：`U, U', U2, D, D', D2, F, F', F2, B, B', B2, L, L', L2, R, R', R2`。
- 服务端校验方式：用同样的 scramble 把一个新魔方打乱，然后应用你的解，检查是否 solved。

因此，只要能从「5 个面」恢复出当前状态，并给出 **≤11 的解**就稳赢。

本题解只讲“思路/算法/实现要点”，不贴整份代码；仓库里提供的 `solver.cpp` + `exp.py` 就是可工作的参考实现。

---

## 目录

- [题目模型与限制](#题目模型与限制)
- [核心观察：2x2 角块模型](#核心观察2x2-角块模型)
- [整体流程](#整体流程)
- [A. 贴纸坐标与角块映射（必须对齐服务端）](#a-贴纸坐标与角块映射必须对齐服务端)
- [B. 从 5 个面重建 cp/co（约束搜索）](#b-从-5-个面重建-cpco约束搜索)
- [C. Move Table：从贴纸置换推导角块转移](#c-move-table从贴纸置换推导角块转移)
- [D. Pruning Table：单空间最短距离](#d-pruning-table单空间最短距离)
- [E. IDA*：深度 ≤ 11 的最优/可行解搜索](#e-ida深度--11-的最优可行解搜索)
- [F. 交互脚本要点（exp.py）](#f-交互脚本要点exppy)
- [常见踩坑清单](#常见踩坑清单)

---

## 题目模型与限制

服务端逻辑（见 `app.py`）：

1. 生成一个新 2x2 魔方 `cube`。
2. 执行 `scramble = cube.scramble(randint(114,514))`，得到被打乱状态。
3. 随机隐藏一个面 `hidden`，输出其余 5 个面的 2x2 贴纸。
4. 你在 1 秒内输入一行 moves（空格分隔），要求：
  - 每个 token 在 `VALID` 集合内
  - token 数量 ≤ 11
5. 校验：新建 `check_cube`，应用相同 scramble，再应用你的 moves，必须 `is_solved()`。

换句话说：你拿到的是 “被打乱后的状态的 5 面投影”，任务是回到 solved。

---

## 核心观察：2x2 角块模型

### 1. 2x2 只需要 corner 状态（cp/co）

2x2 没有棱块，只含 8 个角块（corner）。一个 2x2 状态可以表示为：

- `cp`（corner permutation）：8 个角块分别在 8 个位置上的排列，状态数 $8!=40320$。
- `co`（corner orientation）：每个角块有 3 种朝向；但整体有约束：所有角块朝向之和 $\equiv 0\pmod 3$，状态数 $3^7=2187$。

总状态数约：$40320\times 2187\approx 8.8\times 10^7$。

### 2. 为什么 11 手足够

2x2 在 face-turn metric 下的 God’s number 是 **11**，也就是任意状态都能在 11 手内复原。

所以题目把 `MAX_MOVES` 设置为 11，本质是在逼你写一个真正的 2x2 求解器。

---

## 整体流程

我们把“每轮求解”拆成 3 个阶段：

1. **解析 5 个面贴纸**，恢复到角块状态 `(cp, co)`。
2. 使用预计算的 `MOVE_CP/MOVE_CO` 和 `DIST_CP/DIST_CO` 提供快速转移与启发式。
3. 用 **IDA\***（迭代加深 A*）在深度 ≤ 11 内找到一条解。

这三步都在 `solver.cpp` 内完成；`exp.py` 只负责读服务端输出、喂给 solver、把解发回去。

---

## A. 贴纸坐标与角块映射（必须对齐服务端）

服务端打印每个面的格式（`display()`）：

```
Face U:
+-----+
| a b |
| c d |
+-----+
```

也就是面内坐标：

- `(r=0,c=0)` 对应 `a`（第一行第一列）
- `(0,1)` 对应 `b`
- `(1,0)` 对应 `c`
- `(1,1)` 对应 `d`

接下来最关键的是给出 **“每个角块位置 pos，其三张贴纸分别落在哪个面、哪个 (r,c)”**。

2x2 的 8 个角块位置命名（常用约定）：

- 顶层（U层）：URF, UFL, ULB, UBR
- 底层（D层）：DFR, DLF, DBL, DRB

其中字母含义：例如 URF 表示该角块贴着 U 面、R 面、F 面。

在本题实现里（见 `solver.cpp` 的 `CORNER_FACELETS`），位置到贴纸坐标的映射是：

| 角块位置 | 三面顺序（用于定义 twist） | U/D 面贴纸坐标 | 另两面贴纸坐标 |
|---|---|---|---|
| URF | (U,R,F) | U(1,1) | R(0,0), F(0,1) |
| UFL | (U,F,L) | U(1,0) | F(0,0), L(0,1) |
| ULB | (U,L,B) | U(0,0) | L(0,0), B(0,1) |
| UBR | (U,B,R) | U(0,1) | B(0,0), R(0,1) |
| DFR | (D,F,R) | D(0,1) | F(1,1), R(1,0) |
| DLF | (D,L,F) | D(0,0) | L(1,1), F(1,0) |
| DBL | (D,B,L) | D(1,0) | B(1,1), L(1,0) |
| DRB | (D,R,B) | D(1,1) | R(1,1), B(1,0) |

这个表 **必须** 与服务端 `move_U/move_D/...` 的实现一致；错一格会导致“重建得到的角块状态不可能”，最后报 `reconstruct failed` 或求解输出错误。

> 验证技巧：本地用 `app.py` 打印 solved 魔方（不 scramble），确认每个面都是同字母；再对某一个 move（比如 `U`）手动跑一次，观察哪些贴纸在打印中互换，以此验证坐标对应。

---

## B. 从 5 个面重建 cp/co（约束搜索）

### 目标与数据结构

我们最终要得到：

- `cp[pos] ∈ {0..7}`：位置 `pos` 上放的是哪个角块（用角块 ID 表示）
- `co[pos] ∈ {0,1,2}`：这个角块在该位置的朝向（twist）

角块 ID 的定义（见 `solver.cpp` 的 `CUBIES`）：

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

输入只包含 5 个面（缺 1 个面），因此有些贴纸是 unknown。

### 第一步：每个位置的局部候选集（只看颜色集合）

对每个位置 `pos`，它有 3 张贴纸，对应三面顺序 `CORNER_FACES[pos]`（例如 URF 的顺序是 U/R/F）。

我们从输入的 5 面里尝试取这 3 个贴纸：

- 如果该面是隐藏面，则该贴纸 unknown
- 否则贴纸颜色是 `U/D/F/B/L/R` 之一

把已知颜色收集成集合 `seen(pos)`，例如 `seen={U,R}`。

那么候选角块必须满足：该角块的三颜色集合包含 `seen`。

这一步在 `solver.cpp` 里是 `is_in_cubie(cubie_id, char color)` 的组合过滤。

### 第二步：全局一致性（DFS/回溯）

仅用集合过滤还不够（因为不考虑朝向、也不考虑每个贴纸落在哪个面），接下来做全局 DFS：

- 每个位置从 `cands[pos]` 里挑一个 cubie
- 保证 8 个 cubie 互不重复（`used[cubie]=true`）
- 对每个 (pos,cubie) 再枚举 3 种 twist，看是否匹配已知贴纸

为提速，采用“最受限优先”排序：

1. 候选数少的 pos 优先
2. unknown 更少的 pos 优先

这样回溯深度虽为 8，但分支极小，通常瞬间出解。

### 只看到 5 个面时的约束

隐藏 1 个面会导致 4 个贴纸未知，但每个角块有 3 个贴纸——实际会出现：

- 有些角块 3 贴纸全可见（强约束）
- 有些角块缺 1 贴纸（仍然能用 “颜色集合” 缩小候选）

做法：对每个角块位置 pos：

1. 读取该位置 3 个贴纸的已知颜色（来自 5 个面）；未知的记为 `None/optional`。
2. 先用“颜色集合包含关系”筛掉不可能的 cubie：
   - 如果已知颜色集合 seen = {U,R}，那么候选 cubie 必须包含 U 和 R。
3. 得到 `cands[pos]` 后，在全局做 DFS/backtracking，把 8 个 cubie 分配到 8 个位置（不可重复）。

### twist（co）的定义与 `colors_with_twist` 推导

这题最容易踩坑的是：`co`（twist）的定义必须和 move table 推导一致。

`solver.cpp` 的定义是：

> `co[pos] = 角块三面(按 CORNER_FACES[pos] 顺序)中，U/D 颜色落在第几个槽位 (0/1/2)`

也就是：假设该位置的面序是 (U,R,F)，那么

- 如果 U/D 贴纸在第 0 个（U 面），twist=0
- 在第 1 个（R 面），twist=1
- 在第 2 个（F 面），twist=2

本题把 twist 定义为：

> $co[pos] =$ 在 `CORNER_FACES[pos]` 的三面顺序中，U/D 颜色落在哪个槽位（0/1/2）。

例如 URF 的面序是 (U,R,F)：

- U/D 在 U 面槽位 → twist=0
- U/D 在 R 面槽位 → twist=1
- U/D 在 F 面槽位 → twist=2

为了在 DFS 检查“某 cubie 以某 twist 放到某 pos 是否匹配”，需要生成该 cubie 在该 twist 下的三面颜色序列。

设 `CUBIES[cub] = (x0,x1,x2)` 是该角块的基准顺序（基准顺序与 `CORNER_FACES` 一致：第 0 个必为 U 或 D），
我们希望 U/D 颜色出现在 index = twist。

把三元组做循环移位即可：

$$
cols[i] = base[(i - twist)\bmod 3]
$$

`solver.cpp` 里写成：

```cpp
int k = (3 - (twist % 3)) % 3;
return { base[k], base[(k + 1) % 3], base[(k + 2) % 3] };
```

这与 Python 版 `exp.py.bak` 的 `k = (-twist)%3` 是同一意思。

然后 `fits(pos,cub,twist)` 就是逐个槽位 i 比对：若 `need[pos][i]` 已知，则必须等于 `cols[i]`。

### 为什么要有 “twist parity” 约束

2x2 的角块朝向并非独立：

$$\sum_{i=0}^{7} co[i] \equiv 0 \pmod 3$$

这是魔方群的基本不变量：任何合法转动都会保持该等式。

因此 DFS 到底时必须检查这个条件，否则可能得到一个“贴纸上看起来匹配，但实际上不可达”的组合。

在实现里：

- DFS 结束时检查 sum%3==0
- 或者直接让第 8 个角块朝向由前 7 个决定：`co[7] = (-sum(co[0..6])) mod 3`

$$\sum_{i=0}^{7} co[i] \equiv 0 \pmod 3$$

并据此修正最后一个角块的 twist。

### 伪代码（重建）

```
for pos in 0..7:
  need[pos][i] = facelet color if that face is shown else UNKNOWN
  seen = { all known colors in need[pos] }
  cands[pos] = { cubie | cubie colorset contains seen }

order = positions sorted by (len(cands[pos]), number_of_UNKNOWN)

dfs(i):
  if i==8:
    return sum(co)%3==0
  pos = order[i]
  for cub in cands[pos] where not used[cub]:
    for twist in {0,1,2}:
      if fits(pos,cub,twist):
        used[cub]=true; cp[pos]=cub; co[pos]=twist
        if dfs(i+1): return true
        rollback
  return false
```

> 实战中：只要坐标映射对齐服务端，5 面信息通常足够唯一确定状态。

---

## C. Move Table：从贴纸置换推导角块转移

为了做到每轮毫秒级求解，需要把“状态转移”做成数组查表。

### 24 贴纸编号方案（facelet indexing）

固定一个 24 贴纸索引，把每个面 2x2 展平：

- U 面 4 个贴纸编号：0..3
- D 面：4..7
- F 面：8..11
- B 面：12..15
- L 面：16..19
- R 面：20..23

并且面内的 `(r,c)` 映射为 `r*2+c`。

即：

$$facelet\_idx(face,r,c) = base(face) + (r\cdot 2 + c)$$

`solver.cpp` 的 `facelet_idx()` 函数就是这个定义。

### Sticker 级 24 贴纸模型生成 move 的置换

2x2 每个面 2x2，一共 6 个面 => 24 个贴纸。

`solver.cpp` 构建一个 `StickerCube2x2`：

- 初始化时每个贴纸填充自身编号 0..23。
- 对每个 move（18 种）执行一次，得到一个 24 长度的置换 `perm24`。

这里 `perm24` 的含义要非常明确：

> `new[i] = old[perm24[i]]`

也就是“move 之后第 i 个位置来自 move 之前的哪个位置”。

这样应用置换就只是：

```cpp
out[i] = st[perm[i]];
```

这套定义能保证后续推导 corner 转移时不会反。

### 从 perm24 推导 corner 的置换与朝向变化

预先固定每个 corner position 对应 3 个贴纸索引（`CORNER_FACELETS_IDX[pos]`）。

对于某个 move：

对每个 corner position，我们知道它由 3 个 facelet 组成（按 `CORNER_FACES[pos]` 的顺序），例如：

```
URF = (U(1,1), R(0,0), F(0,1))
```

对应 24 贴纸索引三元组 `CORNER_FACELETS_IDX[pos]`。

对某个 move：

1. 先求 `moved24 = apply_perm24(solved24, perm24)`，得到 move 后每个位置装着哪个旧编号。
2. 对每个 `new_pos`，取它的三元组 `(moved24[a], moved24[b], moved24[c])`。
3. 这三元组对应的是 **某个 old_pos 的三贴纸集合**。为了快速匹配，用 bitmask：

$$mask(triple)=2^{t_0}+2^{t_1}+2^{t_2}$$

对每个 old_pos 预先算好 mask，这样 `new_pos` 就能通过 mask 相等找到 `old_pos`。

4. 朝向变化：用 `twist_of_corner(triple)` 计算 U/D 贴纸在 triple 中出现的位置（0/1/2），它就是“扭转增量”。

注意：这里的 `triple` 里存的是旧贴纸编号；而 U/D 面贴纸编号范围在 0..7，因此 `twist_of_corner` 的判定是“哪个元素落在 0..7”。

这样就能得到：

- `MOVE_CP[mi][cp_idx]`：cp 走一步后的新 cp 索引
- `MOVE_CO[mi][co_idx]`：co 走一步后的新 co 索引

---

## D. Pruning Table：单空间最短距离

我们分别在两个“投影空间”上做 BFS：

- 只看 cp（40320 个状态）
- 只看 co（2187 个状态）

从 solved（idx=0）出发，用 18 种 move 扩展，得到每个 idx 到 solved 的最短步数。

这个距离是严格的“下界”：

- 任意完整状态要复原，至少要把它的 cp 修回去，至少需要 `DIST_CP[cp_idx]` 步。
- 同理至少需要 `DIST_CO[co_idx]` 步。

因此它们可用于 IDA* 的启发式剪枝。

分别对 cp 空间（40320）和 co 空间（2187）做 BFS，得到：

- `DIST_CP[cp_idx]`
- `DIST_CO[co_idx]`

它们作为 IDA* 的启发式下界。

### 缓存

第一次生成表会花一点时间，因此把所有表写入 `cube2x2_tables.bin`，后续直接加载。

---

## E. IDA*：深度 ≤ 11 的最优/可行解搜索

状态是 `(cp_idx, co_idx)`。

### 启发函数（h）

最常见且安全的做法是 `h = max(DIST_CP, DIST_CO)`；本实现额外加了一个平均项以加强剪枝：

$$h=\max\left(d_{cp}, d_{co}, \left\lfloor\frac{d_{cp}+d_{co}}{2}\right\rfloor\right)$$

其直觉是：有时候 cp 和 co 都“差得多”，真实距离往往大于单纯的 max；平均项可以更接近真实值，从而减少搜索节点。

IDA* 的流程：

1. 初始 bound = h(start)
2. 在 bound 内做深度优先搜索（DFS），只扩展使得 `g + h <= bound` 的节点
3. 若没找到解，则 bound++ 继续
4. 直到 bound > 11 结束（理论上不会；因为 God’s number=11）

### 分支剪枝（不影响可解性）

- 不允许连续两步转同一面（例如上一手是 U，则下一手不再扩展 U/U2/U'）。
- 不走“上一手的逆操作”（例如上一手是 U，则下一手跳过 U'；U2 的逆是自身）。

这些剪枝不会漏解：

- 连续转同一面可以合并成一步（例如 `U U` 等价于 `U2`，`U U'` 等价于无操作）。
- 紧跟逆操作更是显然冗余。

因此搜索仍覆盖所有最短解/可行解，节点数却大幅下降。

### 复杂度直觉

最坏情况下分支因子约为 6 面 * 3 = 18，但剪枝后平均会小很多（通常接近 12 左右）；深度最多 11。
再乘上启发式剪枝后，实际搜索规模可以控制在非常小的量级，满足 1 秒交互。

由于 2x2 的最优解深度上限就是 11，IDA* 在这个问题上非常合适。

---

---

## F. 交互脚本要点（exp.py）

`exp.py` 的关键目标是：把服务端每轮输出的 5 张面，快速喂给本地求解器，然后把解送回去。

### 输出解析

每个 face block 的格式固定：

1. `Face X:`
2. `+-----+`
3. `| a b |`
4. `| c d |`
5. `+-----+`

因此用 `recvline()` 连续读 5 行即可；`parse_row()` 把 `|` 去掉后按空格 split 得到两个 token。

### solver 子进程协议

为了避免每轮都重新启动 solver（启动进程 + 读取缓存会很慢），脚本使用 **常驻子进程**：

- 启动一次 `./solver`
- 每轮发送：

```
BEGIN
U a b c d
F a b c d
...
END
```

注意：服务端会随机隐藏一个面，但 solver 不要求你补齐 6 面；它接受“任意顺序的 5 个面”，缺失面自然当作 unknown。

### 为什么要做 fallback

正常情况下 IDA* 一定会在 ≤11 内找到解；但为了让管道协议更鲁棒（例如某轮输入解析出错导致 solver 输出空行），脚本做了：

- `if not sol: sol = "U"`

至少保证不会因为发送空行卡住交互。

### 日志与性能

每轮打印一次 `sol_len` 和耗时（ms），方便发现缓存没命中或 solver 退化。

如果远程交互对输出敏感，可以把 `context.log_level` 调低，减少 I/O。

---

---

## 常见踩坑清单

1. **坐标对齐**：`CORNER_FACELETS` 的 (r,c) 必须与服务端打印完全一致；错一格就会导致重建失败或状态错误。
2. **twist 定义统一**：`co[pos]` 的含义必须与 `twist_of_corner()`、move table 的 twist delta 一致；不一致会出现“重建能过、但解永远不对”。
3. **perm24 方向别写反**：明确 `new[i]=old[perm[i]]`，否则 corner 置换推导会错。
4. **隐藏面导致的歧义**：如果你自己重写重建器，要记得做全局 DFS（只靠局部集合过滤不够）。
5. **别每轮重启 solver**：否则会被进程启动/表生成拖慢。

---

---

## 一句话总结

把 2x2 用 corner `(cp,co)` 建模；从 5 面通过约束搜索恢复状态；预计算 move/pruning table；用 IDA* 在深度 ≤ 11 内求解并自动化交互，即可稳定 100 轮拿 flag。
