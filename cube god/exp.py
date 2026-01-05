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
