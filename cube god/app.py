#!/usr/bin/env python3
import os
import random
import signal
import sys


class RubiksCube2x2:
    def __init__(self):
        # 2x2 魔方，每个面是 2x2 的矩阵
        # 初始状态：U(全U), D(全D), ...
        self.faces = {k: [[k] * 2 for _ in range(2)] for k in "UDFBLR"}

    def _rotate_face_cw(self, face):
        n = len(face)
        return [[face[n - 1 - j][i] for j in range(n)] for i in range(n)]

    def _rotate_face_ccw(self, face):
        n = len(face)
        return [[face[j][n - 1 - i] for j in range(n)] for i in range(n)]

    def _get_row(self, face, row):
        return self.faces[face][row][:]

    def _set_row(self, face, row, values):
        self.faces[face][row] = values[:]

    def _get_col(self, face, col):
        return [self.faces[face][i][col] for i in range(2)]

    def _set_col(self, face, col, values):
        for i in range(2):
            self.faces[face][i][col] = values[i]

    def move_U(self, prime=False):
        if prime:
            self.faces["U"] = self._rotate_face_ccw(self.faces["U"])
            t = self._get_row("F", 0)
            self._set_row("F", 0, self._get_row("L", 0))
            self._set_row("L", 0, self._get_row("B", 0))
            self._set_row("B", 0, self._get_row("R", 0))
            self._set_row("R", 0, t)
        else:
            self.faces["U"] = self._rotate_face_cw(self.faces["U"])
            t = self._get_row("F", 0)
            self._set_row("F", 0, self._get_row("R", 0))
            self._set_row("R", 0, self._get_row("B", 0))
            self._set_row("B", 0, self._get_row("L", 0))
            self._set_row("L", 0, t)

    def move_D(self, prime=False):
        if prime:
            self.faces["D"] = self._rotate_face_ccw(self.faces["D"])
            t = self._get_row("F", 1)
            self._set_row("F", 1, self._get_row("R", 1))
            self._set_row("R", 1, self._get_row("B", 1))
            self._set_row("B", 1, self._get_row("L", 1))
            self._set_row("L", 1, t)
        else:
            self.faces["D"] = self._rotate_face_cw(self.faces["D"])
            t = self._get_row("F", 1)
            self._set_row("F", 1, self._get_row("L", 1))
            self._set_row("L", 1, self._get_row("B", 1))
            self._set_row("B", 1, self._get_row("R", 1))
            self._set_row("R", 1, t)

    def move_F(self, prime=False):
        if prime:
            self.faces["F"] = self._rotate_face_ccw(self.faces["F"])
            t = self._get_row("U", 1)
            self._set_row("U", 1, self._get_col("R", 0))
            self._set_col("R", 0, self._get_row("D", 0)[::-1])
            self._set_row("D", 0, self._get_col("L", 1))
            self._set_col("L", 1, t[::-1])
        else:
            self.faces["F"] = self._rotate_face_cw(self.faces["F"])
            t = self._get_row("U", 1)
            self._set_row("U", 1, self._get_col("L", 1)[::-1])
            self._set_col("L", 1, self._get_row("D", 0))
            self._set_row("D", 0, self._get_col("R", 0)[::-1])
            self._set_col("R", 0, t)

    def move_B(self, prime=False):
        if prime:
            self.faces["B"] = self._rotate_face_ccw(self.faces["B"])
            t = self._get_row("U", 0)
            self._set_row("U", 0, self._get_col("L", 0)[::-1])
            self._set_col("L", 0, self._get_row("D", 1))
            self._set_row("D", 1, self._get_col("R", 1)[::-1])
            self._set_col("R", 1, t)
        else:
            self.faces["B"] = self._rotate_face_cw(self.faces["B"])
            t = self._get_row("U", 0)
            self._set_row("U", 0, self._get_col("R", 1))
            self._set_col("R", 1, self._get_row("D", 1)[::-1])
            self._set_row("D", 1, self._get_col("L", 0))
            self._set_col("L", 0, t[::-1])

    def move_L(self, prime=False):
        if prime:
            self.faces["L"] = self._rotate_face_ccw(self.faces["L"])
            t = self._get_col("U", 0)
            self._set_col("U", 0, self._get_col("F", 0))
            self._set_col("F", 0, self._get_col("D", 0))
            self._set_col("D", 0, self._get_col("B", 1)[::-1])
            self._set_col("B", 1, t[::-1])
        else:
            self.faces["L"] = self._rotate_face_cw(self.faces["L"])
            t = self._get_col("U", 0)
            self._set_col("U", 0, self._get_col("B", 1)[::-1])
            self._set_col("B", 1, self._get_col("D", 0)[::-1])
            self._set_col("D", 0, self._get_col("F", 0))
            self._set_col("F", 0, t)

    def move_R(self, prime=False):
        if prime:
            self.faces["R"] = self._rotate_face_ccw(self.faces["R"])
            t = self._get_col("U", 1)
            self._set_col("U", 1, self._get_col("B", 0)[::-1])
            self._set_col("B", 0, self._get_col("D", 1)[::-1])
            self._set_col("D", 1, self._get_col("F", 1))
            self._set_col("F", 1, t)
        else:
            self.faces["R"] = self._rotate_face_cw(self.faces["R"])
            t = self._get_col("U", 1)
            self._set_col("U", 1, self._get_col("F", 1))
            self._set_col("F", 1, self._get_col("D", 1))
            self._set_col("D", 1, self._get_col("B", 0)[::-1])
            self._set_col("B", 0, t[::-1])

    def apply_move(self, move):
        move = move.strip()
        if not move:
            return False
        if move[-1] == "2":
            self.apply_move(move[:-1])
            self.apply_move(move[:-1])
            return True
        prime = "'" in move
        face = move.replace("'", "")
        moves = {
            "U": self.move_U,
            "D": self.move_D,
            "F": self.move_F,
            "B": self.move_B,
            "L": self.move_L,
            "R": self.move_R,
        }
        if face in moves:
            moves[face](prime)
            return True
        return False

    def apply_moves(self, moves_str):
        for move in moves_str.split():
            if not self.apply_move(move):
                return False
        return True

    def scramble(self, num_moves=50):
        moves = [
            "U",
            "U'",
            "U2",
            "D",
            "D'",
            "D2",
            "F",
            "F'",
            "F2",
            "B",
            "B'",
            "B2",
            "L",
            "L'",
            "L2",
            "R",
            "R'",
            "R2",
        ]
        seq = []
        last = ""
        for _ in range(num_moves):
            m = random.choice(moves)
            while m[0] == last:
                m = random.choice(moves)
            seq.append(m)
            last = m[0]
            self.apply_move(m)
        return " ".join(seq)

    def is_solved(self):
        for face in self.faces.values():
            c = face[0][0]
            if any(cell != c for row in face for cell in row):
                return False
        return True

    def display(self, show_faces):
        r = ""
        for f in show_faces:
            r += f"Face {f}:\n+-----+\n"
            for row in self.faces[f]:
                r += f"| {' '.join(row)} |\n"
            r += "+-----+\n"
        return r


def timeout_handler(signum, frame):
    print("\n[-] Time's up!")
    sys.exit(1)


def main():
    FLAG = os.environ.get("FLAG", "flag{2x2_cube_is_small_but_mighty}")
    VALID = {
        "U",
        "U'",
        "U2",
        "D",
        "D'",
        "D2",
        "F",
        "F'",
        "F2",
        "B",
        "B'",
        "B2",
        "L",
        "L'",
        "L2",
        "R",
        "R'",
        "R2",
    }
    ROUNDS = 100
    MAX_MOVES = 11

    signal.signal(signal.SIGALRM, timeout_handler)

    print(f"Solve {ROUNDS} cubes to get the flag!\n")

    for rnd in range(1, ROUNDS + 1):
        print(f"=== Round {rnd}/{ROUNDS} ===\n")

        cube = RubiksCube2x2()
        scramble = cube.scramble(random.randint(114, 514))

        all_faces = ["U", "D", "F", "B", "L", "R"]
        hidden = random.choice(all_faces)
        show = [f for f in all_faces if f != hidden]

        # print(f"Scramble: {scramble}\n")
        print(cube.display(show))
        print("[?] Enter your solution:")

        # signal.alarm(15)
        signal.alarm(1)

        try:
            sol = input().strip()
        except EOFError:
            return

        if not sol:
            print("[-] Empty solution!")
            return

        moves_list = sol.split()
        if not all(m in VALID for m in moves_list):
            print("[-] Invalid move syntax!")
            return

        if len(moves_list) > MAX_MOVES:
            print(f"[-] Too many moves!")
            return

        check_cube = RubiksCube2x2()
        check_cube.apply_moves(scramble)
        check_cube.apply_moves(sol)

        if not check_cube.is_solved():
            print("[-] Not solved!")
            return

        print(f"[+] Round {rnd} passed!\n")

    print(f"[+] FLAG: {FLAG}")


if __name__ == "__main__":
    main()
