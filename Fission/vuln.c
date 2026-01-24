#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define INLINE static __attribute__((always_inline))

static char stdin_buf[1];

__attribute__((noreturn, always_inline)) void die(void)
{
	syscall(SYS_exit, 0);
	__builtin_unreachable();
}

INLINE void init()
{
	for (int fd = 3; fd < 256; fd++)
		close(fd);
	struct rlimit rl = {
		.rlim_cur = 4,
		.rlim_max = 4,
	};
	if (setrlimit(RLIMIT_NOFILE, &rl) != 0)
		die();
	setvbuf(stdin, stdin_buf, _IOFBF, sizeof(stdin_buf));
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

INLINE void seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fork, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		die();
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
		die();
}

INLINE void readseccomp(void)
{
	uint64_t stdin_addr = (uint64_t)stdin_buf;
	uint32_t stdin_low = (uint32_t)stdin_addr;
	uint32_t stdin_high = (uint32_t)(stdin_addr >> 32);

	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		// Only filter read syscall
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		// Check fd: branch based on fd == 0 or fd != 0
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0]) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 5, 0),

		// Branch 1: fd != 0 (for ORW read from flag file)
		// Allow read(fd, buf, count) where fd != 0 and count <= 0x100
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[2]) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 12),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[2])),
		BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 0x100, 10, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		// Branch 2: fd == 0 (for gets internal buffer)
		// Only allow read(0, stdin_buf, count) where count <= 1
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[2]) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 7),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[2])),
		BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 1, 5, 0),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, stdin_low, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[1]) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, stdin_high, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		// Kill all other read attempts
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
		die();
}

INLINE void read_full(int fd, void *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, (char *)buf + off, n - off);
		if (r <= 0)
			die();
		off += (size_t)r;
	}
}

INLINE void write_mem(void)
{
	struct __attribute__((packed)) {
		uint64_t addr;
		uint64_t size;
	} req;

	read_full(0, &req, sizeof(req));
	if (req.size > 100)
		die();
	read_full(0, (void *)req.addr, (size_t)req.size);
	readseccomp();
}

INLINE void gift(void)
{
	void *buf = NULL;
	printf("gift: ");
	fflush(NULL);
	asm volatile("" : "=D"(buf));
	(void)write(1, buf, 8);
}

int main(int argc, char **argv)
{
	init();
	seccomp();
	gift();
	write_mem();
	fork();
	die();
}
