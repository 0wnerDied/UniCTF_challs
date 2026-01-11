#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void read_full(int fd, void *buf, size_t n)
{
	size_t off = 0;
	while (off < n) {
		ssize_t r = read(fd, (char *)buf + off, n - off);
		if (r <= 0)
			syscall(SYS_exit, 0);
		off += (size_t)r;
	}
}

void write_mem(void)
{
	struct __attribute__((packed)) {
		uint64_t addr;
		uint64_t size;
	} req;

	read_full(0, &req, sizeof(req));
	if (req.size > 0x100)
		syscall(SYS_exit, 0);
	read_full(0, (void *)req.addr, (size_t)req.size);
}

int main(int argc, char **argv)
{
	init();
	printf("gift: %p\n", stdin);
	write_mem();
	fork();
	syscall(SYS_exit, 0);
}
