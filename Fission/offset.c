#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	void *cleanup_buf;
	uint64_t leak;
	Dl_info info;

	printf("gift: ");
	fflush(NULL);
	asm volatile("mov %%rdi, %0" : "=r"(cleanup_buf));
	leak = *(uint64_t *)cleanup_buf;

	if (dladdr((void *)leak, &info) == 0) {
		puts("dladdr failed");
		return 1;
	}

	printf("cleanup_buf=%p\n", cleanup_buf);
	printf("leak=%p\n", (void *)leak);
	printf("libc_base=%p\n", info.dli_fbase);
	printf("offset=0x%lx\n", leak - (uint64_t)info.dli_fbase);
	return 0;
}
