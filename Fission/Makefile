all:
	clang vuln.c -o vuln -s -O3 -flto -fuse-ld=lld -fPIE -pie -fvisibility=hidden -fno-plt -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -fsanitize=cfi -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections,--icf=all,-O2 -lm
