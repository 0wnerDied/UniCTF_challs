all:
	clang vuln.c -o vuln -s -O3 -fPIE -pie -D_FORTIFY_SOURCE=3 -flto -fsanitize=cfi -fstack-protector-strong -fstack-clash-protection -fvisibility=hidden -fno-plt -fcf-protection=full -fuse-ld=lld -Wl,-z,relro,-z,now,-z,noexecstack,-O2,--gc-sections,--as-needed -lm
