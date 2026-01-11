all:
	gcc vuln.c -o vuln -O3 -fuse-ld=lld -Wl,-z,relro,-z,now,-O2,--gc-sections,--as-needed -lm
