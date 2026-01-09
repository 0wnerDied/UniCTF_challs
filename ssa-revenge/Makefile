all:
	clang++ vuln.cpp -o vuln -s -fPIE -pie -fstack-protector-strong -fstack-clash-protection -fvisibility=hidden -fno-plt -flto -fcf-protection=full -fuse-ld=lld -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wall -Wextra
