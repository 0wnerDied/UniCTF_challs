all:
	gcc vuln.c -o vuln -fPIE -pie -fstack-protector-strong -fstack-clash-protection -fvisibility=hidden -fno-plt -flto -fcf-protection=full -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wall -Wextra
