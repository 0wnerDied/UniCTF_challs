/*
 * UniCTF Challenge - Sur prize
 * 
 * Animation based on IOCCC 2024 entry "weaver" by weaver
 * Original: https://www.ioccc.org/2024/weaver/
 * Copyright © 1984-2025 by Landon Curt Noll and Leonid A. Broukhis.
 * Licensed under CC BY-SA 4.0: https://creativecommons.org/licenses/by-sa/4.0/
 * 
 * Modified for CTF challenge purposes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>

char *A = "~\\^__a^\\Z~\\\\^_ZZffa~\\^__a^\\Z~\\\\^_\\Zaaaca~_~ac_aaacaZ~\\^_\\aca~ZZZ\\ccaZZ\\Zaa_ZZ\\Z_a^\\ZZa_ZZ\\Zcca~ZZ\\Zf^_^\\ZZ\\Z_a^\\ZZa_~__\\_a~^\\Z~\\\\^_\\Zffaca_\\\\^_\\_a^\\Z~\\\\^_\\Z~acca_~ac_aaacaZ~\\^_\\aca~ZZZ\\ccaZZ\\Zaa_ZZ\\Z_a^\\ZZa_ZZ\\ZccaZZ\\Zf^_^\\ZZ\\Z_a^\\ZZa_~ZZ\\ZccaZZ\\Zaa_ZZ\\Z_a^\\ZZa_ZZ\\",
     *B = "?<<<<<=;?E<<<<><><>D<<<<<=;?E<<<<<><<<<?=C;<<<<<<<>>B<<<><<?;;;;;==@;;;;==@;;;;><=;><>B;;;;==?;;;;;><;;>;;;;><=;><>@B<<<<?=<<@@<<<<<@<<><<><<<<<<><<@@<<<<<?;<<>@C;<<<<<<<>>B<<<><<?;;;;;==@;;;;==@;;;;><=;><>B;;;;==@;;;;><;;>;;;;><=;><>@<;;;;==@;;;;==@;;;;><=;><>B;;;",
     *C = "~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~D~D~B~B~D~D~B~B~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~D~D~B~B~D~D~B~B~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L~L~N~K~L",
     *D = ";?;???;>@?;???;>@?;???;???;>@D@?;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;???;?",
     E[] = "ZxZxZxZxZxZxZl`<^<ZxZ>_>^>ZxZ<Nb@NZxZ<NTRd<NZxZ<QNQb>ZxZ>Q[<b<ZxZ>QVQRZxZBh<RZxZBh<RWh<ZxZ<h<QWhBZtOJVg<hDZnh<OJg<hHZjh@Jg<hHZjh@Jg<hHZjh@Jg<hHZjh@Jg<hJZhh@Jg<Qh@Yh>Zhh@Jg<a<h>Yh>Zhh@Jg<Xa<h<Yh@ZH~",
     G[] = "ZxZxZxZ>]<^<ZxZ@^<_<NZxZ>Na<RNZxZ>MQRSNZxZ<RPLRLQZxZ<a<VQRQZxZ>QVQRZxZ@a<RZxZBa<RZxZBa>Wh<Zv_<Wh<WhDZlXOXOWh<WhFZjh@Wh<WhFZjXYh>Jg<hFZjhBJg<hFZjhBJWhJZhhBJWh<Qb<Xi<h<Zfi>h<JWh<Qb<XYh@Zbh<i<h<JWh>a<YhBZbh@QXJWh>i>hDZbh<a>JWXiBhBZdi<Ra<JXiFZP~",
     H[] = "ZxZxZxZxZL`BZxZ>N_<^<ZxZ>TQRSTZxZ<TQKb<TZxZ<La<RTZxZ>a>KRQZxZ>Va<RZxZ@f<RZxZBa<RWZxZ>WQh<Wh<ZtOXOWJh<Wh@Znh@g<h<WhBZjhBg<JWhFZhhDWJWhFZhhDWJWhFZhXYh@WJhHZhXYh@WJhHZhXi<h>WJh>a<Rh<ZhXi<h>WJh>b<Qh<ZhXi<h>WJh>a>h<ZhXi>h<WJh>YQh>ZP~",
     *I = "/usr/bin/aplay", *h[] = { E, G, G, H, H, G, G, E }, *b, *n, *l, *W;

int f[64], o = 0, w, i = 0, s = 0, S = 0, j, d, x, c, r, Z = 704e3,
	   g[] = { 9474192,  11302972, 13664348, 14718064, 6572056, 4466688,
		   9985064,  13660272, 14715016, 15507616, 8677424, 11549756,
		   12605528, 13158600, 4210752,	 2895872 };

pid_t pid = 0;
volatile int alive = 1;

void a(char *N, char *L)
{
	for (n = N, l = L; *n; n++, l++) {
		d = (*l - 58) * 1e3;
		w = *n > 'z' ? 0 : 8e3 / f[*n - 58];
		for (j = 0; j < d; j++, o++)
			if (w && (j % w < w / 2))
				b[o] += (j > d / 2) ? 32 : 63;
	}
}

int gogogo()
{
	struct termios oldt, newt;
	int ch;
	int oldf;

	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);

	ch = getchar();

	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	fcntl(STDIN_FILENO, F_SETFL, oldf);

	if (ch != EOF) {
		ungetc(ch, stdin);
		return 1;
	}

	return 0;
}

void lmao()
{
	FILE *P;
	for (i = 0; i < 64; i++)
		f[i] = 440 * pow(2, (i - 45) / 12.0);
	if (!(b = calloc(Z, 1)))
		return;
	a(A, B);
	o = 0;
	a(C, D);

	pid = fork();
	if (!pid) {
		if ((P = fopen(I, "r"))) {
			fclose(P);
			P = popen(I, "w");
			s = 1;
		}
		if (P) {
			fwrite(b, Z, 1, P);
		}
		if (!s)
			fclose(P);
		else
			pclose(P);
		for (;;)
			sleep(1);
	}

	while (alive) {
		W = h[S++ & 7];
		x = 0;
		printf("\x1b[1;1H");
		while (*W < '~') {
			c = *W - 58;
			r = c < 16 ? 1 : c < 32 ? 2 : *(++W) - 56;
			c &= 15;
			printf("\x1b[48;2;%d;%d;%dm", (g[c] >> 16) & 255,
			       (g[c] >> 8) & 255, g[c] & 255);
			for (i = 0; i < r; i++, x++)
				printf(x % 80 ? " " : "\n ");
			W++;
		}
		usleep(Z / 3);
		if (gogogo()) {
			getchar();
			alive = 0;
		}
	}

	printf("\x1b[2J\x1b[1;1H\x1b[0m");

	if (pid > 0) {
		kill(pid, 9);
	}

	free(b);
}

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void wutihave()
{
	char *path = "/bin/ls";
	char *argv[] = { "/bin/ls", NULL, NULL };
	char *envp[] = { NULL };

	__asm__ volatile("syscall"
			 :
			 : "a"(59), "D"(path), "S"(argv), "d"(envp));
}

void leimicc(const char *filename)
{
	struct stat st;
	if (stat(filename, &st) != 0) {
		write(STDOUT_FILENO, "No such file or directory\n", 26);
		return;
	}

	char *path = "/bin/cat";
	char *argv[] = { "/bin/cat", (char *)filename, NULL };
	char *envp[] = { NULL };

	__asm__ volatile("syscall"
			 :
			 : "a"(59), "D"(path), "S"(argv), "d"(envp));
}

__attribute__((naked)) void _main()
{
	__asm__("push %rbp\n"
		"mov %rsp, %rbp\n"
		"jmp .1\n"

		".byte 0xe8, 0xff, 0xff, 0xff, 0xff\n"

		".1:\n"
		"sub $0x40, %rsp\n"

		"push $0x8\n"
		"pop %rcx\n"
		"jmp .2\n"

		".byte 0x0f, 0x0b\n"

		".2:\n"
		"mov %rsp, %rdi\n"
		"sub %rcx, %rdi\n"

		"mov $0x1, %eax\n"
		"test %eax, %eax\n"
		"jz .3\n"
		"sub $0x10, %rbp\n"

		".3:\n"
		"call gets\n"

		"xor %eax, %eax\n"
		"test %eax, %eax\n"
		"jnz .4\n"
		"leave\n"
		"ret\n"

		".4:\n"
		".byte 0xcc\n");
}

int main(int argc, char **argv)
{
	init();
	lmao();
	_main();

	return 0;
}
