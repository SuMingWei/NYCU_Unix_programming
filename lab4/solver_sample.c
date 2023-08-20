#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	// char msg[16] = "hello, world!";
	char msg[16];
	fptr("%lx %lx %lx\n", *(uint64_t *)msg+0x28, *(uint64_t *)msg+0x20, *(uint64_t *)msg+0x20);
	// fptr("%s\n", msg);
	// void *ret = msg + 0x28;
	// void *rbp = msg + 0x20;
	// void *canary = msg + 0x18;
	// void *frameTop = msg + 0x30;

	// fptr("ret: %lx\n", *(uint64_t *)ret);
	// fptr("rbp: %lx\n", *(uint64_t *)rbp);
	// fptr("canary: %lx\n", *(uint64_t *)canary);
	// fptr("frameTop: %lx\n", frameTop);
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}
