#include <stdio.h>

extern long FILE_LIST(void);
extern char FILELIST_BUF[];

int main(void) {
	long n = FILE_LIST();
	printf("ret=%ld\n", n);
	for (long i = 0; i < n && i < 500; i++) putchar(FILELIST_BUF[i]);
	return 0;
}
