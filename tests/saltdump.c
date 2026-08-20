#include <stdio.h>

extern void USER_CREATE(const char *user, unsigned long ulen,
			const char *pass, unsigned long plen);
extern char USER_TABLE[];

static void dump(int slot) {
	printf("slot %d user: ", slot);
	for (int i = 0; i < 32; i++) putchar(USER_TABLE[slot*96+i] ?: '.');
	printf("\nsalt: ");
	for (int i = 32; i < 48; i++) printf("%02x", (unsigned char)USER_TABLE[slot*96+i]);
	printf("\nhash: ");
	for (int i = 48; i < 80; i++) printf("%02x", (unsigned char)USER_TABLE[slot*96+i]);
	printf("\n\n");
}

int main(void) {
	USER_CREATE("alice", 5, "secret1", 7);
	USER_CREATE("bob", 3, "secret1", 7);
	dump(0);
	dump(1);
	return 0;
}
