#include "curve25519_key.h"

int main(void) {
	curve25519_key_t k = {.key64 = {
		0xB0DFD43460D7AC00ULL,
		0x3F68D16C4532AD13ULL,
		0x891C88961236535DULL,
		0x14FDA5783297B561ULL
	}};
	curve25519_key_lshift_inplace(&k, 5);
	curve25519_key_rshift_inplace(&k, 5);
	return 0;
}