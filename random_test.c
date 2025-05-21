#include "curve25519_key.h"

void print_bits(uint64_t n) {
	for (uint64_t i = 63; i > 0; --i) {
		printf("%llu", (n & (1ULL << i)) >> i);
	}
	printf("%llu\n", (n & 1));
}

void curve25519_key_lshift_inplace(curve25519_key_t *k, int64_t shift) {
	uint64_t *key = k->key64;
	printf("Before:\n");
	for (size_t i = 7; i > 0; --i) {
		print_bits(key[i]);
	}
	print_bits(key[0]);
	uint64_t nshift = (64ULL - shift) & (63ULL);
	size_t carry = key[0] >> nshift;
	key[0] <<= shift;
	for (size_t offset = 1; offset < 8; offset++) {
		uint64_t temp = key[offset] >> nshift;
		key[offset] = (key[offset] << shift) | carry;
		carry = temp;
	}
	printf("After:\n");
	for (size_t i = 7; i > 0; --i) {
		print_bits(key[i]);
	}
	print_bits(key[0]);
}

void curve25519_key_rshift_inplace(curve25519_key_t *k, int64_t shift) {
	uint64_t *key = k->key64;
	printf("Before:\n");
	for (size_t i = 7; i > 0; --i) {
		print_bits(key[i]);
	}
	print_bits(key[0]);
	uint64_t mask = ((1ULL << shift) - 1);
	size_t carry = key[0] & mask, nshift = (64ULL - shift) & (63ULL);
	key[7] >>= shift;
	for (size_t offset = 6; offset > 0; --offset) {
		uint64_t temp = key[offset] & mask;
		key[offset] = (carry << nshift) | (key[offset] >> shift);
		carry = temp;
	}
	uint64_t temp = key[0] & mask;
	key[0] = (carry << nshift) | (key[0] >> shift);
	carry = temp;
	printf("After:\n");
	for (size_t i = 7; i > 0; --i) {
		print_bits(key[i]);
	}
	print_bits(key[0]);
}

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