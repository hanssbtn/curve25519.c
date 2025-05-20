#include "tests.h"

int32_t curve25519_priv_key_init_test(void) {
	printf("Private Key Initialization Test\n\n");
	curve25519_key_t key = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t prev_key = {.key64 = {0, 0, 0, 0}};
	printf("Test Case 1\n");
	if (curve25519_priv_key_init(&key)) {
		return -1;
		printf("Test Case 1 FAILED\n");
	}
	curve25519_key_printf(&key, STR);
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 1 FAILED\n");
			return -2;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 1 PASSED\n---\n\n");
	printf("Test Case 2\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 2 FAILED\n");
		return -3;
	}
	curve25519_key_printf(&key, STR);
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 2 FAILED\n");
			return -4;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 2 PASSED\n---\n\n");
	printf("Test Case 3\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 3 FAILED\n");
		return -5;
	}
	curve25519_key_printf(&key, STR);
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 3 FAILED\n");
			return -6;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 3 PASSED\n---\n\n");
	printf("Test Case 4\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 4 FAILED\n");
		return -7;
	}
	curve25519_key_printf(&key, STR);
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 4 FAILED\n");
			return -8;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 4 PASSED\n---\n\n");
	printf("Test Case 5\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 5 FAILED\n");
		return -9;
	}
	curve25519_key_printf(&key, STR);
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 5 FAILED\n");
			return -10;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 5 PASSED\n---\n\n");
	return 0;
}