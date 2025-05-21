#include "../tests.h"

int32_t curve25519_priv_key_init_test(void) {
	printf("Private Key Initialization Test\n");
	curve25519_key_t key = {.key64 = { }};
	curve25519_key_t prev_key = {.key64 = { }};
	printf("Test Case 1\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 1 FAILED\n");
		return -1;
	}
	for (size_t i = 0; i < 8; ++i) {
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
		return -2;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 2 FAILED\n");
			return -3;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 2 PASSED\n---\n\n");
	printf("Test Case 4\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 4 FAILED\n");
		return -4;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 4 FAILED\n");
			return -5;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 4 PASSED\n---\n\n");
	printf("Test Case 6\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 6 FAILED\n");
		return -6;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 6 FAILED\n");
			return -7;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 6 PASSED\n---\n\n");
	printf("Test Case 8\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 8 FAILED\n");
		return -8;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 8 FAILED\n");
			return -9;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 8 PASSED\n---\n\n");
	printf("Test Case 10\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 10 FAILED\n");
		return -10;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 10 FAILED\n");
			return -11;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 10 PASSED\n---\n\n");
	printf("Test Case 12\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 12 FAILED\n");
		return -12;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 12 FAILED\n");
			return -13;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 12 PASSED\n---\n\n");
	printf("Test Case 14\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 14 FAILED\n");
		return -14;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 14 FAILED\n");
			return -15;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 14 PASSED\n---\n\n");
	printf("Test Case 16\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 16 FAILED\n");
		return -16;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 16 FAILED\n");
			return -17;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 16 PASSED\n---\n\n");
	printf("Test Case 18\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 18 FAILED\n");
		return -18;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 18 FAILED\n");
			return -19;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 18 PASSED\n---\n\n");
	printf("Test Case 20\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 20 FAILED\n");
		return -20;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 20 FAILED\n");
			return -21;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 20 PASSED\n---\n\n");
	printf("Test Case 22\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 22 FAILED\n");
		return -22;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 22 FAILED\n");
			return -23;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 22 PASSED\n---\n\n");
	printf("Test Case 24\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 24 FAILED\n");
		return -24;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 24 FAILED\n");
			return -25;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 24 PASSED\n---\n\n");
	printf("Test Case 26\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 26 FAILED\n");
		return -26;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 26 FAILED\n");
			return -27;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 26 PASSED\n---\n\n");
	printf("Test Case 28\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 28 FAILED\n");
		return -28;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 28 FAILED\n");
			return -29;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 28 PASSED\n---\n\n");
	printf("Test Case 30\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 30 FAILED\n");
		return -30;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 30 FAILED\n");
			return -31;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 30 PASSED\n---\n\n");
	printf("Test Case 32\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 32 FAILED\n");
		return -32;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 32 FAILED\n");
			return -33;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 32 PASSED\n---\n\n");
	printf("Test Case 34\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 34 FAILED\n");
		return -34;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 34 FAILED\n");
			return -35;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 34 PASSED\n---\n\n");
	printf("Test Case 36\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 36 FAILED\n");
		return -36;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 36 FAILED\n");
			return -37;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 36 PASSED\n---\n\n");
	printf("Test Case 38\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 38 FAILED\n");
		return -38;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 38 FAILED\n");
			return -39;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 38 PASSED\n---\n\n");
	printf("Test Case 40\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 40 FAILED\n");
		return -40;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 40 FAILED\n");
			return -41;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 40 PASSED\n---\n\n");
	printf("Test Case 42\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 42 FAILED\n");
		return -42;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 42 FAILED\n");
			return -43;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 42 PASSED\n---\n\n");
	printf("Test Case 44\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 44 FAILED\n");
		return -44;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 44 FAILED\n");
			return -45;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 44 PASSED\n---\n\n");
	printf("Test Case 46\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 46 FAILED\n");
		return -46;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 46 FAILED\n");
			return -47;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 46 PASSED\n---\n\n");
	printf("Test Case 48\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 48 FAILED\n");
		return -48;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 48 FAILED\n");
			return -49;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 48 PASSED\n---\n\n");
	printf("Test Case 50\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 50 FAILED\n");
		return -50;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 50 FAILED\n");
			return -51;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 50 PASSED\n---\n\n");
	printf("Test Case 52\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 52 FAILED\n");
		return -52;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 52 FAILED\n");
			return -53;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 52 PASSED\n---\n\n");
	printf("Test Case 54\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 54 FAILED\n");
		return -54;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 54 FAILED\n");
			return -55;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 54 PASSED\n---\n\n");
	printf("Test Case 56\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 56 FAILED\n");
		return -56;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 56 FAILED\n");
			return -57;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 56 PASSED\n---\n\n");
	printf("Test Case 58\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 58 FAILED\n");
		return -58;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 58 FAILED\n");
			return -59;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 58 PASSED\n---\n\n");
	printf("Test Case 60\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 60 FAILED\n");
		return -60;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 60 FAILED\n");
			return -61;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 60 PASSED\n---\n\n");
	printf("Test Case 62\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 62 FAILED\n");
		return -62;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 62 FAILED\n");
			return -63;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 62 PASSED\n---\n\n");
	printf("Test Case 64\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 64 FAILED\n");
		return -64;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 64 FAILED\n");
			return -65;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 64 PASSED\n---\n\n");
	printf("Test Case 66\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 66 FAILED\n");
		return -66;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 66 FAILED\n");
			return -67;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 66 PASSED\n---\n\n");
	printf("Test Case 68\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 68 FAILED\n");
		return -68;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 68 FAILED\n");
			return -69;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 68 PASSED\n---\n\n");
	printf("Test Case 70\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 70 FAILED\n");
		return -70;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 70 FAILED\n");
			return -71;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 70 PASSED\n---\n\n");
	printf("Test Case 72\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 72 FAILED\n");
		return -72;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 72 FAILED\n");
			return -73;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 72 PASSED\n---\n\n");
	printf("Test Case 74\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 74 FAILED\n");
		return -74;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 74 FAILED\n");
			return -75;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 74 PASSED\n---\n\n");
	printf("Test Case 76\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 76 FAILED\n");
		return -76;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 76 FAILED\n");
			return -77;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 76 PASSED\n---\n\n");
	printf("Test Case 78\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 78 FAILED\n");
		return -78;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 78 FAILED\n");
			return -79;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 78 PASSED\n---\n\n");
	printf("Test Case 80\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 80 FAILED\n");
		return -80;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 80 FAILED\n");
			return -81;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 80 PASSED\n---\n\n");
	printf("Test Case 82\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 82 FAILED\n");
		return -82;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 82 FAILED\n");
			return -83;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 82 PASSED\n---\n\n");
	printf("Test Case 84\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 84 FAILED\n");
		return -84;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 84 FAILED\n");
			return -85;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 84 PASSED\n---\n\n");
	printf("Test Case 86\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 86 FAILED\n");
		return -86;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 86 FAILED\n");
			return -87;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 86 PASSED\n---\n\n");
	printf("Test Case 88\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 88 FAILED\n");
		return -88;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 88 FAILED\n");
			return -89;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 88 PASSED\n---\n\n");
	printf("Test Case 90\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 90 FAILED\n");
		return -90;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 90 FAILED\n");
			return -91;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 90 PASSED\n---\n\n");
	printf("Test Case 92\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 92 FAILED\n");
		return -92;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 92 FAILED\n");
			return -93;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 92 PASSED\n---\n\n");
	printf("Test Case 94\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 94 FAILED\n");
		return -94;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 94 FAILED\n");
			return -95;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 94 PASSED\n---\n\n");
	printf("Test Case 96\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 96 FAILED\n");
		return -96;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 96 FAILED\n");
			return -97;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 96 PASSED\n---\n\n");
	printf("Test Case 98\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 98 FAILED\n");
		return -98;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 98 FAILED\n");
			return -99;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 98 PASSED\n---\n\n");
	printf("Test Case 100\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 100 FAILED\n");
		return -100;
	}
	for (size_t i = 0; i < 8; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 100 FAILED\n");
			return -101;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 100 PASSED\n---\n\n");
	return 0;
}