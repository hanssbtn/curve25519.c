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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
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
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 100 FAILED\n");
			return -101;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 100 PASSED\n---\n\n");
	printf("Test Case 102\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 102 FAILED\n");
		return -102;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 102 FAILED\n");
			return -103;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 102 PASSED\n---\n\n");
	printf("Test Case 104\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 104 FAILED\n");
		return -104;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 104 FAILED\n");
			return -105;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 104 PASSED\n---\n\n");
	printf("Test Case 106\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 106 FAILED\n");
		return -106;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 106 FAILED\n");
			return -107;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 106 PASSED\n---\n\n");
	printf("Test Case 108\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 108 FAILED\n");
		return -108;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 108 FAILED\n");
			return -109;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 108 PASSED\n---\n\n");
	printf("Test Case 110\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 110 FAILED\n");
		return -110;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 110 FAILED\n");
			return -111;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 110 PASSED\n---\n\n");
	printf("Test Case 112\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 112 FAILED\n");
		return -112;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 112 FAILED\n");
			return -113;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 112 PASSED\n---\n\n");
	printf("Test Case 114\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 114 FAILED\n");
		return -114;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 114 FAILED\n");
			return -115;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 114 PASSED\n---\n\n");
	printf("Test Case 116\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 116 FAILED\n");
		return -116;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 116 FAILED\n");
			return -117;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 116 PASSED\n---\n\n");
	printf("Test Case 118\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 118 FAILED\n");
		return -118;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 118 FAILED\n");
			return -119;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 118 PASSED\n---\n\n");
	printf("Test Case 120\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 120 FAILED\n");
		return -120;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 120 FAILED\n");
			return -121;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 120 PASSED\n---\n\n");
	printf("Test Case 122\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 122 FAILED\n");
		return -122;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 122 FAILED\n");
			return -123;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 122 PASSED\n---\n\n");
	printf("Test Case 124\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 124 FAILED\n");
		return -124;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 124 FAILED\n");
			return -125;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 124 PASSED\n---\n\n");
	printf("Test Case 126\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 126 FAILED\n");
		return -126;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 126 FAILED\n");
			return -127;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 126 PASSED\n---\n\n");
	printf("Test Case 128\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 128 FAILED\n");
		return -128;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 128 FAILED\n");
			return -129;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 128 PASSED\n---\n\n");
	printf("Test Case 130\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 130 FAILED\n");
		return -130;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 130 FAILED\n");
			return -131;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 130 PASSED\n---\n\n");
	printf("Test Case 132\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 132 FAILED\n");
		return -132;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 132 FAILED\n");
			return -133;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 132 PASSED\n---\n\n");
	printf("Test Case 134\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 134 FAILED\n");
		return -134;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 134 FAILED\n");
			return -135;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 134 PASSED\n---\n\n");
	printf("Test Case 136\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 136 FAILED\n");
		return -136;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 136 FAILED\n");
			return -137;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 136 PASSED\n---\n\n");
	printf("Test Case 138\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 138 FAILED\n");
		return -138;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 138 FAILED\n");
			return -139;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 138 PASSED\n---\n\n");
	printf("Test Case 140\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 140 FAILED\n");
		return -140;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 140 FAILED\n");
			return -141;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 140 PASSED\n---\n\n");
	printf("Test Case 142\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 142 FAILED\n");
		return -142;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 142 FAILED\n");
			return -143;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 142 PASSED\n---\n\n");
	printf("Test Case 144\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 144 FAILED\n");
		return -144;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 144 FAILED\n");
			return -145;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 144 PASSED\n---\n\n");
	printf("Test Case 146\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 146 FAILED\n");
		return -146;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 146 FAILED\n");
			return -147;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 146 PASSED\n---\n\n");
	printf("Test Case 148\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 148 FAILED\n");
		return -148;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 148 FAILED\n");
			return -149;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 148 PASSED\n---\n\n");
	printf("Test Case 150\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 150 FAILED\n");
		return -150;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 150 FAILED\n");
			return -151;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 150 PASSED\n---\n\n");
	printf("Test Case 152\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 152 FAILED\n");
		return -152;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 152 FAILED\n");
			return -153;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 152 PASSED\n---\n\n");
	printf("Test Case 154\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 154 FAILED\n");
		return -154;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 154 FAILED\n");
			return -155;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 154 PASSED\n---\n\n");
	printf("Test Case 156\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 156 FAILED\n");
		return -156;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 156 FAILED\n");
			return -157;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 156 PASSED\n---\n\n");
	printf("Test Case 158\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 158 FAILED\n");
		return -158;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 158 FAILED\n");
			return -159;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 158 PASSED\n---\n\n");
	printf("Test Case 160\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 160 FAILED\n");
		return -160;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 160 FAILED\n");
			return -161;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 160 PASSED\n---\n\n");
	printf("Test Case 162\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 162 FAILED\n");
		return -162;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 162 FAILED\n");
			return -163;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 162 PASSED\n---\n\n");
	printf("Test Case 164\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 164 FAILED\n");
		return -164;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 164 FAILED\n");
			return -165;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 164 PASSED\n---\n\n");
	printf("Test Case 166\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 166 FAILED\n");
		return -166;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 166 FAILED\n");
			return -167;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 166 PASSED\n---\n\n");
	printf("Test Case 168\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 168 FAILED\n");
		return -168;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 168 FAILED\n");
			return -169;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 168 PASSED\n---\n\n");
	printf("Test Case 170\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 170 FAILED\n");
		return -170;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 170 FAILED\n");
			return -171;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 170 PASSED\n---\n\n");
	printf("Test Case 172\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 172 FAILED\n");
		return -172;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 172 FAILED\n");
			return -173;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 172 PASSED\n---\n\n");
	printf("Test Case 174\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 174 FAILED\n");
		return -174;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 174 FAILED\n");
			return -175;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 174 PASSED\n---\n\n");
	printf("Test Case 176\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 176 FAILED\n");
		return -176;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 176 FAILED\n");
			return -177;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 176 PASSED\n---\n\n");
	printf("Test Case 178\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 178 FAILED\n");
		return -178;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 178 FAILED\n");
			return -179;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 178 PASSED\n---\n\n");
	printf("Test Case 180\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 180 FAILED\n");
		return -180;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 180 FAILED\n");
			return -181;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 180 PASSED\n---\n\n");
	printf("Test Case 182\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 182 FAILED\n");
		return -182;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 182 FAILED\n");
			return -183;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 182 PASSED\n---\n\n");
	printf("Test Case 184\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 184 FAILED\n");
		return -184;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 184 FAILED\n");
			return -185;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 184 PASSED\n---\n\n");
	printf("Test Case 186\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 186 FAILED\n");
		return -186;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 186 FAILED\n");
			return -187;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 186 PASSED\n---\n\n");
	printf("Test Case 188\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 188 FAILED\n");
		return -188;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 188 FAILED\n");
			return -189;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 188 PASSED\n---\n\n");
	printf("Test Case 190\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 190 FAILED\n");
		return -190;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 190 FAILED\n");
			return -191;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 190 PASSED\n---\n\n");
	printf("Test Case 192\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 192 FAILED\n");
		return -192;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 192 FAILED\n");
			return -193;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 192 PASSED\n---\n\n");
	printf("Test Case 194\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 194 FAILED\n");
		return -194;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 194 FAILED\n");
			return -195;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 194 PASSED\n---\n\n");
	printf("Test Case 196\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 196 FAILED\n");
		return -196;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 196 FAILED\n");
			return -197;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 196 PASSED\n---\n\n");
	printf("Test Case 198\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 198 FAILED\n");
		return -198;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 198 FAILED\n");
			return -199;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 198 PASSED\n---\n\n");
	printf("Test Case 200\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 200 FAILED\n");
		return -200;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 200 FAILED\n");
			return -201;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 200 PASSED\n---\n\n");
	printf("Test Case 202\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 202 FAILED\n");
		return -202;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 202 FAILED\n");
			return -203;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 202 PASSED\n---\n\n");
	printf("Test Case 204\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 204 FAILED\n");
		return -204;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 204 FAILED\n");
			return -205;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 204 PASSED\n---\n\n");
	printf("Test Case 206\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 206 FAILED\n");
		return -206;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 206 FAILED\n");
			return -207;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 206 PASSED\n---\n\n");
	printf("Test Case 208\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 208 FAILED\n");
		return -208;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 208 FAILED\n");
			return -209;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 208 PASSED\n---\n\n");
	printf("Test Case 210\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 210 FAILED\n");
		return -210;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 210 FAILED\n");
			return -211;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 210 PASSED\n---\n\n");
	printf("Test Case 212\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 212 FAILED\n");
		return -212;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 212 FAILED\n");
			return -213;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 212 PASSED\n---\n\n");
	printf("Test Case 214\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 214 FAILED\n");
		return -214;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 214 FAILED\n");
			return -215;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 214 PASSED\n---\n\n");
	printf("Test Case 216\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 216 FAILED\n");
		return -216;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 216 FAILED\n");
			return -217;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 216 PASSED\n---\n\n");
	printf("Test Case 218\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 218 FAILED\n");
		return -218;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 218 FAILED\n");
			return -219;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 218 PASSED\n---\n\n");
	printf("Test Case 220\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 220 FAILED\n");
		return -220;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 220 FAILED\n");
			return -221;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 220 PASSED\n---\n\n");
	printf("Test Case 222\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 222 FAILED\n");
		return -222;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 222 FAILED\n");
			return -223;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 222 PASSED\n---\n\n");
	printf("Test Case 224\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 224 FAILED\n");
		return -224;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 224 FAILED\n");
			return -225;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 224 PASSED\n---\n\n");
	printf("Test Case 226\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 226 FAILED\n");
		return -226;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 226 FAILED\n");
			return -227;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 226 PASSED\n---\n\n");
	printf("Test Case 228\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 228 FAILED\n");
		return -228;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 228 FAILED\n");
			return -229;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 228 PASSED\n---\n\n");
	printf("Test Case 230\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 230 FAILED\n");
		return -230;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 230 FAILED\n");
			return -231;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 230 PASSED\n---\n\n");
	printf("Test Case 232\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 232 FAILED\n");
		return -232;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 232 FAILED\n");
			return -233;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 232 PASSED\n---\n\n");
	printf("Test Case 234\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 234 FAILED\n");
		return -234;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 234 FAILED\n");
			return -235;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 234 PASSED\n---\n\n");
	printf("Test Case 236\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 236 FAILED\n");
		return -236;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 236 FAILED\n");
			return -237;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 236 PASSED\n---\n\n");
	printf("Test Case 238\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 238 FAILED\n");
		return -238;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 238 FAILED\n");
			return -239;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 238 PASSED\n---\n\n");
	printf("Test Case 240\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 240 FAILED\n");
		return -240;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 240 FAILED\n");
			return -241;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 240 PASSED\n---\n\n");
	printf("Test Case 242\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 242 FAILED\n");
		return -242;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 242 FAILED\n");
			return -243;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 242 PASSED\n---\n\n");
	printf("Test Case 244\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 244 FAILED\n");
		return -244;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 244 FAILED\n");
			return -245;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 244 PASSED\n---\n\n");
	printf("Test Case 246\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 246 FAILED\n");
		return -246;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 246 FAILED\n");
			return -247;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 246 PASSED\n---\n\n");
	printf("Test Case 248\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 248 FAILED\n");
		return -248;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 248 FAILED\n");
			return -249;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 248 PASSED\n---\n\n");
	printf("Test Case 250\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 250 FAILED\n");
		return -250;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 250 FAILED\n");
			return -251;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 250 PASSED\n---\n\n");
	printf("Test Case 252\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 252 FAILED\n");
		return -252;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 252 FAILED\n");
			return -253;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 252 PASSED\n---\n\n");
	printf("Test Case 254\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 254 FAILED\n");
		return -254;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 254 FAILED\n");
			return -255;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 254 PASSED\n---\n\n");
	printf("Test Case 256\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 256 FAILED\n");
		return -256;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 256 FAILED\n");
			return -257;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 256 PASSED\n---\n\n");
	printf("Test Case 258\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 258 FAILED\n");
		return -258;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 258 FAILED\n");
			return -259;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 258 PASSED\n---\n\n");
	printf("Test Case 260\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 260 FAILED\n");
		return -260;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 260 FAILED\n");
			return -261;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 260 PASSED\n---\n\n");
	printf("Test Case 262\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 262 FAILED\n");
		return -262;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 262 FAILED\n");
			return -263;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 262 PASSED\n---\n\n");
	printf("Test Case 264\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 264 FAILED\n");
		return -264;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 264 FAILED\n");
			return -265;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 264 PASSED\n---\n\n");
	printf("Test Case 266\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 266 FAILED\n");
		return -266;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 266 FAILED\n");
			return -267;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 266 PASSED\n---\n\n");
	printf("Test Case 268\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 268 FAILED\n");
		return -268;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 268 FAILED\n");
			return -269;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 268 PASSED\n---\n\n");
	printf("Test Case 270\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 270 FAILED\n");
		return -270;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 270 FAILED\n");
			return -271;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 270 PASSED\n---\n\n");
	printf("Test Case 272\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 272 FAILED\n");
		return -272;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 272 FAILED\n");
			return -273;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 272 PASSED\n---\n\n");
	printf("Test Case 274\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 274 FAILED\n");
		return -274;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 274 FAILED\n");
			return -275;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 274 PASSED\n---\n\n");
	printf("Test Case 276\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 276 FAILED\n");
		return -276;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 276 FAILED\n");
			return -277;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 276 PASSED\n---\n\n");
	printf("Test Case 278\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 278 FAILED\n");
		return -278;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 278 FAILED\n");
			return -279;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 278 PASSED\n---\n\n");
	printf("Test Case 280\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 280 FAILED\n");
		return -280;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 280 FAILED\n");
			return -281;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 280 PASSED\n---\n\n");
	printf("Test Case 282\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 282 FAILED\n");
		return -282;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 282 FAILED\n");
			return -283;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 282 PASSED\n---\n\n");
	printf("Test Case 284\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 284 FAILED\n");
		return -284;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 284 FAILED\n");
			return -285;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 284 PASSED\n---\n\n");
	printf("Test Case 286\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 286 FAILED\n");
		return -286;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 286 FAILED\n");
			return -287;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 286 PASSED\n---\n\n");
	printf("Test Case 288\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 288 FAILED\n");
		return -288;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 288 FAILED\n");
			return -289;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 288 PASSED\n---\n\n");
	printf("Test Case 290\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 290 FAILED\n");
		return -290;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 290 FAILED\n");
			return -291;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 290 PASSED\n---\n\n");
	printf("Test Case 292\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 292 FAILED\n");
		return -292;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 292 FAILED\n");
			return -293;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 292 PASSED\n---\n\n");
	printf("Test Case 294\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 294 FAILED\n");
		return -294;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 294 FAILED\n");
			return -295;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 294 PASSED\n---\n\n");
	printf("Test Case 296\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 296 FAILED\n");
		return -296;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 296 FAILED\n");
			return -297;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 296 PASSED\n---\n\n");
	printf("Test Case 298\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 298 FAILED\n");
		return -298;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 298 FAILED\n");
			return -299;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 298 PASSED\n---\n\n");
	printf("Test Case 300\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 300 FAILED\n");
		return -300;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 300 FAILED\n");
			return -301;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 300 PASSED\n---\n\n");
	printf("Test Case 302\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 302 FAILED\n");
		return -302;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 302 FAILED\n");
			return -303;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 302 PASSED\n---\n\n");
	printf("Test Case 304\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 304 FAILED\n");
		return -304;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 304 FAILED\n");
			return -305;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 304 PASSED\n---\n\n");
	printf("Test Case 306\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 306 FAILED\n");
		return -306;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 306 FAILED\n");
			return -307;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 306 PASSED\n---\n\n");
	printf("Test Case 308\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 308 FAILED\n");
		return -308;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 308 FAILED\n");
			return -309;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 308 PASSED\n---\n\n");
	printf("Test Case 310\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 310 FAILED\n");
		return -310;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 310 FAILED\n");
			return -311;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 310 PASSED\n---\n\n");
	printf("Test Case 312\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 312 FAILED\n");
		return -312;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 312 FAILED\n");
			return -313;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 312 PASSED\n---\n\n");
	printf("Test Case 314\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 314 FAILED\n");
		return -314;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 314 FAILED\n");
			return -315;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 314 PASSED\n---\n\n");
	printf("Test Case 316\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 316 FAILED\n");
		return -316;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 316 FAILED\n");
			return -317;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 316 PASSED\n---\n\n");
	printf("Test Case 318\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 318 FAILED\n");
		return -318;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 318 FAILED\n");
			return -319;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 318 PASSED\n---\n\n");
	printf("Test Case 320\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 320 FAILED\n");
		return -320;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 320 FAILED\n");
			return -321;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 320 PASSED\n---\n\n");
	printf("Test Case 322\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 322 FAILED\n");
		return -322;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 322 FAILED\n");
			return -323;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 322 PASSED\n---\n\n");
	printf("Test Case 324\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 324 FAILED\n");
		return -324;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 324 FAILED\n");
			return -325;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 324 PASSED\n---\n\n");
	printf("Test Case 326\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 326 FAILED\n");
		return -326;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 326 FAILED\n");
			return -327;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 326 PASSED\n---\n\n");
	printf("Test Case 328\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 328 FAILED\n");
		return -328;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 328 FAILED\n");
			return -329;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 328 PASSED\n---\n\n");
	printf("Test Case 330\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 330 FAILED\n");
		return -330;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 330 FAILED\n");
			return -331;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 330 PASSED\n---\n\n");
	printf("Test Case 332\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 332 FAILED\n");
		return -332;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 332 FAILED\n");
			return -333;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 332 PASSED\n---\n\n");
	printf("Test Case 334\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 334 FAILED\n");
		return -334;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 334 FAILED\n");
			return -335;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 334 PASSED\n---\n\n");
	printf("Test Case 336\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 336 FAILED\n");
		return -336;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 336 FAILED\n");
			return -337;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 336 PASSED\n---\n\n");
	printf("Test Case 338\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 338 FAILED\n");
		return -338;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 338 FAILED\n");
			return -339;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 338 PASSED\n---\n\n");
	printf("Test Case 340\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 340 FAILED\n");
		return -340;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 340 FAILED\n");
			return -341;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 340 PASSED\n---\n\n");
	printf("Test Case 342\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 342 FAILED\n");
		return -342;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 342 FAILED\n");
			return -343;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 342 PASSED\n---\n\n");
	printf("Test Case 344\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 344 FAILED\n");
		return -344;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 344 FAILED\n");
			return -345;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 344 PASSED\n---\n\n");
	printf("Test Case 346\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 346 FAILED\n");
		return -346;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 346 FAILED\n");
			return -347;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 346 PASSED\n---\n\n");
	printf("Test Case 348\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 348 FAILED\n");
		return -348;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 348 FAILED\n");
			return -349;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 348 PASSED\n---\n\n");
	printf("Test Case 350\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 350 FAILED\n");
		return -350;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 350 FAILED\n");
			return -351;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 350 PASSED\n---\n\n");
	printf("Test Case 352\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 352 FAILED\n");
		return -352;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 352 FAILED\n");
			return -353;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 352 PASSED\n---\n\n");
	printf("Test Case 354\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 354 FAILED\n");
		return -354;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 354 FAILED\n");
			return -355;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 354 PASSED\n---\n\n");
	printf("Test Case 356\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 356 FAILED\n");
		return -356;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 356 FAILED\n");
			return -357;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 356 PASSED\n---\n\n");
	printf("Test Case 358\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 358 FAILED\n");
		return -358;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 358 FAILED\n");
			return -359;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 358 PASSED\n---\n\n");
	printf("Test Case 360\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 360 FAILED\n");
		return -360;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 360 FAILED\n");
			return -361;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 360 PASSED\n---\n\n");
	printf("Test Case 362\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 362 FAILED\n");
		return -362;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 362 FAILED\n");
			return -363;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 362 PASSED\n---\n\n");
	printf("Test Case 364\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 364 FAILED\n");
		return -364;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 364 FAILED\n");
			return -365;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 364 PASSED\n---\n\n");
	printf("Test Case 366\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 366 FAILED\n");
		return -366;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 366 FAILED\n");
			return -367;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 366 PASSED\n---\n\n");
	printf("Test Case 368\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 368 FAILED\n");
		return -368;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 368 FAILED\n");
			return -369;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 368 PASSED\n---\n\n");
	printf("Test Case 370\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 370 FAILED\n");
		return -370;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 370 FAILED\n");
			return -371;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 370 PASSED\n---\n\n");
	printf("Test Case 372\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 372 FAILED\n");
		return -372;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 372 FAILED\n");
			return -373;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 372 PASSED\n---\n\n");
	printf("Test Case 374\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 374 FAILED\n");
		return -374;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 374 FAILED\n");
			return -375;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 374 PASSED\n---\n\n");
	printf("Test Case 376\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 376 FAILED\n");
		return -376;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 376 FAILED\n");
			return -377;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 376 PASSED\n---\n\n");
	printf("Test Case 378\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 378 FAILED\n");
		return -378;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 378 FAILED\n");
			return -379;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 378 PASSED\n---\n\n");
	printf("Test Case 380\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 380 FAILED\n");
		return -380;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 380 FAILED\n");
			return -381;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 380 PASSED\n---\n\n");
	printf("Test Case 382\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 382 FAILED\n");
		return -382;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 382 FAILED\n");
			return -383;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 382 PASSED\n---\n\n");
	printf("Test Case 384\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 384 FAILED\n");
		return -384;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 384 FAILED\n");
			return -385;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 384 PASSED\n---\n\n");
	printf("Test Case 386\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 386 FAILED\n");
		return -386;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 386 FAILED\n");
			return -387;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 386 PASSED\n---\n\n");
	printf("Test Case 388\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 388 FAILED\n");
		return -388;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 388 FAILED\n");
			return -389;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 388 PASSED\n---\n\n");
	printf("Test Case 390\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 390 FAILED\n");
		return -390;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 390 FAILED\n");
			return -391;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 390 PASSED\n---\n\n");
	printf("Test Case 392\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 392 FAILED\n");
		return -392;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 392 FAILED\n");
			return -393;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 392 PASSED\n---\n\n");
	printf("Test Case 394\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 394 FAILED\n");
		return -394;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 394 FAILED\n");
			return -395;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 394 PASSED\n---\n\n");
	printf("Test Case 396\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 396 FAILED\n");
		return -396;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 396 FAILED\n");
			return -397;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 396 PASSED\n---\n\n");
	printf("Test Case 398\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 398 FAILED\n");
		return -398;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 398 FAILED\n");
			return -399;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 398 PASSED\n---\n\n");
	printf("Test Case 400\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 400 FAILED\n");
		return -400;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 400 FAILED\n");
			return -401;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 400 PASSED\n---\n\n");
	printf("Test Case 402\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 402 FAILED\n");
		return -402;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 402 FAILED\n");
			return -403;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 402 PASSED\n---\n\n");
	printf("Test Case 404\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 404 FAILED\n");
		return -404;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 404 FAILED\n");
			return -405;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 404 PASSED\n---\n\n");
	printf("Test Case 406\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 406 FAILED\n");
		return -406;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 406 FAILED\n");
			return -407;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 406 PASSED\n---\n\n");
	printf("Test Case 408\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 408 FAILED\n");
		return -408;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 408 FAILED\n");
			return -409;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 408 PASSED\n---\n\n");
	printf("Test Case 410\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 410 FAILED\n");
		return -410;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 410 FAILED\n");
			return -411;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 410 PASSED\n---\n\n");
	printf("Test Case 412\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 412 FAILED\n");
		return -412;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 412 FAILED\n");
			return -413;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 412 PASSED\n---\n\n");
	printf("Test Case 414\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 414 FAILED\n");
		return -414;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 414 FAILED\n");
			return -415;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 414 PASSED\n---\n\n");
	printf("Test Case 416\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 416 FAILED\n");
		return -416;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 416 FAILED\n");
			return -417;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 416 PASSED\n---\n\n");
	printf("Test Case 418\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 418 FAILED\n");
		return -418;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 418 FAILED\n");
			return -419;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 418 PASSED\n---\n\n");
	printf("Test Case 420\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 420 FAILED\n");
		return -420;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 420 FAILED\n");
			return -421;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 420 PASSED\n---\n\n");
	printf("Test Case 422\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 422 FAILED\n");
		return -422;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 422 FAILED\n");
			return -423;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 422 PASSED\n---\n\n");
	printf("Test Case 424\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 424 FAILED\n");
		return -424;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 424 FAILED\n");
			return -425;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 424 PASSED\n---\n\n");
	printf("Test Case 426\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 426 FAILED\n");
		return -426;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 426 FAILED\n");
			return -427;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 426 PASSED\n---\n\n");
	printf("Test Case 428\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 428 FAILED\n");
		return -428;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 428 FAILED\n");
			return -429;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 428 PASSED\n---\n\n");
	printf("Test Case 430\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 430 FAILED\n");
		return -430;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 430 FAILED\n");
			return -431;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 430 PASSED\n---\n\n");
	printf("Test Case 432\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 432 FAILED\n");
		return -432;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 432 FAILED\n");
			return -433;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 432 PASSED\n---\n\n");
	printf("Test Case 434\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 434 FAILED\n");
		return -434;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 434 FAILED\n");
			return -435;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 434 PASSED\n---\n\n");
	printf("Test Case 436\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 436 FAILED\n");
		return -436;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 436 FAILED\n");
			return -437;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 436 PASSED\n---\n\n");
	printf("Test Case 438\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 438 FAILED\n");
		return -438;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 438 FAILED\n");
			return -439;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 438 PASSED\n---\n\n");
	printf("Test Case 440\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 440 FAILED\n");
		return -440;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 440 FAILED\n");
			return -441;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 440 PASSED\n---\n\n");
	printf("Test Case 442\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 442 FAILED\n");
		return -442;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 442 FAILED\n");
			return -443;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 442 PASSED\n---\n\n");
	printf("Test Case 444\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 444 FAILED\n");
		return -444;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 444 FAILED\n");
			return -445;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 444 PASSED\n---\n\n");
	printf("Test Case 446\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 446 FAILED\n");
		return -446;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 446 FAILED\n");
			return -447;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 446 PASSED\n---\n\n");
	printf("Test Case 448\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 448 FAILED\n");
		return -448;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 448 FAILED\n");
			return -449;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 448 PASSED\n---\n\n");
	printf("Test Case 450\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 450 FAILED\n");
		return -450;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 450 FAILED\n");
			return -451;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 450 PASSED\n---\n\n");
	printf("Test Case 452\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 452 FAILED\n");
		return -452;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 452 FAILED\n");
			return -453;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 452 PASSED\n---\n\n");
	printf("Test Case 454\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 454 FAILED\n");
		return -454;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 454 FAILED\n");
			return -455;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 454 PASSED\n---\n\n");
	printf("Test Case 456\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 456 FAILED\n");
		return -456;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 456 FAILED\n");
			return -457;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 456 PASSED\n---\n\n");
	printf("Test Case 458\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 458 FAILED\n");
		return -458;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 458 FAILED\n");
			return -459;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 458 PASSED\n---\n\n");
	printf("Test Case 460\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 460 FAILED\n");
		return -460;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 460 FAILED\n");
			return -461;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 460 PASSED\n---\n\n");
	printf("Test Case 462\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 462 FAILED\n");
		return -462;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 462 FAILED\n");
			return -463;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 462 PASSED\n---\n\n");
	printf("Test Case 464\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 464 FAILED\n");
		return -464;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 464 FAILED\n");
			return -465;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 464 PASSED\n---\n\n");
	printf("Test Case 466\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 466 FAILED\n");
		return -466;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 466 FAILED\n");
			return -467;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 466 PASSED\n---\n\n");
	printf("Test Case 468\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 468 FAILED\n");
		return -468;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 468 FAILED\n");
			return -469;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 468 PASSED\n---\n\n");
	printf("Test Case 470\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 470 FAILED\n");
		return -470;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 470 FAILED\n");
			return -471;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 470 PASSED\n---\n\n");
	printf("Test Case 472\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 472 FAILED\n");
		return -472;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 472 FAILED\n");
			return -473;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 472 PASSED\n---\n\n");
	printf("Test Case 474\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 474 FAILED\n");
		return -474;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 474 FAILED\n");
			return -475;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 474 PASSED\n---\n\n");
	printf("Test Case 476\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 476 FAILED\n");
		return -476;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 476 FAILED\n");
			return -477;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 476 PASSED\n---\n\n");
	printf("Test Case 478\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 478 FAILED\n");
		return -478;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 478 FAILED\n");
			return -479;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 478 PASSED\n---\n\n");
	printf("Test Case 480\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 480 FAILED\n");
		return -480;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 480 FAILED\n");
			return -481;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 480 PASSED\n---\n\n");
	printf("Test Case 482\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 482 FAILED\n");
		return -482;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 482 FAILED\n");
			return -483;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 482 PASSED\n---\n\n");
	printf("Test Case 484\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 484 FAILED\n");
		return -484;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 484 FAILED\n");
			return -485;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 484 PASSED\n---\n\n");
	printf("Test Case 486\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 486 FAILED\n");
		return -486;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 486 FAILED\n");
			return -487;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 486 PASSED\n---\n\n");
	printf("Test Case 488\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 488 FAILED\n");
		return -488;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 488 FAILED\n");
			return -489;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 488 PASSED\n---\n\n");
	printf("Test Case 490\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 490 FAILED\n");
		return -490;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 490 FAILED\n");
			return -491;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 490 PASSED\n---\n\n");
	printf("Test Case 492\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 492 FAILED\n");
		return -492;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 492 FAILED\n");
			return -493;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 492 PASSED\n---\n\n");
	printf("Test Case 494\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 494 FAILED\n");
		return -494;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 494 FAILED\n");
			return -495;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 494 PASSED\n---\n\n");
	printf("Test Case 496\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 496 FAILED\n");
		return -496;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 496 FAILED\n");
			return -497;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 496 PASSED\n---\n\n");
	printf("Test Case 498\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 498 FAILED\n");
		return -498;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 498 FAILED\n");
			return -499;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 498 PASSED\n---\n\n");
	printf("Test Case 500\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 500 FAILED\n");
		return -500;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 500 FAILED\n");
			return -501;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 500 PASSED\n---\n\n");
	printf("Test Case 502\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 502 FAILED\n");
		return -502;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 502 FAILED\n");
			return -503;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 502 PASSED\n---\n\n");
	printf("Test Case 504\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 504 FAILED\n");
		return -504;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 504 FAILED\n");
			return -505;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 504 PASSED\n---\n\n");
	printf("Test Case 506\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 506 FAILED\n");
		return -506;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 506 FAILED\n");
			return -507;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 506 PASSED\n---\n\n");
	printf("Test Case 508\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 508 FAILED\n");
		return -508;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 508 FAILED\n");
			return -509;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 508 PASSED\n---\n\n");
	printf("Test Case 510\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 510 FAILED\n");
		return -510;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 510 FAILED\n");
			return -511;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 510 PASSED\n---\n\n");
	printf("Test Case 512\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 512 FAILED\n");
		return -512;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 512 FAILED\n");
			return -513;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 512 PASSED\n---\n\n");
	printf("Test Case 514\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 514 FAILED\n");
		return -514;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 514 FAILED\n");
			return -515;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 514 PASSED\n---\n\n");
	printf("Test Case 516\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 516 FAILED\n");
		return -516;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 516 FAILED\n");
			return -517;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 516 PASSED\n---\n\n");
	printf("Test Case 518\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 518 FAILED\n");
		return -518;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 518 FAILED\n");
			return -519;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 518 PASSED\n---\n\n");
	printf("Test Case 520\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 520 FAILED\n");
		return -520;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 520 FAILED\n");
			return -521;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 520 PASSED\n---\n\n");
	printf("Test Case 522\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 522 FAILED\n");
		return -522;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 522 FAILED\n");
			return -523;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 522 PASSED\n---\n\n");
	printf("Test Case 524\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 524 FAILED\n");
		return -524;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 524 FAILED\n");
			return -525;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 524 PASSED\n---\n\n");
	printf("Test Case 526\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 526 FAILED\n");
		return -526;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 526 FAILED\n");
			return -527;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 526 PASSED\n---\n\n");
	printf("Test Case 528\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 528 FAILED\n");
		return -528;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 528 FAILED\n");
			return -529;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 528 PASSED\n---\n\n");
	printf("Test Case 530\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 530 FAILED\n");
		return -530;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 530 FAILED\n");
			return -531;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 530 PASSED\n---\n\n");
	printf("Test Case 532\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 532 FAILED\n");
		return -532;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 532 FAILED\n");
			return -533;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 532 PASSED\n---\n\n");
	printf("Test Case 534\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 534 FAILED\n");
		return -534;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 534 FAILED\n");
			return -535;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 534 PASSED\n---\n\n");
	printf("Test Case 536\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 536 FAILED\n");
		return -536;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 536 FAILED\n");
			return -537;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 536 PASSED\n---\n\n");
	printf("Test Case 538\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 538 FAILED\n");
		return -538;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 538 FAILED\n");
			return -539;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 538 PASSED\n---\n\n");
	printf("Test Case 540\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 540 FAILED\n");
		return -540;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 540 FAILED\n");
			return -541;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 540 PASSED\n---\n\n");
	printf("Test Case 542\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 542 FAILED\n");
		return -542;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 542 FAILED\n");
			return -543;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 542 PASSED\n---\n\n");
	printf("Test Case 544\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 544 FAILED\n");
		return -544;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 544 FAILED\n");
			return -545;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 544 PASSED\n---\n\n");
	printf("Test Case 546\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 546 FAILED\n");
		return -546;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 546 FAILED\n");
			return -547;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 546 PASSED\n---\n\n");
	printf("Test Case 548\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 548 FAILED\n");
		return -548;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 548 FAILED\n");
			return -549;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 548 PASSED\n---\n\n");
	printf("Test Case 550\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 550 FAILED\n");
		return -550;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 550 FAILED\n");
			return -551;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 550 PASSED\n---\n\n");
	printf("Test Case 552\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 552 FAILED\n");
		return -552;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 552 FAILED\n");
			return -553;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 552 PASSED\n---\n\n");
	printf("Test Case 554\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 554 FAILED\n");
		return -554;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 554 FAILED\n");
			return -555;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 554 PASSED\n---\n\n");
	printf("Test Case 556\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 556 FAILED\n");
		return -556;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 556 FAILED\n");
			return -557;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 556 PASSED\n---\n\n");
	printf("Test Case 558\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 558 FAILED\n");
		return -558;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 558 FAILED\n");
			return -559;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 558 PASSED\n---\n\n");
	printf("Test Case 560\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 560 FAILED\n");
		return -560;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 560 FAILED\n");
			return -561;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 560 PASSED\n---\n\n");
	printf("Test Case 562\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 562 FAILED\n");
		return -562;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 562 FAILED\n");
			return -563;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 562 PASSED\n---\n\n");
	printf("Test Case 564\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 564 FAILED\n");
		return -564;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 564 FAILED\n");
			return -565;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 564 PASSED\n---\n\n");
	printf("Test Case 566\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 566 FAILED\n");
		return -566;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 566 FAILED\n");
			return -567;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 566 PASSED\n---\n\n");
	printf("Test Case 568\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 568 FAILED\n");
		return -568;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 568 FAILED\n");
			return -569;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 568 PASSED\n---\n\n");
	printf("Test Case 570\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 570 FAILED\n");
		return -570;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 570 FAILED\n");
			return -571;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 570 PASSED\n---\n\n");
	printf("Test Case 572\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 572 FAILED\n");
		return -572;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 572 FAILED\n");
			return -573;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 572 PASSED\n---\n\n");
	printf("Test Case 574\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 574 FAILED\n");
		return -574;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 574 FAILED\n");
			return -575;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 574 PASSED\n---\n\n");
	printf("Test Case 576\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 576 FAILED\n");
		return -576;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 576 FAILED\n");
			return -577;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 576 PASSED\n---\n\n");
	printf("Test Case 578\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 578 FAILED\n");
		return -578;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 578 FAILED\n");
			return -579;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 578 PASSED\n---\n\n");
	printf("Test Case 580\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 580 FAILED\n");
		return -580;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 580 FAILED\n");
			return -581;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 580 PASSED\n---\n\n");
	printf("Test Case 582\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 582 FAILED\n");
		return -582;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 582 FAILED\n");
			return -583;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 582 PASSED\n---\n\n");
	printf("Test Case 584\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 584 FAILED\n");
		return -584;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 584 FAILED\n");
			return -585;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 584 PASSED\n---\n\n");
	printf("Test Case 586\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 586 FAILED\n");
		return -586;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 586 FAILED\n");
			return -587;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 586 PASSED\n---\n\n");
	printf("Test Case 588\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 588 FAILED\n");
		return -588;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 588 FAILED\n");
			return -589;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 588 PASSED\n---\n\n");
	printf("Test Case 590\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 590 FAILED\n");
		return -590;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 590 FAILED\n");
			return -591;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 590 PASSED\n---\n\n");
	printf("Test Case 592\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 592 FAILED\n");
		return -592;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 592 FAILED\n");
			return -593;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 592 PASSED\n---\n\n");
	printf("Test Case 594\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 594 FAILED\n");
		return -594;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 594 FAILED\n");
			return -595;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 594 PASSED\n---\n\n");
	printf("Test Case 596\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 596 FAILED\n");
		return -596;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 596 FAILED\n");
			return -597;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 596 PASSED\n---\n\n");
	printf("Test Case 598\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 598 FAILED\n");
		return -598;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 598 FAILED\n");
			return -599;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 598 PASSED\n---\n\n");
	printf("Test Case 600\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 600 FAILED\n");
		return -600;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 600 FAILED\n");
			return -601;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 600 PASSED\n---\n\n");
	printf("Test Case 602\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 602 FAILED\n");
		return -602;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 602 FAILED\n");
			return -603;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 602 PASSED\n---\n\n");
	printf("Test Case 604\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 604 FAILED\n");
		return -604;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 604 FAILED\n");
			return -605;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 604 PASSED\n---\n\n");
	printf("Test Case 606\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 606 FAILED\n");
		return -606;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 606 FAILED\n");
			return -607;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 606 PASSED\n---\n\n");
	printf("Test Case 608\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 608 FAILED\n");
		return -608;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 608 FAILED\n");
			return -609;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 608 PASSED\n---\n\n");
	printf("Test Case 610\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 610 FAILED\n");
		return -610;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 610 FAILED\n");
			return -611;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 610 PASSED\n---\n\n");
	printf("Test Case 612\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 612 FAILED\n");
		return -612;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 612 FAILED\n");
			return -613;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 612 PASSED\n---\n\n");
	printf("Test Case 614\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 614 FAILED\n");
		return -614;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 614 FAILED\n");
			return -615;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 614 PASSED\n---\n\n");
	printf("Test Case 616\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 616 FAILED\n");
		return -616;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 616 FAILED\n");
			return -617;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 616 PASSED\n---\n\n");
	printf("Test Case 618\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 618 FAILED\n");
		return -618;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 618 FAILED\n");
			return -619;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 618 PASSED\n---\n\n");
	printf("Test Case 620\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 620 FAILED\n");
		return -620;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 620 FAILED\n");
			return -621;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 620 PASSED\n---\n\n");
	printf("Test Case 622\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 622 FAILED\n");
		return -622;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 622 FAILED\n");
			return -623;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 622 PASSED\n---\n\n");
	printf("Test Case 624\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 624 FAILED\n");
		return -624;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 624 FAILED\n");
			return -625;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 624 PASSED\n---\n\n");
	printf("Test Case 626\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 626 FAILED\n");
		return -626;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 626 FAILED\n");
			return -627;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 626 PASSED\n---\n\n");
	printf("Test Case 628\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 628 FAILED\n");
		return -628;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 628 FAILED\n");
			return -629;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 628 PASSED\n---\n\n");
	printf("Test Case 630\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 630 FAILED\n");
		return -630;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 630 FAILED\n");
			return -631;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 630 PASSED\n---\n\n");
	printf("Test Case 632\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 632 FAILED\n");
		return -632;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 632 FAILED\n");
			return -633;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 632 PASSED\n---\n\n");
	printf("Test Case 634\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 634 FAILED\n");
		return -634;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 634 FAILED\n");
			return -635;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 634 PASSED\n---\n\n");
	printf("Test Case 636\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 636 FAILED\n");
		return -636;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 636 FAILED\n");
			return -637;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 636 PASSED\n---\n\n");
	printf("Test Case 638\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 638 FAILED\n");
		return -638;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 638 FAILED\n");
			return -639;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 638 PASSED\n---\n\n");
	printf("Test Case 640\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 640 FAILED\n");
		return -640;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 640 FAILED\n");
			return -641;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 640 PASSED\n---\n\n");
	printf("Test Case 642\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 642 FAILED\n");
		return -642;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 642 FAILED\n");
			return -643;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 642 PASSED\n---\n\n");
	printf("Test Case 644\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 644 FAILED\n");
		return -644;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 644 FAILED\n");
			return -645;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 644 PASSED\n---\n\n");
	printf("Test Case 646\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 646 FAILED\n");
		return -646;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 646 FAILED\n");
			return -647;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 646 PASSED\n---\n\n");
	printf("Test Case 648\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 648 FAILED\n");
		return -648;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 648 FAILED\n");
			return -649;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 648 PASSED\n---\n\n");
	printf("Test Case 650\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 650 FAILED\n");
		return -650;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 650 FAILED\n");
			return -651;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 650 PASSED\n---\n\n");
	printf("Test Case 652\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 652 FAILED\n");
		return -652;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 652 FAILED\n");
			return -653;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 652 PASSED\n---\n\n");
	printf("Test Case 654\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 654 FAILED\n");
		return -654;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 654 FAILED\n");
			return -655;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 654 PASSED\n---\n\n");
	printf("Test Case 656\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 656 FAILED\n");
		return -656;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 656 FAILED\n");
			return -657;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 656 PASSED\n---\n\n");
	printf("Test Case 658\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 658 FAILED\n");
		return -658;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 658 FAILED\n");
			return -659;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 658 PASSED\n---\n\n");
	printf("Test Case 660\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 660 FAILED\n");
		return -660;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 660 FAILED\n");
			return -661;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 660 PASSED\n---\n\n");
	printf("Test Case 662\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 662 FAILED\n");
		return -662;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 662 FAILED\n");
			return -663;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 662 PASSED\n---\n\n");
	printf("Test Case 664\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 664 FAILED\n");
		return -664;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 664 FAILED\n");
			return -665;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 664 PASSED\n---\n\n");
	printf("Test Case 666\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 666 FAILED\n");
		return -666;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 666 FAILED\n");
			return -667;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 666 PASSED\n---\n\n");
	printf("Test Case 668\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 668 FAILED\n");
		return -668;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 668 FAILED\n");
			return -669;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 668 PASSED\n---\n\n");
	printf("Test Case 670\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 670 FAILED\n");
		return -670;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 670 FAILED\n");
			return -671;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 670 PASSED\n---\n\n");
	printf("Test Case 672\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 672 FAILED\n");
		return -672;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 672 FAILED\n");
			return -673;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 672 PASSED\n---\n\n");
	printf("Test Case 674\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 674 FAILED\n");
		return -674;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 674 FAILED\n");
			return -675;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 674 PASSED\n---\n\n");
	printf("Test Case 676\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 676 FAILED\n");
		return -676;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 676 FAILED\n");
			return -677;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 676 PASSED\n---\n\n");
	printf("Test Case 678\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 678 FAILED\n");
		return -678;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 678 FAILED\n");
			return -679;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 678 PASSED\n---\n\n");
	printf("Test Case 680\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 680 FAILED\n");
		return -680;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 680 FAILED\n");
			return -681;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 680 PASSED\n---\n\n");
	printf("Test Case 682\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 682 FAILED\n");
		return -682;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 682 FAILED\n");
			return -683;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 682 PASSED\n---\n\n");
	printf("Test Case 684\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 684 FAILED\n");
		return -684;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 684 FAILED\n");
			return -685;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 684 PASSED\n---\n\n");
	printf("Test Case 686\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 686 FAILED\n");
		return -686;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 686 FAILED\n");
			return -687;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 686 PASSED\n---\n\n");
	printf("Test Case 688\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 688 FAILED\n");
		return -688;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 688 FAILED\n");
			return -689;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 688 PASSED\n---\n\n");
	printf("Test Case 690\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 690 FAILED\n");
		return -690;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 690 FAILED\n");
			return -691;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 690 PASSED\n---\n\n");
	printf("Test Case 692\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 692 FAILED\n");
		return -692;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 692 FAILED\n");
			return -693;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 692 PASSED\n---\n\n");
	printf("Test Case 694\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 694 FAILED\n");
		return -694;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 694 FAILED\n");
			return -695;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 694 PASSED\n---\n\n");
	printf("Test Case 696\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 696 FAILED\n");
		return -696;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 696 FAILED\n");
			return -697;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 696 PASSED\n---\n\n");
	printf("Test Case 698\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 698 FAILED\n");
		return -698;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 698 FAILED\n");
			return -699;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 698 PASSED\n---\n\n");
	printf("Test Case 700\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 700 FAILED\n");
		return -700;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 700 FAILED\n");
			return -701;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 700 PASSED\n---\n\n");
	printf("Test Case 702\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 702 FAILED\n");
		return -702;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 702 FAILED\n");
			return -703;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 702 PASSED\n---\n\n");
	printf("Test Case 704\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 704 FAILED\n");
		return -704;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 704 FAILED\n");
			return -705;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 704 PASSED\n---\n\n");
	printf("Test Case 706\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 706 FAILED\n");
		return -706;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 706 FAILED\n");
			return -707;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 706 PASSED\n---\n\n");
	printf("Test Case 708\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 708 FAILED\n");
		return -708;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 708 FAILED\n");
			return -709;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 708 PASSED\n---\n\n");
	printf("Test Case 710\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 710 FAILED\n");
		return -710;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 710 FAILED\n");
			return -711;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 710 PASSED\n---\n\n");
	printf("Test Case 712\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 712 FAILED\n");
		return -712;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 712 FAILED\n");
			return -713;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 712 PASSED\n---\n\n");
	printf("Test Case 714\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 714 FAILED\n");
		return -714;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 714 FAILED\n");
			return -715;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 714 PASSED\n---\n\n");
	printf("Test Case 716\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 716 FAILED\n");
		return -716;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 716 FAILED\n");
			return -717;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 716 PASSED\n---\n\n");
	printf("Test Case 718\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 718 FAILED\n");
		return -718;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 718 FAILED\n");
			return -719;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 718 PASSED\n---\n\n");
	printf("Test Case 720\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 720 FAILED\n");
		return -720;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 720 FAILED\n");
			return -721;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 720 PASSED\n---\n\n");
	printf("Test Case 722\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 722 FAILED\n");
		return -722;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 722 FAILED\n");
			return -723;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 722 PASSED\n---\n\n");
	printf("Test Case 724\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 724 FAILED\n");
		return -724;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 724 FAILED\n");
			return -725;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 724 PASSED\n---\n\n");
	printf("Test Case 726\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 726 FAILED\n");
		return -726;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 726 FAILED\n");
			return -727;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 726 PASSED\n---\n\n");
	printf("Test Case 728\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 728 FAILED\n");
		return -728;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 728 FAILED\n");
			return -729;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 728 PASSED\n---\n\n");
	printf("Test Case 730\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 730 FAILED\n");
		return -730;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 730 FAILED\n");
			return -731;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 730 PASSED\n---\n\n");
	printf("Test Case 732\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 732 FAILED\n");
		return -732;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 732 FAILED\n");
			return -733;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 732 PASSED\n---\n\n");
	printf("Test Case 734\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 734 FAILED\n");
		return -734;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 734 FAILED\n");
			return -735;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 734 PASSED\n---\n\n");
	printf("Test Case 736\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 736 FAILED\n");
		return -736;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 736 FAILED\n");
			return -737;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 736 PASSED\n---\n\n");
	printf("Test Case 738\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 738 FAILED\n");
		return -738;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 738 FAILED\n");
			return -739;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 738 PASSED\n---\n\n");
	printf("Test Case 740\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 740 FAILED\n");
		return -740;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 740 FAILED\n");
			return -741;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 740 PASSED\n---\n\n");
	printf("Test Case 742\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 742 FAILED\n");
		return -742;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 742 FAILED\n");
			return -743;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 742 PASSED\n---\n\n");
	printf("Test Case 744\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 744 FAILED\n");
		return -744;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 744 FAILED\n");
			return -745;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 744 PASSED\n---\n\n");
	printf("Test Case 746\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 746 FAILED\n");
		return -746;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 746 FAILED\n");
			return -747;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 746 PASSED\n---\n\n");
	printf("Test Case 748\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 748 FAILED\n");
		return -748;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 748 FAILED\n");
			return -749;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 748 PASSED\n---\n\n");
	printf("Test Case 750\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 750 FAILED\n");
		return -750;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 750 FAILED\n");
			return -751;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 750 PASSED\n---\n\n");
	printf("Test Case 752\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 752 FAILED\n");
		return -752;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 752 FAILED\n");
			return -753;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 752 PASSED\n---\n\n");
	printf("Test Case 754\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 754 FAILED\n");
		return -754;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 754 FAILED\n");
			return -755;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 754 PASSED\n---\n\n");
	printf("Test Case 756\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 756 FAILED\n");
		return -756;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 756 FAILED\n");
			return -757;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 756 PASSED\n---\n\n");
	printf("Test Case 758\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 758 FAILED\n");
		return -758;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 758 FAILED\n");
			return -759;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 758 PASSED\n---\n\n");
	printf("Test Case 760\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 760 FAILED\n");
		return -760;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 760 FAILED\n");
			return -761;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 760 PASSED\n---\n\n");
	printf("Test Case 762\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 762 FAILED\n");
		return -762;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 762 FAILED\n");
			return -763;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 762 PASSED\n---\n\n");
	printf("Test Case 764\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 764 FAILED\n");
		return -764;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 764 FAILED\n");
			return -765;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 764 PASSED\n---\n\n");
	printf("Test Case 766\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 766 FAILED\n");
		return -766;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 766 FAILED\n");
			return -767;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 766 PASSED\n---\n\n");
	printf("Test Case 768\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 768 FAILED\n");
		return -768;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 768 FAILED\n");
			return -769;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 768 PASSED\n---\n\n");
	printf("Test Case 770\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 770 FAILED\n");
		return -770;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 770 FAILED\n");
			return -771;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 770 PASSED\n---\n\n");
	printf("Test Case 772\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 772 FAILED\n");
		return -772;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 772 FAILED\n");
			return -773;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 772 PASSED\n---\n\n");
	printf("Test Case 774\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 774 FAILED\n");
		return -774;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 774 FAILED\n");
			return -775;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 774 PASSED\n---\n\n");
	printf("Test Case 776\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 776 FAILED\n");
		return -776;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 776 FAILED\n");
			return -777;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 776 PASSED\n---\n\n");
	printf("Test Case 778\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 778 FAILED\n");
		return -778;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 778 FAILED\n");
			return -779;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 778 PASSED\n---\n\n");
	printf("Test Case 780\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 780 FAILED\n");
		return -780;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 780 FAILED\n");
			return -781;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 780 PASSED\n---\n\n");
	printf("Test Case 782\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 782 FAILED\n");
		return -782;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 782 FAILED\n");
			return -783;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 782 PASSED\n---\n\n");
	printf("Test Case 784\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 784 FAILED\n");
		return -784;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 784 FAILED\n");
			return -785;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 784 PASSED\n---\n\n");
	printf("Test Case 786\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 786 FAILED\n");
		return -786;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 786 FAILED\n");
			return -787;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 786 PASSED\n---\n\n");
	printf("Test Case 788\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 788 FAILED\n");
		return -788;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 788 FAILED\n");
			return -789;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 788 PASSED\n---\n\n");
	printf("Test Case 790\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 790 FAILED\n");
		return -790;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 790 FAILED\n");
			return -791;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 790 PASSED\n---\n\n");
	printf("Test Case 792\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 792 FAILED\n");
		return -792;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 792 FAILED\n");
			return -793;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 792 PASSED\n---\n\n");
	printf("Test Case 794\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 794 FAILED\n");
		return -794;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 794 FAILED\n");
			return -795;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 794 PASSED\n---\n\n");
	printf("Test Case 796\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 796 FAILED\n");
		return -796;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 796 FAILED\n");
			return -797;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 796 PASSED\n---\n\n");
	printf("Test Case 798\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 798 FAILED\n");
		return -798;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 798 FAILED\n");
			return -799;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 798 PASSED\n---\n\n");
	printf("Test Case 800\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 800 FAILED\n");
		return -800;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 800 FAILED\n");
			return -801;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 800 PASSED\n---\n\n");
	printf("Test Case 802\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 802 FAILED\n");
		return -802;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 802 FAILED\n");
			return -803;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 802 PASSED\n---\n\n");
	printf("Test Case 804\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 804 FAILED\n");
		return -804;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 804 FAILED\n");
			return -805;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 804 PASSED\n---\n\n");
	printf("Test Case 806\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 806 FAILED\n");
		return -806;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 806 FAILED\n");
			return -807;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 806 PASSED\n---\n\n");
	printf("Test Case 808\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 808 FAILED\n");
		return -808;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 808 FAILED\n");
			return -809;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 808 PASSED\n---\n\n");
	printf("Test Case 810\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 810 FAILED\n");
		return -810;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 810 FAILED\n");
			return -811;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 810 PASSED\n---\n\n");
	printf("Test Case 812\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 812 FAILED\n");
		return -812;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 812 FAILED\n");
			return -813;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 812 PASSED\n---\n\n");
	printf("Test Case 814\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 814 FAILED\n");
		return -814;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 814 FAILED\n");
			return -815;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 814 PASSED\n---\n\n");
	printf("Test Case 816\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 816 FAILED\n");
		return -816;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 816 FAILED\n");
			return -817;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 816 PASSED\n---\n\n");
	printf("Test Case 818\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 818 FAILED\n");
		return -818;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 818 FAILED\n");
			return -819;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 818 PASSED\n---\n\n");
	printf("Test Case 820\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 820 FAILED\n");
		return -820;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 820 FAILED\n");
			return -821;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 820 PASSED\n---\n\n");
	printf("Test Case 822\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 822 FAILED\n");
		return -822;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 822 FAILED\n");
			return -823;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 822 PASSED\n---\n\n");
	printf("Test Case 824\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 824 FAILED\n");
		return -824;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 824 FAILED\n");
			return -825;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 824 PASSED\n---\n\n");
	printf("Test Case 826\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 826 FAILED\n");
		return -826;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 826 FAILED\n");
			return -827;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 826 PASSED\n---\n\n");
	printf("Test Case 828\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 828 FAILED\n");
		return -828;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 828 FAILED\n");
			return -829;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 828 PASSED\n---\n\n");
	printf("Test Case 830\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 830 FAILED\n");
		return -830;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 830 FAILED\n");
			return -831;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 830 PASSED\n---\n\n");
	printf("Test Case 832\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 832 FAILED\n");
		return -832;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 832 FAILED\n");
			return -833;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 832 PASSED\n---\n\n");
	printf("Test Case 834\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 834 FAILED\n");
		return -834;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 834 FAILED\n");
			return -835;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 834 PASSED\n---\n\n");
	printf("Test Case 836\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 836 FAILED\n");
		return -836;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 836 FAILED\n");
			return -837;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 836 PASSED\n---\n\n");
	printf("Test Case 838\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 838 FAILED\n");
		return -838;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 838 FAILED\n");
			return -839;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 838 PASSED\n---\n\n");
	printf("Test Case 840\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 840 FAILED\n");
		return -840;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 840 FAILED\n");
			return -841;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 840 PASSED\n---\n\n");
	printf("Test Case 842\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 842 FAILED\n");
		return -842;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 842 FAILED\n");
			return -843;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 842 PASSED\n---\n\n");
	printf("Test Case 844\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 844 FAILED\n");
		return -844;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 844 FAILED\n");
			return -845;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 844 PASSED\n---\n\n");
	printf("Test Case 846\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 846 FAILED\n");
		return -846;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 846 FAILED\n");
			return -847;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 846 PASSED\n---\n\n");
	printf("Test Case 848\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 848 FAILED\n");
		return -848;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 848 FAILED\n");
			return -849;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 848 PASSED\n---\n\n");
	printf("Test Case 850\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 850 FAILED\n");
		return -850;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 850 FAILED\n");
			return -851;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 850 PASSED\n---\n\n");
	printf("Test Case 852\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 852 FAILED\n");
		return -852;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 852 FAILED\n");
			return -853;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 852 PASSED\n---\n\n");
	printf("Test Case 854\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 854 FAILED\n");
		return -854;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 854 FAILED\n");
			return -855;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 854 PASSED\n---\n\n");
	printf("Test Case 856\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 856 FAILED\n");
		return -856;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 856 FAILED\n");
			return -857;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 856 PASSED\n---\n\n");
	printf("Test Case 858\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 858 FAILED\n");
		return -858;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 858 FAILED\n");
			return -859;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 858 PASSED\n---\n\n");
	printf("Test Case 860\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 860 FAILED\n");
		return -860;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 860 FAILED\n");
			return -861;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 860 PASSED\n---\n\n");
	printf("Test Case 862\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 862 FAILED\n");
		return -862;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 862 FAILED\n");
			return -863;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 862 PASSED\n---\n\n");
	printf("Test Case 864\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 864 FAILED\n");
		return -864;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 864 FAILED\n");
			return -865;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 864 PASSED\n---\n\n");
	printf("Test Case 866\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 866 FAILED\n");
		return -866;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 866 FAILED\n");
			return -867;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 866 PASSED\n---\n\n");
	printf("Test Case 868\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 868 FAILED\n");
		return -868;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 868 FAILED\n");
			return -869;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 868 PASSED\n---\n\n");
	printf("Test Case 870\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 870 FAILED\n");
		return -870;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 870 FAILED\n");
			return -871;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 870 PASSED\n---\n\n");
	printf("Test Case 872\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 872 FAILED\n");
		return -872;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 872 FAILED\n");
			return -873;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 872 PASSED\n---\n\n");
	printf("Test Case 874\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 874 FAILED\n");
		return -874;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 874 FAILED\n");
			return -875;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 874 PASSED\n---\n\n");
	printf("Test Case 876\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 876 FAILED\n");
		return -876;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 876 FAILED\n");
			return -877;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 876 PASSED\n---\n\n");
	printf("Test Case 878\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 878 FAILED\n");
		return -878;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 878 FAILED\n");
			return -879;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 878 PASSED\n---\n\n");
	printf("Test Case 880\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 880 FAILED\n");
		return -880;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 880 FAILED\n");
			return -881;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 880 PASSED\n---\n\n");
	printf("Test Case 882\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 882 FAILED\n");
		return -882;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 882 FAILED\n");
			return -883;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 882 PASSED\n---\n\n");
	printf("Test Case 884\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 884 FAILED\n");
		return -884;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 884 FAILED\n");
			return -885;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 884 PASSED\n---\n\n");
	printf("Test Case 886\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 886 FAILED\n");
		return -886;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 886 FAILED\n");
			return -887;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 886 PASSED\n---\n\n");
	printf("Test Case 888\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 888 FAILED\n");
		return -888;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 888 FAILED\n");
			return -889;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 888 PASSED\n---\n\n");
	printf("Test Case 890\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 890 FAILED\n");
		return -890;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 890 FAILED\n");
			return -891;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 890 PASSED\n---\n\n");
	printf("Test Case 892\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 892 FAILED\n");
		return -892;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 892 FAILED\n");
			return -893;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 892 PASSED\n---\n\n");
	printf("Test Case 894\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 894 FAILED\n");
		return -894;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 894 FAILED\n");
			return -895;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 894 PASSED\n---\n\n");
	printf("Test Case 896\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 896 FAILED\n");
		return -896;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 896 FAILED\n");
			return -897;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 896 PASSED\n---\n\n");
	printf("Test Case 898\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 898 FAILED\n");
		return -898;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 898 FAILED\n");
			return -899;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 898 PASSED\n---\n\n");
	printf("Test Case 900\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 900 FAILED\n");
		return -900;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 900 FAILED\n");
			return -901;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 900 PASSED\n---\n\n");
	printf("Test Case 902\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 902 FAILED\n");
		return -902;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 902 FAILED\n");
			return -903;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 902 PASSED\n---\n\n");
	printf("Test Case 904\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 904 FAILED\n");
		return -904;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 904 FAILED\n");
			return -905;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 904 PASSED\n---\n\n");
	printf("Test Case 906\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 906 FAILED\n");
		return -906;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 906 FAILED\n");
			return -907;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 906 PASSED\n---\n\n");
	printf("Test Case 908\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 908 FAILED\n");
		return -908;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 908 FAILED\n");
			return -909;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 908 PASSED\n---\n\n");
	printf("Test Case 910\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 910 FAILED\n");
		return -910;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 910 FAILED\n");
			return -911;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 910 PASSED\n---\n\n");
	printf("Test Case 912\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 912 FAILED\n");
		return -912;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 912 FAILED\n");
			return -913;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 912 PASSED\n---\n\n");
	printf("Test Case 914\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 914 FAILED\n");
		return -914;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 914 FAILED\n");
			return -915;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 914 PASSED\n---\n\n");
	printf("Test Case 916\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 916 FAILED\n");
		return -916;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 916 FAILED\n");
			return -917;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 916 PASSED\n---\n\n");
	printf("Test Case 918\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 918 FAILED\n");
		return -918;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 918 FAILED\n");
			return -919;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 918 PASSED\n---\n\n");
	printf("Test Case 920\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 920 FAILED\n");
		return -920;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 920 FAILED\n");
			return -921;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 920 PASSED\n---\n\n");
	printf("Test Case 922\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 922 FAILED\n");
		return -922;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 922 FAILED\n");
			return -923;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 922 PASSED\n---\n\n");
	printf("Test Case 924\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 924 FAILED\n");
		return -924;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 924 FAILED\n");
			return -925;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 924 PASSED\n---\n\n");
	printf("Test Case 926\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 926 FAILED\n");
		return -926;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 926 FAILED\n");
			return -927;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 926 PASSED\n---\n\n");
	printf("Test Case 928\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 928 FAILED\n");
		return -928;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 928 FAILED\n");
			return -929;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 928 PASSED\n---\n\n");
	printf("Test Case 930\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 930 FAILED\n");
		return -930;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 930 FAILED\n");
			return -931;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 930 PASSED\n---\n\n");
	printf("Test Case 932\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 932 FAILED\n");
		return -932;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 932 FAILED\n");
			return -933;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 932 PASSED\n---\n\n");
	printf("Test Case 934\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 934 FAILED\n");
		return -934;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 934 FAILED\n");
			return -935;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 934 PASSED\n---\n\n");
	printf("Test Case 936\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 936 FAILED\n");
		return -936;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 936 FAILED\n");
			return -937;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 936 PASSED\n---\n\n");
	printf("Test Case 938\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 938 FAILED\n");
		return -938;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 938 FAILED\n");
			return -939;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 938 PASSED\n---\n\n");
	printf("Test Case 940\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 940 FAILED\n");
		return -940;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 940 FAILED\n");
			return -941;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 940 PASSED\n---\n\n");
	printf("Test Case 942\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 942 FAILED\n");
		return -942;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 942 FAILED\n");
			return -943;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 942 PASSED\n---\n\n");
	printf("Test Case 944\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 944 FAILED\n");
		return -944;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 944 FAILED\n");
			return -945;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 944 PASSED\n---\n\n");
	printf("Test Case 946\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 946 FAILED\n");
		return -946;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 946 FAILED\n");
			return -947;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 946 PASSED\n---\n\n");
	printf("Test Case 948\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 948 FAILED\n");
		return -948;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 948 FAILED\n");
			return -949;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 948 PASSED\n---\n\n");
	printf("Test Case 950\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 950 FAILED\n");
		return -950;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 950 FAILED\n");
			return -951;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 950 PASSED\n---\n\n");
	printf("Test Case 952\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 952 FAILED\n");
		return -952;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 952 FAILED\n");
			return -953;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 952 PASSED\n---\n\n");
	printf("Test Case 954\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 954 FAILED\n");
		return -954;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 954 FAILED\n");
			return -955;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 954 PASSED\n---\n\n");
	printf("Test Case 956\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 956 FAILED\n");
		return -956;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 956 FAILED\n");
			return -957;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 956 PASSED\n---\n\n");
	printf("Test Case 958\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 958 FAILED\n");
		return -958;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 958 FAILED\n");
			return -959;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 958 PASSED\n---\n\n");
	printf("Test Case 960\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 960 FAILED\n");
		return -960;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 960 FAILED\n");
			return -961;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 960 PASSED\n---\n\n");
	printf("Test Case 962\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 962 FAILED\n");
		return -962;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 962 FAILED\n");
			return -963;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 962 PASSED\n---\n\n");
	printf("Test Case 964\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 964 FAILED\n");
		return -964;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 964 FAILED\n");
			return -965;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 964 PASSED\n---\n\n");
	printf("Test Case 966\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 966 FAILED\n");
		return -966;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 966 FAILED\n");
			return -967;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 966 PASSED\n---\n\n");
	printf("Test Case 968\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 968 FAILED\n");
		return -968;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 968 FAILED\n");
			return -969;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 968 PASSED\n---\n\n");
	printf("Test Case 970\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 970 FAILED\n");
		return -970;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 970 FAILED\n");
			return -971;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 970 PASSED\n---\n\n");
	printf("Test Case 972\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 972 FAILED\n");
		return -972;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 972 FAILED\n");
			return -973;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 972 PASSED\n---\n\n");
	printf("Test Case 974\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 974 FAILED\n");
		return -974;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 974 FAILED\n");
			return -975;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 974 PASSED\n---\n\n");
	printf("Test Case 976\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 976 FAILED\n");
		return -976;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 976 FAILED\n");
			return -977;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 976 PASSED\n---\n\n");
	printf("Test Case 978\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 978 FAILED\n");
		return -978;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 978 FAILED\n");
			return -979;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 978 PASSED\n---\n\n");
	printf("Test Case 980\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 980 FAILED\n");
		return -980;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 980 FAILED\n");
			return -981;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 980 PASSED\n---\n\n");
	printf("Test Case 982\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 982 FAILED\n");
		return -982;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 982 FAILED\n");
			return -983;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 982 PASSED\n---\n\n");
	printf("Test Case 984\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 984 FAILED\n");
		return -984;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 984 FAILED\n");
			return -985;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 984 PASSED\n---\n\n");
	printf("Test Case 986\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 986 FAILED\n");
		return -986;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 986 FAILED\n");
			return -987;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 986 PASSED\n---\n\n");
	printf("Test Case 988\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 988 FAILED\n");
		return -988;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 988 FAILED\n");
			return -989;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 988 PASSED\n---\n\n");
	printf("Test Case 990\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 990 FAILED\n");
		return -990;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 990 FAILED\n");
			return -991;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 990 PASSED\n---\n\n");
	printf("Test Case 992\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 992 FAILED\n");
		return -992;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 992 FAILED\n");
			return -993;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 992 PASSED\n---\n\n");
	printf("Test Case 994\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 994 FAILED\n");
		return -994;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 994 FAILED\n");
			return -995;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 994 PASSED\n---\n\n");
	printf("Test Case 996\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 996 FAILED\n");
		return -996;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 996 FAILED\n");
			return -997;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 996 PASSED\n---\n\n");
	printf("Test Case 998\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 998 FAILED\n");
		return -998;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 998 FAILED\n");
			return -999;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 998 PASSED\n---\n\n");
	printf("Test Case 1000\n");
	if (curve25519_priv_key_init(&key)) {
		printf("Test Case 1000 FAILED\n");
		return -1000;
	}
	for (size_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			printf("Test Case 1000 FAILED\n");
			return -1001;
		}
		prev_key.key64[i] = key.key64[i];
	}
	printf("Test Case 1000 PASSED\n---\n\n");
	return 0;
}