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
	return 0;
}