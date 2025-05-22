#include "../tests.h"

int main(void) {
	printf("Running shift tests\n");
	if (curve25519_key_x2_test()) {
		fprintf(stderr, "Failed key doubling test\n");
		return -1;
	}
	if (curve25519_key_x2_inplace_test()) {
		fprintf(stderr, "Failed key doubling inplace test\n");
		return -1;
	}
	if (curve25519_key_lshift_test()) {
		fprintf(stderr, "Failed key left shift test\n");
		return -1;
	}
	if (curve25519_key_rshift_test()) {
		fprintf(stderr, "Failed key right shift test\n");
		return -1;
	}
	if (curve25519_key_lshift_inplace_test()) {
		fprintf(stderr, "Failed key inplace left shift test\n");
		return -1;
	}
	if (curve25519_key_rshift_inplace_test()) {
		fprintf(stderr, "Failed key inplace right shift test\n");
		return -1;
	}
	if (curve25519_key_log2_test()) {
		fprintf(stderr, "Failed key log2 test\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}