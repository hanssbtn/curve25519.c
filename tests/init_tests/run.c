#include "../tests.h"

int main(void) {
	printf("Running initialization tests\n");
	if (curve25519_priv_key_init_test()) {
		fprintf(stderr, "Failed private key initialization test\n");
		return -1;
	}
	if (curve25519_key_modulo_test()) {
		fprintf(stderr, "Failed key modulo test\n");
		return -1;
	}
	if (curve25519_key_cmp_low_test()) {
		fprintf(stderr, "Failed key low bytes comparison test\n");
		return -1;
	}
	if (curve25519_key_cmp_high_test()) {
		fprintf(stderr, "Failed key high bytes comparison test\n");
		return -1;
	}
	if (curve25519_key_cmp_test()) {
		fprintf(stderr, "Failed key comparison test\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}