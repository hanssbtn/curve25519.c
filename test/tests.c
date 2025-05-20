#include "tests.h"

int32_t main(void) {
	if (curve25519_priv_key_init_test()) {
		fprintf(stderr, "Failed to initialize key\n");
		return -1;
	}
	if (curve25519_key_cmp_test()) {
		fprintf(stderr, "Failed to compare key\n");
		return -1;
	}
	if (curve25519_key_modulo_test()) {
		fprintf(stderr, "Failed to compute key\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}