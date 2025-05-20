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
	if (curve25519_key_add_test()) {
		fprintf(stderr, "Failed to add key\n");
		return -1;
	}
	if (curve25519_key_add_inplace_test()) {
		fprintf(stderr, "Failed to add key inplace\n");
		return -1;
	}
	if (curve25519_key_sub_test()) {
		fprintf(stderr, "Failed to subtract key\n");
		return -1;
	}
	if (curve25519_key_sub_inplace_test()) {
		fprintf(stderr, "Failed to subtract key inplace\n");
		return -1;
	}
	if (curve25519_key_add_self_test()) {
		fprintf(stderr, "Failed to add key to self\n");
		return -1;	
	}
	if (curve25519_key_x2_test()) {
		fprintf(stderr, "Failed to double key\n");
		return -1;
	}
	if (curve25519_key_x2_inplace_test()) {
		fprintf(stderr, "Failed to double key inplace\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}