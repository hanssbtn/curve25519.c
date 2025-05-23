#include "../tests.h"

int main(void) {
	printf("Running product tests\n");
	if (curve25519_key_mul_test()) {
		fprintf(stderr, "Failed key multiplication test\n");
		return -1;
	}
	if (curve25519_key_mul_modulo_test()) {
		fprintf(stderr, "Failed modular key multiplication test\n");
		return -1;
	}
	if (curve25519_key_mul_inplace_test()) {
		fprintf(stderr, "Failed inplace key multiplication test\n");
		return -1;
	}
	if (curve25519_key_mul_modulo_inplace_test()) {
		fprintf(stderr, "Failed inplace modular key multiplication test\n");
		return -1;
	}
	if (curve25519_key_divmod_test()) {
		fprintf(stderr, "Failed key division + modulo test\n");
		return -1;
	}
	if (curve25519_key_inv_test()) {
		fprintf(stderr, "Failed modular key inverse test\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}
