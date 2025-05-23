#include "../tests.h"

int main(void) {
	printf("Running subtraction tests\n");
	if (curve25519_key_sub_test()) {
		fprintf(stderr, "Failed key subtraction test\n");
		return -1;
	}
	if (curve25519_key_sub_inplace_test()) {
		fprintf(stderr, "Failed inplace key subtraction test\n");
		return -1;
	}
	if (curve25519_key_sub_modulo_test()) {
		fprintf(stderr, "Failed modular key subtraction test\n");
		return -1;
	}
	if (curve25519_key_sub_modulo_inplace_test()) {
		fprintf(stderr, "Failed inplace modular key subtraction test\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}