#include "../tests.h"

int main(void) {
	printf("Running shift tests\n");
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