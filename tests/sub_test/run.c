#include "../tests.h"

int main(void) {
	printf("Running subtraction tests\n");
	if (curve25519_key_sub_test()) {
		fprintf(stderr, "Failed to key subtraction test\n");
		return -1;
	}
	if (curve25519_key_sub_inplace_test()) {
		fprintf(stderr, "Failed to subtract key inplace\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}