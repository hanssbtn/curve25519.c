#include "../tests.h"

int main(void) {
	if (curve25519_key_mul_test()) {
		fprintf(stderr, "Failed key multiplication test\n");
		return -1;
	}
	return 0;
}
