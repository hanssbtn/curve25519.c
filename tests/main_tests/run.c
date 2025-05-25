#include "../tests.h"

int main(void) {
	printf("Running main tests\n");
	if (curve25519_pub_key_init_test()) {
		fprintf(stderr, "Failed public key generation test\n");
		return -1;
	}
	if (curve25519_shared_key_gen_test()) {
		fprintf(stderr, "Failed shared key generation test\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}