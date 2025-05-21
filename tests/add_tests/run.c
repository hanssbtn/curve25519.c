#include "../tests.h"

int main(void) {
	printf("Running addition tests\n");
	if (curve25519_key_add_test()) {
		fprintf(stderr, "Failed to add key\n");
		return -1;
	}
	if (curve25519_key_add_inplace_test()) {
		fprintf(stderr, "Failed to add key inplace\n");
		return -1;
	}
	if (curve25519_key_add_modulo_test()) {
		fprintf(stderr, "Failed to add key\n");
		return -1;
	}
	if (curve25519_key_add_modulo_inplace_test()) {
		fprintf(stderr, "Failed to add key inplace\n");
		return -1;
	}
	if (curve25519_key_add_self_test()) {
		fprintf(stderr, "Failed to add key inplace\n");
		return -1;
	}
	if (curve25519_key_add_self_modulo_test()) {
		fprintf(stderr, "Failed to add key\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}