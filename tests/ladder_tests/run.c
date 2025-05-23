#include "../curve25519.h"

int main(void) {
	if (curve25519_cswap_test()) {
		fprintf(stderr, "Failed conditional swap test\n");
		return -1;
	}
	if (curve25519_ladder_step_test()) {
		fprintf(stderr, "Failed ladder step test\n");
		return -1;
	}
	if (curve25519_ladder_test()) {
		fprintf(stderr, "Failed ladder test\n");
		return -1;
	}
	return 0;
}