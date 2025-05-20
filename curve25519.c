#include "curve25519.h"

int32_t curve25519_add(curve25519_key_t *x1, curve25519_key_t *x2, curve25519_key_t *y1, curve25519_key_t *y2, curve25519_key_t *r) {
	curve25519_key_t dx, dy, lambda, x1x2, lambda2;
	curve25519_key_sub(x2, x1, &dx);
	curve25519_key_sub(y2, y1, &dy);
	curve25519_key_div(&dy, &dx, &lambda);
	curve25519_key_mul(&lambda, &lambda, &lambda2);
	curve25519_key_add(x2, x1, &x1x2);
	curve25519_key_sub(&lambda2, &x1x2, r);
	return 0;
}