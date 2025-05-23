#include "curve25519.h" // Assuming this header includes curve25519_key_t and your other functions

int32_t curve25519_proj_to_affine(const curve25519_proj_point_t *const p1, curve25519_key_t *const out) {
	return curve25519_key_divmod(&p1->X, &p1->Z, out, NULL);
}

void curve25519_cswap(
	curve25519_proj_point_t *const restrict XZ2, 
	curve25519_proj_point_t *const restrict XZ3,
	bool bit
) {
	curve25519_key_t __mask, *mask = &__mask, __T1, __T2, *T1 = &__T1, *T2 = &__T2, __T3, __T4, *T3 = &__T3, *T4 = &__T4;
	memset(mask->key8, bit, sizeof(curve25519_key_t));
	curve25519_key_xor(&XZ2->X, &XZ3->X, T3);
	curve25519_key_and(mask, T3, T1);
	curve25519_key_xor(&XZ2->Z, &XZ3->Z, T4);
	curve25519_key_and(mask, T4, T2);
	curve25519_key_xor(T1, &XZ2->X, T3);
	curve25519_key_copy(&XZ2->X, T3);
	curve25519_key_xor(T2, &XZ2->Z, T4);
	curve25519_key_copy(&XZ2->Z, T4);
	curve25519_key_xor(T1, &XZ3->X, T3);
	curve25519_key_copy(&XZ3->X, T3);
	curve25519_key_xor(T2, &XZ3->Z, T4);
	curve25519_key_copy(&XZ3->Z, T4);
}

int32_t curve25519_ladder_step(
	curve25519_proj_point_t *const restrict XZ2, 
	curve25519_proj_point_t *const restrict XZ3, 
	const curve25519_key_t *const restrict X1
) {
	curve25519_key_t __T1, __T2, __T3, __T4, __T5, __T6, __T1_old, __T2_old;
	curve25519_key_t *T1 = &__T1, *T2 = &__T2, *T3 = &__T3, *T4 = &__T4, *T5 = &__T5, *T6 = &__T6, *T1_old = &__T1_old, *T2_old = &__T2_old;
	// T1 <- X2 + Z2
	curve25519_key_add_modulo(&XZ2->X, &XZ2->Z, T1);
	// T2 <- X2 - Z2
	curve25519_key_sub_modulo(&XZ2->X, &XZ2->Z, T2);
	// T3 <- X3 + Z3
	curve25519_key_add_modulo(&XZ3->X, &XZ3->Z, T3);
	// T4 <- X3 - Z3
	curve25519_key_sub_modulo(&XZ3->X, &XZ3->Z, T4);
	// T5 <- T1 ^ 2
	curve25519_key_copy(T1_old, T1);
	curve25519_key_mul_modulo(T1, T1_old, T5);
	// T6 <- T2 ^ 2
	curve25519_key_copy(T2_old, T2);
	curve25519_key_mul_modulo(T2, T2_old, T6);
	// T2 <- T2 · T3
	curve25519_key_mul_modulo_inplace(T2, T3);
	// T1 <- T1 · T4
	curve25519_key_mul_modulo_inplace(T1, T4);
	// T1 <- T1 + T2
	curve25519_key_add_modulo_inplace(T1, T2);
	// T2 <- T1 - T2
	curve25519_key_copy(T2_old, T2);
	curve25519_key_sub_modulo(T1, T2_old, T2);
	// X3 <- T1 ^ 2
	curve25519_key_copy(T1_old, T1);
	curve25519_key_mul_modulo(T1, T1_old, &XZ3->X);
	// T2 <- T2 ^ 2
	curve25519_key_copy(T2_old, T2);
	curve25519_key_mul_modulo_inplace(T2, T2_old);
	// Z3 <- T2 · X1
	curve25519_key_mul_modulo(T2, X1, &XZ3->Z);
	// X2 <- T5 · T6
	curve25519_key_mul_modulo(T5, T6, &XZ2->X);
	// T5 <- T5 - T6
	curve25519_key_sub_modulo_inplace(T5, T6);
	// T1 <- A24 · T5
	curve25519_key_mul_modulo(A24, T5, T1);
	// T6 <- T6 + T1
	curve25519_key_add_modulo_inplace(T6, T1);
	// Z2 <- T5 · T6
	curve25519_key_add_modulo(T5, T6, &XZ2->Z);
	return 0;
}

int32_t curve25519_ladder(const curve25519_key_t *const restrict Xp, const curve25519_key_t *const restrict n, curve25519_key_t *const restrict nXp) {
	curve25519_proj_point_t XZ2 = {.X = {.key8 = {1}}}, XZ3;
	curve25519_key_copy(&XZ3.X, Xp);
	XZ3.Z = (curve25519_key_t){.key8 = {1}};
	bool prev_bit = 0;

	for (int64_t idx = 255; idx >= 0; --idx) {
		bool bit = n->key64[idx / 64] & (1ULL << (idx & 63));
		bool b = bit ^ prev_bit;
		prev_bit = bit;
		curve25519_swap(&XZ2, &XZ3, b);
		curve25519_ladder_step(&XZ2, &XZ3, Xp);
	}

	return curve25519_proj_to_affine(&XZ2, nXp);
}