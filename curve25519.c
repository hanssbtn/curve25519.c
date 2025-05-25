#include "curve25519.h" // Assuming this header includes curve25519_key_t and your other functions

int32_t curve25519_proj_to_affine(const curve25519_proj_point_t *const p1, curve25519_key_t *const out) {
	return curve25519_key_divmod(&p1->X, &p1->Z, out);
}

int32_t curve25519_cmp_eq(curve25519_proj_point_t *const restrict XZ1, curve25519_proj_point_t *const restrict XZ2) {
	__m256i key1 = _mm256_loadu_epi64(XZ1->X.key64 + 4), key2 = _mm256_loadu_epi64(XZ2->X.key64 + 4);
	__mmask8 lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	__mmask8 gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	if ((lt_mask - gt_mask)) {
		return -1;
	}
	key1 = _mm256_loadu_epi64(XZ1->X.key64);
	key2 = _mm256_loadu_epi64(XZ2->X.key64);
	lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	if ((lt_mask - gt_mask)) {
		return -1;
	}
	key1 = _mm256_loadu_epi64(XZ1->Z.key64 + 4), key2 = _mm256_loadu_epi64(XZ2->Z.key64 + 4);
	lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	if ((lt_mask - gt_mask)) {
		return -1;
	}
	key1 = _mm256_loadu_epi64(XZ1->Z.key64);
	key2 = _mm256_loadu_epi64(XZ2->Z.key64);
	lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	if ((lt_mask - gt_mask)) {
		return -1;
	}
	return 0;
}

void curve25519_cswap(
	curve25519_proj_point_t *const restrict XZ2, 
	curve25519_proj_point_t *const restrict XZ3,
	bool bit
) {
	curve25519_key_t __mask, *mask = &__mask, 
	__T1, __T2, *T1 = &__T1, *T2 = &__T2, 
	__T3, __T4, *T3 = &__T3, *T4 = &__T4;
	for (int64_t i = 0; i < 8; ++i) {
		mask->key64[i] = -bit;
	}
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
	curve25519_key_t T1, T1T1, T2, T2T2, T1T4, T2T3, T3, T4, T5;
	// # Step 2: T1 <- X2 + Z2
	// T1 = (X2 + Z2) % M
	curve25519_key_add_modulo(&XZ2->X, &XZ2->Z, &T1);
	// # Step 6: T5 <- T1 ^ 2
	// T1T1 = (T1 * T1) % M
	curve25519_key_t tmp;
	curve25519_key_copy(&tmp, &T1);
	curve25519_key_mul_modulo(&T1, &tmp, &T1T1);
	// # Step 3: T2 <- X2 − Z2
	// T2 = (X2 - Z2) % M
	curve25519_key_sub_modulo(&XZ2->X, &XZ2->Z, &T2);
	// # Step 7: T6 <- T2 ^ 2
	// T2T2 = (T2 * T2) % M
	curve25519_key_copy(&tmp, &T2);
	curve25519_key_mul_modulo(&T2, &tmp, &T2T2);
	// # Step 16: T5 <- T5 − T6
	// T5 = (T1T1 - T2T2) % M 
	curve25519_key_sub_modulo(&T1T1, &T2T2, &T5);
	// # Step 4: T3 <- X3 + Z3
	// T3 = (X3 + Z3) % M
	curve25519_key_add_modulo(&XZ3->X, &XZ3->Z, &T3);
	// # Step 5: T4 <- X3 - Z3
	// T4 = (X3 - Z3) % M
	curve25519_key_sub_modulo(&XZ3->X, &XZ3->Z, &T4);
	// # Step 9: T1 <- T1 · T4
	// T1T4 = (T4 * T1) % M
	curve25519_key_mul_modulo(&T1, &T4, &T1T4);
	// # Step 8: T2 <- T2 · T3
	// T2T3 = (T3 * T2) % M
	curve25519_key_mul_modulo(&T2, &T3, &T2T3);	
	// # Step 10: T1 <- T1 + T2
	// # Step 12: X3 <- T1 ^ 2
	// X3 = (((T1T4 + T2T3) % M) ** 2) % M
	curve25519_key_add_modulo(&T1T4, &T2T3, &tmp);
	curve25519_key_copy(&XZ3->X, &tmp);
	curve25519_key_mul_modulo_inplace(&XZ3->X, &tmp);
	// # Step 11: T2 <- T1 − T2
	// # Step 13: T2 <- T2 ^ 2
	// # Step 14: Z3 <- T2 · X1
	// Z3 = (X1 * (((T1T4 - T2T3) % M) ** 2)) % M
	curve25519_key_sub_modulo(&T1T4, &T2T3, &XZ3->Z);
	curve25519_key_copy(&tmp, &XZ3->Z);
	curve25519_key_mul_inplace(&XZ3->Z, &tmp);
	curve25519_key_mul_modulo_inplace(&XZ3->Z, X1);
	// # Step 15: X2 <- T5 · T6
	// X2 = (T1T1 * T2T2) % M
	curve25519_key_mul_modulo(&T1T1, &T2T2, &XZ2->X);
	// # Step 17: T1 <- ((A + 2)/4) · T5
	// # Step 18: T6 <- T6 + T1
	// # Step 19: Z2 <- T5 · T6
	// Z2 = (T5 * ((T1T1 + (A24 * T5) % M) % M)) % M
	curve25519_key_mul_modulo(A24, &T5, &XZ2->Z);
	curve25519_key_add_modulo_inplace(&XZ2->Z, &T1T1);
	curve25519_key_mul_modulo_inplace(&XZ2->Z, &T5);
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
		curve25519_cswap(&XZ2, &XZ3, b);
		curve25519_ladder_step(&XZ2, &XZ3, Xp);
	}
	return curve25519_proj_to_affine(&XZ2, nXp);
}

int32_t curve25519_pub_key_init(const curve25519_key_t *const restrict priv_key, const curve25519_key_t *const restrict pt, curve25519_key_t *const restrict r) {
	return curve25519_ladder(priv_key, pt, r);
}

#define curve25519_base_mul(priv_key, r) curve25519_ladder(priv_key, BASE, r)

int32_t curve25519_generate_shared_key(const curve25519_key_t *const restrict priv_key, const curve25519_key_t *const restrict pub_key, curve25519_key_t *const restrict shared_key) {
	return curve25519_ladder(priv_key, pub_key, shared_key);
}