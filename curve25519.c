#include "curve25519.h" // Assuming this header includes curve25519_key_t and your other functions

int32_t curve25519_proj_to_affine(const curve25519_proj_point_t *const p1, curve25519_proj_point_t *const out) {
	curve25519_key_copy(&p1->Z, &out->Z, sizeof(curve25519_key_t));
	return curve25519_key_mul_modulo(&p1->X, &p1->Z, &out->X);
}

void curve25519_ladder(const curve25519_key_t *const restrict Xp, const curve25519_key_t *const restrict nXp) {
	curve25519_proj_point_t XZ2 = {.X = {.key8 = {1}}}, XZ3;
	curve25519_key_copy(&XZ3.X.key8, Xp->key8, sizeof(curve25519_key_t));
	XZ3.Z = (curve25519_key_t){.key8 = {1}};

}

int32_t curve25519_ladder_step(
	curve25519_proj_point_t *const restrict XZ2, 
	curve25519_proj_point_t *const restrict XZ3, 
	const curve25519_key_t *const restrict X1
) {
	curve25519_key_t T1, T2, T3, T4, T5, T6;
	curve25519_key_t T1_old, T2_old;
	// T1 <- X2 + Z2
	curve25519_key_add_modulo(&XZ2->X, &XZ2->Z, &T1);
	// T2 <- X2 - Z2
	curve25519_key_sub_modulo(&XZ2->X, &XZ2->Z, &T2);
	// T3 <- X3 + Z3
	curve25519_key_add_modulo(&XZ3->X, &XZ3->Z, &T3);
	// T4 <- X3 - Z3
	curve25519_key_sub_modulo(&XZ3->X, &XZ3->Z, &T4);
	// T5 <- T1 ^ 2
	curve25519_key_copy(T1_old.key8, T1.key8, sizeof(curve25519_key_t));
	curve25519_key_mul_modulo(&T1, &T1_old, &T5);
	// T6 <- T2 ^ 2
	curve25519_key_copy(T2_old.key8, T2.key8, sizeof(curve25519_key_t));
	curve25519_key_mul_modulo(&T2, &T2_old, &T6);
	// T2 <- T2 · T3
	curve25519_key_mul_modulo_inplace(&T2, &T3);
	// T1 <- T1 · T4
	curve25519_key_mul_modulo_inplace(&T1, &T4);
	// T1 <- T1 + T2
	curve25519_key_add_modulo_inplace(&T1, &T2);
	// T2 <- T1 - T2
	curve25519_key_copy(T2_old.key8, T2.key8, sizeof(curve25519_key_t));
	curve25519_key_sub_modulo(&T1, &T2_old, &T2);
	// X3 <- T1 ^ 2
	curve25519_key_copy(T1_old.key8, T1.key8, sizeof(curve25519_key_t));
	curve25519_key_mul_modulo(&T1, &T1_old, &XZ3->X);
	// T2 <- T2 ^ 2
	curve25519_key_copy(T2_old.key8, T2.key8, sizeof(curve25519_key_t));
	curve25519_key_mul_modulo_inplace(&T2, &T2_old);
	// Z3 <- T2 · X1
	curve25519_key_mul_modulo(&T2, &X1, &XZ3->Z);
	// X2 <- T5 · T6
	curve25519_key_mul_modulo(&T5, &T6, &XZ2->X);
	// T5 <- T5 - T6
	curve25519_key_sub_modulo_inplace(&T5, &T6);
	// T1 <- A24 · T5
	curve25519_key_mul_modulo(A24, &T5, &T1);
	// T6 <- T6 + T1
	curve25519_key_add_inplace_modulo(&T6, &T1);
	// Z2 <- T5 · T6
	curve25519_key_add_inplace_modulo(&T5, &T6, &XZ2->Z);
	return 0;
}