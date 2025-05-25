#pragma once
#ifndef CURVE25519_KEY_H__
#define CURVE25519_KEY_H__
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <immintrin.h>

#include <windows.h>
#include <bcrypt.h>
// #pragma comment(lib, "bcrypt.lib")

typedef union curve25519_key {
	__uint128_t key128[4];
	uint64_t key64[8];
	uint32_t key32[16];
	uint16_t key16[32];
	uint8_t key8[64];
} curve25519_key_t __attribute__((aligned(64)));

typedef struct curve25519_key_signed {
	curve25519_key_t key;
	uint64_t borrow;
} curve25519_key_signed_t;

typedef enum curve25519_key_fmt {
	B8,
	B16,
	B32,
	B64,
	STR,
	COMPLETE
} curve25519_key_fmt_t;

int32_t curve25519_priv_key_init(curve25519_key_t *const key);
void curve25519_key_copy(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);
int64_t curve25519_key_cmp_low(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
int64_t curve25519_key_cmp_high(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
int64_t curve25519_key_cmp(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
void curve25519_key_compute_modulo(curve25519_key_t *const n);
int32_t curve25519_key_add(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_add_modulo(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_add_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_signed_t *const restrict r);  
int32_t curve25519_key_sub_inplace(curve25519_key_signed_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_sub_modulo(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_sub_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_x2(const curve25519_key_t *const k, curve25519_key_t *const restrict r);
int32_t curve25519_key_x2_inplace(curve25519_key_t *const k);
int32_t curve25519_key_x2_modulo(const curve25519_key_t *const restrict k, curve25519_key_t *const restrict r);
int32_t curve25519_key_x2_modulo_inplace(curve25519_key_t *const k);
uint64_t curve25519_key_lshift(const curve25519_key_t *const restrict k, int64_t shift, curve25519_key_t *const restrict r);
uint64_t curve25519_key_rshift(const curve25519_key_t *const restrict k, int64_t shift, curve25519_key_t *const restrict r);
uint64_t curve25519_key_lshift_inplace(curve25519_key_t *const restrict k, int64_t shift);
uint64_t curve25519_key_rshift_inplace(curve25519_key_t *const restrict k, int64_t shift);
void curve25519_key_and(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);
void curve25519_key_xor(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);
int64_t curve25519_key_log2(const curve25519_key_t *const k, curve25519_key_t *const restrict r);
int32_t curve25519_key_mul(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r);
int32_t curve25519_key_mul_modulo(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r);
int32_t curve25519_key_mul_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);
int32_t curve25519_key_mul_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);
int32_t curve25519_key_div(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict q, curve25519_key_t *const r);
int32_t curve25519_key_divmod(const curve25519_key_t *const restrict num, const curve25519_key_t *const restrict den, curve25519_key_t *const restrict q);
/** 
 * @brief Calculates inverse of key modulo 2 ^ 255 - 19
 * @param k Key to invert
 * @param r Out parameter containing the modular inverse of k
 * @return 0 if the key can be inverted. -1 otherwise.
 */
int32_t curve25519_key_inv(const curve25519_key_t *const k, curve25519_key_t *const restrict r);
/** 
 * @brief Prints key to stdout
 * @param k Key to print
 * @param size Formatting enum
 * @return Number of bytes printed
 */
int32_t curve25519_key_printf(const curve25519_key_t *const k, const curve25519_key_fmt_t size);

#endif // CURVE25519_KEY_H__