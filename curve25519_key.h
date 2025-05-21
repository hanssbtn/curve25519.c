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

#ifndef BASE_X
#define BASE_X 9
#endif // BASE_X

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

typedef enum curve25519_key_fmt {
	B8,
	B16,
	B32,
	B64,
	STR,
	COMPLETE
} curve25519_key_fmt_t;

int32_t curve25519_priv_key_init(curve25519_key_t *const key);
int64_t curve25519_key_cmp_low(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
int64_t curve25519_key_cmp_high(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
int64_t curve25519_key_cmp(const curve25519_key_t *const k1, const curve25519_key_t *const k2);
void compute_modulo_25519(curve25519_key_t *const n);
int32_t curve25519_key_add(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_sub_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_x2(const curve25519_key_t *const k, curve25519_key_t *const restrict r);
int32_t curve25519_key_x2_inplace(curve25519_key_t *const k);
int32_t curve25519_key_add_modulo(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_add_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_x2_modulo(const curve25519_key_t *const k, curve25519_key_t *const restrict r);
int32_t curve25519_key_x2_modulo_inplace(curve25519_key_t *const k);
void curve25519_key_lshift(const curve25519_key_t *const restrict k, int64_t shift, curve25519_key_t *const restrict r);
void curve25519_key_rshift(const curve25519_key_t *const restrict k, int64_t shift, curve25519_key_t *const restrict r);
void curve25519_key_lshift_inplace(curve25519_key_t *const k, int64_t shift);
void curve25519_key_rshift_inplace(curve25519_key_t *const k, int64_t shift);
int32_t curve25519_key_mul(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r);
int32_t curve25519_key_div(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r);
int32_t curve25519_key_exp(curve25519_key_t *const k1, uint64_t n);
int32_t curve25519_key_printf(const curve25519_key_t *const k, const curve25519_key_fmt_t size);

#endif // CURVE25519_KEY_H__