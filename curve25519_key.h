#pragma once
#ifndef CURVE25519_KEY_H__
#define CURVE25519_KEY_H__
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <immintrin.h>

#ifndef BASE_POINT
#define BASE_POINT 9
#endif // BASE_POINT

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef union curve25519_key {
	uint64_t key64[4];
	uint32_t key32[8];
	uint16_t key16[16];
	uint8_t key8[32];
} curve25519_key_t __attribute__((aligned(64)));

typedef enum curve25519_key_fmt {
	B8,
	B16,
	B32,
	B64,
	STR
} curve25519_key_fmt_t;

int32_t curve25519_key_init(curve25519_key_t *key);
int64_t curve25519_key_cmp(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2);
int32_t curve25519_key_add(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);  
int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_sub_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src);  
int32_t curve25519_key_double(const curve25519_key_t *const restrict key, curve25519_key_t *const restrict r);
int32_t curve25519_key_multiply(curve25519_key_t *const restrict  k1, curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r);
int32_t curve25519_key_printf(const curve25519_key_t *const key, const curve25519_key_fmt_t size);

#endif // CURVE25519_KEY_H__