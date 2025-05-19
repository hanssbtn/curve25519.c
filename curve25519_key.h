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
} __attribute__((aligned(64))) curve25519_key_t;

typedef enum byte_size {
	B8,
	B16,
	B32,
	B64,
} byte_size_t;

int curve25519_key_init(curve25519_key_t *key);
int curve25519_key_add(curve25519_key_t *const restrict k1, curve25519_key_t *const restrict k2, curve25519_key_t *restrict r);  
int curve25519_key_double(curve25519_key_t *const restrict key, curve25519_key_t *restrict r); 
int curve25519_key_multiply(curve25519_key_t *const restrict  k1, curve25519_key_t *const restrict k2, curve25519_key_t *restrict r);
int curve25519_key_printf(const curve25519_key_t *const key, const byte_size_t size);

#endif // CURVE25519_KEY_H__