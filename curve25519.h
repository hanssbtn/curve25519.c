#pragma once
#ifndef CURVE25519_H__
#define CURVE25519_H__

#include "curve25519_key.h"

#ifndef BASE_X
#define BASE_X 9
#endif // BASE_X

typedef struct curve25519_proj_point {
    curve25519_key_t X;
    curve25519_key_t Z;
} curve25519_proj_point_t;

static const curve25519_key_t __BASE = {.key64 = {BASE_X}};
static const curve25519_key_t *const BASE = &__BASE;

static const curve25519_key_t __A24 = {.key64 = {121665}};
static const curve25519_key_t *const A24 = &__A24;

int32_t curve25519_proj_to_affine(const curve25519_proj_point_t *const p1, curve25519_key_t *const out);
void curve25519_cswap(curve25519_proj_point_t *const restrict XZ2, curve25519_proj_point_t *const restrict XZ3, bool bit);
int32_t curve25519_cmp_eq(curve25519_proj_point_t *const restrict XZ2, curve25519_proj_point_t *const restrict XZ3);
int32_t curve25519_ladder_step(curve25519_proj_point_t *const restrict XZ2, curve25519_proj_point_t *const restrict XZ3, const curve25519_key_t *const restrict X1);
int32_t curve25519_ladder(const curve25519_key_t *const restrict Xp, const curve25519_key_t *const restrict n, curve25519_key_t *const restrict nXp);
int32_t curve25519_pub_key_init(const curve25519_key_t *const restrict priv_key, const curve25519_key_t *const restrict pt, curve25519_key_t *const restrict r);
int32_t curve25519_generate_shared_key(const curve25519_key_t *const restrict priv_key, const curve25519_key_t *const restrict pub_key, curve25519_key_t *const restrict shared_key);

#endif // CURVE25519_H__