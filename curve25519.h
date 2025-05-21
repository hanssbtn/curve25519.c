#pragma once
#ifndef CURVE25519_H__
#define CURVE25519_H__

#include "curve25519_key.h"

typedef struct curve25519_affine_point {
    curve25519_key_t X;
    curve25519_key_t Z;
} curve25519_affine_point_t;

int32_t curve25519_point_add(curve25519_key_t *p1, curve25519_key_t *p2, curve25519_key_t *r);
int32_t curve25519_point_x2(curve25519_key_t *p1, curve25519_key_t *p2, curve25519_key_t *r);
int32_t curve25519_pub_key_init(const curve25519_key_t *const restrict priv_key, const curve25519_key_t *const restrict pt, curve25519_key_t *const restrict r);

#endif // CURVE25519_H__