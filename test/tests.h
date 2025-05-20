#pragma once
#ifndef CURVE25519_TESTS_H__
#define CURVE25519_TESTS_H__
#include "../curve25519_key.h"

int32_t curve25519_priv_key_init_test(void);
int32_t curve25519_key_cmp_test(void);
int32_t curve25519_key_modulo_test(void);
int32_t curve25519_key_add_test(void);
int32_t curve25519_key_add_inplace_test(void);
int32_t curve25519_key_sub_test(void);
int32_t curve25519_key_sub_inplace_test(void);

#endif // CURVE25519_TESTS_H__