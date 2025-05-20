#include "curve25519_key.h"

const curve25519_key_t __c25519 = {
	.key64 = {
		0x7FFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFEDULL,
	}
};
const curve25519_key_t *const c25519 = &__c25519;

int32_t curve25519_key_init(curve25519_key_t *key) {
	NTSTATUS status;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error opening crypto algorithm provider\n");
        return -1;
    }
	uint8_t *key8 = key->key8;
    status = BCryptGenRandom(hAlgorithm, key8, (uint32_t)sizeof(curve25519_key_t), 0);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "Error generating random bytes\n");
        return -2;
    }
	key8[0] &= ~(uint8_t)(0b111);
	key8[31] = (key8[31] | 0x40) & 0x7F;
    return 0;
}

int64_t curve25519_key_cmp(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2) {
	__m256i key1 = _mm256_loadu_epi64(k1->key64), key2 = _mm256_loadu_epi64(k2->key64);
	__mmask8 lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	__mmask8 gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	printf("%08x, %08x\n", lt_mask, gt_mask);
	return gt_mask - lt_mask;
}

int32_t curve25519_key_sub_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	uint64_t carry = (key1[0] > UINT64_MAX - key2[0]);
	key1[0] += key2[0];
	for (size_t i = 1; i < 4; i++) {
		uint64_t curr = key1[i] + key2[i] + carry;
		carry = (curr < key1[i]);
	}
	return 0;
}

int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	return 0;
}

int32_t curve25519_key_add(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	// __m256i key1 = _mm256_loadu_si256((__m256i*)k1->key64), key2 = _mm256_loadu_si256((__m256i*)k2->key64), carry = _mm256_set1_epi64x(1ULL);
	// __m256i s1 = _mm256_add_epi64(key1, key2);
	// __mmask8 carry_mask = _mm256_cmplt_epu64_mask(s1, key1);
	// carry_mask = _kshiftli_mask8(carry_mask, 1);
	// __m256i s2 = _mm256_mask_add_epi64(s1, carry_mask, s1, carry);
	// carry_mask = _mm256_cmplt_epu64_mask(s2, s1);
	// carry_mask = _kshiftli_mask8(carry_mask, 1);
	// __m256i s3 = _mm256_mask_add_epi64(s2, carry_mask, s2, carry);
	// carry_mask = _mm256_cmplt_epu64_mask(s3, s2);
	// carry_mask = _kshiftli_mask8(carry_mask, 1);
	// __m256i s4 = _mm256_mask_add_epi64(s3, carry_mask, s3, carry);
	// __m256i c25519 = _mm256_set_epi64x(0x7FFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFEDULL);
	// carry_mask = _mm256_cmpge_epu64_mask(s4, c25519);
	
	// _mm256_storeu_si256((__m256i*)r->key64, s5);
	const uint64_t *key1 = k1->key64, *key2 = k2->key64;
	uint64_t *key_res = r->key64;
	key_res[0] = key1[0] + key2[0]; 
	uint64_t carry = (key1[0] > UINT64_MAX - key2[0]);
	for (size_t i = 1; i < 4; i++) {
		key_res[i] = key1[i] + key2[i] + carry;
		carry = (key_res[i] <= key1[i]);
	}
	curve25519_key_printf(r, STR);
	if (curve25519_key_cmp(c25519, r) >= 0) {
		curve25519_key_sub_inplace(r, c25519);
	}
	return 0;
}  

int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	// __m256i key1 = _mm256_loadu_si256((__m256i*)k1->key64), key2 = _mm256_loadu_si256((__m256i*)k2->key64), res, carry;
	// __m256i sign64 = _mm256_set1_epi64x(0x8000000000000000L);
	// res = _mm256_add_epi64(key1, key2);
	// carry = 
	return 0;
}  

int32_t curve25519_key_double(const curve25519_key_t *const restrict key, curve25519_key_t *const restrict r) {

	return 0;
} 

int32_t curve25519_key_multiply(curve25519_key_t *const restrict  k1, curve25519_key_t *const restrict k2, curve25519_key_t *restrict r) {
	return 0;
}

int32_t curve25519_key_printf(const curve25519_key_t *const key, const curve25519_key_fmt_t size) {
	switch (size) {
		case STR: {
			return printf("%016X%016X%016X%016X\n", 
				key->key64[3], key->key64[2], key->key64[1], key->key64[0]);
		}
		case B64: {
			return printf("%016X:%016X:\n%016X:%016X\n", 
				key->key64[3], key->key64[2], key->key64[1], key->key64[0]);
		}
		case B32: {
			return printf("%08X:%08X:%08X:%08X:\n%08X:%08X:%08X:%08X\n", 
				key->key32[7], key->key32[6], key->key32[5], key->key32[4], key->key32[3], key->key32[2], key->key32[1], key->key32[0]);
		}
		case B16: {
			return printf("%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X:\n%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", 
				key->key16[15], key->key16[14], key->key16[13], key->key16[12], key->key16[11], key->key16[10], key->key16[9], key->key16[8], 
				key->key16[7], key->key16[6], key->key16[5], key->key16[4], key->key16[3], key->key16[2], key->key16[1], key->key16[0]);
		}
		case B8: {
			return printf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:\n%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", 
				key->key8[31], key->key8[30], key->key8[29], key->key8[28], key->key8[27], key->key8[26], key->key8[25], key->key8[24], 
				key->key8[23], key->key8[22], key->key8[21], key->key8[20], key->key8[19], key->key8[18], key->key8[17], key->key8[16],
				key->key8[15], key->key8[14], key->key8[13], key->key8[12], key->key8[11], key->key8[10], key->key8[9], key->key8[8], 
				key->key8[7], key->key8[6], key->key8[5], key->key8[4], key->key8[3], key->key8[2], key->key8[1], key->key8[0]);
		}
	}
}

int32_t curve25519_key_init_test() {
	curve25519_key_t key = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t prev_key = {.key64 = {0, 0, 0, 0}};
	if (curve25519_key_init(&key)) {
		return -1;
	}
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			return -2;
		}
		prev_key.key64[i] = key.key64[i];
	}
	if (curve25519_key_init(&key)) {
		return -3;
	}
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			return -4;
		}
		prev_key.key64[i] = key.key64[i];
	}
	if (curve25519_key_init(&key)) {
		return -5;
	}
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			return -6;
		}
		prev_key.key64[i] = key.key64[i];
	}
	if (curve25519_key_init(&key)) {
		return -7;
	}
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			return -8;
		}
		prev_key.key64[i] = key.key64[i];
	}
	if (curve25519_key_init(&key)) {
		return -9;
	}
	for (int32_t i = 0; i < 4; ++i) {
		if (prev_key.key64[i] == key.key64[i]) {
			return -10;
		}
		prev_key.key64[i] = key.key64[i];
	}
	return 0;
}

int32_t curve25519_key_cmp_test() {
	curve25519_key_t k1 = {.key64 = {0,0,0,0}};
	curve25519_key_t k2 = {.key64 = {0,0,0,0}};
	int64_t res = curve25519_key_cmp(&k1, &k2);
    printf("Test Case 1: k1 == k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    printf("res: %lld (Expected: 0)\n", res);
    if (!res) {
        printf("Test Case 1 PASSED\n");
    } else {
        printf("Test Case 1 FAILED\n");
        return -1;
    }
	printf("---\n\n");

	k1 = (curve25519_key_t){.key64 = {
        0x123456789ABCDEF0ULL, // This is smaller
        0xFFEEDDCCBBAA9988ULL,
        0x1122334455667788ULL,
        0xAABBCCDDEEFF0011ULL
    }};
    k2 = (curve25519_key_t){.key64 = {
        0x123456789ABCDEF1ULL, // This is larger
        0xFFEEDDCCBBAA9988ULL,
        0x1122334455667788ULL,
        0xAABBCCDDEEFF0011ULL
    }};
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    printf("Test Case 2: k1 < k2\n");
    res = curve25519_key_cmp(&k1, &k2);
    printf("res: %lld (Expected: -1)\n", res);
    if (res == -1) {
        printf("Test Case 2 PASSED\n");
    } else {
        printf("Test Case 2 FAILED\n");
        return -2;
    }
	printf("---\n\n");

	k1 = (curve25519_key_t){.key64 = {
        0xABCDEF0123456789ULL,
        0xDEADBEEFCAFEBABEULL,
        0x0000000000000002ULL, // This is larger
        0x5A5A5A5A5A5A5A5AUll
    }};
    k2 = (curve25519_key_t){.key64 = {
        0xABCDEF0123456789ULL, 
        0xDEADBEEFCAFEBABEULL,
        0x0000000000000001ULL, // This is smaller
        0xFFFFFFFFFFFFFFFFULL // This would be larger if comparison continued
    }};

    printf("Test Case 3: k1 < k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    res = curve25519_key_cmp(&k1, &k2);
    printf("res: %lld (Expected: 4)\n", res);
    if (res == -4) {
        printf("Test Case 3 PASSED\n");
    } else {
        printf("Test Case 3 FAILED\n");
        return -3;
    }
    printf("---\n\n");

	k1 = (curve25519_key_t){.key64 = {
        0x7FFFFFFFFFFFFFFFULL,
        0x8000000000000000ULL,
        0x1111111122222222ULL,
        0xCCCCCCCCDDDDDDDDULL
    }};
    k2 = (curve25519_key_t){.key64 = {
        0x7FFFFFFFFFFFFFFFULL,
        0x8000000000000000ULL,
        0x1111111122222222ULL,
        0xCCCCCCCCDDDDDDDDULL
    }};
    printf("Test Case 4: k1 == k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    res = curve25519_key_cmp(&k1, &k2);
    printf("res: %lld (Expected: 0)\n", res);
    if (!res) {
        printf("Test Case 4 PASSED\n");
    } else {
        printf("Test Case 4 FAILED\n");
        return -4;
    }
    printf("---\n\n");

	k1 = (curve25519_key_t){.key64 = {
        0x1020304050607080ULL,
        0x90A0B0C0D0E0F000ULL,
        0x1122334455667788ULL,
        0x0000000000000001ULL // This is smaller
    }};
    k2 = (curve25519_key_t){.key64 = {
        0x1020304050607080ULL, // These are the same
        0x90A0B0C0D0E0F000ULL,
        0x1122334455667788ULL,
        0x0000000000000002ULL // This is larger
    }};

    printf("Test Case 5: k1 < k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    res = curve25519_key_cmp(&k1, &k2);
    printf("res: %lld (Expected: -8)\n", res);
    if (res == -8) {
        printf("Test Case 5 PASSED\n");
    } else {
        printf("Test Case 5 FAILED\n");
        return -5;
    }
    printf("---\n\n");


    // Test Case 5: k1 > k2 (Difference at second uint64_t)
    k1 = (curve25519_key_t){.key64 = {
        0xAABBCCDDEEFF0011ULL, // This is the same
        0x0FFFFFFFFFFFFFFFULL, // This is smaller
        0xFFFFFFFFFFFFFFFFULL, // This would be larger if comparison continued
        0xFFFFFFFFFFFFFFFFULL
    }};
	k2 = (curve25519_key_t){.key64 = {
		0xAABBCCDDEEFF0011ULL,
		0x1000000000000000ULL, // This is larger
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};

    res = curve25519_key_cmp(&k1, &k2);
    printf("Test Case 6: k1 < k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    printf("res: %lld (Expected: > 0)\n", res);
    if (res < 0) {
        printf("Test Case 6 FAILED\n");
        return -6;
    }
    printf("---\n\n");

	return 0;
}

int32_t main(void) {
	if (curve25519_key_init_test()) {
		fprintf(stderr, "Failed to initialize key\n");
		return -1;
	}
	if (curve25519_key_cmp_test()) {
		fprintf(stderr, "Failed to compare key\n");
		return -1;
	}
	printf("DONE\n");
	return 0;
}