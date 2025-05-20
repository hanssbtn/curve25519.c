#include "tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Comparison Test\n\n");
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
    printf("res: %lld (Expected: -4)\n", res);
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
    printf("Test Case 6: k1 > k2\n");
	printf("key1:\n");
	curve25519_key_printf(&k1, B64);
	printf("key2:\n");
	curve25519_key_printf(&k2, B64);
    printf("res: %lld (Expected: 10)\n", res);
    if (res < 0) {
        printf("Test Case 6 FAILED\n");
        return -6;
    }
    printf("---\n\n");

	return 0;
}