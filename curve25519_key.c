#include "curve25519_key.h"

const curve25519_key_t __c25519 = {
	.key64 = {
		0xFFFFFFFFFFFFFFEDULL,
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFFULL,
		0x7FFFFFFFFFFFFFFFULL,
	}
};
const curve25519_key_t *const c25519 = &__c25519;
const curve25519_key_t __p = {
	.key64 = {
		0x0,
		0x0,
		0x0,
		0x9,
	}
};
const curve25519_key_t *const p = &__p;

void compute_modulo_25519(curve25519_key_t *const n) {
	while (curve25519_key_cmp(c25519, n) <= 0) {
		// check if n >= 2^255
		if (n->key8[31] & 0x80) {
			n->key8[31] &= 0x7F;
			uint64_t c = (n->key64[0] > UINT64_MAX - 19ULL);
			n->key64[0] += 19ULL;
			for (size_t i = 1; i < 4 && c; i++) {
				uint64_t sum = n->key64[i] + c;
				c = (n->key64[i] > sum);
				n->key64[i] = sum;
			}
		} 
		// 2^255 - 19 <= n < 2^255
		else {
			for (size_t i = 0; i < 4; i++) {
				n->key64[i] -= c25519->key64[i];
			}
		}
	}
}

int32_t curve25519_priv_key_init(curve25519_key_t *const key) {
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
	return gt_mask - lt_mask;
}

int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	uint64_t carry = (key1[0] > UINT64_MAX - key2[0]);
	key1[0] += key2[0];
	for (size_t i = 1; i < 4; i++) {
		uint64_t val = key1[i];
		key1[i] += key2[i] + carry;
		carry = (val > UINT64_MAX - key2[i]) || (val + key2[i] > UINT64_MAX - carry);
	}
	compute_modulo_25519(dst);
	return carry;
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
		carry = (key1[i] > UINT64_MAX - key2[i]) || (key1[i] + key2[i] > UINT64_MAX - carry);
	}

	compute_modulo_25519(r);
	return carry;
}  


int32_t curve25519_key_sub_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	
	uint64_t borrow = 0;
	for (int i = 0; i < 4; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		key1[i] = temp_res;
	}
	
	if (borrow) return curve25519_key_add_inplace(dst, c25519); 
	else compute_modulo_25519(dst);
	return 0;
}

int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	const uint64_t *const key1 = k1->key64, *key2 = k2->key64;
	uint64_t *const res = r->key64;

	uint64_t borrow = 0;
	for (int i = 0; i < 4; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		res[i] = temp_res;
	}
	if (borrow) return curve25519_key_add_inplace(r, c25519); 
	else compute_modulo_25519(r);
	return 0;
}  

int32_t curve25519_key_x2_inplace(curve25519_key_t *const k) {
	uint64_t *const key = k->key64;
	uint64_t carry = (key[0] > UINT64_MAX / 2);
	key[0] <<= 1;
	for (int i = 1; i < 4; ++i) {
		uint64_t tmp = (key[i] << 1) + carry;
		carry = (key[i] > UINT64_MAX / 2 - carry);
		key[i] = tmp;
	}
	compute_modulo_25519(k);
	return carry;
}

int32_t curve25519_key_x2(const curve25519_key_t *const restrict k, curve25519_key_t *const restrict r) {
	const uint64_t *const key = k->key64;
	uint64_t *key_res = r->key64;
	uint64_t carry = (key[0] > UINT64_MAX / 2);
	key_res[0] = (key[0] << 1);
	for (int i = 1; i < 4; ++i) {
		key_res[i] = (key[i] << 1) + carry;
		carry = (key[i] > UINT64_MAX / 2 - carry);
	}
	compute_modulo_25519(r);
	return carry;
} 

int32_t curve25519_key_div(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r) {

}

int32_t curve25519_key_mul(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r) {
	

	curve25519_key_printf(r, STR);
	if (curve25519_key_cmp(c25519, r) <= 0) {
		return curve25519_key_sub_inplace(r, c25519);
	}
	return 0;
}

int32_t curve25519_key_printf(const curve25519_key_t *const k, const curve25519_key_fmt_t size) {
	switch (size) {
		case STR: {
			return printf("%016llX%016llX%016llX%016llX\n", 
				k->key64[3], k->key64[2], k->key64[1], k->key64[0]);
		}
		case B64: {
			return printf("%016llX:%016llX:\n%016llX:%016llX\n", 
				k->key64[3], k->key64[2], k->key64[1], k->key64[0]);
		}
		case B32: {
			return printf("%08X:%08X:%08X:%08X:\n%08X:%08X:%08X:%08X\n", 
				k->key32[7], k->key32[6], k->key32[5], k->key32[4], k->key32[3], k->key32[2], k->key32[1], k->key32[0]);
		}
		case B16: {
			return printf("%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X:\n%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", 
				k->key16[15], k->key16[14], k->key16[13], k->key16[12], k->key16[11], k->key16[10], k->key16[9], k->key16[8], 
				k->key16[7], k->key16[6], k->key16[5], k->key16[4], k->key16[3], k->key16[2], k->key16[1], k->key16[0]);
		}
		case B8: {
			return printf("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:\n%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", 
				k->key8[31], k->key8[30], k->key8[29], k->key8[28], k->key8[27], k->key8[26], k->key8[25], k->key8[24], 
				k->key8[23], k->key8[22], k->key8[21], k->key8[20], k->key8[19], k->key8[18], k->key8[17], k->key8[16],
				k->key8[15], k->key8[14], k->key8[13], k->key8[12], k->key8[11], k->key8[10], k->key8[9], k->key8[8], 
				k->key8[7], k->key8[6], k->key8[5], k->key8[4], k->key8[3], k->key8[2], k->key8[1], k->key8[0]);
		}
	}
	return 0;
}
