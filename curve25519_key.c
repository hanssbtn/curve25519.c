#include "curve25519_key.h"

const curve25519_key_t __c25519 = {
	.key64 = {
		0xFFFFFFFFFFFFFFEDULL, // LSB
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFFULL,
		0x7FFFFFFFFFFFFFFFULL, 
		0,
		0,
		0,
		0 // MSB
	}
};
const curve25519_key_t *const c25519 = &__c25519;
const curve25519_key_t __ZERO = {};
const curve25519_key_t *const ZERO = &__ZERO;
const curve25519_key_t __ONE = {.key64 = {1}};
const curve25519_key_t *const ONE = &__ONE;

void print_bits(uint64_t n) {
	for (uint64_t i = 63; i > 0; --i) {
		printf("%llu", (n & (1ULL << i)) >> i);
	}
	printf("%llu\n", (n & 1));
}

uint64_t curve25519_key_lshift_inplace(curve25519_key_t *const k, int64_t shift) {
	uint64_t *key = k->key64;
	// printf("Left shifting\n");
	// printf("Before:\n");
	// for (uint64_t k = 7; k > 0; --k) {
	// 	print_bits(key[k]);
	// }
	// print_bits(key[0]);
	// printf("\n\n");
	int64_t parts = shift/64;
	shift &= 63LL;

	// k->key[i] -> k->key[i + parts]
	// shift by 64 bytes, then shift the rest normally
	int64_t i;
	for (i = 7; i - parts >= 0; --i) {
		key[i] = key[i - parts];
	}
	int64_t offset = i >= 0 ? i : 0;
	for (; i >= 0; --i){
		key[i] = 0;
	}
	if (!shift) return 0;
	int64_t nshift = 64ULL - shift;
	uint64_t carry = 0;
	for (; offset < 8; offset++) {
		uint64_t temp = key[offset] >> nshift;
		key[offset] = (key[offset] << shift) | carry;
		carry = temp;
	}
	// printf("After:\n");
	// for (uint64_t k = 7; k > 0; --k) {
	// 	print_bits(key[k]);
	// }
	// print_bits(key[0]);
	// printf("\n\n\n");

	return carry;
}

uint64_t curve25519_key_rshift_inplace(curve25519_key_t *const k, int64_t shift) {
	// printf("Right shifting\n");
	// printf("Before:\n");
	// for (ssize_t i = 7; i >= 0; --i) {
	// 	print_bits(key[i]);
	// }
	// curve25519_key_printf(k, COMPLETE);
	uint64_t *key = k->key64;
	int64_t parts = shift / 64;
	int64_t i;
	for (i = 0; i + parts < 8; ++i) {
		key[i] = key[i + parts];
	}		
	int64_t offset = i < 8 ? i : 7;
	for (; i < 8; ++i){
		key[i] = 0;
	}
	// printf("After:\n");
	// curve25519_key_printf(k, COMPLETE);
	shift &= 63LL;
	if (!shift) return 0;
	uint64_t mask = ((1ULL << shift) - 1), nshift = 64ULL - shift, carry_from_higher_word = 0; // No carry into the highest word

    for (; offset >= 0; --offset) {
        uint64_t bits_to_carry_down = (key[offset] & mask);
        key[offset] >>= shift;
        key[offset] |= (carry_from_higher_word << nshift);
        carry_from_higher_word = bits_to_carry_down;
    }

	// printf("After:\n");
	// for (ssize_t i = 7; i >= 0; --i) {
	// 	print_bits(key[i]);
	// }
	return carry_from_higher_word;
}

uint64_t curve25519_key_lshift(const curve25519_key_t *const k, int64_t shift, curve25519_key_t *const restrict r) {
	const uint64_t *const key = k->key64;
	uint64_t *const res = r->key64;
	// printf("Before:\n");
	// for (uint64_t i = 7; i > 0; --i) {
	// 	print_bits(key[i]);
	// }
	// print_bits(key[0]);
	int64_t parts = shift/64;
	// printf("parts: %lld, shift: %lld\n", parts, shift);
	// printf("Before:\n");
	// for (uint64_t i = 7; i > 0; --i) {
	// 	print_bits(res[i]);
	// }
	// print_bits(res[0]);
	// curve25519_key_printf(r, COMPLETE);
	int64_t i;
	for (i = 7; i - parts >= 0; --i) {
		res[i] = key[i - parts];
	}
	int64_t offset = i >= 0 ? i : 0;
	for (; i >= 0; --i){
		res[i] = 0;
	}
	// printf("After:\n");
	// for (uint64_t i = 7; i > 0; --i) {
		// 	print_bits(res[i]);
		// }
		// print_bits(res[0]);
	// curve25519_key_printf(r, COMPLETE);
	shift &= 63LL;
	if (!shift) {
		return 0;
	}
	uint64_t nshift = 64ULL - shift;
	// printf("Offset: %lld, shift: %lld, nshift: %lld\n", offset, shift, nshift);
	uint64_t carry = 0;
	for (; offset < 8; offset++) {
		uint64_t temp = res[offset] >> nshift;
		res[offset] = (res[offset] << shift) | carry;
		carry = temp;
	}
	// printf("After:\n");
	// curve25519_key_printf(r, COMPLETE);
	// for (uint64_t i = 7; i > 0; --i) {
	// 	print_bits(res[i]);
	// }
	// print_bits(res[0]);
	return carry;
}

uint64_t curve25519_key_rshift(const curve25519_key_t *const restrict k, int64_t shift, curve25519_key_t *const restrict r) {
	const uint64_t *const key = k->key64;
	uint64_t *const res = r->key64;
	int64_t parts = shift / 64;
	int64_t i;
	for (i = 0; i + parts < 8; ++i) {
		res[i] = key[i + parts];
	}		
	int64_t offset = i < 8 ? i : 7;
	for (; i < 8; ++i){
		res[i] = 0;
	}
	// printf("After:\n");
	// curve25519_key_printf(k, COMPLETE);
	shift &= 63LL;
	if (!shift) return 0;
	// printf("Before:\n");
	// for (ssize_t i = 7; i >= 0; --i) {
	// 	print_bits(key[i]);
	// }
	uint64_t mask = ((1ULL << shift) - 1), nshift = 64ULL - shift;
	uint64_t carry_from_higher_word = 0; // No carry into the highest word

    for (; offset >= 0; --offset) {
        uint64_t bits_to_carry_down = (res[offset] & mask);
        res[offset] = res[offset] >> shift;
        res[offset] |= (carry_from_higher_word << nshift);
        carry_from_higher_word = bits_to_carry_down;
    }

	// printf("After:\n");
	// for (ssize_t i = 7; i >= 0; --i) {
	// 	print_bits(res[i]);
	// }
	return carry_from_higher_word;
}

void compute_modulo_25519(curve25519_key_t *const n) {
	while (curve25519_key_cmp(c25519, n) <= 0) {
		uint64_t *low = n->key64, *high = n->key64 + 4;
		// n >= 2^256
		if (curve25519_key_cmp_high(n, ZERO) > 0) {
			curve25519_key_t q0_38 = {};
			do {
				curve25519_key_t q0 = {.key64 = {high[0], high[1], high[2], high[3]}};
				curve25519_key_t temp = {};
				curve25519_key_lshift(&q0, 5, &q0_38);
				curve25519_key_lshift(&q0, 2, &temp);
				curve25519_key_add_inplace(&q0_38, &temp);
				curve25519_key_lshift(&q0, 1, &temp);
				curve25519_key_add_inplace(&q0_38, &temp);
			} while (0);
			high[3] = 0;
			high[2] = 0;
			high[1] = 0;
			high[0] = 0;
			curve25519_key_add_inplace(n, &q0_38);
		} 
		// 2^255 <= n < 2^256
		else if (n->key8[31] & 0x80) {
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
		// check if n >= 2^255
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
	status = BCryptGenRandom(hAlgorithm, key8, 32, 0);
	key->key64[4] = 0ULL;
	key->key64[5] = 0ULL;
	key->key64[6] = 0ULL;
	key->key64[7] = 0ULL;
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (!BCRYPT_SUCCESS(status)) {
		fprintf(stderr, "Error generating random bytes\n");
		return -2;
	}
	key8[0] &= ~(uint8_t)(0b111);
	key8[31] = (key8[31] | 0x40) & 0x7F;
	return 0;
}

int64_t curve25519_key_cmp_low(const curve25519_key_t *const k1, const curve25519_key_t *const k2) {
	__m256i key1 = _mm256_loadu_epi64(k1->key64), key2 = _mm256_loadu_epi64(k2->key64);
	__mmask8 lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	__mmask8 gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	return gt_mask - lt_mask;
}

int64_t curve25519_key_cmp_high(const curve25519_key_t *const k1, const curve25519_key_t *const k2) {
	__m256i key1 = _mm256_loadu_epi64(k1->key64 + 4), key2 = _mm256_loadu_epi64(k2->key64 + 4);
	__mmask8 lt_mask = _mm256_cmplt_epu64_mask(key1, key2);
	__mmask8 gt_mask = _mm256_cmpgt_epu64_mask(key1, key2);
	return gt_mask - lt_mask;
}

int64_t curve25519_key_cmp(const curve25519_key_t *const k1, const curve25519_key_t *const k2) {
	int64_t res = curve25519_key_cmp_high(k1, k2);
	if (!res) return curve25519_key_cmp_low(k1, k2);
	else return res;
}

int32_t curve25519_key_add(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	const uint64_t *key1 = k1->key64, *key2 = k2->key64;
	uint64_t *key_res = r->key64;
	key_res[0] = key1[0] + key2[0]; 
	uint64_t carry = (key1[0] > UINT64_MAX - key2[0]);
	for (size_t i = 1; i < 8; i++) {
		key_res[i] = key1[i] + key2[i] + carry;
		carry = (key1[i] > UINT64_MAX - key2[i]) || (key1[i] + key2[i] > UINT64_MAX - carry);
	}
	return carry;
}  

int32_t curve25519_key_add_modulo(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	int32_t carry = curve25519_key_add(k1, k2, r);
	compute_modulo_25519(r);
	return carry;
}

int32_t curve25519_key_add_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	uint64_t carry = (key1[0] > UINT64_MAX - key2[0]);
	key1[0] += key2[0];
	for (size_t i = 1; i < 8; i++) {
		uint64_t val = key1[i];
		key1[i] += key2[i] + carry;
		carry = (val > UINT64_MAX - key2[i]) || (val + key2[i] > UINT64_MAX - carry);
	}
	return carry;
}

int32_t curve25519_key_add_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	int32_t carry = curve25519_key_add_inplace(dst, src);
	compute_modulo_25519(dst);
	return carry;
}

int32_t curve25519_key_sub_modulo_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	
	uint64_t borrow = 0;
	for (int i = 0; i < 8; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		key1[i] = temp_res;
	}
	
	if (borrow) return curve25519_key_add_inplace(dst, c25519);
	else compute_modulo_25519(dst);
	return 0;
}

int32_t curve25519_key_sub_modulo(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	const uint64_t *const key1 = k1->key64, *key2 = k2->key64;
	uint64_t *const res = r->key64;

	uint64_t borrow = 0;
	for (int i = 0; i < 8; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		res[i] = temp_res;
	}
	if (borrow) return curve25519_key_add_inplace(r, c25519); 
	else compute_modulo_25519(r);
	return 0;
}

int32_t curve25519_key_sub_inplace(curve25519_key_t *const restrict dst, const curve25519_key_t *const restrict src) {
	if (curve25519_key_cmp(dst, src) < 0) return -1;
	uint64_t *const key1 = dst->key64;
	const uint64_t *const key2 = src->key64;
	
	uint64_t borrow = 0;
	for (int i = 0; i < 8; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		key1[i] = temp_res;
	}
	return 0;
}

int32_t curve25519_key_sub(const curve25519_key_t *const restrict k1, const curve25519_key_t *const restrict k2, curve25519_key_t *const restrict r) {
	if (curve25519_key_cmp(k1, k2) < 0) return -1;
	const uint64_t *const key1 = k1->key64, *key2 = k2->key64;
	uint64_t *const res = r->key64;

	uint64_t borrow = 0;
	for (int i = 0; i < 8; ++i) {
		uint64_t temp_res = key1[i] - key2[i] - borrow;
		borrow = (key1[i] < key2[i]) || (key1[i] - key2[i] < borrow);
		res[i] = temp_res;
	}
	return 0;
}

int32_t curve25519_key_x2(const curve25519_key_t *const restrict k, curve25519_key_t *const restrict r) {
	const uint64_t *const key = k->key64;
	uint64_t *key_res = r->key64;
	uint64_t carry = (key[0] > UINT64_MAX / 2);
	key_res[0] = (key[0] << 1);
	for (int i = 1; i < 8; ++i) {
		key_res[i] = (key[i] << 1) + carry;
		carry = (key[i] > UINT64_MAX / 2 - carry);
	}
	return carry;
} 

int32_t curve25519_key_x2_inplace(curve25519_key_t *const k) {
	uint64_t *const key = k->key64;
	uint64_t carry = (key[0] > UINT64_MAX / 2);
	key[0] <<= 1;
	for (int i = 1; i < 8; ++i) {
		uint64_t tmp = (key[i] << 1) + carry;
		carry = (key[i] > UINT64_MAX / 2 - carry);
		key[i] = tmp;
	}
	return carry;
}

int32_t curve25519_key_x2_modulo(const curve25519_key_t *const restrict k, curve25519_key_t *const restrict r) {
	int32_t carry = curve25519_key_x2(k, r);
	compute_modulo_25519(r);
	return carry;
}

int32_t curve25519_key_x2_modulo_inplace(curve25519_key_t *const k) {
	int32_t carry = curve25519_key_x2_inplace(k);
	compute_modulo_25519(k);
	return carry;
}

int32_t curve25519_key_inv(const curve25519_key_t *const k, curve25519_key_t *const restrict r) {
	
	return 0;
}

int32_t curve25519_key_mul(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r) {
	if (!curve25519_key_cmp(ZERO, k1) || !curve25519_key_cmp(ZERO, k2)) {
		memset(r->key8, 0, sizeof(curve25519_key_t));
		return 0;
	}
	const uint64_t *const key1 = k1->key64, *const key2 = k2->key64;
	uint64_t *const res = r->key64;

	memset(res, 0ULL, sizeof(curve25519_key_t));

	for (size_t i = 0; i < 4; i++) {
		uint64_t carry_out = 0;
		for (size_t j = 0; j < 4; ++j) {
			__uint128_t p = ((__uint128_t)key1[j]) * ((__uint128_t)key2[i]);
			uint64_t hi = (uint64_t)(p >> 64), lo = (uint64_t)p, carry_in = 0;

			__uint128_t tmp = ((__uint128_t)lo) + ((__uint128_t)res[i + j]) + ((__uint128_t)carry_out);
			res[i + j] = (uint64_t)tmp;
			carry_in = (uint64_t)(tmp >> 64);
			carry_out = carry_in + hi;
		}
        for (size_t k = i + 4; k < 8; k++) {
			__uint128_t tmp = ((__uint128_t)res[k]) + carry_out;
			res[k] = (uint64_t)tmp;
			carry_out = (uint64_t)(tmp >> 64);
			if (!carry_out && k >= i + 4) break;
        }
	}
	return 0;
}

int32_t curve25519_key_mul_modulo(const curve25519_key_t *const k1, const curve25519_key_t *const k2, curve25519_key_t *const restrict r) {
	curve25519_key_mul(k1, k2, r);
	compute_modulo_25519(r);
	return 0;
}

int64_t curve25519_key_log2(const curve25519_key_t *const restrict k, curve25519_key_t *const restrict p) {
	int64_t i, count = 512;
	for (i = 7; i >= 0; --i) {
		if (!k->key64[i]) {
			if (p) p->key64[i] = 0;
			count -= 64;
			continue;
		}
		int exponent = __builtin_clzll(k->key64[i]);
		count -= exponent + 1;
		if (p) p->key64[i] = 1ULL << (63 - exponent);
		break;
	}
	if (p) {
		i--;
		for (; i >= 0; --i) {
			p->key64[i] = 0;
		}
	}
	return count;
} 

int32_t curve25519_key_divmod(const curve25519_key_t *const restrict num, const curve25519_key_t *const restrict den, curve25519_key_t *const restrict q, curve25519_key_t *const restrict r) {
	int32_t res = curve25519_key_cmp(num, den);
	if (!res) {
		q->key128[0] = 1;
		q->key128[1] = 0;
		q->key128[2] = 0;
		q->key128[3] = 0;
		memset(r, 0, sizeof(curve25519_key_t));
		return 0;
	}
	if (res < 0) {
		memcpy(r->key8, num->key8, sizeof(curve25519_key_t));
		memset(q, 0, sizeof(curve25519_key_t));
		return 0;
	}
	memset(q->key8, 0, sizeof(curve25519_key_t));
	memcpy(r->key8, num, sizeof(curve25519_key_t));
	curve25519_key_t den_cpy, temp;
	do {
		temp = (curve25519_key_t){.key8 = {1}};
		memcpy(den_cpy.key8, den, sizeof(curve25519_key_t));
		int64_t shift = curve25519_key_log2(r, NULL) - curve25519_key_log2(&den_cpy, NULL);
		// printf("shift: %lld\n", shift);
		curve25519_key_lshift_inplace(&den_cpy, shift);
		curve25519_key_lshift_inplace(&temp, shift);
		// printf("den_cpy:\n");
		// curve25519_key_printf(&den_cpy, COMPLETE);
		if (curve25519_key_cmp(r, &den_cpy) < 0) {
			curve25519_key_rshift_inplace(&den_cpy, 1);
			curve25519_key_rshift_inplace(&temp, 1);
		}
		curve25519_key_sub_inplace(r, &den_cpy);
		// printf("r:\n");
		// curve25519_key_printf(r, COMPLETE);
		// printf("q:\n");
		// curve25519_key_printf(q, COMPLETE);
		curve25519_key_add_inplace(q, &temp);
	} while (curve25519_key_cmp(r, den) >= 0);
	return 0;
}

int32_t curve25519_key_printf(const curve25519_key_t *const k, const curve25519_key_fmt_t size) {
	switch (size) {
		case COMPLETE: {
			return printf("%016llX%016llX%016llX%016llX\n----------------------------------------------------------------\n%016llX%016llX%016llX%016llX\n", 
				k->key64[7], k->key64[6], k->key64[5], k->key64[4], k->key64[3], k->key64[2], k->key64[1], k->key64[0]);
		}
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
