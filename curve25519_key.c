#include "curve25519_key.h"

int curve25519_key_init(curve25519_key_t *key) {
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
        return -1;
    }
	key->key8[0] &= ~(uint8_t)(0b111);
	key->key8[31] = (key->key8[31] | 0x40) & 0x7F;
    return 0;
}

int curve25519_key_add(curve25519_key_t *const restrict k1, curve25519_key_t *const restrict k2, curve25519_key_t *restrict r) {
	__m512i m1, m2;
	
	return 0;
}  

int curve25519_key_double(curve25519_key_t *const restrict key, curve25519_key_t *restrict r) {
	return 0;
} 

int curve25519_key_multiply(curve25519_key_t *const restrict  k1, curve25519_key_t *const restrict k2, curve25519_key_t *restrict r) {
	return 0;
}

int curve25519_key_printf(const curve25519_key_t *const key, const byte_size_t size) {
	switch (size) {
		case B64: {
			return printf("key: \n%016X:%016X:\n%016X:%016X\n", 
				key->key64[3], key->key64[2], key->key64[1], key->key64[0]);
		}
		case B32: {
			return printf("key: \n%08X:%08X:%08X:%08X:\n%08X:%08X:%08X:%08X\n", 
				key->key32[7], key->key32[6], key->key32[5], key->key32[4], key->key32[3], key->key32[2], key->key32[1], key->key32[0]);
		}
		case B16: {
			return printf("key: \n%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X:\n%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X\n", 
				key->key16[15], key->key16[14], key->key16[13], key->key16[12], key->key16[11], key->key16[10], key->key16[9], key->key16[8], 
				key->key16[7], key->key16[6], key->key16[5], key->key16[4], key->key16[3], key->key16[2], key->key16[1], key->key16[0]);
		}
		case B8: {
			return printf("key: \n%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:\n%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n", 
				key->key8[31], key->key8[30], key->key8[29], key->key8[28], key->key8[27], key->key8[26], key->key8[25], key->key8[24], 
				key->key8[23], key->key8[22], key->key8[21], key->key8[20], key->key8[19], key->key8[18], key->key8[17], key->key8[16],
				key->key8[15], key->key8[14], key->key8[13], key->key8[12], key->key8[11], key->key8[10], key->key8[9], key->key8[8], 
				key->key8[7], key->key8[6], key->key8[5], key->key8[4], key->key8[3], key->key8[2], key->key8[1], key->key8[0]);
		}
	}
}

int main(void) {
	curve25519_key_t key;
	memset(key.key64, 0, sizeof(curve25519_key_t));
	curve25519_key_printf(&key,B8);
	if (curve25519_key_init(&key) == -1) {
		return -1;		
	}
	curve25519_key_printf(&key,B8);
	printf("DONE\n");
	return 0;
}