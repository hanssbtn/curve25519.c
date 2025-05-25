#include "../tests.h"

int32_t curve25519_key_x2_modulo_test(void) {
	printf("Modular Key Doubling Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xDE5C00579FC9B7F1ULL,
		0xB123389EF6B4664DULL,
		0x76A8A37135550881ULL,
		0x77A1F5B3FAA4A8F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xBCB800AF3F936FF5ULL,
		0x6246713DED68CC9BULL,
		0xED5146E26AAA1103ULL,
		0x6F43EB67F54951F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57BB493B8699F1C2ULL,
		0x21785073E456F917ULL,
		0xD8CE8AA0779D08E1ULL,
		0x049FFB3035730267ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7692770D33E384ULL,
		0x42F0A0E7C8ADF22EULL,
		0xB19D1540EF3A11C2ULL,
		0x093FF6606AE604CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x539456F94DBE4651ULL,
		0x8D64719E12C6A4B2ULL,
		0x7B312D484F013064ULL,
		0x47C83F6E1502200FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA728ADF29B7C8CB5ULL,
		0x1AC8E33C258D4964ULL,
		0xF6625A909E0260C9ULL,
		0x0F907EDC2A04401EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE2A0E54D272D358CULL,
		0xA5FD642B708DBB24ULL,
		0x51A43CB443420C83ULL,
		0x48445DAD2FE6FF1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC541CA9A4E5A6B2BULL,
		0x4BFAC856E11B7649ULL,
		0xA348796886841907ULL,
		0x1088BB5A5FCDFE3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF2383658E0597E7ULL,
		0x04D43089C38867ABULL,
		0x512C9C715808D163ULL,
		0x173377809EB176D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4706CB1C0B2FCEULL,
		0x09A861138710CF57ULL,
		0xA25938E2B011A2C6ULL,
		0x2E66EF013D62EDA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A2750AFF6A2571ULL,
		0x55570BB67CAC4E99ULL,
		0x79F55C107A43D57BULL,
		0x3A4BC3FED183418AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F44EA15FED44AE2ULL,
		0xAAAE176CF9589D32ULL,
		0xF3EAB820F487AAF6ULL,
		0x749787FDA3068314ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C1B4E090E2C1BF8ULL,
		0x2C016360DCFDDBADULL,
		0xEC9681551F70FF95ULL,
		0x318581DEBD718C12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78369C121C5837F0ULL,
		0x5802C6C1B9FBB75AULL,
		0xD92D02AA3EE1FF2AULL,
		0x630B03BD7AE31825ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F7D85222D0EF522ULL,
		0x4E91B72DC0918887ULL,
		0xCF99A2E3C0E90BAAULL,
		0x304F3E150DCC2101ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EFB0A445A1DEA44ULL,
		0x9D236E5B8123110EULL,
		0x9F3345C781D21754ULL,
		0x609E7C2A1B984203ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x777C9640CB70E535ULL,
		0xE78ECBD5FC2F2954ULL,
		0x10CB6D54491C8AC5ULL,
		0x27E5C79952C6F31FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEF92C8196E1CA6AULL,
		0xCF1D97ABF85E52A8ULL,
		0x2196DAA89239158BULL,
		0x4FCB8F32A58DE63EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x400A5E7F708C5CA9ULL,
		0x71F0B61C28D30181ULL,
		0xDEC07243DAE9919FULL,
		0x3875598B7AD2AE73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8014BCFEE118B952ULL,
		0xE3E16C3851A60302ULL,
		0xBD80E487B5D3233EULL,
		0x70EAB316F5A55CE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA18E8A76CCB0CCBULL,
		0x5CC0A890B22D800AULL,
		0xF3EB3DE6F548D9DBULL,
		0x1FDDE78048F9DE0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7431D14ED9961996ULL,
		0xB9815121645B0015ULL,
		0xE7D67BCDEA91B3B6ULL,
		0x3FBBCF0091F3BC1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x007C745856D608C5ULL,
		0xE13D25C116DC9AEAULL,
		0x94B9551BB26BF2EAULL,
		0x2347C5A8F3EEA76CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00F8E8B0ADAC118AULL,
		0xC27A4B822DB935D4ULL,
		0x2972AA3764D7E5D5ULL,
		0x468F8B51E7DD4ED9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72AE73634AED7BCFULL,
		0x61DC244D35A9A0B1ULL,
		0x04CCDBA522FE3CFAULL,
		0x4EFB733845A1C040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55CE6C695DAF7B1ULL,
		0xC3B8489A6B534162ULL,
		0x0999B74A45FC79F4ULL,
		0x1DF6E6708B438080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2677094BEBE121FDULL,
		0x964EB2895FA33D46ULL,
		0xB82FA9A8A4F36672ULL,
		0x6D3AEFB062AD7180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CEE1297D7C2440DULL,
		0x2C9D6512BF467A8CULL,
		0x705F535149E6CCE5ULL,
		0x5A75DF60C55AE301ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6643A9CB0E55FACULL,
		0x437F3E5576D1518FULL,
		0x2C7EDC7D8442359EULL,
		0x7285CB604D5D47D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECC8753961CABF6BULL,
		0x86FE7CAAEDA2A31FULL,
		0x58FDB8FB08846B3CULL,
		0x650B96C09ABA8FB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x208586E26CA725EFULL,
		0x2771B3F4A711125FULL,
		0x6E83F7B453A6BF55ULL,
		0x770FB6C9C3394D19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x410B0DC4D94E4BF1ULL,
		0x4EE367E94E2224BEULL,
		0xDD07EF68A74D7EAAULL,
		0x6E1F6D9386729A32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95A1D2082EC7E731ULL,
		0x93A8C90618AA0A4AULL,
		0x65DC109A7765DB20ULL,
		0x6E69F1E7FAD73E7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B43A4105D8FCE75ULL,
		0x2751920C31541495ULL,
		0xCBB82134EECBB641ULL,
		0x5CD3E3CFF5AE7CF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE12C8C87B9F691B1ULL,
		0xBAADAD98017FE357ULL,
		0x726D481FB50436AEULL,
		0x3CBB2D0252CDFF5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC259190F73ED2362ULL,
		0x755B5B3002FFC6AFULL,
		0xE4DA903F6A086D5DULL,
		0x79765A04A59BFEBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAFA95F02892F504ULL,
		0xA4A61F666B486D6DULL,
		0xF0D8F17CF4433038ULL,
		0x608AE78C5EDCE941ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5F52BE05125EA1BULL,
		0x494C3ECCD690DADBULL,
		0xE1B1E2F9E8866071ULL,
		0x4115CF18BDB9D283ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xADBD69865C679DA4ULL,
		0x5791693AB0CA0E2EULL,
		0xD33628F86C2ECEE9ULL,
		0x0C2D54B3B60C31B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B7AD30CB8CF3B48ULL,
		0xAF22D27561941C5DULL,
		0xA66C51F0D85D9DD2ULL,
		0x185AA9676C186369ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C58964CFA957698ULL,
		0xD7E0732529AD0BCBULL,
		0x3866CA64B61401C1ULL,
		0x4E200AFAAC73069BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18B12C99F52AED43ULL,
		0xAFC0E64A535A1797ULL,
		0x70CD94C96C280383ULL,
		0x1C4015F558E60D36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C5A457AE061FE5EULL,
		0x7ADE23E3CC5B7A22ULL,
		0x0377BF86C8FAB911ULL,
		0x624A9A955958FB58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8B48AF5C0C3FCCFULL,
		0xF5BC47C798B6F444ULL,
		0x06EF7F0D91F57222ULL,
		0x4495352AB2B1F6B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB750DC40AE751E7ULL,
		0x9055C10B54D08A47ULL,
		0x69F0BDD5F78C1FFFULL,
		0x68FE23E0247F57F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6EA1B8815CEA3E1ULL,
		0x20AB8216A9A1148FULL,
		0xD3E17BABEF183FFFULL,
		0x51FC47C048FEAFEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A3FA7DC7B0A00EFULL,
		0x8FA2CD83881D0405ULL,
		0xFDF0F9CB410C45D5ULL,
		0x2910F460D17999D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD47F4FB8F61401DEULL,
		0x1F459B07103A080AULL,
		0xFBE1F39682188BABULL,
		0x5221E8C1A2F333A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1A46DA0A1982D44ULL,
		0xA43F96C0B3A97FE9ULL,
		0x376EA1A503BB9A74ULL,
		0x57A610E895DC6EF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC348DB4143305A9BULL,
		0x487F2D816752FFD3ULL,
		0x6EDD434A077734E9ULL,
		0x2F4C21D12BB8DDE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x334293D56B0FEB8EULL,
		0x2792750E9F1D01DEULL,
		0x88D20D5681FEAA87ULL,
		0x2969D61AFDE8D60FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x668527AAD61FD71CULL,
		0x4F24EA1D3E3A03BCULL,
		0x11A41AAD03FD550EULL,
		0x52D3AC35FBD1AC1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8528E0162BA3C3ACULL,
		0x908BED915F5DC79DULL,
		0x3FC95F520F12FF48ULL,
		0x5E428B1C99CE936EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A51C02C5747876BULL,
		0x2117DB22BEBB8F3BULL,
		0x7F92BEA41E25FE91ULL,
		0x3C851639339D26DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2210D5FC9304FEC1ULL,
		0x739D1C7E7FD12A85ULL,
		0xEF28185BB1CBFC89ULL,
		0x5B1C4485F69F8E56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4421ABF92609FD95ULL,
		0xE73A38FCFFA2550AULL,
		0xDE5030B76397F912ULL,
		0x3638890BED3F1CADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B9414F34D68AA53ULL,
		0x648A01232BBC625AULL,
		0x6D40BBAED64B9100ULL,
		0x51739CF981162459ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172829E69AD154B9ULL,
		0xC91402465778C4B4ULL,
		0xDA81775DAC972200ULL,
		0x22E739F3022C48B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC45631EA7451E307ULL,
		0xF0A568E0CC2B5F7CULL,
		0xAB4E926FACDDF757ULL,
		0x5ED13A2E27C17BAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88AC63D4E8A3C621ULL,
		0xE14AD1C19856BEF9ULL,
		0x569D24DF59BBEEAFULL,
		0x3DA2745C4F82F75DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF72CDFEA84F4166ULL,
		0x8DA8796A210792A4ULL,
		0xEC0F854A55A71F77ULL,
		0x7F14C893F0460E43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEE59BFD509E82DFULL,
		0x1B50F2D4420F2549ULL,
		0xD81F0A94AB4E3EEFULL,
		0x7E299127E08C1C87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B67CC5D0A0001FAULL,
		0x2BEA1ACA5EE55BE9ULL,
		0xA9B94F89BDD2A9DDULL,
		0x5349F4D14D4CCE35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36CF98BA14000407ULL,
		0x57D43594BDCAB7D2ULL,
		0x53729F137BA553BAULL,
		0x2693E9A29A999C6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94EE2B9E7C98CBD2ULL,
		0xB38E2E0311D99BE4ULL,
		0x0B75C577E8403474ULL,
		0x74DDE9D9A918E5A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29DC573CF93197B7ULL,
		0x671C5C0623B337C9ULL,
		0x16EB8AEFD08068E9ULL,
		0x69BBD3B35231CB4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AED932907CB6F31ULL,
		0xC835B85997864610ULL,
		0xFCEA785F7BD38A89ULL,
		0x6E41101726B8877AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95DB26520F96DE75ULL,
		0x906B70B32F0C8C20ULL,
		0xF9D4F0BEF7A71513ULL,
		0x5C82202E4D710EF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7A711D48C11A496ULL,
		0x1C8630CFD4253FFAULL,
		0x3A987382125B5D0BULL,
		0x2F699C3EC7246661ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF4E23A91823492CULL,
		0x390C619FA84A7FF5ULL,
		0x7530E70424B6BA16ULL,
		0x5ED3387D8E48CCC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E14771AD8695A32ULL,
		0xD7257BF790F9EAF6ULL,
		0xBF95EF002B337654ULL,
		0x2B921F9AB73E0A72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C28EE35B0D2B464ULL,
		0xAE4AF7EF21F3D5EDULL,
		0x7F2BDE005666ECA9ULL,
		0x57243F356E7C14E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0062E41BD8E98C9ULL,
		0xE51E3A2E976EDB6FULL,
		0xBC277E10BAA0B2CEULL,
		0x0EB8AEE3839F30E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x600C5C837B1D3192ULL,
		0xCA3C745D2EDDB6DFULL,
		0x784EFC217541659DULL,
		0x1D715DC7073E61C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C0FD53771E1FDC3ULL,
		0xC951A074A818884CULL,
		0x8EBC32008F19A97AULL,
		0x6D4C93AE9171EEF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381FAA6EE3C3FB99ULL,
		0x92A340E950311099ULL,
		0x1D7864011E3352F5ULL,
		0x5A99275D22E3DDE1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x66F2AE6EEC5F17A2ULL,
		0x89B6395C766AAAB3ULL,
		0xAC99E18F3566D871ULL,
		0x76384477E9BC053FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE55CDDD8BE2F57ULL,
		0x136C72B8ECD55566ULL,
		0x5933C31E6ACDB0E3ULL,
		0x6C7088EFD3780A7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1539D299D4F409D4ULL,
		0x4AF2CE2A5028B39BULL,
		0xD1F04196BFF31896ULL,
		0x281026778CC36096ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A73A533A9E813A8ULL,
		0x95E59C54A0516736ULL,
		0xA3E0832D7FE6312CULL,
		0x50204CEF1986C12DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE85004F8566400D2ULL,
		0x2DC5B76036E42D87ULL,
		0xC615FC81985923E4ULL,
		0x473EC53758944FC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0A009F0ACC801B7ULL,
		0x5B8B6EC06DC85B0FULL,
		0x8C2BF90330B247C8ULL,
		0x0E7D8A6EB1289F8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9654DA95C3C9FA63ULL,
		0x9FE0CCD666043C9BULL,
		0xCCB6B6562B82B16DULL,
		0x48EDB4FAF21868BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA9B52B8793F4D9ULL,
		0x3FC199ACCC087937ULL,
		0x996D6CAC570562DBULL,
		0x11DB69F5E430D175ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7A615D7A8579328ULL,
		0x4E3042067380E5EEULL,
		0xB61AB06458950A63ULL,
		0x65FAA9BF8BD06EC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF4C2BAF50AF2663ULL,
		0x9C60840CE701CBDDULL,
		0x6C3560C8B12A14C6ULL,
		0x4BF5537F17A0DD81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2ACF435A360F8D25ULL,
		0x7DDC19DC5FAFCDAFULL,
		0x4DF90D4097564273ULL,
		0x2B1621C4C26D671DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x559E86B46C1F1A4AULL,
		0xFBB833B8BF5F9B5EULL,
		0x9BF21A812EAC84E6ULL,
		0x562C438984DACE3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7A14DF9CD207735ULL,
		0x7477EAF55D9774A8ULL,
		0x0AA2B11F8C59D9A4ULL,
		0x2863A6410EA8F6F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF429BF39A40EE6AULL,
		0xE8EFD5EABB2EE951ULL,
		0x1545623F18B3B348ULL,
		0x50C74C821D51EDE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12E8591627813700ULL,
		0x324F9CD555088275ULL,
		0x212FA1361708F6CFULL,
		0x54FCA0FD3C6A374FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25D0B22C4F026E13ULL,
		0x649F39AAAA1104EAULL,
		0x425F426C2E11ED9EULL,
		0x29F941FA78D46E9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE6F4010C928F074ULL,
		0xE54BD931CE82C581ULL,
		0x3F20956C34A8A6DCULL,
		0x7BBE603F802220BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CDE80219251E0FBULL,
		0xCA97B2639D058B03ULL,
		0x7E412AD869514DB9ULL,
		0x777CC07F0044417CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC15E78CB3BD9156ULL,
		0xCA2E545653775304ULL,
		0x280FDA1F5D679480ULL,
		0x3FAFA309600607DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x582BCF19677B22ACULL,
		0x945CA8ACA6EEA609ULL,
		0x501FB43EBACF2901ULL,
		0x7F5F4612C00C0FB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x894940162A1F9A5DULL,
		0x4D037A371471200AULL,
		0xFDE7DD7C0AC6BA61ULL,
		0x35AAB8624273C1D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1292802C543F34BAULL,
		0x9A06F46E28E24015ULL,
		0xFBCFBAF8158D74C2ULL,
		0x6B5570C484E783ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E3FB8F9677D1809ULL,
		0x57F9EEABDF5A9A0AULL,
		0x0C941E849020AC4BULL,
		0x7BC1B99BFAF58784ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C7F71F2CEFA3025ULL,
		0xAFF3DD57BEB53414ULL,
		0x19283D0920415896ULL,
		0x77837337F5EB0F08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5870CBD3A8B2942ULL,
		0xDF2689844EC008AEULL,
		0x829464E86E0F0EFDULL,
		0x597B787F4A15CA95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB0E197A75165297ULL,
		0xBE4D13089D80115DULL,
		0x0528C9D0DC1E1DFBULL,
		0x32F6F0FE942B952BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF28A88244A6C839BULL,
		0x75136380861E0432ULL,
		0x82B9033F09359989ULL,
		0x0471E75E0D315FDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE515104894D90736ULL,
		0xEA26C7010C3C0865ULL,
		0x0572067E126B3312ULL,
		0x08E3CEBC1A62BFBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B5FFA66519FBD6EULL,
		0xA48CE60EB4569FB0ULL,
		0xEAFE9FDE3B43670BULL,
		0x052298A5BA6CE2EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16BFF4CCA33F7ADCULL,
		0x4919CC1D68AD3F60ULL,
		0xD5FD3FBC7686CE17ULL,
		0x0A45314B74D9C5D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAC4EF19E34306EFULL,
		0xE4F40000066EF1ACULL,
		0xB238C7AECD828582ULL,
		0x54122838B6D59909ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD589DE33C6860DF1ULL,
		0xC9E800000CDDE359ULL,
		0x64718F5D9B050B05ULL,
		0x282450716DAB3213ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF2B8A35616B573EULL,
		0xAD2175BFA7D70937ULL,
		0x15618CCBA2B6E8C4ULL,
		0x600FB494861D004FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E57146AC2D6AE8FULL,
		0x5A42EB7F4FAE126FULL,
		0x2AC31997456DD189ULL,
		0x401F69290C3A009EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77F322260CD9F685ULL,
		0xEA743E26BFB970B2ULL,
		0xA57AFD3909F255D5ULL,
		0x429459D2C0F87C89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE6444C19B3ED1DULL,
		0xD4E87C4D7F72E164ULL,
		0x4AF5FA7213E4ABABULL,
		0x0528B3A581F0F913ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4711E3F0FD2C8C9ULL,
		0xA63A93642AD25F0FULL,
		0x3A0C2CB7718DD934ULL,
		0x35A57AD6E02A53F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88E23C7E1FA59192ULL,
		0x4C7526C855A4BE1FULL,
		0x7418596EE31BB269ULL,
		0x6B4AF5ADC054A7EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E4E68B451F5DF2AULL,
		0x9AF7A5A9086BB735ULL,
		0x2C9546792A349357ULL,
		0x727FD3E0698EE547ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C9CD168A3EBBE67ULL,
		0x35EF4B5210D76E6BULL,
		0x592A8CF2546926AFULL,
		0x64FFA7C0D31DCA8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DFA0A1F5750053CULL,
		0xB8C23A1894C44377ULL,
		0xE2696F37C3734127ULL,
		0x3CC1D840F0D6E143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BF4143EAEA00A78ULL,
		0x71847431298886EEULL,
		0xC4D2DE6F86E6824FULL,
		0x7983B081E1ADC287ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFED153E57B9A86BBULL,
		0x0AEDAF22E04E5D00ULL,
		0x7AEA7CFC940B3386ULL,
		0x22F03E7A98CA961BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDA2A7CAF7350D76ULL,
		0x15DB5E45C09CBA01ULL,
		0xF5D4F9F92816670CULL,
		0x45E07CF531952C36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19013D7EFCCB1EC1ULL,
		0x4C3A6C109BD0DD09ULL,
		0x9CEE2E0C8F04523BULL,
		0x0797261D570CCCCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32027AFDF9963D82ULL,
		0x9874D82137A1BA12ULL,
		0x39DC5C191E08A476ULL,
		0x0F2E4C3AAE19999FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF74D881FF033AA3AULL,
		0xDA9370FABA814E11ULL,
		0xC4E84314FB3FA20CULL,
		0x5E9A0486B66733CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE9B103FE0675487ULL,
		0xB526E1F575029C23ULL,
		0x89D08629F67F4419ULL,
		0x3D34090D6CCE679DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EC6B04726C6B26CULL,
		0xAA396B736868F749ULL,
		0x4F4E20C3DCB6B5A3ULL,
		0x3EDEC87453A0B8CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8D608E4D8D64D8ULL,
		0x5472D6E6D0D1EE92ULL,
		0x9E9C4187B96D6B47ULL,
		0x7DBD90E8A741719EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x489B7702DAD51079ULL,
		0xAD441BAD0CD753DEULL,
		0x4D66836AFC0992C0ULL,
		0x5525388AC2E4B8A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9136EE05B5AA2105ULL,
		0x5A88375A19AEA7BCULL,
		0x9ACD06D5F8132581ULL,
		0x2A4A711585C97142ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D28606035FA4771ULL,
		0xBF79AE4A8E217F24ULL,
		0xF8751F1C5755E5DBULL,
		0x3488B50F28C402ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA50C0C06BF48EE2ULL,
		0x7EF35C951C42FE48ULL,
		0xF0EA3E38AEABCBB7ULL,
		0x69116A1E51880559ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5F644DB66BEF4FBULL,
		0xA547C13F27D12EAAULL,
		0xE0DE35EC3715B79EULL,
		0x66F729092B97E9FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BEC89B6CD7DEA09ULL,
		0x4A8F827E4FA25D55ULL,
		0xC1BC6BD86E2B6F3DULL,
		0x4DEE5212572FD3FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA51EE0DFA7E603A1ULL,
		0x708FC43028F78BD9ULL,
		0x62E5A0A2059A3235ULL,
		0x523BCD939BD8ADCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A3DC1BF4FCC0755ULL,
		0xE11F886051EF17B3ULL,
		0xC5CB41440B34646AULL,
		0x24779B2737B15B98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4CC48DD55902064ULL,
		0x297A0550724E66E5ULL,
		0xC1939129D1E0971FULL,
		0x7F4BEA1E04D395C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA99891BAAB2040DBULL,
		0x52F40AA0E49CCDCBULL,
		0x83272253A3C12E3EULL,
		0x7E97D43C09A72B8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x808E28AC0D07FC23ULL,
		0x4FB04CDB8D6EAC4EULL,
		0x6FC56E33573B5575ULL,
		0x4F506DA509EBDA6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x011C51581A0FF859ULL,
		0x9F6099B71ADD589DULL,
		0xDF8ADC66AE76AAEAULL,
		0x1EA0DB4A13D7B4DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDD8421082CF73FECULL,
		0xDF718F35462F136DULL,
		0x5929429B39BB3BD6ULL,
		0x1D5495F17A8D0F01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB08421059EE7FD8ULL,
		0xBEE31E6A8C5E26DBULL,
		0xB2528536737677ADULL,
		0x3AA92BE2F51A1E02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EFC1A52EC717A8DULL,
		0x96142A6139EE0CD8ULL,
		0x47612DBE1BDDB34EULL,
		0x43A4FDF31A5CD663ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDF834A5D8E2F52DULL,
		0x2C2854C273DC19B0ULL,
		0x8EC25B7C37BB669DULL,
		0x0749FBE634B9ACC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE497A16E99AEBFC5ULL,
		0x81B1477E4F783EABULL,
		0xFF006B7BFF33A324ULL,
		0x273703578861C2E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC92F42DD335D7F8AULL,
		0x03628EFC9EF07D57ULL,
		0xFE00D6F7FE674649ULL,
		0x4E6E06AF10C385D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4605657356C82FB7ULL,
		0x1CDB5225C6E7D033ULL,
		0x2BE8E588B3B8E58CULL,
		0x0A8A17F02CE31D69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0ACAE6AD905F6EULL,
		0x39B6A44B8DCFA066ULL,
		0x57D1CB116771CB18ULL,
		0x15142FE059C63AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1152E94065025180ULL,
		0x39D40CAC3822BECDULL,
		0x5CD05F3529086814ULL,
		0x628776EEAEBD1036ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22A5D280CA04A313ULL,
		0x73A8195870457D9AULL,
		0xB9A0BE6A5210D028ULL,
		0x450EEDDD5D7A206CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16C8CA5A5DE1F2F6ULL,
		0x3A485B22F0CF5337ULL,
		0x0F6B860C4D5F38D8ULL,
		0x6C5AA75C9B2C9042ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D9194B4BBC3E5FFULL,
		0x7490B645E19EA66EULL,
		0x1ED70C189ABE71B0ULL,
		0x58B54EB936592084ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D2DD5F11593A023ULL,
		0x12E44790CB372266ULL,
		0x4295E7C66F32A375ULL,
		0x623329E6A841CFA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA5BABE22B274059ULL,
		0x25C88F21966E44CCULL,
		0x852BCF8CDE6546EAULL,
		0x446653CD50839F4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF994113A3041ACC9ULL,
		0x6A3A72C937F5E23CULL,
		0xFE54614EABB52B7AULL,
		0x448C8D974FE3AED0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3282274608359A5ULL,
		0xD474E5926FEBC479ULL,
		0xFCA8C29D576A56F4ULL,
		0x09191B2E9FC75DA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1A46CC9DD5A54B6ULL,
		0x40EF49A94869BE1FULL,
		0xE928F06D542DB14AULL,
		0x3672918047BC5748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8348D993BAB4A96CULL,
		0x81DE935290D37C3FULL,
		0xD251E0DAA85B6294ULL,
		0x6CE523008F78AE91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D8DF7AA028276E1ULL,
		0x0B14D2CF413ADD87ULL,
		0xC0398131720AB7BAULL,
		0x06FC09CC3A986006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB1BEF540504EDC2ULL,
		0x1629A59E8275BB0EULL,
		0x80730262E4156F74ULL,
		0x0DF813987530C00DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07596C0E1C692D47ULL,
		0x94EB7F2A3153B26AULL,
		0x16E61E18902BCA05ULL,
		0x5B3FCA1421B3BE63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB2D81C38D25AA1ULL,
		0x29D6FE5462A764D4ULL,
		0x2DCC3C312057940BULL,
		0x367F942843677CC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DAA3B3AF96639C6ULL,
		0xF6B1B90BA32D0363ULL,
		0xE5913DEFB269F9A0ULL,
		0x30A3D72AB1C0045AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB547675F2CC738CULL,
		0xED637217465A06C6ULL,
		0xCB227BDF64D3F341ULL,
		0x6147AE55638008B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13CCAF88882A6590ULL,
		0xA5A3F8C4BBC364B7ULL,
		0x005CB3D3AFAE2A24ULL,
		0x4FE966AB436EA671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27995F111054CB33ULL,
		0x4B47F1897786C96EULL,
		0x00B967A75F5C5449ULL,
		0x1FD2CD5686DD4CE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10863E3008203851ULL,
		0x4FD8922B384566F3ULL,
		0x979AF09A5E4C33B8ULL,
		0x222711EB3521FB99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x210C7C60104070A2ULL,
		0x9FB12456708ACDE6ULL,
		0x2F35E134BC986770ULL,
		0x444E23D66A43F733ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63B8A8360AC754ADULL,
		0x4B225AB906463AB7ULL,
		0x0C074B61C10097ECULL,
		0x02B247FC93EA8FF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC771506C158EA95AULL,
		0x9644B5720C8C756EULL,
		0x180E96C382012FD8ULL,
		0x05648FF927D51FEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C5768223229CCE3ULL,
		0x3CD75D5A79110E4AULL,
		0x7B941E30CA0389D2ULL,
		0x4C2E6D337528F9F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18AED044645399D9ULL,
		0x79AEBAB4F2221C95ULL,
		0xF7283C61940713A4ULL,
		0x185CDA66EA51F3ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63BF72C80D202A1EULL,
		0xA428CEDCCFEDB640ULL,
		0xE756540A632C2B67ULL,
		0x74C1B295298ED4BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC77EE5901A40544FULL,
		0x48519DB99FDB6C80ULL,
		0xCEACA814C65856CFULL,
		0x6983652A531DA97BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23DB9C74326441CAULL,
		0x238C74CA9C459CF5ULL,
		0xC36E4CCA0044EC43ULL,
		0x07C2A587A902D158ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47B738E864C88394ULL,
		0x4718E995388B39EAULL,
		0x86DC99940089D886ULL,
		0x0F854B0F5205A2B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC51024A858E35BEBULL,
		0xAAD7082913139E84ULL,
		0xE571C0A5175AC2F7ULL,
		0x715D082663BA7B3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A204950B1C6B7E9ULL,
		0x55AE105226273D09ULL,
		0xCAE3814A2EB585EFULL,
		0x62BA104CC774F679ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2541BA30C959CE09ULL,
		0xE7E8BF2BDB15C29AULL,
		0xC65DD5FA2BEE2102ULL,
		0x2C23C0F844B9A3CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A83746192B39C12ULL,
		0xCFD17E57B62B8534ULL,
		0x8CBBABF457DC4205ULL,
		0x584781F089734797ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DCA21D9999124C3ULL,
		0x24B06C22C67AD921ULL,
		0x61B170D6DB83C33FULL,
		0x38565B6C94013CEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB9443B333224986ULL,
		0x4960D8458CF5B242ULL,
		0xC362E1ADB707867EULL,
		0x70ACB6D9280279D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA26A61A95E15224FULL,
		0x62288835F7323C71ULL,
		0x3F88422510703668ULL,
		0x5C085C8553A5C4D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D4C352BC2A44B1ULL,
		0xC451106BEE6478E3ULL,
		0x7F10844A20E06CD0ULL,
		0x3810B90AA74B89AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE28A28529388A22CULL,
		0x607FC8F4398A13E5ULL,
		0xC4C3BD8E6544F764ULL,
		0x1D5B5B44AC83996AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC51450A527114458ULL,
		0xC0FF91E8731427CBULL,
		0x89877B1CCA89EEC8ULL,
		0x3AB6B689590732D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x035DD75B8745D320ULL,
		0xB0224DC005FF4E30ULL,
		0x026122FADE78A6CCULL,
		0x0D36A430A523037CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06BBAEB70E8BA640ULL,
		0x60449B800BFE9C60ULL,
		0x04C245F5BCF14D99ULL,
		0x1A6D48614A4606F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3DB50BB4CEE21051ULL,
		0xB6FAF827FF1252FDULL,
		0x5FAD0ED733974700ULL,
		0x3FAD4A2707BDB9CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B6A17699DC420A2ULL,
		0x6DF5F04FFE24A5FAULL,
		0xBF5A1DAE672E8E01ULL,
		0x7F5A944E0F7B739AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0DF1C565A3EB8E4ULL,
		0x7ED71FB70B281D88ULL,
		0x23EACDF07EDB8B98ULL,
		0x4065D8E5F70BE8E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1BE38ACB47D71DBULL,
		0xFDAE3F6E16503B11ULL,
		0x47D59BE0FDB71730ULL,
		0x00CBB1CBEE17D1CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB40DD27FCFD391EULL,
		0x48EEA645D286B5ACULL,
		0xD4FC16773CDBF99AULL,
		0x3EA933AE3EA698B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9681BA4FF9FA723CULL,
		0x91DD4C8BA50D6B59ULL,
		0xA9F82CEE79B7F334ULL,
		0x7D52675C7D4D3163ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x76952A02E5984D45ULL,
		0x45AC209D555E1F35ULL,
		0x8CD03B9352902A0EULL,
		0x3C8F8786D9366F2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2A5405CB309A8AULL,
		0x8B58413AAABC3E6AULL,
		0x19A07726A520541CULL,
		0x791F0F0DB26CDE5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF69424F5352BC1BCULL,
		0x8BB7D104A0FFDDA1ULL,
		0xD97E1762B6801893ULL,
		0x2C7447FCC3D49A89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED2849EA6A578378ULL,
		0x176FA20941FFBB43ULL,
		0xB2FC2EC56D003127ULL,
		0x58E88FF987A93513ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1F4044616F68A1BULL,
		0x89E7B18353066502ULL,
		0xC63CE42FEE6A6109ULL,
		0x21894A32ECD5A1A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43E8088C2DED1436ULL,
		0x13CF6306A60CCA05ULL,
		0x8C79C85FDCD4C213ULL,
		0x43129465D9AB4343ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FEE3E95D84AEF0BULL,
		0x77B77D5D4C44B5A1ULL,
		0x49AF0819EA45DCFEULL,
		0x16C149AE2A6D1D4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FDC7D2BB095DE16ULL,
		0xEF6EFABA98896B42ULL,
		0x935E1033D48BB9FCULL,
		0x2D82935C54DA3A94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7E03F38B2A687F1ULL,
		0x210B2649FBF75621ULL,
		0x71A5BF5F2362B2F7ULL,
		0x4CA6DC1D43431CECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFC07E71654D0FF5ULL,
		0x42164C93F7EEAC43ULL,
		0xE34B7EBE46C565EEULL,
		0x194DB83A868639D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7ADBC3BFC097A2CULL,
		0x9876F432DFB96D49ULL,
		0x005BD3DFC568679CULL,
		0x2F06EBB58EF0823EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF5B7877F812F458ULL,
		0x30EDE865BF72DA93ULL,
		0x00B7A7BF8AD0CF39ULL,
		0x5E0DD76B1DE1047CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9BE09FE823A122BULL,
		0x4AE21EEEFBCC2BD2ULL,
		0x0C5A08111E9883F1ULL,
		0x32EE7B9B429CE29EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x737C13FD04742456ULL,
		0x95C43DDDF79857A5ULL,
		0x18B410223D3107E2ULL,
		0x65DCF7368539C53CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2229DC06DBEE48A6ULL,
		0x646D10697B798461ULL,
		0xEC7BF7065A86972AULL,
		0x034D20928B6A9FD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4453B80DB7DC914CULL,
		0xC8DA20D2F6F308C2ULL,
		0xD8F7EE0CB50D2E54ULL,
		0x069A412516D53FA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF500F519B934EC93ULL,
		0x7D43E0CF773F51F5ULL,
		0x81AFF0647458B219ULL,
		0x0E929A7AB51FEF0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA01EA337269D926ULL,
		0xFA87C19EEE7EA3EBULL,
		0x035FE0C8E8B16432ULL,
		0x1D2534F56A3FDE1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06175A556BF5A3E6ULL,
		0xE6FC7BABAD6633E1ULL,
		0x42A239154A141BADULL,
		0x303C61C3F4315D3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C2EB4AAD7EB47CCULL,
		0xCDF8F7575ACC67C2ULL,
		0x8544722A9428375BULL,
		0x6078C387E862BA7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6C293442DA7CFC5ULL,
		0xA17BA8D681AD9037ULL,
		0xC334FA0A9A78A7A8ULL,
		0x7FDBBA4E642E0413ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD8526885B4F9F9DULL,
		0x42F751AD035B206FULL,
		0x8669F41534F14F51ULL,
		0x7FB7749CC85C0827ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71CD0C2114687CD3ULL,
		0xC435ED13F49E8F70ULL,
		0x9D79E08661F6D1B2ULL,
		0x5C14E4B92B6277CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE39A184228D0F9B9ULL,
		0x886BDA27E93D1EE0ULL,
		0x3AF3C10CC3EDA365ULL,
		0x3829C97256C4EF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x972C92BF1738B8B7ULL,
		0x2EE559E0726E1809ULL,
		0xF05DCF5F6E1FD8B3ULL,
		0x5A2D9E8C304EB69FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E59257E2E717181ULL,
		0x5DCAB3C0E4DC3013ULL,
		0xE0BB9EBEDC3FB166ULL,
		0x345B3D18609D6D3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94A4BF2B8636340DULL,
		0x6FD4C2328B4D2880ULL,
		0xB31651B163695892ULL,
		0x67789A22466F10F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29497E570C6C682DULL,
		0xDFA98465169A5101ULL,
		0x662CA362C6D2B124ULL,
		0x4EF134448CDE21EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x524BDC38CA808F89ULL,
		0x270B2DC6F101A528ULL,
		0x3F4C8DC8237CB99BULL,
		0x739D43F367F75BD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA497B87195011F25ULL,
		0x4E165B8DE2034A50ULL,
		0x7E991B9046F97336ULL,
		0x673A87E6CFEEB7AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F568CBC13B875EEULL,
		0x689BBB73B28D10A2ULL,
		0x8C0D6A4FF14CD679ULL,
		0x4FC3E65C15699928ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEAD19782770EBEFULL,
		0xD13776E7651A2144ULL,
		0x181AD49FE299ACF2ULL,
		0x1F87CCB82AD33251ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B09F13F3A4BFDACULL,
		0x89B30B8B869FF1C9ULL,
		0xC034B69E9097CDC9ULL,
		0x2A2D0FCD817AC0C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB613E27E7497FB58ULL,
		0x136617170D3FE392ULL,
		0x80696D3D212F9B93ULL,
		0x545A1F9B02F58187ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DC9F1E3FCEB1073ULL,
		0x9017970A0C7C02F1ULL,
		0xEED7E090776C8ECEULL,
		0x0E661E9FDE248760ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB93E3C7F9D620E6ULL,
		0x202F2E1418F805E2ULL,
		0xDDAFC120EED91D9DULL,
		0x1CCC3D3FBC490EC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x802179C536D5715DULL,
		0x5CC0D899D0411708ULL,
		0x1C0B35E437D380F3ULL,
		0x3B7FABD9CAEB7975ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0042F38A6DAAE2BAULL,
		0xB981B133A0822E11ULL,
		0x38166BC86FA701E6ULL,
		0x76FF57B395D6F2EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA6E842694DCAD4FULL,
		0x0D70A6D189DD9259ULL,
		0x37378E92B02778F2ULL,
		0x6FDA67CD577E6E7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4DD084D29B95AB1ULL,
		0x1AE14DA313BB24B3ULL,
		0x6E6F1D25604EF1E4ULL,
		0x5FB4CF9AAEFCDCFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE73769CB76D4CB38ULL,
		0x09CD09F1D310416DULL,
		0xF352566A8D80A85DULL,
		0x00B60DE0CA5D11B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE6ED396EDA99670ULL,
		0x139A13E3A62082DBULL,
		0xE6A4ACD51B0150BAULL,
		0x016C1BC194BA2367ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0A99147E29C62F4ULL,
		0x893F36E7A2027DF2ULL,
		0xB2F20C50845255CAULL,
		0x4AE1BD02F1EE738CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA153228FC538C5FBULL,
		0x127E6DCF4404FBE5ULL,
		0x65E418A108A4AB95ULL,
		0x15C37A05E3DCE719ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DA9DA57AB3DB14AULL,
		0xBC4DE4A0CC15697DULL,
		0xB35279998BCC190BULL,
		0x1A412C7C33A41F63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B53B4AF567B6294ULL,
		0x789BC941982AD2FAULL,
		0x66A4F33317983217ULL,
		0x348258F867483EC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AEB94891E9875F4ULL,
		0xC2557FA17D8368F0ULL,
		0x95931FFD16B2FE68ULL,
		0x4BC540447596CBE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D729123D30EBFBULL,
		0x84AAFF42FB06D1E0ULL,
		0x2B263FFA2D65FCD1ULL,
		0x178A8088EB2D97CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51AF4E6F27D598E7ULL,
		0x1FDBBFEDE7B4D8F3ULL,
		0x81084417A782C81DULL,
		0x2E398646B4C8C193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA35E9CDE4FAB31CEULL,
		0x3FB77FDBCF69B1E6ULL,
		0x0210882F4F05903AULL,
		0x5C730C8D69918327ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA8D829692EBCD58CULL,
		0xFEA846100D277AE8ULL,
		0x2F45ACAB0B068487ULL,
		0x3695AC778FE383A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B052D25D79AB18ULL,
		0xFD508C201A4EF5D1ULL,
		0x5E8B5956160D090FULL,
		0x6D2B58EF1FC70742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09CF5AF78AE67084ULL,
		0xBFCB8509311ECA7FULL,
		0x85CFE5942B4336AAULL,
		0x3C293C54C6CF0694ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x139EB5EF15CCE108ULL,
		0x7F970A12623D94FEULL,
		0x0B9FCB2856866D55ULL,
		0x785278A98D9E0D29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x476D37ED222A5F32ULL,
		0x70C7D78A3E34CB9BULL,
		0x21BB7540F8607811ULL,
		0x0F3AB9FDC3C8AEEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EDA6FDA4454BE64ULL,
		0xE18FAF147C699736ULL,
		0x4376EA81F0C0F022ULL,
		0x1E7573FB87915DDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FD00EF575A41280ULL,
		0x48934E7C0CECD7CEULL,
		0xFF2DCD3B781E4DF2ULL,
		0x705DB56BBADD1429ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFA01DEAEB482513ULL,
		0x91269CF819D9AF9CULL,
		0xFE5B9A76F03C9BE4ULL,
		0x60BB6AD775BA2853ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4AE46AEA55F02BDULL,
		0x0F8B8FF11925A8C2ULL,
		0x97CC5F8AB42ED955ULL,
		0x7F06F3D40CBA0E36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95C8D5D4ABE058DULL,
		0x1F171FE2324B5185ULL,
		0x2F98BF15685DB2AAULL,
		0x7E0DE7A819741C6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x093EAA71A1547C16ULL,
		0xE99408F17F3A9A54ULL,
		0xE758257992A6D8D0ULL,
		0x74A192D0B69AB4D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x127D54E342A8F83FULL,
		0xD32811E2FE7534A8ULL,
		0xCEB04AF3254DB1A1ULL,
		0x694325A16D3569B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D706B6F9F53A719ULL,
		0xDD209AB017CD3A00ULL,
		0x7097DF001719AF71ULL,
		0x3D2FF79D3927C58CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE0D6DF3EA74E32ULL,
		0xBA4135602F9A7400ULL,
		0xE12FBE002E335EE3ULL,
		0x7A5FEF3A724F8B18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7942418E35462D97ULL,
		0xA96456113EE12DC0ULL,
		0xF4546888C434F1E2ULL,
		0x3520BB2EFAA35ABAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF284831C6A8C5B2EULL,
		0x52C8AC227DC25B80ULL,
		0xE8A8D1118869E3C5ULL,
		0x6A41765DF546B575ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FE15C5EAAA62715ULL,
		0x4688E85B75847C37ULL,
		0xA2880D441AD556EDULL,
		0x38971434A8A1DEEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FC2B8BD554C4E2AULL,
		0x8D11D0B6EB08F86EULL,
		0x45101A8835AAADDAULL,
		0x712E28695143BDDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23CD2C2A5D623489ULL,
		0xAD65F9D18C6BEDB8ULL,
		0x12439E807D71123DULL,
		0x75B2073DC667ED30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x479A5854BAC46925ULL,
		0x5ACBF3A318D7DB70ULL,
		0x24873D00FAE2247BULL,
		0x6B640E7B8CCFDA60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x884E85F109300BB2ULL,
		0x1760CD3D411CC3F0ULL,
		0xAA06476078982273ULL,
		0x47A04ED156748A38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x109D0BE212601777ULL,
		0x2EC19A7A823987E1ULL,
		0x540C8EC0F13044E6ULL,
		0x0F409DA2ACE91471ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D713AB481B6B816ULL,
		0x0C504CE4A0356FBEULL,
		0x789E67B09CF66F6DULL,
		0x2892FBC06F14E298ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE27569036D702CULL,
		0x18A099C9406ADF7DULL,
		0xF13CCF6139ECDEDAULL,
		0x5125F780DE29C530ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA4BC73DA43FC724ULL,
		0xE42B36F9015B625CULL,
		0x9A6D15B8DE433FB3ULL,
		0x60072408F3F93791ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54978E7B487F8E5BULL,
		0xC8566DF202B6C4B9ULL,
		0x34DA2B71BC867F67ULL,
		0x400E4811E7F26F23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE83BE96921570C03ULL,
		0xD293B22AF5FB1547ULL,
		0x69D0175EB0C19ADEULL,
		0x627AFC8AD9D450E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD077D2D242AE1819ULL,
		0xA5276455EBF62A8FULL,
		0xD3A02EBD618335BDULL,
		0x44F5F915B3A8A1C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BEA88B51647545FULL,
		0xFC2C7EAF3F92FB9FULL,
		0x80757191E2070E34ULL,
		0x4366C9626C7A8836ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D5116A2C8EA8D1ULL,
		0xF858FD5E7F25F73FULL,
		0x00EAE323C40E1C69ULL,
		0x06CD92C4D8F5106DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAC6BC4F731CA3EFULL,
		0xBFEAA3F7EF6A1F3BULL,
		0xE0FA0F97AFBEAB44ULL,
		0x21AE43B1642E29A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58D789EE63947DEULL,
		0x7FD547EFDED43E77ULL,
		0xC1F41F2F5F7D5689ULL,
		0x435C8762C85C5347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x29A5E6AC36A4A9C0ULL,
		0xE215520E325D161CULL,
		0x5C986D21959F4A8FULL,
		0x70B9A9A8F0D5DF11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x534BCD586D495393ULL,
		0xC42AA41C64BA2C38ULL,
		0xB930DA432B3E951FULL,
		0x61735351E1ABBE22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7D983EB5AF4E5404ULL,
		0xD1F1189E01252CF3ULL,
		0x512B75ED907450A5ULL,
		0x1D8050BF22EB060BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB307D6B5E9CA808ULL,
		0xA3E2313C024A59E6ULL,
		0xA256EBDB20E8A14BULL,
		0x3B00A17E45D60C16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB68BD390A0FB01C3ULL,
		0x4C7A69C38109E9F9ULL,
		0x4FFE405C08E47C8EULL,
		0x47A8F36E255EE992ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D17A72141F60399ULL,
		0x98F4D3870213D3F3ULL,
		0x9FFC80B811C8F91CULL,
		0x0F51E6DC4ABDD324ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AAC45F92926BC37ULL,
		0xBE5E6927B1E2046AULL,
		0x643CB6B2BDBD4053ULL,
		0x7DC454FBD39BFB69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75588BF2524D7881ULL,
		0x7CBCD24F63C408D4ULL,
		0xC8796D657B7A80A7ULL,
		0x7B88A9F7A737F6D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE17EBD3E1CE87A4EULL,
		0x75BD9454BEBA0F96ULL,
		0xBA206F6AEC8EB96BULL,
		0x11C566EAF0709C7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2FD7A7C39D0F49CULL,
		0xEB7B28A97D741F2DULL,
		0x7440DED5D91D72D6ULL,
		0x238ACDD5E0E138F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x191F31F87F1BB7F6ULL,
		0xAD997B57B5C7B5BDULL,
		0x430C32D5810B894FULL,
		0x726F96FF88BF98D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x323E63F0FE376FFFULL,
		0x5B32F6AF6B8F6B7AULL,
		0x861865AB0217129FULL,
		0x64DF2DFF117F31A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4D96D9F4E8CAB72ULL,
		0x0E28626CEA2F523AULL,
		0xE6AA3C08A7EFC16BULL,
		0x4D949A2CF9BE3EB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9B2DB3E9D1956F7ULL,
		0x1C50C4D9D45EA475ULL,
		0xCD5478114FDF82D6ULL,
		0x1B293459F37C7D71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C94D975C43EB29CULL,
		0x2C5A65A6417384AEULL,
		0x289A7692B1AC51E9ULL,
		0x0948D3EF9E77B5D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD929B2EB887D6538ULL,
		0x58B4CB4C82E7095CULL,
		0x5134ED256358A3D2ULL,
		0x1291A7DF3CEF6BA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73AD1F7454C0EDB0ULL,
		0x7C156D3062C0737AULL,
		0x5470431F6B46CB13ULL,
		0x08BC0489C713AE8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE75A3EE8A981DB60ULL,
		0xF82ADA60C580E6F4ULL,
		0xA8E0863ED68D9626ULL,
		0x117809138E275D14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF979862A5BC9E6D0ULL,
		0x875416CD1A7ECB7EULL,
		0x75905B9E2D2B1016ULL,
		0x228C683A627C051DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2F30C54B793CDA0ULL,
		0x0EA82D9A34FD96FDULL,
		0xEB20B73C5A56202DULL,
		0x4518D074C4F80A3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77DD63C7EB1F89CAULL,
		0xC16E6189F5FBD3A6ULL,
		0x4D2A51C2E843020BULL,
		0x6821F00D09EE2D1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFBAC78FD63F13A7ULL,
		0x82DCC313EBF7A74CULL,
		0x9A54A385D0860417ULL,
		0x5043E01A13DC5A3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52161EDFFC538B85ULL,
		0xFCA8EDDE3EFC03F8ULL,
		0xB79F9983A35CF560ULL,
		0x588EF289BBE071A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA42C3DBFF8A7171DULL,
		0xF951DBBC7DF807F0ULL,
		0x6F3F330746B9EAC1ULL,
		0x311DE51377C0E34FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EF475AF7CB987B1ULL,
		0xCDB71BCF54BD4FEEULL,
		0x5D1BA29F902C01C9ULL,
		0x47EE5EB6BEC5F7C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE8EB5EF9730F75ULL,
		0x9B6E379EA97A9FDDULL,
		0xBA37453F20580393ULL,
		0x0FDCBD6D7D8BEF8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9458150AB1B4D8A7ULL,
		0xD0DF8F729E346816ULL,
		0x7BF367AC3B457D6CULL,
		0x4F4122FC504AE0C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28B02A156369B161ULL,
		0xA1BF1EE53C68D02DULL,
		0xF7E6CF58768AFAD9ULL,
		0x1E8245F8A095C180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C5F5D1266D9EEEEULL,
		0xA2FB5B80D470C627ULL,
		0x28DBC2E5D298C399ULL,
		0x1753009958474B4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18BEBA24CDB3DDDCULL,
		0x45F6B701A8E18C4FULL,
		0x51B785CBA5318733ULL,
		0x2EA60132B08E969AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51347CD0EC428C83ULL,
		0x3CE8D439E232E467ULL,
		0x1D7A88AF54B8B344ULL,
		0x6CB93EF122540A68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA268F9A1D8851919ULL,
		0x79D1A873C465C8CEULL,
		0x3AF5115EA9716688ULL,
		0x59727DE244A814D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8FAE99E00AF53B90ULL,
		0x36D7A30A5B27D661ULL,
		0x8B87E6B95E1B3A3BULL,
		0x159DE05C1F524BF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F5D33C015EA7720ULL,
		0x6DAF4614B64FACC3ULL,
		0x170FCD72BC367476ULL,
		0x2B3BC0B83EA497E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6352B26CCC512B02ULL,
		0xC7EBA0A79DD8CE80ULL,
		0xA0693B142F62984BULL,
		0x4CABA6A39FC5763FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A564D998A25617ULL,
		0x8FD7414F3BB19D00ULL,
		0x40D276285EC53097ULL,
		0x19574D473F8AEC7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3702B6B543A80A15ULL,
		0x8CE294C3D8A784D1ULL,
		0xB56A383AF88F1EC3ULL,
		0x7A476A0F92B6C25BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E056D6A8750143DULL,
		0x19C52987B14F09A2ULL,
		0x6AD47075F11E3D87ULL,
		0x748ED41F256D84B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDBF1B477BDCEEBFULL,
		0x9872CA1C2EDDBBE4ULL,
		0x6E8726894EBC2C67ULL,
		0x124358E88ED3B24CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7E368EF7B9DD7EULL,
		0x30E594385DBB77C9ULL,
		0xDD0E4D129D7858CFULL,
		0x2486B1D11DA76498ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38EDB8B63D494D6AULL,
		0x7C50C46F38CB315CULL,
		0x543B5BD654380338ULL,
		0x7E1CDC991256C288ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71DB716C7A929AE7ULL,
		0xF8A188DE719662B8ULL,
		0xA876B7ACA8700670ULL,
		0x7C39B93224AD8510ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x440D1810374CFF67ULL,
		0x9BBD766AD186E5E3ULL,
		0xCEC9E185C46D9747ULL,
		0x6617A6E0BC5985D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x881A30206E99FEE1ULL,
		0x377AECD5A30DCBC6ULL,
		0x9D93C30B88DB2E8FULL,
		0x4C2F4DC178B30BADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECD2A637164463B5ULL,
		0xE00E60F7F87D70D1ULL,
		0xEA7B9AFC2979855EULL,
		0x0D50FAD3169003A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A54C6E2C88C76AULL,
		0xC01CC1EFF0FAE1A3ULL,
		0xD4F735F852F30ABDULL,
		0x1AA1F5A62D200753ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6A3FFB52ADB5E1FULL,
		0xB2C88E0973D6A32BULL,
		0x7EB1B737AB090094ULL,
		0x1D55CCD0C71E6F4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD47FF6A55B6BC3EULL,
		0x65911C12E7AD4657ULL,
		0xFD636E6F56120129ULL,
		0x3AAB99A18E3CDE9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90FC897164C9D993ULL,
		0x453110F8D48DFCBFULL,
		0x488A91A78C4DA7C5ULL,
		0x24E02C2617EE6DA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21F912E2C993B326ULL,
		0x8A6221F1A91BF97FULL,
		0x9115234F189B4F8AULL,
		0x49C0584C2FDCDB40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C3091E446163FC7ULL,
		0x9B2F790E76A5B157ULL,
		0x3EF5AD93CED4F5F8ULL,
		0x1303F64F178D6538ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x986123C88C2C7F8EULL,
		0x365EF21CED4B62AEULL,
		0x7DEB5B279DA9EBF1ULL,
		0x2607EC9E2F1ACA70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x26F1347FC4C4A0C8ULL,
		0xA77FDD9D6EB40C9BULL,
		0xA09286B0DFB6FA8DULL,
		0x2FE4BA6CA14FE765ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DE268FF89894190ULL,
		0x4EFFBB3ADD681936ULL,
		0x41250D61BF6DF51BULL,
		0x5FC974D9429FCECBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CDCEDA45540AE30ULL,
		0xB548F0D3C9A2DD87ULL,
		0xF9CAF6568B606727ULL,
		0x3C315D8EACFEC8C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B9DB48AA815C60ULL,
		0x6A91E1A79345BB0EULL,
		0xF395ECAD16C0CE4FULL,
		0x7862BB1D59FD9193ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9A1FE705DC9061ULL,
		0xD9A999D3FA70C108ULL,
		0x9DFBADD52D034739ULL,
		0x0DCB723C43A7CC1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39343FCE0BB920C2ULL,
		0xB35333A7F4E18211ULL,
		0x3BF75BAA5A068E73ULL,
		0x1B96E478874F9835ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7ADD469C08F1EF0ULL,
		0xDD1706DBB1D61B92ULL,
		0xB570C1D4DA9FDC02ULL,
		0x781E2B9C6A66AF83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F5BA8D3811E3DF3ULL,
		0xBA2E0DB763AC3725ULL,
		0x6AE183A9B53FB805ULL,
		0x703C5738D4CD5F07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF0940ECCEB194EAULL,
		0xACE7ADEBF6813978ULL,
		0x09FCCAB88E354562ULL,
		0x2F096A5976DD2196ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1281D99D6329D4ULL,
		0x59CF5BD7ED0272F1ULL,
		0x13F995711C6A8AC5ULL,
		0x5E12D4B2EDBA432CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB628783C392FE6AULL,
		0x0D8C646E67F1BEE7ULL,
		0xCA4DFF1E708CF51BULL,
		0x2F351B4C89B6D597ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C50F078725FCD4ULL,
		0x1B18C8DCCFE37DCFULL,
		0x949BFE3CE119EA36ULL,
		0x5E6A3699136DAB2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x842274CDF352726BULL,
		0xD8FAC42C29B4641BULL,
		0x6B13F359BD5794A2ULL,
		0x46A7839030CE3F81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0844E99BE6A4E4E9ULL,
		0xB1F588585368C837ULL,
		0xD627E6B37AAF2945ULL,
		0x0D4F0720619C7F02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3D39BBD4B8FD9C7ULL,
		0x10DC656792E3F38EULL,
		0x144ED08C74F87679ULL,
		0x7B4D2B23F12897CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7A7377A971FB3A1ULL,
		0x21B8CACF25C7E71DULL,
		0x289DA118E9F0ECF2ULL,
		0x769A5647E2512F98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FB0E3CFC3FA84C4ULL,
		0x436B81DD601969A7ULL,
		0x9D044E28209F4459ULL,
		0x4B0295A501406719ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F61C79F87F5099BULL,
		0x86D703BAC032D34EULL,
		0x3A089C50413E88B2ULL,
		0x16052B4A0280CE33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF79142E0C044ABULL,
		0x562D80C65DA8EBEBULL,
		0x084F3573640E2C1FULL,
		0x26402F416BF0787BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFEF2285C1808956ULL,
		0xAC5B018CBB51D7D6ULL,
		0x109E6AE6C81C583EULL,
		0x4C805E82D7E0F0F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xED1A5D85B8657896ULL,
		0x95240F9F034D4398ULL,
		0xDD37530B954CB221ULL,
		0x7D5D090D58DD3E49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA34BB0B70CAF13FULL,
		0x2A481F3E069A8731ULL,
		0xBA6EA6172A996443ULL,
		0x7ABA121AB1BA7C93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x317E8EA0965BA199ULL,
		0x6AF3DD4B2588BFF6ULL,
		0x70E870223E7AB279ULL,
		0x3C71EFBB73073382ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62FD1D412CB74332ULL,
		0xD5E7BA964B117FECULL,
		0xE1D0E0447CF564F2ULL,
		0x78E3DF76E60E6704ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCC6B1FC1C43CC1EULL,
		0x6094084547C7D0DCULL,
		0xC13E96A921F70B93ULL,
		0x43B7026C49667DBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x998D63F83887984FULL,
		0xC128108A8F8FA1B9ULL,
		0x827D2D5243EE1726ULL,
		0x076E04D892CCFB77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x039547A27A11B3ABULL,
		0x9890BBCB060E7EFBULL,
		0x721E2DC3E89FE7E4ULL,
		0x534834E0BC7058C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x072A8F44F4236769ULL,
		0x312177960C1CFDF6ULL,
		0xE43C5B87D13FCFC9ULL,
		0x269069C178E0B180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50DE34300BABF3B9ULL,
		0xCBFA60B9106E89A0ULL,
		0xD438652E887234FEULL,
		0x2D8006D904808A0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1BC68601757E772ULL,
		0x97F4C17220DD1340ULL,
		0xA870CA5D10E469FDULL,
		0x5B000DB20901141BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE06B7D162D39E0DULL,
		0xC26965CED9B9EEE6ULL,
		0xEB12FE4141E7BC7EULL,
		0x0A92621DB4A479BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC0D6FA2C5A73C1AULL,
		0x84D2CB9DB373DDCDULL,
		0xD625FC8283CF78FDULL,
		0x1524C43B6948F37FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8672A494CBAE281AULL,
		0x5C0CFA8D0393711FULL,
		0x3B50CDAE8F7D3137ULL,
		0x4D2CF4666CC51535ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CE54929975C5047ULL,
		0xB819F51A0726E23FULL,
		0x76A19B5D1EFA626EULL,
		0x1A59E8CCD98A2A6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52B12B200DA89C44ULL,
		0x91E43148A9E51C9FULL,
		0xE1C7648FDA5DEF00ULL,
		0x005F595A309871FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA56256401B513888ULL,
		0x23C8629153CA393EULL,
		0xC38EC91FB4BBDE01ULL,
		0x00BEB2B46130E3F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BAFD48977F08C15ULL,
		0x57762CF524C1F4D6ULL,
		0x58BF3D0AB925764EULL,
		0x4A906F3FA06126C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB75FA912EFE1183DULL,
		0xAEEC59EA4983E9ACULL,
		0xB17E7A15724AEC9CULL,
		0x1520DE7F40C24D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09843193AB21BEFCULL,
		0x7699E6BE93E37BCCULL,
		0x1DE71FABC9FB8448ULL,
		0x27F30F78307DB42DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1308632756437DF8ULL,
		0xED33CD7D27C6F798ULL,
		0x3BCE3F5793F70890ULL,
		0x4FE61EF060FB685AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB05788CE8BC4E82AULL,
		0x7B3F9DEDC05774DFULL,
		0x4064EB71546B22B8ULL,
		0x564A0B6DBFDFCFEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60AF119D1789D067ULL,
		0xF67F3BDB80AEE9BFULL,
		0x80C9D6E2A8D64570ULL,
		0x2C9416DB7FBF9FD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x504D3FCBFD039713ULL,
		0xBE12079EA96ABE80ULL,
		0xC5D31EE21AE18F7AULL,
		0x30BA5F42080350DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA09A7F97FA072E26ULL,
		0x7C240F3D52D57D00ULL,
		0x8BA63DC435C31EF5ULL,
		0x6174BE841006A1B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49F63A27F3B24824ULL,
		0x74616A079BB14452ULL,
		0x00ED44DF8B5D03B6ULL,
		0x7F922B2E46C80B5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93EC744FE764905BULL,
		0xE8C2D40F376288A4ULL,
		0x01DA89BF16BA076CULL,
		0x7F24565C8D9016BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE9DCB73BE8867D3ULL,
		0xF7F663E0E562672AULL,
		0x7EAD6726E6844C5FULL,
		0x0A513B41B0D09972ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D3B96E77D10CFA6ULL,
		0xEFECC7C1CAC4CE55ULL,
		0xFD5ACE4DCD0898BFULL,
		0x14A2768361A132E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F3EE9AF386E44F7ULL,
		0x127707D4EBAE98ADULL,
		0x23D3BFCC3D5124A4ULL,
		0x796E9A30BCA74B23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E7DD35E70DC8A01ULL,
		0x24EE0FA9D75D315BULL,
		0x47A77F987AA24948ULL,
		0x72DD3461794E9646ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8AD69DB690BA3BCULL,
		0xF4DBB57410546E90ULL,
		0xF86AFD186971B98CULL,
		0x2447A3D48B86AF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x715AD3B6D2174778ULL,
		0xE9B76AE820A8DD21ULL,
		0xF0D5FA30D2E37319ULL,
		0x488F47A9170D5F33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD24AD45A96376DBEULL,
		0x1115B962B33A97E8ULL,
		0x47570AF0D37EB97EULL,
		0x460AD402135986B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA495A8B52C6EDB8FULL,
		0x222B72C566752FD1ULL,
		0x8EAE15E1A6FD72FCULL,
		0x0C15A80426B30D68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA50AB7882130DD2ULL,
		0x6DDEB8B02D4D1637ULL,
		0x911228FDFF6EFABAULL,
		0x006F257B657895B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94A156F104261BA4ULL,
		0xDBBD71605A9A2C6FULL,
		0x222451FBFEDDF574ULL,
		0x00DE4AF6CAF12B71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFDC226DC32928CCBULL,
		0x8C479E224F66AC58ULL,
		0x95AE72694BAE7EB3ULL,
		0x57AB7B35DA879DE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB844DB8652519A9ULL,
		0x188F3C449ECD58B1ULL,
		0x2B5CE4D2975CFD67ULL,
		0x2F56F66BB50F3BC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4CF4DCCEB02EAA70ULL,
		0x85C5E836F796A3E4ULL,
		0x122C1F439AB7B184ULL,
		0x2CEBFF49658192ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99E9B99D605D54E0ULL,
		0x0B8BD06DEF2D47C8ULL,
		0x24583E87356F6309ULL,
		0x59D7FE92CB032556ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88EEC5130D7A9B64ULL,
		0x573332676D17AF08ULL,
		0x51B26BE0D3636D3FULL,
		0x476D12EAD4154D28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11DD8A261AF536DBULL,
		0xAE6664CEDA2F5E11ULL,
		0xA364D7C1A6C6DA7EULL,
		0x0EDA25D5A82A9A50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x031FAEA03DB12C44ULL,
		0x26700FBC91C06536ULL,
		0x536E2EE7E8740E09ULL,
		0x4D15100A967886EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x063F5D407B62589BULL,
		0x4CE01F792380CA6CULL,
		0xA6DC5DCFD0E81C12ULL,
		0x1A2A20152CF10DDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81BBE34D468A8395ULL,
		0x597DBECB54A677AFULL,
		0x308172C301C95E2AULL,
		0x553F2A6B5356EC13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0377C69A8D15073DULL,
		0xB2FB7D96A94CEF5FULL,
		0x6102E5860392BC54ULL,
		0x2A7E54D6A6ADD826ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1567401549A8D89ULL,
		0xDDDD4D718779C95CULL,
		0x32C417A6DD42C1EDULL,
		0x551601D7BC083130ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62ACE802A9351B25ULL,
		0xBBBA9AE30EF392B9ULL,
		0x65882F4DBA8583DBULL,
		0x2A2C03AF78106260ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6544E42A3DC42D25ULL,
		0x5F88558C6A08C099ULL,
		0xAE28DB74E8D223B4ULL,
		0x1F851CC61CB2946DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA89C8547B885A4AULL,
		0xBF10AB18D4118132ULL,
		0x5C51B6E9D1A44768ULL,
		0x3F0A398C396528DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x796918E7E9C8AAB7ULL,
		0xB9DBC8EC2D2394F5ULL,
		0x559DBC4109C5731BULL,
		0x69E10BD431D2CBC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D231CFD3915581ULL,
		0x73B791D85A4729EAULL,
		0xAB3B7882138AE637ULL,
		0x53C217A863A59780ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA596A33ABD7F8EC2ULL,
		0x8B90C47DA8774FB0ULL,
		0x705C89DA96E19FEFULL,
		0x236960FA5DE2E75FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2D46757AFF1D84ULL,
		0x172188FB50EE9F61ULL,
		0xE0B913B52DC33FDFULL,
		0x46D2C1F4BBC5CEBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B730A8937D73C97ULL,
		0x63AFE6CD52295A52ULL,
		0x41161E970E56A7D0ULL,
		0x17AE5E7DEB7463BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E615126FAE792EULL,
		0xC75FCD9AA452B4A4ULL,
		0x822C3D2E1CAD4FA0ULL,
		0x2F5CBCFBD6E8C77EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE3973DE94E2B6F38ULL,
		0x415D459CABF5A531ULL,
		0x4E49EF5FFD8B7BFFULL,
		0x750219F9974F6EDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC72E7BD29C56DE83ULL,
		0x82BA8B3957EB4A63ULL,
		0x9C93DEBFFB16F7FEULL,
		0x6A0433F32E9EDDB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD29B54710CF08B5ULL,
		0x83E9D050BB1D57F8ULL,
		0x8D0EF851717B8E90ULL,
		0x77B89835A9F27435ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA536A8E219E117DULL,
		0x07D3A0A1763AAFF1ULL,
		0x1A1DF0A2E2F71D21ULL,
		0x6F71306B53E4E86BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C403A9FD89BF408ULL,
		0xD4A9919E3A422CFEULL,
		0xDF8B610AFCB969D6ULL,
		0x069FC8AB05B84244ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB880753FB137E810ULL,
		0xA953233C748459FCULL,
		0xBF16C215F972D3ADULL,
		0x0D3F91560B708489ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7DB0838A74D93719ULL,
		0xE4ECD65B90D7FFB7ULL,
		0x0F33B8C2B2526C44ULL,
		0x69EA135016DE33A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB610714E9B26E45ULL,
		0xC9D9ACB721AFFF6EULL,
		0x1E67718564A4D889ULL,
		0x53D426A02DBC6748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93F8901B0B77FC09ULL,
		0xA1FFD4FE0DCE29BDULL,
		0x9EF1CBECE1A345F4ULL,
		0x2FEBCD7BDFAABC46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F1203616EFF812ULL,
		0x43FFA9FC1B9C537BULL,
		0x3DE397D9C3468BE9ULL,
		0x5FD79AF7BF55788DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x306BDF42EAE1E5BEULL,
		0xCE98CCA8BA280D17ULL,
		0x3A3C608E1A8E3034ULL,
		0x650BDE9B909023C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D7BE85D5C3CB8FULL,
		0x9D31995174501A2EULL,
		0x7478C11C351C6069ULL,
		0x4A17BD3721204786ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D3B3EF3C48B3607ULL,
		0xF44F4E87735F899BULL,
		0x51928E3C99D01D46ULL,
		0x3DF7AD74C0D174F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A767DE789166C0EULL,
		0xE89E9D0EE6BF1336ULL,
		0xA3251C7933A03A8DULL,
		0x7BEF5AE981A2E9E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1A524F5D005A41EULL,
		0x3295B847099E2C0EULL,
		0x1F44D7230E3EF50BULL,
		0x5B344A3A62AB34F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x834A49EBA00B484FULL,
		0x652B708E133C581DULL,
		0x3E89AE461C7DEA16ULL,
		0x36689474C55669E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF543649180385781ULL,
		0x4CABA9BED0F43042ULL,
		0xABF8D18A52896D39ULL,
		0x0E82DB594EA0795CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA86C9230070AF02ULL,
		0x9957537DA1E86085ULL,
		0x57F1A314A512DA72ULL,
		0x1D05B6B29D40F2B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x150FE48540AA18C5ULL,
		0x6BC4BEEDCF09E0E8ULL,
		0x9546738BE1A3A7D8ULL,
		0x42065962B4CE1290ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A1FC90A8154319DULL,
		0xD7897DDB9E13C1D0ULL,
		0x2A8CE717C3474FB0ULL,
		0x040CB2C5699C2521ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x059FDD997419BAD6ULL,
		0x09A8B11494972DD1ULL,
		0x3B6F632F02395504ULL,
		0x59FE1C0644AE2C4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B3FBB32E83375BFULL,
		0x13516229292E5BA2ULL,
		0x76DEC65E0472AA08ULL,
		0x33FC380C895C589AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE123B540B40F9351ULL,
		0xE43273A8544D1C62ULL,
		0x24627E00D6EF5076ULL,
		0x57E0B4DD75058718ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2476A81681F26B5ULL,
		0xC864E750A89A38C5ULL,
		0x48C4FC01ADDEA0EDULL,
		0x2FC169BAEA0B0E30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AB9CFC6644A852AULL,
		0x9914C497551ADAB1ULL,
		0xA0B39E4FFBEDDF67ULL,
		0x2766EA656E045C83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75739F8CC8950A54ULL,
		0x3229892EAA35B562ULL,
		0x41673C9FF7DBBECFULL,
		0x4ECDD4CADC08B907ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F4AC6475ECEFEE1ULL,
		0xB99F2E90C84BB4D7ULL,
		0xF75A86B90FDF65FEULL,
		0x4171DA9F0EC70CC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E958C8EBD9DFDD5ULL,
		0x733E5D21909769AEULL,
		0xEEB50D721FBECBFDULL,
		0x02E3B53E1D8E1983ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C9433E6D0FB7ED8ULL,
		0x170B80C988BE5B36ULL,
		0xC26AFF076C31C9AFULL,
		0x20241768ACE5467AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x592867CDA1F6FDB0ULL,
		0x2E170193117CB66CULL,
		0x84D5FE0ED863935EULL,
		0x40482ED159CA8CF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2543D7876D73E84DULL,
		0xBF1D8065EC73E4CFULL,
		0xC28FD13EB8C990D1ULL,
		0x1FA36D869F6EC1B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A87AF0EDAE7D09AULL,
		0x7E3B00CBD8E7C99EULL,
		0x851FA27D719321A3ULL,
		0x3F46DB0D3EDD836DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17CBF5DEC046D5C3ULL,
		0xC83248B150C596DAULL,
		0x0C9B0C6B38DA5AA6ULL,
		0x0508CA5C865F19BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F97EBBD808DAB86ULL,
		0x90649162A18B2DB4ULL,
		0x193618D671B4B54DULL,
		0x0A1194B90CBE3376ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD066A6F218C8B98AULL,
		0x5D4515BD0E81E978ULL,
		0x98C4481B7DDE494CULL,
		0x268767499CC914F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0CD4DE431917314ULL,
		0xBA8A2B7A1D03D2F1ULL,
		0x31889036FBBC9298ULL,
		0x4D0ECE93399229F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31A19C929815105FULL,
		0x8A7DF3D4DDC79A4CULL,
		0xA52FFF39F025A89DULL,
		0x4112514D2846C7E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63433925302A20D1ULL,
		0x14FBE7A9BB8F3498ULL,
		0x4A5FFE73E04B513BULL,
		0x0224A29A508D8FCDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35608E3625CC8881ULL,
		0x9A101539ABF41533ULL,
		0x18918DD3243FD277ULL,
		0x2CE6DD6E24591C63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AC11C6C4B991102ULL,
		0x34202A7357E82A66ULL,
		0x31231BA6487FA4EFULL,
		0x59CDBADC48B238C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4B7DFB72A7AB542ULL,
		0xFC9CA21CB1014409ULL,
		0x482DB3EDF1DC6447ULL,
		0x44B04DC250C3177FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC96FBF6E54F56A97ULL,
		0xF939443962028813ULL,
		0x905B67DBE3B8C88FULL,
		0x09609B84A1862EFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA78B04A3CCC0597ULL,
		0x8D0D5E2AF471F03CULL,
		0xBEC563989AFD9B82ULL,
		0x2789B4FF2D5EFDA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4F1609479980B2EULL,
		0x1A1ABC55E8E3E079ULL,
		0x7D8AC73135FB3705ULL,
		0x4F1369FE5ABDFB41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDED08261ADDF884ULL,
		0x0CE1896E128546FDULL,
		0xA753003C2DCBC390ULL,
		0x1CC27CB0B6C57ABFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBDA104C35BBF108ULL,
		0x19C312DC250A8DFBULL,
		0x4EA600785B978720ULL,
		0x3984F9616D8AF57FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6F3FFCAD91289B0ULL,
		0x961FB030D00E81E2ULL,
		0x68A249A2BC65BDF9ULL,
		0x0969515F44A75F23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDE7FF95B2251360ULL,
		0x2C3F6061A01D03C5ULL,
		0xD144934578CB7BF3ULL,
		0x12D2A2BE894EBE46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68EC122C0534A955ULL,
		0x6FAC543B0E456B6AULL,
		0x9E3CB3A77EE636CFULL,
		0x7C85305BBABBA882ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D824580A6952BDULL,
		0xDF58A8761C8AD6D4ULL,
		0x3C79674EFDCC6D9EULL,
		0x790A60B775775105ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6300692B72722886ULL,
		0x0C31B0C113439EC4ULL,
		0x220B1819650FDCCCULL,
		0x668788936FCB62F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC600D256E4E4511FULL,
		0x1863618226873D88ULL,
		0x44163032CA1FB998ULL,
		0x4D0F1126DF96C5E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAD298497612C49C0ULL,
		0xFC8E29FB11C0890DULL,
		0x47E570E6B8972AD6ULL,
		0x36EC0840357B7868ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A53092EC2589380ULL,
		0xF91C53F62381121BULL,
		0x8FCAE1CD712E55ADULL,
		0x6DD810806AF6F0D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F1965A51FEA5A83ULL,
		0xEED72B00012231C3ULL,
		0x28C00A01531CF43AULL,
		0x1A1300378791DB1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E32CB4A3FD4B506ULL,
		0xDDAE560002446387ULL,
		0x51801402A639E875ULL,
		0x3426006F0F23B63AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA2866B531254990ULL,
		0x649DA68311917EA4ULL,
		0x6A496EF06A24EF2CULL,
		0x5DF199A17B6DA8F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5450CD6A624A9333ULL,
		0xC93B4D062322FD49ULL,
		0xD492DDE0D449DE58ULL,
		0x3BE33342F6DB51ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD413DDF757730D69ULL,
		0xFFFB78CDB08BF093ULL,
		0x1C8DB76B9C12B6B1ULL,
		0x778D8FB2C4D806B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA827BBEEAEE61AE5ULL,
		0xFFF6F19B6117E127ULL,
		0x391B6ED738256D63ULL,
		0x6F1B1F6589B00D66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x387E4D4B8323861FULL,
		0x73A6D7ED65144601ULL,
		0x36300071C73FEA6CULL,
		0x0FDEDC849A94C905ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70FC9A9706470C3EULL,
		0xE74DAFDACA288C02ULL,
		0x6C6000E38E7FD4D8ULL,
		0x1FBDB9093529920AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x028C9FBB5C2BEDF7ULL,
		0xFD3BCD3E1EDF5355ULL,
		0xE5543BB0265A883EULL,
		0x757E9879BB315B28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05193F76B857DC01ULL,
		0xFA779A7C3DBEA6AAULL,
		0xCAA877604CB5107DULL,
		0x6AFD30F37662B651ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x12860287F705A648ULL,
		0x5C1F94EA32C8F7ECULL,
		0xBBC79F8D095A314AULL,
		0x62E2F849C0395340ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x250C050FEE0B4CA3ULL,
		0xB83F29D46591EFD8ULL,
		0x778F3F1A12B46294ULL,
		0x45C5F0938072A681ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1FB060A9CF3B96D6ULL,
		0xF88D8EC16E60AB19ULL,
		0xD6DDA2D6503DC48AULL,
		0x39A160AA4D275E7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F60C1539E772DACULL,
		0xF11B1D82DCC15632ULL,
		0xADBB45ACA07B8915ULL,
		0x7342C1549A4EBCF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3E36CE5DD0D4557BULL,
		0xAEDA29FB8FDA201BULL,
		0x38D1DD365B88B433ULL,
		0x61B08E94BF3C7854ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C6D9CBBA1A8AB09ULL,
		0x5DB453F71FB44036ULL,
		0x71A3BA6CB7116867ULL,
		0x43611D297E78F0A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF545A49F53C26EE1ULL,
		0x5C89945AB510064FULL,
		0xAE3735CDA2A4F8EEULL,
		0x309A15F92D2D095BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA8B493EA784DDC2ULL,
		0xB91328B56A200C9FULL,
		0x5C6E6B9B4549F1DCULL,
		0x61342BF25A5A12B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB61512FE44812E8ULL,
		0x27A6F9E6639C556AULL,
		0xE032CB7C2A014EB9ULL,
		0x6EC31576F158BBC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6C2A25FC89025E3ULL,
		0x4F4DF3CCC738AAD5ULL,
		0xC06596F854029D72ULL,
		0x5D862AEDE2B17783ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC0BAED03193E42AULL,
		0xEEFE66C5663D49A2ULL,
		0x292CD6254E8EF7A1ULL,
		0x018B730B957D25C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8175DA06327C854ULL,
		0xDDFCCD8ACC7A9345ULL,
		0x5259AC4A9D1DEF43ULL,
		0x0316E6172AFA4B82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B87A08CEA5B6B7EULL,
		0x7B6A4EF4AA3C7BFFULL,
		0x2431D45C535BC8AAULL,
		0x2DAC45B9D60A14BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF70F4119D4B6D6FCULL,
		0xF6D49DE95478F7FEULL,
		0x4863A8B8A6B79154ULL,
		0x5B588B73AC142974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEABED33F8F8FFF7ULL,
		0x1F4CEBE7424D1101ULL,
		0xDBFF9B231EA7877FULL,
		0x2016AC3D2E62A9BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD57DA67F1F1FFEEULL,
		0x3E99D7CE849A2203ULL,
		0xB7FF36463D4F0EFEULL,
		0x402D587A5CC55377ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA112F4061470BC38ULL,
		0x0FBC742E7B308001ULL,
		0xA34A4D3EF5678E7BULL,
		0x19E93E49597C3C4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4225E80C28E17870ULL,
		0x1F78E85CF6610003ULL,
		0x46949A7DEACF1CF6ULL,
		0x33D27C92B2F8789DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5299A8DA191610E6ULL,
		0x1C944401C8D8FF0AULL,
		0xE9F9B0C07214B402ULL,
		0x04CBBF79177049A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA53351B4322C21CCULL,
		0x3928880391B1FE14ULL,
		0xD3F36180E4296804ULL,
		0x09977EF22EE09347ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x706FDCE8962A479FULL,
		0x9EF4F72729348E5BULL,
		0xD92C68A2A6ABDCFCULL,
		0x1F815FBCCAA88BCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0DFB9D12C548F3EULL,
		0x3DE9EE4E52691CB6ULL,
		0xB258D1454D57B9F9ULL,
		0x3F02BF799551179FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF70D1E571F64FA1ULL,
		0x3230D6C6C8C50556ULL,
		0x9B33325B1D6E5A81ULL,
		0x0072C4CBF5FEDCD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EE1A3CAE3EC9F42ULL,
		0x6461AD8D918A0AADULL,
		0x366664B63ADCB502ULL,
		0x00E58997EBFDB9A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x458594295252071EULL,
		0x01254F2C42048D06ULL,
		0xCF2ED2398966A7D6ULL,
		0x265AE3D67EC28100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0B2852A4A40E3CULL,
		0x024A9E5884091A0CULL,
		0x9E5DA47312CD4FACULL,
		0x4CB5C7ACFD850201ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8EDBACD7514BEC4EULL,
		0xA52F7BDB87506D45ULL,
		0x96091D6E025B35FBULL,
		0x6A43BFA495FFBF93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DB759AEA297D8AFULL,
		0x4A5EF7B70EA0DA8BULL,
		0x2C123ADC04B66BF7ULL,
		0x54877F492BFF7F27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x22DBC48F706409A4ULL,
		0xA4799F6CBE91C98CULL,
		0x685CC2731020F035ULL,
		0x5BCEDBBC1905F71FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B7891EE0C8135BULL,
		0x48F33ED97D239318ULL,
		0xD0B984E62041E06BULL,
		0x379DB778320BEE3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF95580F0A57E5EC9ULL,
		0x426C00AC52FFC457ULL,
		0x283B0183730565E9ULL,
		0x62B14000C28AE5E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2AB01E14AFCBDA5ULL,
		0x84D80158A5FF88AFULL,
		0x50760306E60ACBD2ULL,
		0x456280018515CBCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A6DEB7E3FB60982ULL,
		0x1F7DD6F539AA517EULL,
		0x10A92F8799378C23ULL,
		0x5DCA75CF093B70CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74DBD6FC7F6C1317ULL,
		0x3EFBADEA7354A2FCULL,
		0x21525F0F326F1846ULL,
		0x3B94EB9E1276E19CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x499ABA60FA1157FDULL,
		0xA4467C3B3D083D03ULL,
		0x67673133734884FFULL,
		0x6E21D97B2296A7ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x933574C1F422B00DULL,
		0x488CF8767A107A06ULL,
		0xCECE6266E69109FFULL,
		0x5C43B2F6452D4F5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2B0173E8AB04D24ULL,
		0x578029A3FB6CA32DULL,
		0xADACE08852AF8455ULL,
		0x48D5C9961294C417ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85602E7D15609A5BULL,
		0xAF005347F6D9465BULL,
		0x5B59C110A55F08AAULL,
		0x11AB932C2529882FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4483ED2D0BB6A306ULL,
		0xE1E48093EFF12B0EULL,
		0x095750D55699E1DCULL,
		0x6E35FD69A4E98057ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8907DA5A176D461FULL,
		0xC3C90127DFE2561CULL,
		0x12AEA1AAAD33C3B9ULL,
		0x5C6BFAD349D300AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81E5E7A5FCDFE9D2ULL,
		0x7F364FB5B4234E3DULL,
		0xA28BDA61633DAF62ULL,
		0x135E6B6655DFC3A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03CBCF4BF9BFD3A4ULL,
		0xFE6C9F6B68469C7BULL,
		0x4517B4C2C67B5EC4ULL,
		0x26BCD6CCABBF874FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF2B50C749820B51DULL,
		0xD4706A6E3219C182ULL,
		0x385EDAEDBF8E17AAULL,
		0x68A9A685094E684EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE56A18E930416A4DULL,
		0xA8E0D4DC64338305ULL,
		0x70BDB5DB7F1C2F55ULL,
		0x51534D0A129CD09CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4432621755B53448ULL,
		0x29E5686E8BBBAB3FULL,
		0xF1BB9DC5D125BB84ULL,
		0x72ED221DA4F7A030ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8864C42EAB6A68A3ULL,
		0x53CAD0DD1777567EULL,
		0xE3773B8BA24B7708ULL,
		0x65DA443B49EF4061ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DADAE1940DFF65CULL,
		0x5D7D685FC35A3FCEULL,
		0xE482D229BA010BE1ULL,
		0x50F210B0E22A1423ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB5B5C3281BFECCBULL,
		0xBAFAD0BF86B47F9CULL,
		0xC905A453740217C2ULL,
		0x21E42161C4542847ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5AC27AF64CECEE2ULL,
		0xBCA3DB85DF5E0623ULL,
		0x73F8E03CE4639D53ULL,
		0x028EEE6BC0B54016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB584F5EC99D9DC4ULL,
		0x7947B70BBEBC0C47ULL,
		0xE7F1C079C8C73AA7ULL,
		0x051DDCD7816A802CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6AE60E67BD22A5FFULL,
		0x0C02B281A61FC182ULL,
		0x4EA1857485808F25ULL,
		0x08BF86E560C847AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5CC1CCF7A454BFEULL,
		0x180565034C3F8304ULL,
		0x9D430AE90B011E4AULL,
		0x117F0DCAC1908F5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D6472E66CAA52D3ULL,
		0x4DF23868E1BCDEAAULL,
		0x3F43C23B78BAA1A8ULL,
		0x508208998C075741ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC8E5CCD954A5B9ULL,
		0x9BE470D1C379BD54ULL,
		0x7E878476F1754350ULL,
		0x21041133180EAE82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4F23006FB19831EULL,
		0x5AACEF84303BBFB8ULL,
		0x1A8F82D83E16FD3DULL,
		0x076429CBEE736BAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9E4600DF633063CULL,
		0xB559DF0860777F71ULL,
		0x351F05B07C2DFA7AULL,
		0x0EC85397DCE6D75CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x83FAC7FF452C005DULL,
		0xB7C0455569091675ULL,
		0xA58A0772578E3671ULL,
		0x7425EEFC37DD8CA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07F58FFE8A5800CDULL,
		0x6F808AAAD2122CEBULL,
		0x4B140EE4AF1C6CE3ULL,
		0x684BDDF86FBB194BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB502B770C4886CBULL,
		0xD186F0444DBA165BULL,
		0xDD53CEF26C395B49ULL,
		0x54DB1A9EDB49F686ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6A056EE18910DA9ULL,
		0xA30DE0889B742CB7ULL,
		0xBAA79DE4D872B693ULL,
		0x29B6353DB693ED0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF70D396725E09EB4ULL,
		0x606291A6AADCBA3AULL,
		0x5C1AF5D427695378ULL,
		0x230143E9FC7CC2FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE1A72CE4BC13D68ULL,
		0xC0C5234D55B97475ULL,
		0xB835EBA84ED2A6F0ULL,
		0x460287D3F8F985FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC65355B6D005F733ULL,
		0x7C72F73BA15361ABULL,
		0x6186ED007DBFEEEEULL,
		0x6164D0A1348E57F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CA6AB6DA00BEE79ULL,
		0xF8E5EE7742A6C357ULL,
		0xC30DDA00FB7FDDDCULL,
		0x42C9A142691CAFE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F1B6575878595D8ULL,
		0x21491F190131E877ULL,
		0x211FF74FAFBB06CCULL,
		0x2E53EED24FE98900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E36CAEB0F0B2BB0ULL,
		0x42923E320263D0EFULL,
		0x423FEE9F5F760D98ULL,
		0x5CA7DDA49FD31200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2541BAC5E9DFC3B6ULL,
		0x273744568B44F8B6ULL,
		0x70CF83EBCC59528CULL,
		0x6DD187ACF85EA74FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A83758BD3BF877FULL,
		0x4E6E88AD1689F16CULL,
		0xE19F07D798B2A518ULL,
		0x5BA30F59F0BD4E9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD994F7A1138198FDULL,
		0x276656B4A57ACD64ULL,
		0xC1676DD112288B7CULL,
		0x3A840880487885B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB329EF42270331FAULL,
		0x4ECCAD694AF59AC9ULL,
		0x82CEDBA2245116F8ULL,
		0x7508110090F10B73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAA7D8239795180AULL,
		0x6EE7C0800215BB3DULL,
		0xC73D9AE74C131AC8ULL,
		0x328020C89864C5D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x754FB0472F2A3014ULL,
		0xDDCF8100042B767BULL,
		0x8E7B35CE98263590ULL,
		0x6500419130C98BA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA75394773F3A128DULL,
		0x1AA648F5E65CFABFULL,
		0x36C9369F9A1591C6ULL,
		0x5D130ED29E0927A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA728EE7E74252DULL,
		0x354C91EBCCB9F57FULL,
		0x6D926D3F342B238CULL,
		0x3A261DA53C124F4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA40D6C527966409FULL,
		0x0E6A63A48DFF7B66ULL,
		0x3CCD8263E6B5F835ULL,
		0x604FD0090A05875CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x481AD8A4F2CC8151ULL,
		0x1CD4C7491BFEF6CDULL,
		0x799B04C7CD6BF06AULL,
		0x409FA012140B0EB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59DD64273BA96A9CULL,
		0x466086ADD0BA5170ULL,
		0xDA3D27CFB615B3B0ULL,
		0x177B091C0A563FD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3BAC84E7752D538ULL,
		0x8CC10D5BA174A2E0ULL,
		0xB47A4F9F6C2B6760ULL,
		0x2EF6123814AC7FAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD48E282CDC58870CULL,
		0xE65EA008242EAF0EULL,
		0x75C507EE1B48ECF5ULL,
		0x4041FC58027CFFFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA91C5059B8B10E2BULL,
		0xCCBD4010485D5E1DULL,
		0xEB8A0FDC3691D9EBULL,
		0x0083F8B004F9FFF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68D33E11D1997CFCULL,
		0xD8A09E8E5A44F645ULL,
		0x03FB05D32220FF38ULL,
		0x161A2D687BA65257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A67C23A332F9F8ULL,
		0xB1413D1CB489EC8AULL,
		0x07F60BA64441FE71ULL,
		0x2C345AD0F74CA4AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CAB88129B1AFE1EULL,
		0x5EE04C8680EF76F8ULL,
		0xE285A2E01D71353FULL,
		0x3123E8466CC7A221ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95710253635FC3CULL,
		0xBDC0990D01DEEDF0ULL,
		0xC50B45C03AE26A7EULL,
		0x6247D08CD98F4443ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x729DCF86BD52C09FULL,
		0x5D20BB4998D69BB6ULL,
		0xE4EF33BACE156F0AULL,
		0x2A99A370CFE861DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE53B9F0D7AA5813EULL,
		0xBA41769331AD376CULL,
		0xC9DE67759C2ADE14ULL,
		0x553346E19FD0C3B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x038CA66AA952A97AULL,
		0x7F5B5D3CDEEF0D39ULL,
		0xBA9BF094C56FC7A4ULL,
		0x0A26F7599BA5C708ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07194CD552A552F4ULL,
		0xFEB6BA79BDDE1A72ULL,
		0x7537E1298ADF8F48ULL,
		0x144DEEB3374B8E11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9297DF3F350F7621ULL,
		0xDF260C04686D35BBULL,
		0x5BB2182BD0DD1F3DULL,
		0x4983AD768BDB5FCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252FBE7E6A1EEC55ULL,
		0xBE4C1808D0DA6B77ULL,
		0xB7643057A1BA3E7BULL,
		0x13075AED17B6BF98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6809FBEE7418529BULL,
		0xA88B2039C8797379ULL,
		0xE0E87E4A77EF8614ULL,
		0x19B32C980D761E3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD013F7DCE830A536ULL,
		0x5116407390F2E6F2ULL,
		0xC1D0FC94EFDF0C29ULL,
		0x336659301AEC3C79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60E8D49D3225E7E5ULL,
		0x71C8D4F40C60EE87ULL,
		0xED9FB79F7187D4D5ULL,
		0x62A4FADD78A52C76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D1A93A644BCFDDULL,
		0xE391A9E818C1DD0EULL,
		0xDB3F6F3EE30FA9AAULL,
		0x4549F5BAF14A58EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x365D1C7A110B2BE7ULL,
		0x3ADA564F92612FEEULL,
		0x0F1DD9184A6D12D6ULL,
		0x520056D3E774971AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CBA38F4221657E1ULL,
		0x75B4AC9F24C25FDCULL,
		0x1E3BB23094DA25ACULL,
		0x2400ADA7CEE92E34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x909650B64F1C1640ULL,
		0xB130B89C24EBE5CDULL,
		0xC7A73BC9DF17B624ULL,
		0x065F2F2279552EE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x212CA16C9E382C80ULL,
		0x6261713849D7CB9BULL,
		0x8F4E7793BE2F6C49ULL,
		0x0CBE5E44F2AA5DC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51E19AA08100A570ULL,
		0x9BADA18185126145ULL,
		0xE6A2CB65E55840C1ULL,
		0x542D326158471576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3C3354102014AF3ULL,
		0x375B43030A24C28AULL,
		0xCD4596CBCAB08183ULL,
		0x285A64C2B08E2AEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6CDB600093C40CEULL,
		0x89C3D8E6A0CC4A9CULL,
		0x14F5A03A4C7C822CULL,
		0x07262007561F41D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D9B6C001278819CULL,
		0x1387B1CD41989539ULL,
		0x29EB407498F90459ULL,
		0x0E4C400EAC3E83B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0CEEDB0F8A5F77AULL,
		0x1675FD68D34DC13BULL,
		0xB57378771AB9A89CULL,
		0x3E26684A4264D835ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819DDB61F14BEEF4ULL,
		0x2CEBFAD1A69B8277ULL,
		0x6AE6F0EE35735138ULL,
		0x7C4CD09484C9B06BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DB3752A87B21F8EULL,
		0x1768833F9570DD1AULL,
		0xE7579BC2FB54AC74ULL,
		0x3283B06D32E81953ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB66EA550F643F1CULL,
		0x2ED1067F2AE1BA34ULL,
		0xCEAF3785F6A958E8ULL,
		0x650760DA65D032A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5E86E35B980A8B8ULL,
		0x0D2306E7700BE572ULL,
		0x13DC4E9EBA006EA7ULL,
		0x28EDFE795178432DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BD0DC6B73015170ULL,
		0x1A460DCEE017CAE5ULL,
		0x27B89D3D7400DD4EULL,
		0x51DBFCF2A2F0865AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54E7755ACBBA58A5ULL,
		0x550F71FEF57561DDULL,
		0xC3C3DE4F29AF4F6EULL,
		0x0859BDDCBEBAA1CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9CEEAB59774B14AULL,
		0xAA1EE3FDEAEAC3BAULL,
		0x8787BC9E535E9EDCULL,
		0x10B37BB97D75439FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5CF3C269EC92A2E5ULL,
		0xB856300001DA9E88ULL,
		0x00BEE488A2BD3A78ULL,
		0x721B6C9CE7CA79A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9E784D3D92545DDULL,
		0x70AC600003B53D10ULL,
		0x017DC911457A74F1ULL,
		0x6436D939CF94F34AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB88FC76B918F73FAULL,
		0x9BC728FC22D50498ULL,
		0x13029A8D527DED2DULL,
		0x71F0010EF236A81DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x711F8ED7231EE807ULL,
		0x378E51F845AA0931ULL,
		0x2605351AA4FBDA5BULL,
		0x63E0021DE46D503AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99728ABF0B2E7F16ULL,
		0xAB1199F28597FEC2ULL,
		0x3A06F2D81E6AB0FCULL,
		0x4EB211F78047DDE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32E5157E165CFE3FULL,
		0x562333E50B2FFD85ULL,
		0x740DE5B03CD561F9ULL,
		0x1D6423EF008FBBCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE48C16057D3F5E5DULL,
		0x24130B06A182B768ULL,
		0xA886D9AD5D3B2552ULL,
		0x2CF871B58B54B7B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9182C0AFA7EBCBAULL,
		0x4826160D43056ED1ULL,
		0x510DB35ABA764AA4ULL,
		0x59F0E36B16A96F6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAC4FD199D5BD2591ULL,
		0x596A463F202BDE98ULL,
		0x1AB694EAB19AB97AULL,
		0x36B6959645980CE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x589FA333AB7A4B22ULL,
		0xB2D48C7E4057BD31ULL,
		0x356D29D5633572F4ULL,
		0x6D6D2B2C8B3019C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8B5F20C9DF391B47ULL,
		0xB1C579D9F38EA317ULL,
		0x099EF9748EB94393ULL,
		0x35A6BD83994146EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16BE4193BE72368EULL,
		0x638AF3B3E71D462FULL,
		0x133DF2E91D728727ULL,
		0x6B4D7B0732828DD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x440E30D0EE613E4EULL,
		0x36F933CE4D874976ULL,
		0x8452B105A8932C3FULL,
		0x1BBE411C40AA244FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x881C61A1DCC27C9CULL,
		0x6DF2679C9B0E92ECULL,
		0x08A5620B5126587EULL,
		0x377C82388154489FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x60EB8D9E4A04A919ULL,
		0x19409412B9E057F7ULL,
		0x79DE6F5B71422B72ULL,
		0x15E851276F0AB1E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1D71B3C94095232ULL,
		0x3281282573C0AFEEULL,
		0xF3BCDEB6E28456E4ULL,
		0x2BD0A24EDE1563D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC93E64849F0BFEB6ULL,
		0xA9B6105F5A1788D2ULL,
		0x978682357D97D67AULL,
		0x789E69C6F60E79CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x927CC9093E17FD7FULL,
		0x536C20BEB42F11A5ULL,
		0x2F0D046AFB2FACF5ULL,
		0x713CD38DEC1CF39DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB1A7A1333A268415ULL,
		0xACA20C689BD692F8ULL,
		0x0AA0FABBA8306016ULL,
		0x7CCE8DBE7938D59FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634F4266744D083DULL,
		0x594418D137AD25F1ULL,
		0x1541F5775060C02DULL,
		0x799D1B7CF271AB3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x92179F8C6987EC32ULL,
		0x285830366B3E57C7ULL,
		0xA7CE8610EB9532C6ULL,
		0x2B8834DD99F408A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242F3F18D30FD864ULL,
		0x50B0606CD67CAF8FULL,
		0x4F9D0C21D72A658CULL,
		0x571069BB33E81151ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x46871018FEC5B078ULL,
		0x435954AD3B77C49AULL,
		0x810AB57B760513EBULL,
		0x16DF42996C539BD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D0E2031FD8B60F0ULL,
		0x86B2A95A76EF8934ULL,
		0x02156AF6EC0A27D6ULL,
		0x2DBE8532D8A737ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9354B70794899354ULL,
		0x928EF22E62FFF289ULL,
		0x59CB038536714B8EULL,
		0x60D7D4821BAD24BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26A96E0F291326BBULL,
		0x251DE45CC5FFE513ULL,
		0xB396070A6CE2971DULL,
		0x41AFA904375A4974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x112B4F00B526DB4BULL,
		0xA429683DDD560BB6ULL,
		0x5DE0C8E2A75F344FULL,
		0x40B0197993FC04D0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22569E016A4DB6A9ULL,
		0x4852D07BBAAC176CULL,
		0xBBC191C54EBE689FULL,
		0x016032F327F809A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2021460686E80F78ULL,
		0xCC301AA4E8D0B5C1ULL,
		0x09F1267371851F55ULL,
		0x52987302F25DBF6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40428C0D0DD01F03ULL,
		0x98603549D1A16B82ULL,
		0x13E24CE6E30A3EABULL,
		0x2530E605E4BB7ED6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE9B2E0BBC3B41E0ULL,
		0x36EEAB586ADBAD50ULL,
		0x802A579F7FAB8EDFULL,
		0x5077A35630B3AE59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD365C17787683D3ULL,
		0x6DDD56B0D5B75AA1ULL,
		0x0054AF3EFF571DBEULL,
		0x20EF46AC61675CB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57EE8FD0301766C4ULL,
		0x3D0C2F771F880692ULL,
		0x00D1C7B5416D3A5FULL,
		0x240F5BC62BFCCC0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFDD1FA0602ECD88ULL,
		0x7A185EEE3F100D24ULL,
		0x01A38F6A82DA74BEULL,
		0x481EB78C57F99818ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15ED0A2D269F8085ULL,
		0x34A0E8F3544A2AE7ULL,
		0x249204D69B28081FULL,
		0x5555855318A3A691ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BDA145A4D3F011DULL,
		0x6941D1E6A89455CEULL,
		0x492409AD3650103EULL,
		0x2AAB0AA631474D22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30A22917FEE97FD8ULL,
		0x5B8B345247DAFEB3ULL,
		0xF33849DC687DD7ABULL,
		0x05494C11796E8BD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6144522FFDD2FFB0ULL,
		0xB71668A48FB5FD66ULL,
		0xE67093B8D0FBAF56ULL,
		0x0A929822F2DD17B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x429C80A663BB5554ULL,
		0xEA2EE27595E6995FULL,
		0xABE73530AD03901FULL,
		0x625389AC15371FE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8539014CC776AABBULL,
		0xD45DC4EB2BCD32BEULL,
		0x57CE6A615A07203FULL,
		0x44A713582A6E3FCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BE123F6BCDF9E3FULL,
		0x6987305EFB9D13CAULL,
		0x26B38D113833D7C5ULL,
		0x1931C0AA78BF7EF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C247ED79BF3C7EULL,
		0xD30E60BDF73A2795ULL,
		0x4D671A227067AF8AULL,
		0x32638154F17EFDEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x517A1172C0284B36ULL,
		0xF0CE49EC61FFABE7ULL,
		0x43A3E3CF893ED82BULL,
		0x0F02B756E0A66AC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F422E58050966CULL,
		0xE19C93D8C3FF57CEULL,
		0x8747C79F127DB057ULL,
		0x1E056EADC14CD592ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEDD299321F58D346ULL,
		0xF7BD900BE876F190ULL,
		0x8234763756F5561EULL,
		0x60CDF15EEE6C62ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBA532643EB1A69FULL,
		0xEF7B2017D0EDE321ULL,
		0x0468EC6EADEAAC3DULL,
		0x419BE2BDDCD8C557ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2754229DA820D269ULL,
		0xC88BF96406A3BE74ULL,
		0x37818F68A71CE283ULL,
		0x7AC7C90D5AB1454BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA8453B5041A4E5ULL,
		0x9117F2C80D477CE8ULL,
		0x6F031ED14E39C507ULL,
		0x758F921AB5628A96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B8CD7915B337C0ULL,
		0x11AA242692AF30DDULL,
		0x3F9FC55F90984A55ULL,
		0x6C1D015B87CF4EE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3719AF22B666F93ULL,
		0x2354484D255E61BAULL,
		0x7F3F8ABF213094AAULL,
		0x583A02B70F9E9DCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56BF50FC7B738A56ULL,
		0x3A7A752176D26A11ULL,
		0xAC92BC6FDD3C2941ULL,
		0x21A456C9023B245EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD7EA1F8F6E714ACULL,
		0x74F4EA42EDA4D422ULL,
		0x592578DFBA785282ULL,
		0x4348AD92047648BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x043261A08C39E937ULL,
		0x4D241926B7EB2C8BULL,
		0x2391749CE6E62C9FULL,
		0x50CDE8209516AC8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0864C3411873D281ULL,
		0x9A48324D6FD65916ULL,
		0x4722E939CDCC593EULL,
		0x219BD0412A2D5918ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x791AFBFADF1B97A7ULL,
		0x35293C23DB486E1EULL,
		0x57039A029242614BULL,
		0x6080B5DCD50A3255ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF235F7F5BE372F61ULL,
		0x6A527847B690DC3CULL,
		0xAE0734052484C296ULL,
		0x41016BB9AA1464AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x613AC23031858A11ULL,
		0x5425FE4912F0E94BULL,
		0xCB1109F5ED894CC9ULL,
		0x50BA060EBD8C35CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2758460630B1435ULL,
		0xA84BFC9225E1D296ULL,
		0x962213EBDB129992ULL,
		0x21740C1D7B186B97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FC0371F7CCE1DF5ULL,
		0xB09D889D76E8997EULL,
		0x62544824A93EACE6ULL,
		0x6B8626BE09770FB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F806E3EF99C3BFDULL,
		0x613B113AEDD132FCULL,
		0xC4A89049527D59CDULL,
		0x570C4D7C12EE1F72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x366C7D42A3CB59C6ULL,
		0x2537543234614B70ULL,
		0xC85694636B85C0A5ULL,
		0x10F376CFB3BEC1C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CD8FA854796B38CULL,
		0x4A6EA86468C296E0ULL,
		0x90AD28C6D70B814AULL,
		0x21E6ED9F677D838BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x994B50CACBE26549ULL,
		0x40FB15742C5C62ECULL,
		0x6BB561E4848845F2ULL,
		0x04503099872E5659ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3296A19597C4CA92ULL,
		0x81F62AE858B8C5D9ULL,
		0xD76AC3C909108BE4ULL,
		0x08A061330E5CACB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x890F9CBDFF7ADA25ULL,
		0x0E63934395A33771ULL,
		0x1D4B1F76E073FF00ULL,
		0x645EBC88F16A5693ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121F397BFEF5B45DULL,
		0x1CC726872B466EE3ULL,
		0x3A963EEDC0E7FE00ULL,
		0x48BD7911E2D4AD26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x52674E9403C2BB5AULL,
		0xFA99BD042D80FF96ULL,
		0xB5E9977CD264D4FAULL,
		0x0EE71F6A108D2DECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4CE9D28078576B4ULL,
		0xF5337A085B01FF2CULL,
		0x6BD32EF9A4C9A9F5ULL,
		0x1DCE3ED4211A5BD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C72A1D46A9765B6ULL,
		0x61AF92EC4C530B12ULL,
		0xF13E8A061D7AA906ULL,
		0x224A47CC52828832ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18E543A8D52ECB6CULL,
		0xC35F25D898A61625ULL,
		0xE27D140C3AF5520CULL,
		0x44948F98A5051065ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2974E4724EB01119ULL,
		0x10E169F1A1279148ULL,
		0xBB88E17C9A2F6A1FULL,
		0x65D23F6B09D7F517ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E9C8E49D602245ULL,
		0x21C2D3E3424F2290ULL,
		0x7711C2F9345ED43EULL,
		0x4BA47ED613AFEA2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7F9497C6399E1605ULL,
		0xA9BF10EDBE4403CDULL,
		0xA5E49611D401C6BDULL,
		0x67959A3E16A56548ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF292F8C733C2C1DULL,
		0x537E21DB7C88079AULL,
		0x4BC92C23A8038D7BULL,
		0x4F2B347C2D4ACA91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB27693C4BEDA9777ULL,
		0x938C2C6800596507ULL,
		0x272910E84BBAEA86ULL,
		0x056A150B1831F362ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64ED27897DB52EEEULL,
		0x271858D000B2CA0FULL,
		0x4E5221D09775D50DULL,
		0x0AD42A163063E6C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4ACF09163A012081ULL,
		0x1780D26E4CA5A47FULL,
		0x8845A1B20A3EA849ULL,
		0x0408E69F192BB93CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959E122C74024102ULL,
		0x2F01A4DC994B48FEULL,
		0x108B4364147D5092ULL,
		0x0811CD3E32577279ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC821A31EB176FD58ULL,
		0x4B2284E23CD14457ULL,
		0x4DDD953948671A7FULL,
		0x3F03E9568C968E09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9043463D62EDFAB0ULL,
		0x964509C479A288AFULL,
		0x9BBB2A7290CE34FEULL,
		0x7E07D2AD192D1C12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8504EFF54B300DFULL,
		0x4589171E5EBBC7DCULL,
		0x608130DB1D82ED0EULL,
		0x1B03171669CA3146ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90A09DFEA96601BEULL,
		0x8B122E3CBD778FB9ULL,
		0xC10261B63B05DA1CULL,
		0x36062E2CD394628CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70D3D857BC7898E9ULL,
		0xFE33E94B884DE045ULL,
		0xEBC79F829538867CULL,
		0x2C61430FF411D922ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1A7B0AF78F131D2ULL,
		0xFC67D297109BC08AULL,
		0xD78F3F052A710CF9ULL,
		0x58C2861FE823B245ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A709E4AE50A399EULL,
		0xFCD0F7564F878B08ULL,
		0xF400CA4AB322EB86ULL,
		0x6AE43EF68EB4053EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E13C95CA14734FULL,
		0xF9A1EEAC9F0F1610ULL,
		0xE80194956645D70DULL,
		0x55C87DED1D680A7DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2A5680FA3306BE20ULL,
		0x73ACE0BEB79F5E7FULL,
		0x1BB06E62AF06D3CDULL,
		0x15D39D4085F7FC06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54AD01F4660D7C40ULL,
		0xE759C17D6F3EBCFEULL,
		0x3760DCC55E0DA79AULL,
		0x2BA73A810BEFF80CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x241BD9B8695CE1EEULL,
		0x2A424C405519F134ULL,
		0xA83FEE781705C917ULL,
		0x4DB3FDC4A5841B8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4837B370D2B9C3EFULL,
		0x54849880AA33E268ULL,
		0x507FDCF02E0B922EULL,
		0x1B67FB894B083717ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA930A95E659356F4ULL,
		0x8D91E95E7BB0F8E2ULL,
		0xC9157D3F94F0B27FULL,
		0x032D35E835329B0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x526152BCCB26ADE8ULL,
		0x1B23D2BCF761F1C5ULL,
		0x922AFA7F29E164FFULL,
		0x065A6BD06A65361BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8988C15790BD7CC0ULL,
		0x3F6E701D17F94A78ULL,
		0x50FA3026BE411F6BULL,
		0x269FF2EDFE432E66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x131182AF217AF980ULL,
		0x7EDCE03A2FF294F1ULL,
		0xA1F4604D7C823ED6ULL,
		0x4D3FE5DBFC865CCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF37CCCA79DD56C18ULL,
		0x047AAE5456818BF5ULL,
		0x516FE9E9D4BD3E86ULL,
		0x6401EE0D64E396A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6F9994F3BAAD843ULL,
		0x08F55CA8AD0317EBULL,
		0xA2DFD3D3A97A7D0CULL,
		0x4803DC1AC9C72D44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC93F8CED26914BCULL,
		0xFB2CE9A15AD2BF0CULL,
		0x4341A27A9F3B09E7ULL,
		0x1E4773ADC59F2CF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB927F19DA4D22978ULL,
		0xF659D342B5A57E19ULL,
		0x868344F53E7613CFULL,
		0x3C8EE75B8B3E59E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B7810248EE30D66ULL,
		0x41A655160447977DULL,
		0x746404A1F009871BULL,
		0x7E269F0270BEBEA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F020491DC61ADFULL,
		0x834CAA2C088F2EFAULL,
		0xE8C80943E0130E36ULL,
		0x7C4D3E04E17D7D4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AF12D4E4D1CAA90ULL,
		0xB44079E01937A78CULL,
		0x6304A29CD0F6BDCFULL,
		0x2FECD5D12241A5FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E25A9C9A395520ULL,
		0x6880F3C0326F4F18ULL,
		0xC6094539A1ED7B9FULL,
		0x5FD9ABA244834BFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99B7D4866D695E33ULL,
		0x048C597DA416DD7AULL,
		0x1ABEF8138680CCA9ULL,
		0x76AB350B1D8C789FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x336FA90CDAD2BC79ULL,
		0x0918B2FB482DBAF5ULL,
		0x357DF0270D019952ULL,
		0x6D566A163B18F13EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2066E16D3F4BCB5EULL,
		0x077977D8FF3A5669ULL,
		0x4DA1277DF845A71CULL,
		0x69796ECBA5EA33ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40CDC2DA7E9796CFULL,
		0x0EF2EFB1FE74ACD2ULL,
		0x9B424EFBF08B4E38ULL,
		0x52F2DD974BD46756ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6C37E8566BB7AE4EULL,
		0x453AD55C866CC7D1ULL,
		0xFAFE6FAA42E1C54BULL,
		0x3C894DB59DF89115ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86FD0ACD76F5C9CULL,
		0x8A75AAB90CD98FA2ULL,
		0xF5FCDF5485C38A96ULL,
		0x79129B6B3BF1222BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E65D676FFF4C76EULL,
		0x5F766564AAE9FC80ULL,
		0x274A114ABBC699E4ULL,
		0x51872252960FB2D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CCBACEDFFE98EEFULL,
		0xBEECCAC955D3F900ULL,
		0x4E942295778D33C8ULL,
		0x230E44A52C1F65B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DE8726E2AE8DB5BULL,
		0x9F938CEEBD31283AULL,
		0xCA754EE5EEB8B4DFULL,
		0x123FEDF4FC6E7818ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD0E4DC55D1B6B6ULL,
		0x3F2719DD7A625075ULL,
		0x94EA9DCBDD7169BFULL,
		0x247FDBE9F8DCF031ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x225C8E3A5339D2CFULL,
		0x2ACD5B61EA728024ULL,
		0xD171C107C85486CEULL,
		0x58BC7A48544CD176ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44B91C74A673A5B1ULL,
		0x559AB6C3D4E50048ULL,
		0xA2E3820F90A90D9CULL,
		0x3178F490A899A2EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E5AB6EAB445D29EULL,
		0xCA8D0A095415A49AULL,
		0x8A02711EA24607F3ULL,
		0x2908BE955C505DB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB56DD5688BA53CULL,
		0x951A1412A82B4934ULL,
		0x1404E23D448C0FE7ULL,
		0x52117D2AB8A0BB6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF76381E04B584CFEULL,
		0xBD71ABFB41CC58B9ULL,
		0x72D5AF3242472895ULL,
		0x5DCA935780E2A63AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEC703C096B09A0FULL,
		0x7AE357F68398B173ULL,
		0xE5AB5E64848E512BULL,
		0x3B9526AF01C54C74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA37277A36353DEAULL,
		0x1B072F587CA8AABEULL,
		0xD99E230642A347AFULL,
		0x208C56D95B8DFAE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB46E4EF46C6A7BD4ULL,
		0x360E5EB0F951557DULL,
		0xB33C460C85468F5EULL,
		0x4118ADB2B71BF5C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCC005A77E206720ULL,
		0xD0B38052722FC5D0ULL,
		0x2EAC8E1C6B473687ULL,
		0x13709C78F3B25CBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79800B4EFC40CE40ULL,
		0xA16700A4E45F8BA1ULL,
		0x5D591C38D68E6D0FULL,
		0x26E138F1E764B974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x28EA07DC8826424CULL,
		0xDEFF6E52B553AE11ULL,
		0x9E699D4D9679A733ULL,
		0x1DBB6EC98841D21AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51D40FB9104C8498ULL,
		0xBDFEDCA56AA75C22ULL,
		0x3CD33A9B2CF34E67ULL,
		0x3B76DD931083A435ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37B483297E7DCADEULL,
		0xD4CFC3AF5E0F225FULL,
		0xEB56046133FF06B8ULL,
		0x4D5ACDC085BD4DCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F690652FCFB95CFULL,
		0xA99F875EBC1E44BEULL,
		0xD6AC08C267FE0D71ULL,
		0x1AB59B810B7A9B99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CADD2D31FC60AFDULL,
		0x8B33E2E8554907DFULL,
		0x9D1B9598191003BDULL,
		0x5D2423B1C71F61F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x595BA5A63F8C160DULL,
		0x1667C5D0AA920FBEULL,
		0x3A372B303220077BULL,
		0x3A4847638E3EC3F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEACFA3394FEC8AB0ULL,
		0x6776A3B96CF55D3DULL,
		0x3481B9F4C4E4447AULL,
		0x06B124B468D7D330ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD59F46729FD91560ULL,
		0xCEED4772D9EABA7BULL,
		0x690373E989C888F4ULL,
		0x0D624968D1AFA660ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x300472E1951DCEC9ULL,
		0xE434FB024437C496ULL,
		0xA5A54D2806AB3BF3ULL,
		0x2FEFFECABF979605ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6008E5C32A3B9D92ULL,
		0xC869F604886F892CULL,
		0x4B4A9A500D5677E7ULL,
		0x5FDFFD957F2F2C0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x812BBDAC3CE7451FULL,
		0x32FC11486727946DULL,
		0xA267377F7CE3324DULL,
		0x18F49C8301881C4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02577B5879CE8A3EULL,
		0x65F82290CE4F28DBULL,
		0x44CE6EFEF9C6649AULL,
		0x31E939060310389BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FB09A03E8C020DEULL,
		0xA2522C8962AF66D9ULL,
		0xD5E28C064684435DULL,
		0x14004B217C93C64CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F613407D18041BCULL,
		0x44A45912C55ECDB2ULL,
		0xABC5180C8D0886BBULL,
		0x28009642F9278C99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x40E364676247C273ULL,
		0x848FA0E72F986CBDULL,
		0x9A05554ACCAFA5B1ULL,
		0x0934B1DC14E7BB3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81C6C8CEC48F84E6ULL,
		0x091F41CE5F30D97AULL,
		0x340AAA95995F4B63ULL,
		0x126963B829CF767FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15A51D5205A64614ULL,
		0xC03C4EA20A3B83D2ULL,
		0x8EDD9847198A387DULL,
		0x1A898E4B9E549D68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4A3AA40B4C8C28ULL,
		0x80789D44147707A4ULL,
		0x1DBB308E331470FBULL,
		0x35131C973CA93AD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x80661C042457A899ULL,
		0xDE25863329B27247ULL,
		0xFC76E157983E9F3FULL,
		0x63C59CBCB50B2580ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00CC380848AF5145ULL,
		0xBC4B0C665364E48FULL,
		0xF8EDC2AF307D3E7FULL,
		0x478B39796A164B01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4F16DEEDF5B7F4AEULL,
		0x630D329250F79B53ULL,
		0xFACF0DF9B598FF50ULL,
		0x0BA2F47C7A2478C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E2DBDDBEB6FE95CULL,
		0xC61A6524A1EF36A6ULL,
		0xF59E1BF36B31FEA0ULL,
		0x1745E8F8F448F18DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA969222803C94E59ULL,
		0xE487BB93306D0F1AULL,
		0x06EB1DBBD0DB8CAEULL,
		0x10ABE9FCE41CB4E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D2445007929CB2ULL,
		0xC90F772660DA1E35ULL,
		0x0DD63B77A1B7195DULL,
		0x2157D3F9C83969C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x970CFAF7531751BEULL,
		0x76D9766AAA02C9AAULL,
		0x0E625A39DA3306DDULL,
		0x6F46CCFC806C5E0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E19F5EEA62EA38FULL,
		0xEDB2ECD554059355ULL,
		0x1CC4B473B4660DBAULL,
		0x5E8D99F900D8BC1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E940F109DA84611ULL,
		0x2C185D549A00D299ULL,
		0xDB57E14CF6F11CDCULL,
		0x1AE0F981C98D3E84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD281E213B508C22ULL,
		0x5830BAA93401A532ULL,
		0xB6AFC299EDE239B8ULL,
		0x35C1F303931A7D09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x378071B56EFA9F18ULL,
		0x9BE8F9D39FBD73DEULL,
		0x9E423E385F22137BULL,
		0x507C6D94B92F8B6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F00E36ADDF53E43ULL,
		0x37D1F3A73F7AE7BCULL,
		0x3C847C70BE4426F7ULL,
		0x20F8DB29725F16DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57CFEF98A54F5FE2ULL,
		0x27BFF55315711946ULL,
		0xDE2AC94BA6E82E6DULL,
		0x56E6E6E7D8BDCEADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF9FDF314A9EBFD7ULL,
		0x4F7FEAA62AE2328CULL,
		0xBC5592974DD05CDAULL,
		0x2DCDCDCFB17B9D5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD798737CEAF200FAULL,
		0x97221DA8BE75E4BFULL,
		0x92A0CDB43646F5F4ULL,
		0x475D4327134F2B80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF30E6F9D5E40207ULL,
		0x2E443B517CEBC97FULL,
		0x25419B686C8DEBE9ULL,
		0x0EBA864E269E5701ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x461B14BAB6B0AC11ULL,
		0x072724588C0D7C8BULL,
		0xA2179CAFF77775BCULL,
		0x4707A7B8D691DDD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C3629756D615835ULL,
		0x0E4E48B1181AF916ULL,
		0x442F395FEEEEEB78ULL,
		0x0E0F4F71AD23BBB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EA7C0DB7666D629ULL,
		0x428610CB0D0B8E67ULL,
		0xF20E73FDDE8DBB2EULL,
		0x5A3745638B3A38A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4F81B6ECCDAC65ULL,
		0x850C21961A171CCEULL,
		0xE41CE7FBBD1B765CULL,
		0x346E8AC716747153ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x410B1CE451CDA47EULL,
		0xB8003DE38946BEEBULL,
		0x4DCED9EFECCB982AULL,
		0x330671C5D563A3FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x821639C8A39B48FCULL,
		0x70007BC7128D7DD6ULL,
		0x9B9DB3DFD9973055ULL,
		0x660CE38BAAC747F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D16CB59ED3B8414ULL,
		0x4EA73B043FB8DAFAULL,
		0x407131AFE86204CCULL,
		0x15BC899D4F34EA5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A2D96B3DA770828ULL,
		0x9D4E76087F71B5F4ULL,
		0x80E2635FD0C40998ULL,
		0x2B79133A9E69D4B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35B6A1868F8C7A7AULL,
		0x0094F7385EBD444AULL,
		0xFD5E862E525064D1ULL,
		0x34EFF9634BD31090ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B6D430D1F18F4F4ULL,
		0x0129EE70BD7A8894ULL,
		0xFABD0C5CA4A0C9A2ULL,
		0x69DFF2C697A62121ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9757807548BF5B71ULL,
		0xCC2EAAFDFD45CBB6ULL,
		0x527A7A3C73C954AFULL,
		0x417F8076AB073477ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAF00EA917EB6F5ULL,
		0x985D55FBFA8B976DULL,
		0xA4F4F478E792A95FULL,
		0x02FF00ED560E68EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA6AFD525D962F34ULL,
		0xFA338A0918456C52ULL,
		0xB2296009B0C1C6D5ULL,
		0x298A77F380EE1ED0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94D5FAA4BB2C5E68ULL,
		0xF4671412308AD8A5ULL,
		0x6452C01361838DABULL,
		0x5314EFE701DC3DA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2C795D3039D5681ULL,
		0x4AB36B6EF4E3DDB7ULL,
		0x2F6AC790B2BB390DULL,
		0x6EE3702983741719ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658F2BA6073AAD15ULL,
		0x9566D6DDE9C7BB6FULL,
		0x5ED58F216576721AULL,
		0x5DC6E05306E82E32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39ACBE23E26550B5ULL,
		0x0674DEEFCD8A6365ULL,
		0xDEDDB95235A242F3ULL,
		0x48CB6A78E28EDFB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73597C47C4CAA17DULL,
		0x0CE9BDDF9B14C6CAULL,
		0xBDBB72A46B4485E6ULL,
		0x1196D4F1C51DBF69ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97B0D8A8BB7FDA4FULL,
		0x8AE4E61AEF1BDC43ULL,
		0x97B57498460958BCULL,
		0x1D136AE3DF7E8309ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F61B15176FFB49EULL,
		0x15C9CC35DE37B887ULL,
		0x2F6AE9308C12B179ULL,
		0x3A26D5C7BEFD0613ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23175709BB2F866EULL,
		0xCDB8E7172FA24002ULL,
		0x7CFAC44F4FE5365FULL,
		0x04AD4ADE4D2095E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462EAE13765F0CDCULL,
		0x9B71CE2E5F448004ULL,
		0xF9F5889E9FCA6CBFULL,
		0x095A95BC9A412BD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC7556E1794B578CULL,
		0x02F12A053990083DULL,
		0x0FA2704CF744C3A2ULL,
		0x64D28D2143D66646ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8EAADC2F296AF2BULL,
		0x05E2540A7320107BULL,
		0x1F44E099EE898744ULL,
		0x49A51A4287ACCC8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33C904637E97982EULL,
		0xD98691E0146D06BAULL,
		0x685A5FEB09238EFEULL,
		0x4057A8637C73121BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x679208C6FD2F306FULL,
		0xB30D23C028DA0D74ULL,
		0xD0B4BFD612471DFDULL,
		0x00AF50C6F8E62436ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF440EFE786274CULL,
		0x554027CE179CC363ULL,
		0x44E63A634C8C14DFULL,
		0x1E0320D64C7CB2D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E881DFCF0C4E98ULL,
		0xAA804F9C2F3986C7ULL,
		0x89CC74C6991829BEULL,
		0x3C0641AC98F965A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E706D1863CFD9E3ULL,
		0xD62360598506496DULL,
		0x7FC6E50FB3660694ULL,
		0x239C0F4C108421DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE0DA30C79FB3C6ULL,
		0xAC46C0B30A0C92DBULL,
		0xFF8DCA1F66CC0D29ULL,
		0x47381E98210843BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B6365AEFC6D4A59ULL,
		0xB0EAB7586699A246ULL,
		0xE644D5399AAC26C1ULL,
		0x520FB680B6FF54D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76C6CB5DF8DA94C5ULL,
		0x61D56EB0CD33448CULL,
		0xCC89AA7335584D83ULL,
		0x241F6D016DFEA9ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E57F2CD633FCC12ULL,
		0xC65AEFB27A6CD6B0ULL,
		0x931A03928FC4C8DEULL,
		0x29BC63F9654AAC87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCAFE59AC67F9824ULL,
		0x8CB5DF64F4D9AD60ULL,
		0x263407251F8991BDULL,
		0x5378C7F2CA95590FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A0A7C1794DEE8FAULL,
		0x8AECEF36E5F085EFULL,
		0xF77A9FB01407EA97ULL,
		0x32BDC3ACAD062396ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1414F82F29BDD1F4ULL,
		0x15D9DE6DCBE10BDFULL,
		0xEEF53F60280FD52FULL,
		0x657B87595A0C472DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82422A53DAF125D4ULL,
		0xDEE9B3D899EE004BULL,
		0x32FF41A543231A9EULL,
		0x231EA4039FFEB513ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x048454A7B5E24BA8ULL,
		0xBDD367B133DC0097ULL,
		0x65FE834A8646353DULL,
		0x463D48073FFD6A26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82FFC92AC4ECFFF9ULL,
		0x37D0E2F335ECCF15ULL,
		0x911A004EEFFCFC60ULL,
		0x41DA63A474262271ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05FF925589DA0005ULL,
		0x6FA1C5E66BD99E2BULL,
		0x2234009DDFF9F8C0ULL,
		0x03B4C748E84C44E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E81568BC8F39F95ULL,
		0x6843D271E79D29D1ULL,
		0x6FDE32F9C2B2C3AFULL,
		0x7EAA234D626BA69AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D02AD1791E73F3DULL,
		0xD087A4E3CF3A53A2ULL,
		0xDFBC65F38565875EULL,
		0x7D54469AC4D74D34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2B60BFD6DFDD7775ULL,
		0x59046EF913C03ADBULL,
		0x53935FB32CB9831CULL,
		0x1EBA53E3C2C6B062ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C17FADBFBAEEEAULL,
		0xB208DDF2278075B6ULL,
		0xA726BF6659730638ULL,
		0x3D74A7C7858D60C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B844C282650AF47ULL,
		0x21547AA6C467687FULL,
		0xA7454A485080CEC6ULL,
		0x6E2B3FF48755EBD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x770898504CA15EA1ULL,
		0x42A8F54D88CED0FEULL,
		0x4E8A9490A1019D8CULL,
		0x5C567FE90EABD7B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97D202FFA44B70B7ULL,
		0xC0359488B582A1DCULL,
		0xAB2B39D3A743C2E9ULL,
		0x33C459BF7537E04FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA405FF4896E16EULL,
		0x806B29116B0543B9ULL,
		0x565673A74E8785D3ULL,
		0x6788B37EEA6FC09FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4FED890D1D1649EULL,
		0x46A27B2AE012CE0FULL,
		0xF1783ACD36DDD05EULL,
		0x4898D9832B8E11D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89FDB121A3A2C94FULL,
		0x8D44F655C0259C1FULL,
		0xE2F0759A6DBBA0BCULL,
		0x1131B306571C23ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x34C2A60CB353F86DULL,
		0xFBB8619BFB22B1EEULL,
		0xF4831A30F0A6AE50ULL,
		0x0B10CF2B0F18DBBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69854C1966A7F0DAULL,
		0xF770C337F64563DCULL,
		0xE9063461E14D5CA1ULL,
		0x16219E561E31B77FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC4E6ECE296DDFFFULL,
		0x1D6AE79C7DB57A11ULL,
		0x5CE7CACEAA86A7BFULL,
		0x0D81E01E7B20EDF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB89CDD9C52DBBFFEULL,
		0x3AD5CF38FB6AF423ULL,
		0xB9CF959D550D4F7EULL,
		0x1B03C03CF641DBE8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53AD2446B7B519BBULL,
		0xA6B0B09311F5E29EULL,
		0xCEBA4B8E05CBF089ULL,
		0x58C96958DF7D3441ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA75A488D6F6A3389ULL,
		0x4D61612623EBC53CULL,
		0x9D74971C0B97E113ULL,
		0x3192D2B1BEFA6883ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB602EB004554E12ULL,
		0x6F0C6E8427EA0BE3ULL,
		0x81F15AA08C8DD7C7ULL,
		0x7A2BB68AE1F20CFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56C05D6008AA9C37ULL,
		0xDE18DD084FD417C7ULL,
		0x03E2B541191BAF8EULL,
		0x74576D15C3E419FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63FC83E0DE095569ULL,
		0x76799D3ABB8A930FULL,
		0x1994A1FB062E27A8ULL,
		0x2FE06F957E922421ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F907C1BC12AAD2ULL,
		0xECF33A757715261EULL,
		0x332943F60C5C4F50ULL,
		0x5FC0DF2AFD244842ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA08D5C3985939792ULL,
		0xC0ABA94CB76BAD4BULL,
		0xD7FC42190E5A94C2ULL,
		0x0119318FD4124617ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x411AB8730B272F24ULL,
		0x815752996ED75A97ULL,
		0xAFF884321CB52985ULL,
		0x0232631FA8248C2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB03BD2911ECF5276ULL,
		0x95CC491D962C5FE3ULL,
		0x2D5C5443A3C63529ULL,
		0x5E94F2051D39A32CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6077A5223D9EA4FFULL,
		0x2B98923B2C58BFC7ULL,
		0x5AB8A887478C6A53ULL,
		0x3D29E40A3A734658ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EEE9E29D521F617ULL,
		0xA69F03F961D6BD63ULL,
		0xF4B24BED289823DFULL,
		0x7C7E5F4164E12C63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDD3C53AA43EC41ULL,
		0x4D3E07F2C3AD7AC6ULL,
		0xE96497DA513047BFULL,
		0x78FCBE82C9C258C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5C9B9A4E979DA3BULL,
		0xA6E52816076C899BULL,
		0xBCF7CBB414C87C11ULL,
		0x06C642A60FBB10B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B937349D2F3B476ULL,
		0x4DCA502C0ED91337ULL,
		0x79EF97682990F823ULL,
		0x0D8C854C1F762163ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9EEDB48ED9DB29C3ULL,
		0x03857B9C9DFCA69CULL,
		0xA4DA29BC48D263D1ULL,
		0x03BCC6108FC1F55AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DDB691DB3B65386ULL,
		0x070AF7393BF94D39ULL,
		0x49B4537891A4C7A2ULL,
		0x07798C211F83EAB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3ECF8D985367D3C4ULL,
		0x0A25D74AD5C8AE47ULL,
		0x6B678C2E0F44B8FCULL,
		0x624490F1E38777ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D9F1B30A6CFA79BULL,
		0x144BAE95AB915C8EULL,
		0xD6CF185C1E8971F8ULL,
		0x448921E3C70EEFD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4B51263E92DA842DULL,
		0x6370C47926CEFFE3ULL,
		0x41E0E84F9A7C9163ULL,
		0x2B45096A83FA7AA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96A24C7D25B5085AULL,
		0xC6E188F24D9DFFC6ULL,
		0x83C1D09F34F922C6ULL,
		0x568A12D507F4F542ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AAE23748CC75371ULL,
		0x768F583DE8F0B3BAULL,
		0x967A612C9DF1CB60ULL,
		0x1213FAFA92C5DE7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955C46E9198EA6E2ULL,
		0xED1EB07BD1E16774ULL,
		0x2CF4C2593BE396C0ULL,
		0x2427F5F5258BBCF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C491DEF547180FBULL,
		0x6CEBD77C8B05B068ULL,
		0x784F028BFEE23C2CULL,
		0x0D75DF3EA2A9CA5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38923BDEA8E301F6ULL,
		0xD9D7AEF9160B60D1ULL,
		0xF09E0517FDC47858ULL,
		0x1AEBBE7D455394BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8695AF3CF88F686CULL,
		0x43BBC476A0D42055ULL,
		0x6AEFD63D1A65608BULL,
		0x23F900B4E52A0071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D2B5E79F11ED0D8ULL,
		0x877788ED41A840ABULL,
		0xD5DFAC7A34CAC116ULL,
		0x47F20169CA5400E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x74779F17BBF87C02ULL,
		0x983A184E8913086FULL,
		0x5B0F4DF8AD787E3BULL,
		0x49CD6DB7D265BB3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8EF3E2F77F0F817ULL,
		0x3074309D122610DEULL,
		0xB61E9BF15AF0FC77ULL,
		0x139ADB6FA4CB7674ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4FB73F085ADB89CDULL,
		0x8376231CB1974EB0ULL,
		0x77E520EE2FE3CF93ULL,
		0x192BC1913AA868B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F6E7E10B5B7139AULL,
		0x06EC4639632E9D60ULL,
		0xEFCA41DC5FC79F27ULL,
		0x325783227550D16CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x88AA8299DD8363E4ULL,
		0x03AFF3DCEF194021ULL,
		0x993059E953007561ULL,
		0x7F6D54A677006BF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11550533BB06C7DBULL,
		0x075FE7B9DE328043ULL,
		0x3260B3D2A600EAC2ULL,
		0x7EDAA94CEE00D7EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF701AA64B8941B5ULL,
		0x8EC2FEBDCC6D7FDAULL,
		0xF513C1903ED07105ULL,
		0x131C1531EDA46111ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEE0354C9712836AULL,
		0x1D85FD7B98DAFFB5ULL,
		0xEA2783207DA0E20BULL,
		0x26382A63DB48C223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E0794524B13EF0DULL,
		0xA6F22E8ADD8A8209ULL,
		0x86491D052F32E426ULL,
		0x2621F16CEA013BF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0F28A49627DE1AULL,
		0x4DE45D15BB150412ULL,
		0x0C923A0A5E65C84DULL,
		0x4C43E2D9D40277E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81EBE728E5E61B24ULL,
		0x24D6FF99C19D6525ULL,
		0x0F46116BAD415BB1ULL,
		0x1833655B52BDEE3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03D7CE51CBCC3648ULL,
		0x49ADFF33833ACA4BULL,
		0x1E8C22D75A82B762ULL,
		0x3066CAB6A57BDC74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB0E311EB304473CULL,
		0xFC2A7D96E3766CF4ULL,
		0x0C32D047492CDBCDULL,
		0x21DFFB994AC3FEBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x561C623D66088E78ULL,
		0xF854FB2DC6ECD9E9ULL,
		0x1865A08E9259B79BULL,
		0x43BFF7329587FD7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x798176E671EAE015ULL,
		0x610FCE5C57C1BE11ULL,
		0xDBDC829D6811B481ULL,
		0x601E9342CC6E8393ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF302EDCCE3D5C03DULL,
		0xC21F9CB8AF837C22ULL,
		0xB7B9053AD0236902ULL,
		0x403D268598DD0727ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F4EF13E95999E1BULL,
		0x4BF40017023C4068ULL,
		0x0D2B0C3CE2798C60ULL,
		0x47216D7ED3629EEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E9DE27D2B333C49ULL,
		0x97E8002E047880D1ULL,
		0x1A561879C4F318C0ULL,
		0x0E42DAFDA6C53DDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x427EA9E0C51625C9ULL,
		0xCDE7CA209823B0D9ULL,
		0x4FD089538CFB23A5ULL,
		0x5DC67A177EDF378AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FD53C18A2C4BA5ULL,
		0x9BCF9441304761B2ULL,
		0x9FA112A719F6474BULL,
		0x3B8CF42EFDBE6F14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BDD0E84CC9F9D09ULL,
		0x18624D885ABE749AULL,
		0x99E305A10F31296BULL,
		0x33FFFD6D3DD00A12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77BA1D09993F3A12ULL,
		0x30C49B10B57CE934ULL,
		0x33C60B421E6252D6ULL,
		0x67FFFADA7BA01425ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD2477F26B4E9912ULL,
		0xDF2178A9C9ADDAF3ULL,
		0xDE6BF9D8D7024095ULL,
		0x57E5ED851055F9C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A48EFE4D69D3237ULL,
		0xBE42F153935BB5E7ULL,
		0xBCD7F3B1AE04812BULL,
		0x2FCBDB0A20ABF393ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19C65329DBAF0C5BULL,
		0xE45F117206B63B29ULL,
		0x3D49E07114A48685ULL,
		0x5AC639C9DEBC276EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x338CA653B75E18C9ULL,
		0xC8BE22E40D6C7652ULL,
		0x7A93C0E229490D0BULL,
		0x358C7393BD784EDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x905F89CE89187CF1ULL,
		0x16E8B2737AF1B390ULL,
		0x22A6E47AEA38DC78ULL,
		0x130AEE326589E29CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20BF139D1230F9E2ULL,
		0x2DD164E6F5E36721ULL,
		0x454DC8F5D471B8F0ULL,
		0x2615DC64CB13C538ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA587C3CC1EE297B2ULL,
		0x4D33F83184800C9AULL,
		0x9C56DD4477C2B928ULL,
		0x7F75573A84E2A36EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B0F87983DC52F77ULL,
		0x9A67F06309001935ULL,
		0x38ADBA88EF857250ULL,
		0x7EEAAE7509C546DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49FD3F78029965A5ULL,
		0xEBD7355B5435963FULL,
		0x080AA7A031899EF3ULL,
		0x04E8C6C89C493650ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93FA7EF00532CB4AULL,
		0xD7AE6AB6A86B2C7EULL,
		0x10154F4063133DE7ULL,
		0x09D18D9138926CA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E45A01AE10ADF50ULL,
		0x1EA4D0A7F6CB9EB1ULL,
		0x40ED495022B482A8ULL,
		0x51768EBD17197F72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8B4035C215BEB3ULL,
		0x3D49A14FED973D62ULL,
		0x81DA92A045690550ULL,
		0x22ED1D7A2E32FEE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33B5A56381EE8A50ULL,
		0x7DE8329F00173CD0ULL,
		0x86D8B1CA7D871D78ULL,
		0x1912F77038B8D121ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x676B4AC703DD14A0ULL,
		0xFBD0653E002E79A0ULL,
		0x0DB16394FB0E3AF0ULL,
		0x3225EEE07171A243ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF89D5CBB8835BB5ULL,
		0x7A3335954D8649D6ULL,
		0x196D10024C392A5EULL,
		0x2E8EC84D36FFEF8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F13AB977106B76AULL,
		0xF4666B2A9B0C93ADULL,
		0x32DA2004987254BCULL,
		0x5D1D909A6DFFDF16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2AC493210502A39DULL,
		0xF7C0772A49A30664ULL,
		0xA5C8855A49FB4B58ULL,
		0x54F41CB10CE47CAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x558926420A05474DULL,
		0xEF80EE5493460CC8ULL,
		0x4B910AB493F696B1ULL,
		0x29E8396219C8F955ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BC03AFFBC5B609CULL,
		0xB24D6C7431200E57ULL,
		0x8EDAA30BDAF5B834ULL,
		0x479DCC3554A38F6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x378075FF78B6C14BULL,
		0x649AD8E862401CAEULL,
		0x1DB54617B5EB7069ULL,
		0x0F3B986AA9471EDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06F98407F7ABE111ULL,
		0x59D3EB5D2CB29EC4ULL,
		0xB6A38824E9B26211ULL,
		0x46DEF2743B542720ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DF3080FEF57C235ULL,
		0xB3A7D6BA59653D88ULL,
		0x6D471049D364C422ULL,
		0x0DBDE4E876A84E41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC9612DD7F3E8D24ULL,
		0xA4605774362CB0D2ULL,
		0xEDCFD1481B6E72FDULL,
		0x0A70C47D0C70E7E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD92C25BAFE7D1A48ULL,
		0x48C0AEE86C5961A5ULL,
		0xDB9FA29036DCE5FBULL,
		0x14E188FA18E1CFC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDEDBBC53DB82A696ULL,
		0xA2CBB113549C1ACAULL,
		0x269A370CD9008DCDULL,
		0x6B5F48D6001C36F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB778A7B7054D3FULL,
		0x45976226A9383595ULL,
		0x4D346E19B2011B9BULL,
		0x56BE91AC00386DE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE7212D88145CFAAULL,
		0x17E8EF00C554FD07ULL,
		0x889984FDBB93202DULL,
		0x4C73D8114B2418E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CE425B1028B9F67ULL,
		0x2FD1DE018AA9FA0FULL,
		0x113309FB7726405AULL,
		0x18E7B022964831C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x853DD51DD9C0C94AULL,
		0x8D0CFA6F73A18ADDULL,
		0xC7A91C9C37E36B0EULL,
		0x455171DB84DCE271ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A7BAA3BB38192A7ULL,
		0x1A19F4DEE74315BBULL,
		0x8F5239386FC6D61DULL,
		0x0AA2E3B709B9C4E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93CD71EA6D34E89FULL,
		0x2108A316A3028585ULL,
		0xC99A87185F1E0E00ULL,
		0x3C6ECD3119517F84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x279AE3D4DA69D13EULL,
		0x4211462D46050B0BULL,
		0x93350E30BE3C1C00ULL,
		0x78DD9A6232A2FF09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBDBFBB689EDE2818ULL,
		0x6F778C904FC9E8DFULL,
		0x9CB84EB39A8BA904ULL,
		0x35D09A5EDAB1ED64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7F76D13DBC5030ULL,
		0xDEEF19209F93D1BFULL,
		0x39709D6735175208ULL,
		0x6BA134BDB563DAC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7935B552CB5371D0ULL,
		0x31EC63EE24B845CFULL,
		0x1D83F3C89F054CEEULL,
		0x513B1A9FA9AC19A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF26B6AA596A6E3B3ULL,
		0x63D8C7DC49708B9EULL,
		0x3B07E7913E0A99DCULL,
		0x2276353F53583346ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AD514B85283EF46ULL,
		0x98C983F1587FAA84ULL,
		0xF9B21C8756584DC2ULL,
		0x515961FBE0A72295ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75AA2970A507DE9FULL,
		0x319307E2B0FF5508ULL,
		0xF364390EACB09B85ULL,
		0x22B2C3F7C14E452BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6B34F6550DEC727ULL,
		0x83A5B189B6F2AB73ULL,
		0x6A66D59FB96BF14CULL,
		0x3B960E2CEE743BCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED669ECAA1BD8E4EULL,
		0x074B63136DE556E7ULL,
		0xD4CDAB3F72D7E299ULL,
		0x772C1C59DCE87798ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA098C027F79EB99FULL,
		0x813817950AFDC8AAULL,
		0x9FA1BC876C482A04ULL,
		0x6F4ECAF77D09494CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4131804FEF3D7351ULL,
		0x02702F2A15FB9155ULL,
		0x3F43790ED8905409ULL,
		0x5E9D95EEFA129299ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC28A8B1AFEE15BD5ULL,
		0x537FC5E48A1C2BE1ULL,
		0x2D1074D4667FF545ULL,
		0x3C601BC54B609685ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85151635FDC2B7AAULL,
		0xA6FF8BC9143857C3ULL,
		0x5A20E9A8CCFFEA8AULL,
		0x78C0378A96C12D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4F00959C76FFA9FULL,
		0x36F456C153F5D9BEULL,
		0x8BB44DA5F3689F18ULL,
		0x2E46E2447FDCFB8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E012B38EDFF53EULL,
		0x6DE8AD82A7EBB37DULL,
		0x17689B4BE6D13E30ULL,
		0x5C8DC488FFB9F71BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF8064F91AB213F68ULL,
		0xC4EB473ED46B69E4ULL,
		0x214C16808CAE4233ULL,
		0x4702439225EB8D73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF00C9F2356427EE3ULL,
		0x89D68E7DA8D6D3C9ULL,
		0x42982D01195C8467ULL,
		0x0E0487244BD71AE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEA8685BEC2F5E8AFULL,
		0x8E97D153B49E0C54ULL,
		0x5C70D266AC85F23AULL,
		0x641309CF3843B40AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50D0B7D85EBD171ULL,
		0x1D2FA2A7693C18A9ULL,
		0xB8E1A4CD590BE475ULL,
		0x4826139E70876814ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16903FA14946B687ULL,
		0xD4170D1A3E4E5788ULL,
		0x222094AE9F564F51ULL,
		0x3D41470A36E5F635ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D207F42928D6D0EULL,
		0xA82E1A347C9CAF10ULL,
		0x4441295D3EAC9EA3ULL,
		0x7A828E146DCBEC6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A2A1DAD9914FBCAULL,
		0xE001BCC8F7AD9024ULL,
		0x9FCD87028F867E59ULL,
		0x1DC770433B6572F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4543B5B3229F794ULL,
		0xC0037991EF5B2048ULL,
		0x3F9B0E051F0CFCB3ULL,
		0x3B8EE08676CAE5F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9FBD1870F505700ULL,
		0x0339E7D965F98290ULL,
		0x65D9B23DE236EA6BULL,
		0x3A1BD8B04BC27B55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F7A30E1EA0AE00ULL,
		0x0673CFB2CBF30521ULL,
		0xCBB3647BC46DD4D6ULL,
		0x7437B1609784F6AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9AEE8C0F4D4C87B3ULL,
		0x299C9A041874EF3AULL,
		0x47EBCD91016BF797ULL,
		0x23D584E6A444634EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35DD181E9A990F66ULL,
		0x5339340830E9DE75ULL,
		0x8FD79B2202D7EF2EULL,
		0x47AB09CD4888C69CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9BF70276F157A67ULL,
		0xEAF140DAB38DA5AEULL,
		0x6CDFC262D031F453ULL,
		0x06CA0C7979D09CDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD37EE04EDE2AF4CEULL,
		0xD5E281B5671B4B5DULL,
		0xD9BF84C5A063E8A7ULL,
		0x0D9418F2F3A139B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x375D329C3D7F8585ULL,
		0x86098016D8A1710FULL,
		0xCFAB72842694AD2CULL,
		0x305F77248A68FFAAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EBA65387AFF0B0AULL,
		0x0C13002DB142E21EULL,
		0x9F56E5084D295A59ULL,
		0x60BEEE4914D1FF55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21EE0337D120437AULL,
		0x31CB953791F2050BULL,
		0xC17F509E90013B18ULL,
		0x50D5B48BAF67FBC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43DC066FA2408707ULL,
		0x63972A6F23E40A16ULL,
		0x82FEA13D20027630ULL,
		0x21AB69175ECFF783ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x118EB0CF3C6D4FADULL,
		0xCDED1268E1BD61F3ULL,
		0x1741243947B5F672ULL,
		0x5BD48C0C19D0E98EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x231D619E78DA9F6DULL,
		0x9BDA24D1C37AC3E6ULL,
		0x2E8248728F6BECE5ULL,
		0x37A9181833A1D31CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ABE5B456D227C47ULL,
		0x2E7100D1E378042EULL,
		0xF55E99E1BAB4FAEEULL,
		0x674238D19B405E1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD57CB68ADA44F8A1ULL,
		0x5CE201A3C6F0085CULL,
		0xEABD33C37569F5DCULL,
		0x4E8471A33680BC3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCE2E6DF16D64C603ULL,
		0x6A5B72AC97C55370ULL,
		0xA2947E92EAFAE595ULL,
		0x7F6C5056392FC226ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C5CDBE2DAC98C19ULL,
		0xD4B6E5592F8AA6E1ULL,
		0x4528FD25D5F5CB2AULL,
		0x7ED8A0AC725F844DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4232E8D9E2EFFD3ULL,
		0x3E33CC4A3056CE18ULL,
		0xBBBBB75B18EC2220ULL,
		0x3CC10198928CB31FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68465D1B3C5DFFA6ULL,
		0x7C67989460AD9C31ULL,
		0x77776EB631D84440ULL,
		0x798203312519663FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FE35B4E5B11FA76ULL,
		0xEACEA43846334DBAULL,
		0x65C16297A08CB100ULL,
		0x36705CE1E4254989ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FC6B69CB623F4ECULL,
		0xD59D48708C669B74ULL,
		0xCB82C52F41196201ULL,
		0x6CE0B9C3C84A9312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75D73F939FE05549ULL,
		0x70D8A8FA55939FDDULL,
		0x81B069633284F41FULL,
		0x3C05B894A4B34438ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBAE7F273FC0AA92ULL,
		0xE1B151F4AB273FBAULL,
		0x0360D2C66509E83EULL,
		0x780B712949668871ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79E0661814CD4870ULL,
		0x30F846750ACB667CULL,
		0x683A6D36171E05E5ULL,
		0x18B32547B307AEA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3C0CC30299A90E0ULL,
		0x61F08CEA1596CCF8ULL,
		0xD074DA6C2E3C0BCAULL,
		0x31664A8F660F5D44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAD51F996E613E2FULL,
		0xAE7852AE5395E4A6ULL,
		0x03598F859999A569ULL,
		0x311B630C9EA4887EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55AA3F32DCC27C5EULL,
		0x5CF0A55CA72BC94DULL,
		0x06B31F0B33334AD3ULL,
		0x6236C6193D4910FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A287D7E7663C62AULL,
		0x796E259AE9ADC045ULL,
		0xD4F31BB64F66D911ULL,
		0x37C4C7BD870F6E49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7450FAFCECC78C54ULL,
		0xF2DC4B35D35B808AULL,
		0xA9E6376C9ECDB222ULL,
		0x6F898F7B0E1EDC93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA79BF74F8616CE37ULL,
		0xB7FA332AACF28795ULL,
		0xFD73BC31BCC183C2ULL,
		0x1A6A173B764EBC7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F37EE9F0C2D9C6EULL,
		0x6FF4665559E50F2BULL,
		0xFAE7786379830785ULL,
		0x34D42E76EC9D78F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB7A9D0774FF53DFULL,
		0x18D6E1C7EFECE5C7ULL,
		0x4F0461C117827AAFULL,
		0x08E19BE05164E9FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96F53A0EE9FEA7BEULL,
		0x31ADC38FDFD9CB8FULL,
		0x9E08C3822F04F55EULL,
		0x11C337C0A2C9D3FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC21F6A5DF4A963CCULL,
		0xBB2A1415E1CF1EEEULL,
		0x8DBD54C9BEC53C02ULL,
		0x6AEA14DBD9B1CC73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x843ED4BBE952C7ABULL,
		0x7654282BC39E3DDDULL,
		0x1B7AA9937D8A7805ULL,
		0x55D429B7B36398E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2E70BE075B75763ULL,
		0x7E1282600A0BC72EULL,
		0xF9320183E97433A4ULL,
		0x306CA740044B111EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45CE17C0EB6EAEC6ULL,
		0xFC2504C014178E5DULL,
		0xF2640307D2E86748ULL,
		0x60D94E800896223DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x73550D4CD47B4935ULL,
		0xDB9A306DB853B6C6ULL,
		0xA1DE14E0C5947877ULL,
		0x1DAECEEC72F81449ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6AA1A99A8F6926AULL,
		0xB73460DB70A76D8CULL,
		0x43BC29C18B28F0EFULL,
		0x3B5D9DD8E5F02893ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5B4AF5BE4637C3AULL,
		0x6FB7134DDD2FDA90ULL,
		0xFF7D15B13DD8077FULL,
		0x24613F5A0EC0EB1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B695EB7C8C6F874ULL,
		0xDF6E269BBA5FB521ULL,
		0xFEFA2B627BB00EFEULL,
		0x48C27EB41D81D635ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD224ABAE532D293CULL,
		0xB1F03364544D6987ULL,
		0x1E6D5E543A97296BULL,
		0x7D2FB01E1D8454FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA449575CA65A528BULL,
		0x63E066C8A89AD30FULL,
		0x3CDABCA8752E52D7ULL,
		0x7A5F603C3B08A9F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0559E39B3A280FC2ULL,
		0x18339FA41C321799ULL,
		0x9AC56D44329634CFULL,
		0x317846186573F0A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AB3C73674501F84ULL,
		0x30673F4838642F32ULL,
		0x358ADA88652C699EULL,
		0x62F08C30CAE7E151ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x33E9AFC74E5BB9DDULL,
		0x5BE22666960F0457ULL,
		0x320A14EBD583AE1DULL,
		0x03E909B26FA7556DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67D35F8E9CB773BAULL,
		0xB7C44CCD2C1E08AEULL,
		0x641429D7AB075C3AULL,
		0x07D21364DF4EAADAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC536DE4E9F212B30ULL,
		0x06F7866C417BD781ULL,
		0xAD038D4B0C6603F9ULL,
		0x02E8138D3FD8FAE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6DBC9D3E425660ULL,
		0x0DEF0CD882F7AF03ULL,
		0x5A071A9618CC07F2ULL,
		0x05D0271A7FB1F5C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEAAA505CD410676EULL,
		0xCB5591C140F5EC29ULL,
		0x21333468FE499CC2ULL,
		0x3C047D4CBB23A117ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD554A0B9A820CEDCULL,
		0x96AB238281EBD853ULL,
		0x426668D1FC933985ULL,
		0x7808FA997647422EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x810E7F10038A06AFULL,
		0x8E8D5BB783D1205CULL,
		0x2B3C7BC0FE435707ULL,
		0x37F9A6B79FD33F7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x021CFE2007140D5EULL,
		0x1D1AB76F07A240B9ULL,
		0x5678F781FC86AE0FULL,
		0x6FF34D6F3FA67EF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3284590509E0BEACULL,
		0xC17542CDB86F5F33ULL,
		0x7CE373BD8634A8B3ULL,
		0x01C9E75D6FA29FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6508B20A13C17D58ULL,
		0x82EA859B70DEBE66ULL,
		0xF9C6E77B0C695167ULL,
		0x0393CEBADF453F90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57D0D08051D71958ULL,
		0x94B289AA4C667A1CULL,
		0xBC6E669BE872DC62ULL,
		0x28513C106E377870ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFA1A100A3AE32B0ULL,
		0x2965135498CCF438ULL,
		0x78DCCD37D0E5B8C5ULL,
		0x50A27820DC6EF0E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D0C562E2FE26474ULL,
		0xB4806E22A197E17DULL,
		0xE13F6CE8B7BB9730ULL,
		0x37808E25C319C698ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A18AC5C5FC4C8E8ULL,
		0x6900DC45432FC2FAULL,
		0xC27ED9D16F772E61ULL,
		0x6F011C4B86338D31ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA138DDE9DCF7151ULL,
		0x3D14753DC5362E29ULL,
		0x2201686C56E65C0BULL,
		0x74C9E07BF16DB74EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4271BBD3B9EE2B5ULL,
		0x7A28EA7B8A6C5C53ULL,
		0x4402D0D8ADCCB816ULL,
		0x6993C0F7E2DB6E9CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x01E25B66C9F95098ULL,
		0xA802807292F4E8D4ULL,
		0xDBD737B831200473ULL,
		0x60FA0689D35D9615ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C4B6CD93F2A143ULL,
		0x500500E525E9D1A8ULL,
		0xB7AE6F70624008E7ULL,
		0x41F40D13A6BB2C2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F4365034482E7C6ULL,
		0x3BBD2B678D7F2123ULL,
		0x565D980143E44538ULL,
		0x3535396274DC633AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE86CA068905CF8CULL,
		0x777A56CF1AFE4246ULL,
		0xACBB300287C88A70ULL,
		0x6A6A72C4E9B8C674ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBFF9308C91084178ULL,
		0x49DDF8ADDC4839C7ULL,
		0x12DECBAD1D07272DULL,
		0x585F11FDB1BE45CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF2611922108303ULL,
		0x93BBF15BB890738FULL,
		0x25BD975A3A0E4E5AULL,
		0x30BE23FB637C8B98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32FB888619CE9B59ULL,
		0xA3DCE96E1B519A34ULL,
		0xB3225C72ADF2B89DULL,
		0x7C3CD3BA214B7D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65F7110C339D36C5ULL,
		0x47B9D2DC36A33468ULL,
		0x6644B8E55BE5713BULL,
		0x7879A7744296FA15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC4F913BC6D029E86ULL,
		0x8365F32DAD195141ULL,
		0xB1D8D353FB235FE7ULL,
		0x75AA6FE7A9F24F8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F22778DA053D1FULL,
		0x06CBE65B5A32A283ULL,
		0x63B1A6A7F646BFCFULL,
		0x6B54DFCF53E49F1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE0CA2DFFEC972D1ULL,
		0xE96A069F0D089862ULL,
		0x938D94A40ACF5F3BULL,
		0x14CC5BDCC55B055CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1945BFFD92E5A2ULL,
		0xD2D40D3E1A1130C5ULL,
		0x271B2948159EBE77ULL,
		0x2998B7B98AB60AB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x576363D4C244C453ULL,
		0x3305F267DBC71E6EULL,
		0x41F31FD7A123AF5FULL,
		0x638041927162C7CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEC6C7A9848988B9ULL,
		0x660BE4CFB78E3CDCULL,
		0x83E63FAF42475EBEULL,
		0x47008324E2C58F94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF93059FA6809CE98ULL,
		0x5BDE094B9DFC3BD1ULL,
		0x98039793B23A72E1ULL,
		0x1862D9410FA7AA94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF260B3F4D0139D30ULL,
		0xB7BC12973BF877A3ULL,
		0x30072F276474E5C2ULL,
		0x30C5B2821F4F5529ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35A7BCFDAFCAD02BULL,
		0x462C078FCFFE9521ULL,
		0x029A66A4F4D160D7ULL,
		0x52175B864497A651ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B4F79FB5F95A069ULL,
		0x8C580F1F9FFD2A42ULL,
		0x0534CD49E9A2C1AEULL,
		0x242EB70C892F4CA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEADB4B922B635592ULL,
		0xE83C158CE0CBB4A2ULL,
		0xD48021B3E4CB53D8ULL,
		0x6CEE55D1B34EE23DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B6972456C6AB37ULL,
		0xD0782B19C1976945ULL,
		0xA9004367C996A7B1ULL,
		0x59DCABA3669DC47BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x395431E3787E7DFEULL,
		0x16DC73C1ABB3D3EEULL,
		0x18ED7969B69CD9D6ULL,
		0x005F2D9E4C2A6191ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72A863C6F0FCFBFCULL,
		0x2DB8E7835767A7DCULL,
		0x31DAF2D36D39B3ACULL,
		0x00BE5B3C9854C322ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC5D23A898CBEF607ULL,
		0xAA7A2BD96797D246ULL,
		0x29ECC65B47124C32ULL,
		0x631B7416102F98E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BA47513197DEC21ULL,
		0x54F457B2CF2FA48DULL,
		0x53D98CB68E249865ULL,
		0x4636E82C205F31CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D6775A94E6A6189ULL,
		0x41AE875A75699604ULL,
		0x0D27997B3CA7725BULL,
		0x21155D1751D41716ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ACEEB529CD4C312ULL,
		0x835D0EB4EAD32C08ULL,
		0x1A4F32F6794EE4B6ULL,
		0x422ABA2EA3A82E2CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A4A355DA28DE206ULL,
		0x34A970D24537FA63ULL,
		0x78BF2466707C78ACULL,
		0x566B6C039AB2716CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14946ABB451BC41FULL,
		0x6952E1A48A6FF4C7ULL,
		0xF17E48CCE0F8F158ULL,
		0x2CD6D8073564E2D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6CE332BB5CBC06EULL,
		0x41F2419A95C227FAULL,
		0x7CC3E5154A54D3C4ULL,
		0x5EAB0077E131D7E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD9C66576B9780EFULL,
		0x83E483352B844FF5ULL,
		0xF987CA2A94A9A788ULL,
		0x3D5600EFC263AFC2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x402F10355B2B030CULL,
		0x89B81D2A24087535ULL,
		0xD7DDDD18E3B03E68ULL,
		0x2B5EBED9BA59A250ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x805E206AB6560618ULL,
		0x13703A544810EA6AULL,
		0xAFBBBA31C7607CD1ULL,
		0x56BD7DB374B344A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1702E04AD8D995EULL,
		0x52AE6DD43543570CULL,
		0xD1C15B25303BD1BBULL,
		0x451DEAEBFDBCB993ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2E05C095B1B32CFULL,
		0xA55CDBA86A86AE19ULL,
		0xA382B64A6077A376ULL,
		0x0A3BD5D7FB797327ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFE12BAC31475AC5CULL,
		0x37F74B94C15BC257ULL,
		0x7380897F44AD18E1ULL,
		0x132B8C3D71032002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC25758628EB58B8ULL,
		0x6FEE972982B784AFULL,
		0xE70112FE895A31C2ULL,
		0x2657187AE2064004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x42AFC1B2D8DCB926ULL,
		0xA344F2D9C9E335CFULL,
		0xA0130C0B85E1B12DULL,
		0x47F820891D0F8B80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x855F8365B1B9725FULL,
		0x4689E5B393C66B9EULL,
		0x402618170BC3625BULL,
		0x0FF041123A1F1701ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49119EF63032A1F5ULL,
		0x072E514744E5E3C9ULL,
		0x42556C1767F2BFA2ULL,
		0x23AD3B5FDC0BD199ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92233DEC606543EAULL,
		0x0E5CA28E89CBC792ULL,
		0x84AAD82ECFE57F44ULL,
		0x475A76BFB817A332ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D3E2BA81C77F024ULL,
		0xE83FD99E3470D3DBULL,
		0x0C39ACA0262BBA52ULL,
		0x4E1A35A43DD9A3A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A7C575038EFE05BULL,
		0xD07FB33C68E1A7B6ULL,
		0x187359404C5774A5ULL,
		0x1C346B487BB34742ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06779F55D579D8F6ULL,
		0x7ABA88D81773D364ULL,
		0xC6C9A8CA21F110DEULL,
		0x05C4614962326E63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CEF3EABAAF3B1ECULL,
		0xF57511B02EE7A6C8ULL,
		0x8D93519443E221BCULL,
		0x0B88C292C464DCC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA230E1DC33EB0114ULL,
		0x96C48A715EC35CBCULL,
		0xB68BC996E3FB1810ULL,
		0x452D45C91BB0FE44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4461C3B867D6023BULL,
		0x2D8914E2BD86B979ULL,
		0x6D17932DC7F63021ULL,
		0x0A5A8B923761FC89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C781F574C9AADAEULL,
		0x0E4C9E6C6CE79799ULL,
		0x11528483AC14C3B6ULL,
		0x21CB0136848E104FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F03EAE99355B5CULL,
		0x1C993CD8D9CF2F32ULL,
		0x22A509075829876CULL,
		0x4396026D091C209EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25E56BAC88F37A6CULL,
		0xF595E7DD25CF2AC4ULL,
		0x1A64F653469ED822ULL,
		0x796568FDA8B4F50EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BCAD75911E6F4EBULL,
		0xEB2BCFBA4B9E5588ULL,
		0x34C9ECA68D3DB045ULL,
		0x72CAD1FB5169EA1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64D4100CD8D978CCULL,
		0x1F1FC7FFAD46F760ULL,
		0x809D444AD19A1E0AULL,
		0x15851829208AABDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A82019B1B2F198ULL,
		0x3E3F8FFF5A8DEEC0ULL,
		0x013A8895A3343C14ULL,
		0x2B0A3052411557BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_x2_modulo(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}