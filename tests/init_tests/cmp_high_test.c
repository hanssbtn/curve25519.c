#include "../tests.h"

int32_t curve25519_key_cmp_high_test(void) {
	printf("Key High Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0,
		0,
		0,
		0,
		0xBA40FB10E959DBC4ULL,
		0xFF840310F7340DC7ULL,
		0xE7E503B2D2FCE03EULL,
		0x491500866A4293F4ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0,
		0,
		0,
		0,
		0xD4B9537DDEBD58F0ULL,
		0xDBF0A4A5ACB9C94DULL,
		0x969AEBBB028690ACULL,
		0x3CADEF409F533856ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x989E586EB07A24D8ULL,
		0x04B376C0278F7B50ULL,
		0x6618154FC5C7C738ULL,
		0x0D9FF359460D51EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x99E0C801B3B96F82ULL,
		0xC9E595DBCDE2427EULL,
		0x49462B0CA59A21F2ULL,
		0x79A7393AE000D4ACULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDE12303B81BDE722ULL,
		0x83E43C6588D3F7F1ULL,
		0xD056333F270055C5ULL,
		0x15B6088C56FE1E6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F49F4543D3712A8ULL,
		0x9CC3A30966DD0A61ULL,
		0x790844B8EE82B2E8ULL,
		0x35F3D4DF7F7BD83BULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF883B8E16CD9C22BULL,
		0xCC694C53BAD2E367ULL,
		0xE5567A394C6CFF79ULL,
		0x15BE4707A01C7C09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x68AE0C0B8BE87885ULL,
		0xB9955F5AE9AEF42CULL,
		0x28F9D70696849433ULL,
		0x0E5B04BFA2A9018DULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5958F55BA69E95FULL,
		0xDC3158D6F47816AEULL,
		0x5B154362C27B3010ULL,
		0x0514A30DB10A6D7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5958F55BA69E95FULL,
		0xDC3158D6F47816AEULL,
		0x5B154362C27B3010ULL,
		0x0514A30DB10A6D7DULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3DD879071808005BULL,
		0xF497B3B054495FD8ULL,
		0xD3A287183895591EULL,
		0x4EFB0C8861101F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6ACD994065FA31A5ULL,
		0xEB6C499EB6451900ULL,
		0x4518F92420DEC687ULL,
		0x7AACCA403C2BBAE4ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA8CD1AD900143B2EULL,
		0xFC59E73B6E0F2E12ULL,
		0xD7CF66C51AD75B1CULL,
		0x5F3438A96FE118BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x896595B4E97448FCULL,
		0x3C7F2A3FFD55C23DULL,
		0x015F49D655024351ULL,
		0x10A3F7CC2EA77B26ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6819174A3CE4DC5ULL,
		0x611DE842AF60B22EULL,
		0x6924FDF6CC49ADEAULL,
		0x01F7E863D5B5756AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA4E399BF9D4DBC2ULL,
		0xCB5088D267D28195ULL,
		0xC4E79C66038737BEULL,
		0x64B2C8FA0D38234AULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF6B079E00EB64D1ULL,
		0xA3B42604E2F7B05CULL,
		0xA77F11A787224228ULL,
		0x1F66871BF1C887B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF6B079E00EB64D1ULL,
		0xA3B42604E2F7B05CULL,
		0xA77F11A787224228ULL,
		0x1F66871BF1C887B7ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE66992AEC22DA70DULL,
		0x132A46C3C0A829D2ULL,
		0x0D1BD548BAFCE367ULL,
		0x738145277A6469DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAB8739FACA4E7F3BULL,
		0x8F0873C71E7D0FE0ULL,
		0xE3AE4A359C31F744ULL,
		0x3B59485568BFCABEULL
	}};
	t = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA0AE518BF1EC914ULL,
		0x3379E9B8AE1D3A7FULL,
		0x7D0B18F153497A01ULL,
		0x3E28C28C5B43578BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7D52F6790252CA9AULL,
		0xB1AD4D5B8335484DULL,
		0x8D9B0143F3D0012AULL,
		0x27BD37D02992C6BFULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC326A8CAD4579C17ULL,
		0x966AB7A9F3AEF8E9ULL,
		0x7D50E54A997C3A80ULL,
		0x3E578947294F904DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD2C1E7A9EDA5D4DFULL,
		0xB00E972B86FD12C8ULL,
		0xDA82153726C57C2CULL,
		0x64E75DE0603F842BULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6AB7C1C2792CBC8ULL,
		0x2A9C9A06A4B8BE5CULL,
		0xD6A7140DED82D9BFULL,
		0x7FA8A29CDFE9FD42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6AB7C1C2792CBC8ULL,
		0x2A9C9A06A4B8BE5CULL,
		0xD6A7140DED82D9BFULL,
		0x7FA8A29CDFE9FD42ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x26D74819E0A81C81ULL,
		0x41B63E2F4FC3424AULL,
		0x968974AC22850209ULL,
		0x08F910A078EC7C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D61A8D7D9382386ULL,
		0x6914C64282F9F235ULL,
		0x0BBC33B2BC6351DAULL,
		0x63F9CC00AEADDA1DULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA701F5E88AB73B96ULL,
		0x14BE92A071311256ULL,
		0xE61C9BDB5137D562ULL,
		0x5FCB970A5010C520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C721DCD380D7859ULL,
		0x84990E0254D2722AULL,
		0x1C01F014CB18415BULL,
		0x49A5336273DB8870ULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x56F89EAA0621C31FULL,
		0x6AC1720B28426A46ULL,
		0x911A10E0D4AD1A90ULL,
		0x4C22175CD1B0403BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7FADF85B12531DA8ULL,
		0x1921ED4FDBBDE7ADULL,
		0xEC3E0D08CAC62305ULL,
		0x7F0D345829447123ULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BD2BFD7FDE61464ULL,
		0x731B6C5D27FF4A17ULL,
		0x4227D36ABE317BE3ULL,
		0x3D2DCA8CF7BC91CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BD2BFD7FDE61464ULL,
		0x731B6C5D27FF4A17ULL,
		0x4227D36ABE317BE3ULL,
		0x3D2DCA8CF7BC91CBULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D04E0D25311075FULL,
		0x1C84B138B6BC2653ULL,
		0x022E75661C21B5E6ULL,
		0x29D4BFAF271903C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5A4775BAEDD9A735ULL,
		0x7452191614A0C665ULL,
		0x716776C6856D4113ULL,
		0x6F48E805C6B156C9ULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53D99A22C6FA896FULL,
		0x156677E8E3E4BB42ULL,
		0x6CB91A5577F6BEEBULL,
		0x258221F7CFCE5EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBB9E25618AC80C07ULL,
		0x98E9A869762C0852ULL,
		0x8895FF8560FAFE57ULL,
		0x7246759B8379DE1CULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90B70B7E7343C178ULL,
		0xC11F96CFE11F917DULL,
		0x5FECFF8B58972287ULL,
		0x0B010CA9A1CC9D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5B0882610D2D608BULL,
		0x3685CA488036045DULL,
		0x834DA9291A0971ACULL,
		0x6D72D2AF136BC749ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59E3008D69850E76ULL,
		0xC3B7564D66544F76ULL,
		0x869B1A5C24A74D74ULL,
		0x7A47467FC70DC821ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59E3008D69850E76ULL,
		0xC3B7564D66544F76ULL,
		0x869B1A5C24A74D74ULL,
		0x7A47467FC70DC821ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4A4CF204939E79BCULL,
		0x4E0E75AE336F2732ULL,
		0xB398675B4FEBC55BULL,
		0x2C52E145AF323561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD85D89E789A02F1ULL,
		0xEAD5630EBE1BCDF0ULL,
		0x4037AAAEB75A0975ULL,
		0x551E28ECF4DE36A5ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x99223C32BD487748ULL,
		0x3109F2E256DC4535ULL,
		0x7CFB267482BAACE7ULL,
		0x3AB0F90C236DF54DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4978573511650905ULL,
		0xCB4B6B4367FCD26EULL,
		0x477A1D7A7751F472ULL,
		0x05C9E02D654FD9CCULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5B70893023BB2A8ULL,
		0x553DAE4F4CE525F5ULL,
		0x0661F28657767736ULL,
		0x3CE94DB86954DFADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4FE3ED878C7AFB18ULL,
		0x0E2E1DF9916F11AFULL,
		0xE75613DBB79A430DULL,
		0x60FD8D6A2C8024EBULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF23AA5F482327543ULL,
		0xC3188D647D2FCDD2ULL,
		0xB28F05397509EF0EULL,
		0x522C3CAA44DE28F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF23AA5F482327543ULL,
		0xC3188D647D2FCDD2ULL,
		0xB28F05397509EF0EULL,
		0x522C3CAA44DE28F0ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x901C114EBFE9D666ULL,
		0x773EBDE12C612E93ULL,
		0xE63C523CF5B6F97EULL,
		0x5111668A4B5127A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2636292B7DD404FCULL,
		0xE84CC97CD97BF472ULL,
		0x003F631532DA1475ULL,
		0x2D556E8B96633A8AULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8A6835EEE6C255A4ULL,
		0x3F351B84EB227666ULL,
		0x98E4CEDDB606127EULL,
		0x5C27B2B2C634A082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF9D170D8DA81578EULL,
		0x44E0B36CE39F4057ULL,
		0xC154068D4A7ED0E5ULL,
		0x2DC0E9119DC65F2BULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79D63F1695F101BDULL,
		0x55A6966F6F4EFB73ULL,
		0xD627363B9E83BEC1ULL,
		0x16BA2D94E7072FB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2EE1B02EBE3E3942ULL,
		0x5809218E849B1F97ULL,
		0xF0B1E8B1FF2AC8D6ULL,
		0x2D6D68FF35B97616ULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F6D5A39DAE92B95ULL,
		0x3C32CCE97F615042ULL,
		0xAE223405E7B43FD7ULL,
		0x262EB60222822875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F6D5A39DAE92B95ULL,
		0x3C32CCE97F615042ULL,
		0xAE223405E7B43FD7ULL,
		0x262EB60222822875ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCCBBDD8674FF4906ULL,
		0xBBFF42A0DCF444BEULL,
		0x7F2165D2A062B3F6ULL,
		0x03234C5D3B54A49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x30E03616C4B5F661ULL,
		0x6762511458F3D3B7ULL,
		0xEDEF7C9E42F2EB6CULL,
		0x134C95D36F3EAFEFULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB45911BBFDC984C8ULL,
		0xDC44F2905D8DFC5BULL,
		0x43D4FAE50B201D14ULL,
		0x10C433795B790DD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29DCDFC63C990D94ULL,
		0x330DA9CD47FB62B3ULL,
		0x975C9035489B4DACULL,
		0x222BFC35093ED001ULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3B00DC8AA1206C24ULL,
		0x41142EC307407545ULL,
		0xE15D265B163028B3ULL,
		0x69F5A8F7FCD43B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B62AFDC2BA460FAULL,
		0x66C95622B1ED9901ULL,
		0x883B0EEB7E366695ULL,
		0x7A67DDFE2EECD473ULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x42D47E1E789216CBULL,
		0x2DEE215CB8B5A78CULL,
		0x926FF77D6AD8DA47ULL,
		0x0C545A7AC76D4EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x42D47E1E789216CBULL,
		0x2DEE215CB8B5A78CULL,
		0x926FF77D6AD8DA47ULL,
		0x0C545A7AC76D4EFFULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF47788726DB6462CULL,
		0x96D54E547A3A61C0ULL,
		0xE26D907090267207ULL,
		0x631A45BFFF2E7465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29A837679BF31CD7ULL,
		0x42A5C52502E99199ULL,
		0x6A8A9A15C6021715ULL,
		0x35BE2EB241CC3E55ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x17DFCEC512B230AAULL,
		0x5DB336AC61FA9F06ULL,
		0x16A813A0870EEC2EULL,
		0x066CDE32715A0D0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D872999EFA0AE57ULL,
		0x35082E6E8456A07CULL,
		0xE4B8050B3A2A16A7ULL,
		0x133C0A258467CDE9ULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18B1DFB76B81DC53ULL,
		0x57D3E4AD32F01E61ULL,
		0x2714BDE84B6FD999ULL,
		0x70AAF2E07717965DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE797B251BE6E8F66ULL,
		0xDF26C75CFACCC478ULL,
		0xD025469B2DDC7983ULL,
		0x20D9B93F3B2837C5ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0827AB3A43D86399ULL,
		0xE73EBAFD689A6546ULL,
		0x212D8215223A271DULL,
		0x5FA5951DDA158189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0827AB3A43D86399ULL,
		0xE73EBAFD689A6546ULL,
		0x212D8215223A271DULL,
		0x5FA5951DDA158189ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x978683223CED196DULL,
		0xC3761FBF9CAF6AC4ULL,
		0xB9FA26873F23642BULL,
		0x6B1698602650811CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1779B1F0E0AA1972ULL,
		0x9E18C63ABCE8BB3BULL,
		0x768276CC439AFFC6ULL,
		0x5917E1320459ABDEULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66A63B64FA6473CDULL,
		0x47A846071EC746C1ULL,
		0x0D8D62293A524C8FULL,
		0x500DD92C32437FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBF1AC30556849A97ULL,
		0x27BFD78F45649BB1ULL,
		0xA239E365E8984C41ULL,
		0x4B6B9CEC020C6F5FULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1040D0399A70533ULL,
		0x7D1859938557DE05ULL,
		0xA6E31181CA2B7F6FULL,
		0x5629EFE900DC29B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7F20432A2BB11D0ULL,
		0x44B9B6A8A5DD26D5ULL,
		0xCFBFCBCB3DDC6D9FULL,
		0x220120EE10E5FAEAULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70832165EAA54C8BULL,
		0xD9FB76EF178D3B09ULL,
		0x999C01811672F797ULL,
		0x7398452CE978BA2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70832165EAA54C8BULL,
		0xD9FB76EF178D3B09ULL,
		0x999C01811672F797ULL,
		0x7398452CE978BA2AULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9DA931DBDBB84E3CULL,
		0x517A3FCAD79A0980ULL,
		0x521151879DA29857ULL,
		0x39AE4DE6D7402D2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBB14C4D96DC28294ULL,
		0x1B42D19D8D6FC53DULL,
		0x3D285E001E03ADEBULL,
		0x55F69EE6FB22BD55ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x93066D90947022A1ULL,
		0xFFBCBA9E91CC7D7AULL,
		0x934F48CC180D0503ULL,
		0x1C9552B0B0F47F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x93A57643E2CD7478ULL,
		0x9268D0B5D3DCBB93ULL,
		0x436EA2122F27D4B7ULL,
		0x2FEC63D98E8F0B92ULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x126A7F23192DED67ULL,
		0x8EE67104DEA96E4BULL,
		0x89F4D8D1FECD72F0ULL,
		0x45131CC197836D97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0C132E828C7AD46ULL,
		0x62717E38CB5DBD2FULL,
		0xCD2C6ED6FC13E639ULL,
		0x05B6C91869C00398ULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF7E06DB02369AABAULL,
		0xC4E7AD8F847B7EB4ULL,
		0x10A0015BE4B55564ULL,
		0x25CB23AD4803D5BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF7E06DB02369AABAULL,
		0xC4E7AD8F847B7EB4ULL,
		0x10A0015BE4B55564ULL,
		0x25CB23AD4803D5BBULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5953DA3814A3558ULL,
		0x1DF1A5B1A0BBEC8EULL,
		0xCCE8B6CE0BA5E1F1ULL,
		0x0125E92F7612B8F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6744BBCD3F714642ULL,
		0xEB3E8AC030DD9164ULL,
		0x2C4707EC297F67DBULL,
		0x3E9BFCECB08E3608ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA89C11DD03F91C4BULL,
		0x3C9D6610AD57C439ULL,
		0x5A3A90931498D063ULL,
		0x3CCAB1FF59D4D5A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8ABE37940A4E5771ULL,
		0xE3130B7EA75E4FEFULL,
		0x342095AB29C712FCULL,
		0x46CED0C0C9E5D07CULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA82639D32D979FE8ULL,
		0x5BD5A4AC8E6BA225ULL,
		0x6DABA5B95BED66FEULL,
		0x3B3C273D1728BBB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC0D7A7AB085B27DFULL,
		0x0455A794D375A3D9ULL,
		0x9B06BB406F99A6D7ULL,
		0x50BF108B44C6B45CULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9BAC5B0699200859ULL,
		0xFE80523BEB76397FULL,
		0x379560841422E256ULL,
		0x2479569A8C4B66F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9BAC5B0699200859ULL,
		0xFE80523BEB76397FULL,
		0x379560841422E256ULL,
		0x2479569A8C4B66F6ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5C2F83510E6E02BULL,
		0x535B71DF14667589ULL,
		0x709DDA9714D813B4ULL,
		0x0AB58D684523125BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEA7207189815EE5ULL,
		0x996E38B5D760078AULL,
		0x1A445BBE175CE378ULL,
		0x7B15D83001A74223ULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD10F6FCDB3443295ULL,
		0xD15EEDA4FF18CB16ULL,
		0x6543CC2EE9A62978ULL,
		0x2B1D3625DAA006BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB756E48C1E69277CULL,
		0x12185D31B33CED91ULL,
		0x64B974159F8BDADAULL,
		0x3B2D5C6E3566ED0EULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xED2F6E6147444AD5ULL,
		0x27BDC75A8B4DA54EULL,
		0x74B6B7D302773450ULL,
		0x3B5B2D23A3489E50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9868B9AB9ADD366FULL,
		0xD1BE71B5E958F8E3ULL,
		0xBB8DA6F7790C86F6ULL,
		0x6AAECF1EFA340943ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18F049AE48EB3651ULL,
		0xE5C8ECECB2EC8E57ULL,
		0xC5E0FB82664E4DF7ULL,
		0x0E1DB5BD8706385EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18F049AE48EB3651ULL,
		0xE5C8ECECB2EC8E57ULL,
		0xC5E0FB82664E4DF7ULL,
		0x0E1DB5BD8706385EULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x464528895B1CEE71ULL,
		0x7D426014B1F5A84CULL,
		0x596EC899862F44E7ULL,
		0x4079F2565D69ADF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BF79434217C2961ULL,
		0xAC0A6E9F83F1D144ULL,
		0x98E9C25BC5C7A635ULL,
		0x045256F7F6A4BF23ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF88E301291ECDCE8ULL,
		0x725D7EBD4F17A336ULL,
		0xF638954DA0BB643FULL,
		0x26773C1A661DB9E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFDA9769D7A78A197ULL,
		0x6C7B0815B8116438ULL,
		0x2571568F75DACFB9ULL,
		0x2E5D3C37E58C7DB6ULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA2CC1CAA73F77DFULL,
		0xAE82320A3FA8C0D5ULL,
		0x9F2EE035FDFC12F6ULL,
		0x2659132EF395907CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB81FEF0C15087823ULL,
		0x110CDB0CCFD7ECF5ULL,
		0x840D4D3EB5D77E58ULL,
		0x06EF46DD2E856FCFULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB91AB8A6D4AC8061ULL,
		0x1CF43E86CCE3B165ULL,
		0xBC12BFDBB0E9CE1FULL,
		0x0FD494A3610E050EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB91AB8A6D4AC8061ULL,
		0x1CF43E86CCE3B165ULL,
		0xBC12BFDBB0E9CE1FULL,
		0x0FD494A3610E050EULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE1A6C80C5D0282BDULL,
		0x23A422878474896EULL,
		0x9FDD19B4B1FD7EF2ULL,
		0x0CEA2B5A7D57892AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD2B9227522C09672ULL,
		0x591AFA306A8E3186ULL,
		0x653C8C1F30898C2AULL,
		0x3225562E7A801C01ULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x483646B1A7A99731ULL,
		0xF82B190F053ECF37ULL,
		0x688D8A394C2F8FBFULL,
		0x56C6F1BDEEC23D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x816931E8C40F3F80ULL,
		0xD53C6538F6A361FFULL,
		0x47853E0BA787149DULL,
		0x5432B9644388A46DULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3786CFDBF89DE4AULL,
		0x942CC0F6D81AAFCFULL,
		0xF404F3BEC887B026ULL,
		0x7C275690689D990AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE6DF7A32D423F3A2ULL,
		0x49301998D1C1B30FULL,
		0xF119256454FF565EULL,
		0x67F4FE17B969CEEBULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0241B66AEAD0989ULL,
		0x679483DF3ADE7067ULL,
		0x8350F2ECC8F827DDULL,
		0x35353D4D4CE9A3DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0241B66AEAD0989ULL,
		0x679483DF3ADE7067ULL,
		0x8350F2ECC8F827DDULL,
		0x35353D4D4CE9A3DCULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x73EBF63E48E04E6FULL,
		0xE270DA7595483371ULL,
		0x9F0DE87E6691C65BULL,
		0x6858B9BDD41241C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0C8ABC6A457CDC6ULL,
		0xB627405A6D2FDA31ULL,
		0x0B98A524584E7B96ULL,
		0x1BEFB34EE3D41B1BULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x608D1728CBB7956DULL,
		0xE14DDC82AC9C674AULL,
		0xD992FF488D7C14C3ULL,
		0x476D7DED8C414172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5495EB756440C34FULL,
		0xF880EAD224916824ULL,
		0xF3CBAD3C35C4641BULL,
		0x229ABC1FF1C3EE01ULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDFE7C6394475C526ULL,
		0x263ADD1F2152FF81ULL,
		0x806AD94CF3C19B1CULL,
		0x7E3072296599FE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB920C057DFF9344DULL,
		0x623C8C1B9463BC8CULL,
		0x91EC5B0A9A16C910ULL,
		0x0C3089243C622DA6ULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D3B1E0217363C3CULL,
		0x4EE62FEB3D5A13C3ULL,
		0x0DC309270F953FB1ULL,
		0x19FF105E72D7826DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D3B1E0217363C3CULL,
		0x4EE62FEB3D5A13C3ULL,
		0x0DC309270F953FB1ULL,
		0x19FF105E72D7826DULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x421CFF072717E720ULL,
		0x953FE92A10301984ULL,
		0x74B166BF89C1EF61ULL,
		0x0843F2F079625EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9A210052E4E2C8D9ULL,
		0x4F81ABFFF591AFF2ULL,
		0x2665E3813CF6BFE0ULL,
		0x7581223E897E3EF5ULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD01B5B9830BEEC4AULL,
		0xB5B33B26E19CCDD1ULL,
		0xC5505779F0246A8CULL,
		0x6A8B27718B101F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x25DDB404AF411E86ULL,
		0x0CC319BA22EED7B8ULL,
		0x62B98EB721BDA8F3ULL,
		0x6327BC04465F0CDBULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x333987D4966470A8ULL,
		0x3427C0278B8A3D25ULL,
		0xDCB6D431852B4E31ULL,
		0x639F6F9540CE744EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE2887279E25EA86ULL,
		0x56E23B3430F1D6C6ULL,
		0x001DF495E4DA2830ULL,
		0x3B3C3FD7F800B150ULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC523E66B360BB1E9ULL,
		0xD01057ACF7FAE856ULL,
		0x00261825C8785412ULL,
		0x2E7D75732262D65AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC523E66B360BB1E9ULL,
		0xD01057ACF7FAE856ULL,
		0x00261825C8785412ULL,
		0x2E7D75732262D65AULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0AE32AB83176C498ULL,
		0x5A9832580FF8C397ULL,
		0x1899F19405F08B35ULL,
		0x33D9A9ECA67FBED8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x71E1780780431452ULL,
		0x11A7B67E95B6ACD2ULL,
		0xD3B99349D0E1D742ULL,
		0x40D4A03D45CC29A3ULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B8F9CCE02FD1527ULL,
		0x19B91372B81677A0ULL,
		0x15452E9BFAEE4BDEULL,
		0x06B6CA84C30CEB05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5907EE293809F661ULL,
		0x28B612A2C913FCEFULL,
		0x18084EF2D233F817ULL,
		0x09307221862E9043ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAB4C5B1539C73F96ULL,
		0xD999494A93E89E41ULL,
		0xE93E1DF418F0FF0EULL,
		0x1F035403C89B5C9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD90E4C2A5C528A7ULL,
		0x772F2A557851FFEEULL,
		0xE723E47F20478EB9ULL,
		0x3CD0D1DC40E46C71ULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1DCEA185104AEBE1ULL,
		0xFDA327E1AF0AB141ULL,
		0xCE06714522E95493ULL,
		0x601F1EF8B7462908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1DCEA185104AEBE1ULL,
		0xFDA327E1AF0AB141ULL,
		0xCE06714522E95493ULL,
		0x601F1EF8B7462908ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB64E53E92A9C8C54ULL,
		0x2B0211EA34C494F0ULL,
		0x1F6BE27EAD6464FFULL,
		0x0812871CA400EB69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD4068ED8C9715FB2ULL,
		0x0BADE13A4FA222E7ULL,
		0x7DE38736DB984231ULL,
		0x5DA06A1019D43254ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x13AB2D3C23806C86ULL,
		0xE1EE2165A9B96168ULL,
		0x3797B07CE9BF4BEFULL,
		0x3057EA5C7E9C62DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB3B9AC5D93AEB002ULL,
		0x29662C01AFA34D45ULL,
		0x4B1911510FCD641CULL,
		0x1D06E68C06C8334CULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7CD9A8214C18C438ULL,
		0x85243202E8D69548ULL,
		0x2BBCC2DDD782647BULL,
		0x1DF66873AA9F884FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2952CC6D77E06A2FULL,
		0xF2335E6A7C23B1BAULL,
		0xAA0C717FF7AEA7F9ULL,
		0x23EA0E9D3677597DULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x420518A3B3D0E319ULL,
		0x02A8305F5DF393DDULL,
		0xDE3866A367D85E59ULL,
		0x542BC778D579A29EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x420518A3B3D0E319ULL,
		0x02A8305F5DF393DDULL,
		0xDE3866A367D85E59ULL,
		0x542BC778D579A29EULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29ABF1EA103195F7ULL,
		0x1E90D6522A77EC92ULL,
		0x2739C77DAB793B3BULL,
		0x467B4920775F5611ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2A6738BE6A27316ULL,
		0x0763D5A64DCA5CAEULL,
		0x7042C76AFAF9B8DDULL,
		0x340927BA14665B16ULL
	}};
	t = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5A7F9F89EC2E046EULL,
		0xBAF4E6C4FA89A2A0ULL,
		0xE766D3BCF7181DD5ULL,
		0x087B2D899C9A6F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x882B9C4FD7FF6386ULL,
		0x59F826EE56F42C22ULL,
		0xA17EDF634EC03EA7ULL,
		0x47B32607EB3A4E62ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x02D14A5547A94E4BULL,
		0xE8DF1AB38611600EULL,
		0xBBE96B505E9DB3A2ULL,
		0x79A75C50E1BE73BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x65DEFE2AEF6BAFBEULL,
		0xE4339128CE959204ULL,
		0xA59733805D018EA0ULL,
		0x6ACE7284922FD0F1ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB6C92FEB3D72CC49ULL,
		0xE2B2E0FA4C8B3417ULL,
		0xECFAE0B34219D5D0ULL,
		0x743F0644C9FE39F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB6C92FEB3D72CC49ULL,
		0xE2B2E0FA4C8B3417ULL,
		0xECFAE0B34219D5D0ULL,
		0x743F0644C9FE39F8ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD524B18811BCC2B1ULL,
		0xF962AAD40D5A6C2AULL,
		0x79B159CC89CEEFEFULL,
		0x16B50C741F502570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5034F8FAB9B9D79ULL,
		0x0CDEA9BB65C21DD5ULL,
		0x39286CE831803CA0ULL,
		0x6BE04221814E224EULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6F19F153596886BULL,
		0x598D2E7ED46DD554ULL,
		0xF0F384827A57B148ULL,
		0x72CB380F7E2414D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3ECB756EDA4C8121ULL,
		0x3AAD33216C07837AULL,
		0x51BF607A3A1D6763ULL,
		0x134EC7D1826C0A49ULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDF82DF8AEC50F87EULL,
		0x3797F367DD9769A0ULL,
		0x887F8D3BD4D0BFBDULL,
		0x3AF3988C97A77F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2C378E5612E61E66ULL,
		0x6313AA8F29EA99F2ULL,
		0xD06B12B82B72C593ULL,
		0x2699859703AD3253ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F839306C6559B2BULL,
		0x288AF0E5014F67F4ULL,
		0x1686EEDF868B42F4ULL,
		0x60239E390A03A32AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F839306C6559B2BULL,
		0x288AF0E5014F67F4ULL,
		0x1686EEDF868B42F4ULL,
		0x60239E390A03A32AULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x773E02B17D3036D4ULL,
		0xF135C3146931937AULL,
		0x4407BF503973CC9DULL,
		0x263F82CC0B7723D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAB3FAE20F22AA838ULL,
		0xB68DA1732BE9592DULL,
		0x918215D85C55496BULL,
		0x200565AF3BAC250CULL
	}};
	t = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A8B22BCB15B59C5ULL,
		0x8F018CA5C50E02C7ULL,
		0x7A511EF4525DB3B8ULL,
		0x615097B09283D8AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x55243F7B5FF43B9DULL,
		0x4AB84FAA6AED115AULL,
		0x7FD8AE8358506B2BULL,
		0x11BEFD10FAD25826ULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE43E5E8EF3B62E7ULL,
		0x12685FF361F65ADAULL,
		0xBBF1536821732122ULL,
		0x572899A24671A54EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF24397A84F1944B0ULL,
		0x309D47CBE7B31BB0ULL,
		0xB526C7B4FDCE4A5AULL,
		0x584B18959E2DCFD1ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3FFFAA65B57A6B3EULL,
		0xBACE15840D840696ULL,
		0x33A8DBE2A54F3BFEULL,
		0x30AEA564D5F9FD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3FFFAA65B57A6B3EULL,
		0xBACE15840D840696ULL,
		0x33A8DBE2A54F3BFEULL,
		0x30AEA564D5F9FD1CULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5DF98A84675DE60ULL,
		0x63C0774F8D77F2A9ULL,
		0xB7456B2C5F1AC2A7ULL,
		0x204D20788ED8860CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCB74A51AA52624F1ULL,
		0x3E041FB08F1AF89AULL,
		0x257DE206E1482436ULL,
		0x4ED535A7E09CEAD3ULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x294B0D75EA4B838EULL,
		0x6C96A129CCBC2A1BULL,
		0x5562B41D91634537ULL,
		0x4B47601A04DC970BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F69124A2C0BF60DULL,
		0xA1CE73D29B8F2AE8ULL,
		0x280F318CE173243DULL,
		0x01201A3A5A6211F7ULL
	}};
	t = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01DC50B888214142ULL,
		0xB6AE2926C1DF5AB7ULL,
		0x8DC2A5278D6D7CCBULL,
		0x6B126D6AC03FB8BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2A30293C26B05132ULL,
		0x608BB4E787DA5607ULL,
		0x4531C2D6368FCE35ULL,
		0x1F30F074400103E3ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6666C567D7170A84ULL,
		0xB422346F7FCB77EBULL,
		0x03618DCB40776428ULL,
		0x67EAB47395B6A385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6666C567D7170A84ULL,
		0xB422346F7FCB77EBULL,
		0x03618DCB40776428ULL,
		0x67EAB47395B6A385ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB7D86CADBAFEAA2ULL,
		0x027ADD04885A5921ULL,
		0x4BF96FCA1410DE0DULL,
		0x210466C96692276AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD7360349D0D55DEDULL,
		0x76C8242D3A4285ECULL,
		0xB566BBD28A183EF2ULL,
		0x6697FE04D82D6DFFULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F94F1C064A30E2DULL,
		0x2D4930D68D750F3FULL,
		0x564788098022256EULL,
		0x7481DAD6F91D9868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4684D8EDD423840DULL,
		0x071002785CAE4F71ULL,
		0xC998BEE4EFC8A2F5ULL,
		0x413B07B07E83F88CULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x311337C51A268D3CULL,
		0x44180E0DFFAFE828ULL,
		0x7EE3B50353EE1F5DULL,
		0x07F8C6476677E984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x669CCF6DC133D1E8ULL,
		0x7FC67023F3A9452EULL,
		0xBCD65476D6C712D1ULL,
		0x184EF1EF0CC662DFULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7F85E7786C306B6ULL,
		0xC12847FC772E8784ULL,
		0x8767B0B2E7715DA8ULL,
		0x78DEB5A9D55B6906ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7F85E7786C306B6ULL,
		0xC12847FC772E8784ULL,
		0x8767B0B2E7715DA8ULL,
		0x78DEB5A9D55B6906ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x65DA9DD1499EB465ULL,
		0x5ED037847B55FA5CULL,
		0x568894BDE9A01E8FULL,
		0x1EAADFEBE6DA717BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB139ED23E8B77150ULL,
		0xD83D3A2777B74B6FULL,
		0xD56FFD54388F640DULL,
		0x12A3664DB53F0479ULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x69B5E138C5971D29ULL,
		0x362D28450A92A12BULL,
		0xDB52CE2C6A4C828CULL,
		0x2D26781D9221A159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C5AC00F267C9F59ULL,
		0x41AA6317C78FCC55ULL,
		0xFD7071AA7EDABA08ULL,
		0x3B2DB6426530F8FEULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E518554F5167847ULL,
		0x5AF155672452EAE3ULL,
		0x221BE7F2FC0EC7EDULL,
		0x67656289B91FC044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3E29F0A10B4EC308ULL,
		0x82A9337DEC040496ULL,
		0x8FCC91D793341077ULL,
		0x0BFDB223E71F2D17ULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1AE0468F85BDC6BCULL,
		0x8D6078BA262AB10EULL,
		0x7D7E7CC99C27FB13ULL,
		0x444EF237D85539C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1AE0468F85BDC6BCULL,
		0x8D6078BA262AB10EULL,
		0x7D7E7CC99C27FB13ULL,
		0x444EF237D85539C2ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF19F4583ACCC7D16ULL,
		0x87B0060B0A9BC8B8ULL,
		0xDB11089B4AAE240CULL,
		0x176068B0B381DC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x28294E58BF126C31ULL,
		0x32A137C65BBB1936ULL,
		0x51F6E35962770AC2ULL,
		0x1D98B492F05C31E7ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC08E239AAD554948ULL,
		0xDAC7C6A24DCA53FDULL,
		0xAEBBE714ED893A20ULL,
		0x53B3D7C98320C5B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7F1929B0D59C1CC1ULL,
		0x2871ABAA7E8D46F9ULL,
		0x5E482EBA6998294DULL,
		0x5A61F5F40863B172ULL
	}};
	t = -1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE62276DBCB5253A9ULL,
		0xC848F3AD4E9688C3ULL,
		0x3CCD7CE03026FE07ULL,
		0x6432899FCB407765ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x17DAAB46C1C47463ULL,
		0xDC7464E957F0173EULL,
		0xC170C52528D5F850ULL,
		0x7741C6D02D63A839ULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x50D6BB8BF191EF85ULL,
		0x88624487E4F8923AULL,
		0x625DE700C765D545ULL,
		0x121284DE41DE54B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x50D6BB8BF191EF85ULL,
		0x88624487E4F8923AULL,
		0x625DE700C765D545ULL,
		0x121284DE41DE54B0ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF976FB20ECE5D2F9ULL,
		0xF30275E5903985D9ULL,
		0x07AAE87268755084ULL,
		0x0C3A5BC68E923849ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8F3D7177D1CDC514ULL,
		0x50E46C8DD51E1A65ULL,
		0xD97E9E08E2C72104ULL,
		0x2533741549996D85ULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC2B0A8254654965EULL,
		0x9A3DEE04CC479EF7ULL,
		0x4BD15990C946B688ULL,
		0x32C9B57153B33733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBC6CE51AFBFE8B9ULL,
		0x6B2CB9C003E7B72DULL,
		0x5272BA6413B3D392ULL,
		0x55F731920BB85705ULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB3D94BFCD88B1CE3ULL,
		0x406AB50D9D146204ULL,
		0xB534640E801370B7ULL,
		0x3625E8E3BFFA0E79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAAEF16A1A31F03FEULL,
		0x056F8FCC1CBBC53BULL,
		0x4E26125D6839FCD5ULL,
		0x0E384AD840426AB0ULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C9E655E2FF219AEULL,
		0x27B8C09FCF30DDB8ULL,
		0xC2E195C3D311679BULL,
		0x4C8244EB8BCDBC02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C9E655E2FF219AEULL,
		0x27B8C09FCF30DDB8ULL,
		0xC2E195C3D311679BULL,
		0x4C8244EB8BCDBC02ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF8AC69DCE9EC58AFULL,
		0x40D8D8716EE2C3C8ULL,
		0xB262E738E45C32BAULL,
		0x61462B9870E10EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBABBE46B7D458497ULL,
		0xD063E245BADF31C0ULL,
		0x3EB18BC521B6C6DFULL,
		0x6DD8D86F1CC0ACDDULL
	}};
	t = -1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC97C022CD8190439ULL,
		0x85CBE7F2740EE920ULL,
		0x294D30A967E6F949ULL,
		0x1E4506FB2ABF1BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCB1E9A9701B018A2ULL,
		0x9070E85B1889D44EULL,
		0x904E90784D291291ULL,
		0x2D577DF2B9DDDBFCULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2394FAFE25C81551ULL,
		0x7D96006A9E935AC3ULL,
		0x86FDA38AFB82D290ULL,
		0x6F9DC8A7CBDDA95AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E0AD7879BBAC90AULL,
		0x455E09370C4E821FULL,
		0x1C2F92ECA5042D07ULL,
		0x728529367EDF9D20ULL
	}};
	t = -1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0BE01F0FE481BA2ULL,
		0xC9CD8B0109ECF487ULL,
		0x5275DB7B2C4015AEULL,
		0x7943B05D6BF3CE74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0BE01F0FE481BA2ULL,
		0xC9CD8B0109ECF487ULL,
		0x5275DB7B2C4015AEULL,
		0x7943B05D6BF3CE74ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7820CEF0055AAECBULL,
		0xD6F67D45FC15EE83ULL,
		0x94DD71B4668BCCA7ULL,
		0x2B59A00C067A8121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA57F7D4AAD8308A0ULL,
		0x424EEFCB1BC58FC4ULL,
		0xEA1D21EF6BC021D0ULL,
		0x444523B4A8BB185FULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC54DC72CFD53FADULL,
		0x8F5E6F4959A02A98ULL,
		0x47F2DC12DA67837FULL,
		0x475C28EC31FB689CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F358B2D063DA27EULL,
		0x06137A979AD007F2ULL,
		0xA4B903DA26C9197BULL,
		0x589DD5858C445200ULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9E996433DA2460B1ULL,
		0xE67E09F4CA284F89ULL,
		0xABF22643FEA635B4ULL,
		0x5097CCB213D68D45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x656FF6F082C64749ULL,
		0x8718DD6DC21978D4ULL,
		0x9917927D8AABF267ULL,
		0x6DE04C9ACC48EDC5ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7FD4B24DBA5401EULL,
		0xB098FE1EE160D98BULL,
		0x0DE281ACADC62C3AULL,
		0x079E8C2D284312FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7FD4B24DBA5401EULL,
		0xB098FE1EE160D98BULL,
		0x0DE281ACADC62C3AULL,
		0x079E8C2D284312FAULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEDA9B14C39088C7ULL,
		0xC21DB045B0A26271ULL,
		0x6F96795BA9A5FC01ULL,
		0x0F707B94299A09D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x89553EEFFD6BA2EBULL,
		0xE36CDACB82F2AC67ULL,
		0xD75BF10B154F4834ULL,
		0x2067211506458150ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x319CBA0A5B225E81ULL,
		0x3091D6B608976867ULL,
		0x3E57729572226AEDULL,
		0x6FFBC6E1A9DA8C0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x687DE8F3F5EF2B08ULL,
		0xA2034F912E309741ULL,
		0x3D1B42FFE029D6CFULL,
		0x1BAEE1BE85559B58ULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA74CE073871C2D78ULL,
		0x11FF213D4922F78FULL,
		0x23FE2B4EB4FB3A07ULL,
		0x67ABBF0F6222DFF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFCD50F4B85DA7D82ULL,
		0x4CBC55635E0BE3A8ULL,
		0xD70A5EE389D35C4AULL,
		0x650D7FCECF29A61BULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D6CFADF993414DAULL,
		0x1BD0389401AA38A6ULL,
		0x17DD966D71A52851ULL,
		0x2D91FF1D8AEAA99DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D6CFADF993414DAULL,
		0x1BD0389401AA38A6ULL,
		0x17DD966D71A52851ULL,
		0x2D91FF1D8AEAA99DULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3E7BCF57F006E3FULL,
		0xC22798D5722EA12AULL,
		0x0D58377A3BE84D66ULL,
		0x446156F28835CD4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x460FC0F986693611ULL,
		0x9E32C152D6010EAFULL,
		0x63642E6CA72A5FD3ULL,
		0x4BFE3858D5A74FB6ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1EA516628D829B5BULL,
		0x87FF66705F39A159ULL,
		0xEF09AA16AA65B78BULL,
		0x61979CFFF5B49814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x463B408A25C3FC55ULL,
		0xEC3FEA469534AF50ULL,
		0xE845B4701853C7BCULL,
		0x0D90491933C22FD9ULL
	}};
	t = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC37640160186E6D1ULL,
		0xF54587E7BCAA8DEBULL,
		0x84DE1E74FBD2FC0AULL,
		0x4A75ED369C7029BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3328314F13E5F9E3ULL,
		0xCEDD4C5ACA4FB8B0ULL,
		0x7A996CCDBA901917ULL,
		0x599258195259E8DAULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFA107EA2013E95CULL,
		0x64C5B36DDD15E447ULL,
		0x8FA368FEC2F43978ULL,
		0x15E70FE2A7112AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFA107EA2013E95CULL,
		0x64C5B36DDD15E447ULL,
		0x8FA368FEC2F43978ULL,
		0x15E70FE2A7112AD4ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C745F1DD0CE17EAULL,
		0xB09F8A3C0DECFB2EULL,
		0xF3BF6A447E2BA0E8ULL,
		0x0272C2DCDCBAC39AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x128942BF1ABE485DULL,
		0x274A6020814D69D8ULL,
		0xAFC3BD3551D3E18BULL,
		0x2013E896386E1704ULL
	}};
	t = -1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA742569DC7B85F48ULL,
		0x2BE828772F2CBEE1ULL,
		0xBE1333D4DB170DD0ULL,
		0x78D65496C6F80DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5DC9E1BF8A28819ULL,
		0xAE275D400EEBA172ULL,
		0x6D1BD85E012594E1ULL,
		0x3E7BD05B2A0B2573ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF52E431DBD5999A0ULL,
		0x75132FB31769308DULL,
		0x3CA933DFDE461B6AULL,
		0x76BBF6D18E493BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79D5C1F123FEEA44ULL,
		0x07127776747612D5ULL,
		0x78436B948D9B5CF7ULL,
		0x08635F9931EAC645ULL
	}};
	t = 1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x765E9492379E0F63ULL,
		0x2D92BFA7E5D5D15FULL,
		0x990C86368232ECC9ULL,
		0x35669924CCAA1AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x765E9492379E0F63ULL,
		0x2D92BFA7E5D5D15FULL,
		0x990C86368232ECC9ULL,
		0x35669924CCAA1AF9ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB482C8E204CDC1A7ULL,
		0xF55CA2379FE26D15ULL,
		0x66FCF7EBC4915353ULL,
		0x6C2DF26A63B2446BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDC31805827AC2FCULL,
		0x117A00E076C280B7ULL,
		0xD4F10719F614DB60ULL,
		0x4A6DEF4C3E5127CFULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC492BFDAFF1F6711ULL,
		0xA6AE5DCEA4165DE1ULL,
		0x708387BE3592A4B8ULL,
		0x406AC8A3C2A8C152ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x924422E561AAF15EULL,
		0x9BB8010E436E0B2DULL,
		0xF9080EA01EBE3D70ULL,
		0x53086FF2629B180BULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B02BCA779D42403ULL,
		0x8730A0F9FC901454ULL,
		0xCBAA87B9EF81A700ULL,
		0x64BC20A766B0A7C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA46E6FAAF9FDDA8AULL,
		0x52DD1E5C78B21317ULL,
		0x682E38ED410C7BF9ULL,
		0x1CB448317A13EA10ULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x485CACD4F4EAAF44ULL,
		0xC77BE0233EF08BACULL,
		0xEE0177B78E994F86ULL,
		0x0A76F3D37AD8C237ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x485CACD4F4EAAF44ULL,
		0xC77BE0233EF08BACULL,
		0xEE0177B78E994F86ULL,
		0x0A76F3D37AD8C237ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x15A531D5BAF23557ULL,
		0x2DC45CFDDEAED975ULL,
		0xC34AFA8BD76683FCULL,
		0x4ECC6801F96D502BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x693430D2C310F3ADULL,
		0x3DDAAB88EF812492ULL,
		0x1EF349000F43556FULL,
		0x0ED080596B4B7FA8ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D2629B98EB64045ULL,
		0x5D775430A753201CULL,
		0xA58CE3309E1CEB47ULL,
		0x29D238E8C7DC9A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC42121844C47081CULL,
		0xFF4013A3A91E5637ULL,
		0x75286CF15B527378ULL,
		0x624426ECAB720242ULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x12ECB6CFE683E9F8ULL,
		0xEE4D003F364340C0ULL,
		0x2E8E8D5415D1E369ULL,
		0x4255844010EF8852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E598C31DD03ADB4ULL,
		0x8F5B4DC1360FE97BULL,
		0xB73AACC9394C6F5CULL,
		0x0C0506997D1D0C9FULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF318C737B02BF161ULL,
		0x9AC8BA49F61CC240ULL,
		0x5FF391B3D5F074F6ULL,
		0x7E4674C067DF608CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF318C737B02BF161ULL,
		0x9AC8BA49F61CC240ULL,
		0x5FF391B3D5F074F6ULL,
		0x7E4674C067DF608CULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B4A11FC2CB00DA7ULL,
		0xDD486D0B5E606BCBULL,
		0x8BB6168446C6F44FULL,
		0x5C7F5F84DE4BF18EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD770A827675F2358ULL,
		0x0355C29065B25770ULL,
		0x2E0448B2EE60C9AFULL,
		0x0308BCC0BCDE4997ULL
	}};
	t = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E3226B2343C5760ULL,
		0xEBBA7C0635016359ULL,
		0xA209B7B6EB8DB2AFULL,
		0x57005A017D0BF0A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44D4FD96929C42B0ULL,
		0xC96230817203638CULL,
		0xCBB98ACD19F9BB27ULL,
		0x563A7D8B2B2E5DF9ULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5F9838DFAF406970ULL,
		0x25250240AAB4454DULL,
		0x941D808E4760E387ULL,
		0x59A12E23DEE312DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x123C8D79FE8264D0ULL,
		0xFBCC4FD2433F72B7ULL,
		0xC700AA6051D30622ULL,
		0x783E19A1D24BB0BBULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x579BDA1E3253A680ULL,
		0x55441F907F526409ULL,
		0x626C15E29E096735ULL,
		0x1D822786AA61ADE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x579BDA1E3253A680ULL,
		0x55441F907F526409ULL,
		0x626C15E29E096735ULL,
		0x1D822786AA61ADE2ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA188F35DB9F8A8FAULL,
		0xA1DD4E8D9AF405B1ULL,
		0xE3C4221864B5ADA6ULL,
		0x7D3DA25914FC6A53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB0C61908C7688B94ULL,
		0xC6FD776D4AD66491ULL,
		0x7F304478E8FBB12EULL,
		0x7275D664FF8C24AEULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x04D50A70B0940ADBULL,
		0xABD7C835A18DADB4ULL,
		0x62D0CADD46008E6BULL,
		0x3C7D5CCF0ABA95F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F35330E4F7CBF76ULL,
		0xA6DDEB411193733AULL,
		0x05DC40ADB5C2A289ULL,
		0x0F14158CF1082501ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFE8A699A46A0E51ULL,
		0xEDF842E302CE2EB3ULL,
		0x2AFD3D2568542F67ULL,
		0x1049F7D5081CA7E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAAE562BC19D70737ULL,
		0x7BC52BC8C97E18F8ULL,
		0x734B673F12BA91D0ULL,
		0x0AF3B5F0539744F6ULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A7A753E4DAED8F3ULL,
		0xF26614370CA81F80ULL,
		0x7A47371F5093A6F2ULL,
		0x53C93842B9AFC367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A7A753E4DAED8F3ULL,
		0xF26614370CA81F80ULL,
		0x7A47371F5093A6F2ULL,
		0x53C93842B9AFC367ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18FC7CA8B0CD859CULL,
		0xAD6C924863D35208ULL,
		0x22ACE7F405F143A9ULL,
		0x7861C655331E11D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x46DE013244542572ULL,
		0x8BD970C141CDCDF7ULL,
		0x56166A8BB356D451ULL,
		0x7EBFFDEC08504601ULL
	}};
	t = -1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x330E7FFEE40D3DBCULL,
		0x272594C7047C5948ULL,
		0x22807AE2B7E07C4AULL,
		0x3BEC62D3466AEE22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0556CD80A394F6E0ULL,
		0x45A264CE5581B42BULL,
		0x7DEC5B722A6D14FBULL,
		0x4833DFA90FAF6674ULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAA971D6F274DA424ULL,
		0x21C4E0C06E3A0C1DULL,
		0x493825B91C530DA1ULL,
		0x184680C7B132F991ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB55DFC54688BD11AULL,
		0x2D4AC12AE63E5AC5ULL,
		0xA661E5D279309AAEULL,
		0x6E9069713C6BC0C1ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18F38A8289DDC94FULL,
		0x185A56D78846CEE3ULL,
		0x457D61992ADE3506ULL,
		0x3D5EFBEBE888139DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18F38A8289DDC94FULL,
		0x185A56D78846CEE3ULL,
		0x457D61992ADE3506ULL,
		0x3D5EFBEBE888139DULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7402B20600C25585ULL,
		0x8CF4AF20F221E1B5ULL,
		0x08949FC5B9ABE8AAULL,
		0x72F41B58E9B01CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x839A5CB9B5383ED8ULL,
		0x82F36E707991281BULL,
		0x282681BD6086E973ULL,
		0x33AB72C3F69E246AULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x079FD54CC00B3994ULL,
		0x393F1951111D4F98ULL,
		0xC0E8775A1AC9B77AULL,
		0x065DCEA829CD1048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B19C9E693DC3B60ULL,
		0xAFE0E5301F945639ULL,
		0xB229C28F42CE7871ULL,
		0x78FD66EC5AE75549ULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x296B5374D6A54CC0ULL,
		0x2F85BCE96692D101ULL,
		0x76EC20C94BA6DA9EULL,
		0x24F7FB8D05CFBCFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EB0A3CE5099B429ULL,
		0xCD97FE7C4CF7DB9FULL,
		0xC3CBB4AAFA96E864ULL,
		0x4442F1A955D8E43CULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA49BDE0773B0DB0ULL,
		0x1A76353711914009ULL,
		0x185D092A6447F54FULL,
		0x1FD7D012D0F663BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA49BDE0773B0DB0ULL,
		0x1A76353711914009ULL,
		0x185D092A6447F54FULL,
		0x1FD7D012D0F663BFULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0C0417AB9674F53ULL,
		0xE7AAD8147AED8038ULL,
		0xA6A1CCB9B83DCB08ULL,
		0x3372533B0942BC4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D55B65A6F954A1CULL,
		0x9A513089A76EE8D9ULL,
		0x681924B693570559ULL,
		0x171BCC12085D2F2EULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA1DE8EFEC714449ULL,
		0x496B612319D1212FULL,
		0xC64846A2465536D3ULL,
		0x4C9841CE670D4949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4C8F2AFA015A1BD9ULL,
		0xFE976C7A9F62C3ABULL,
		0x462910FC15BC1C8BULL,
		0x297AC69B97DC6C47ULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x93123E94C4443E46ULL,
		0x84989C1F7C409505ULL,
		0x8DB85B60DEB10501ULL,
		0x3690CF9787FA53C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE887A42DDED15DB9ULL,
		0xE95BF37D7045C41BULL,
		0x6C920CBCBCA26E7BULL,
		0x0041FFD172E07C0FULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC50DF4B15B93B32CULL,
		0x1387A267FE68EC0BULL,
		0x65266B7E17923340ULL,
		0x44D9AAAB8F6534A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC50DF4B15B93B32CULL,
		0x1387A267FE68EC0BULL,
		0x65266B7E17923340ULL,
		0x44D9AAAB8F6534A9ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B0E4F68E1B4CE9BULL,
		0x736DECC49212DB04ULL,
		0x8596611B5E517477ULL,
		0x3252F3A1027D2704ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3B902169CCC2C4DCULL,
		0x944F173AC15BE110ULL,
		0xAE78283628417DC0ULL,
		0x38C44599F120CAD2ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD3D747C56E70B9FBULL,
		0x6F0ED1C4CF5393F0ULL,
		0x360D57B206C42410ULL,
		0x4A1C6A86FB470D39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x98ECBCAFF3D3992CULL,
		0x879858F2825A3A1FULL,
		0x5530974E2C752D6DULL,
		0x1F1D00A3CED1A91CULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4BE484735F9814E2ULL,
		0xE89D81C9920B2197ULL,
		0xE643445BB982732DULL,
		0x698C943AA88B2750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x277839ACAE8E0E77ULL,
		0xB28A8EF4248BD65FULL,
		0x4BD4366BAB6C9713ULL,
		0x136068E3B8AA7F28ULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01310BA3397BC821ULL,
		0xD51A216B49AFCDE5ULL,
		0x8432FDA141561FD3ULL,
		0x1E919899E0B64118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01310BA3397BC821ULL,
		0xD51A216B49AFCDE5ULL,
		0x8432FDA141561FD3ULL,
		0x1E919899E0B64118ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBE769489C8DEAE2EULL,
		0x4219377847AACB01ULL,
		0x0E4BEFB41991590DULL,
		0x621BA1E1B544E664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C97AAB69EBCF9EDULL,
		0xD72A763B2C66C062ULL,
		0x80473A8FA5D2D24EULL,
		0x3F26CD84F785EFE7ULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF0B6B2D66FBD2A5CULL,
		0xEBF45E85A4FA5E79ULL,
		0xA8DDF3699FAE8881ULL,
		0x298666050DDB8B1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEA9D8B2B6F9E76EULL,
		0xAAF9969F20274B55ULL,
		0x61511B800C60DB1AULL,
		0x313477B3A81460BAULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x008510A4F5F87BA7ULL,
		0x7542C55F380A9493ULL,
		0x4982A6EDC81E9C76ULL,
		0x22949ACA3C0F6E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF042B3C14299C48EULL,
		0xF869782E17B1E227ULL,
		0x881DD1F0890B6B5FULL,
		0x295093F447E6CEB8ULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A19F8B8A63E3DFBULL,
		0xB27F41531889742DULL,
		0xCEE3DE62B8EEEE70ULL,
		0x5FFBA9D887B2FEA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A19F8B8A63E3DFBULL,
		0xB27F41531889742DULL,
		0xCEE3DE62B8EEEE70ULL,
		0x5FFBA9D887B2FEA4ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x231959233D947AE2ULL,
		0x57B9942058B78BB1ULL,
		0x9AE9F515057B1711ULL,
		0x3E16B565891CA8DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x452A4DA18EBCC135ULL,
		0x7A8C89B1355474C1ULL,
		0x54C3C3634989378CULL,
		0x1DE9EB5FE3315B77ULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEC31252D911C5FFDULL,
		0x0D42CBEB68267E0BULL,
		0x28E617292EE66760ULL,
		0x288D303208FD9E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29C9DA93FF109293ULL,
		0xA4DF1788B917AC2FULL,
		0xB51CF4BC3CC14780ULL,
		0x78AE2E9661F5D557ULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB462B70EACDFB722ULL,
		0x2272F8C4ADBCB9AAULL,
		0xE9FF7EED5B216B94ULL,
		0x0ADC32BBE4467574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70DA5EBED1AA2203ULL,
		0x73271A52F37B0998ULL,
		0x8A4A76F028790322ULL,
		0x7EFF22E91A5F67F4ULL
	}};
	t = -1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x91088EC2E3A1707EULL,
		0xFD494EEF47D84CC1ULL,
		0xA88BBBF5FEE6B632ULL,
		0x20D4A83A61F6F089ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x91088EC2E3A1707EULL,
		0xFD494EEF47D84CC1ULL,
		0xA88BBBF5FEE6B632ULL,
		0x20D4A83A61F6F089ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFAE1A133BCBF54A6ULL,
		0xAC1205C893333E32ULL,
		0x02875B019F8C95FCULL,
		0x6F4CC5AD703BC12BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB025FB06A7089ABFULL,
		0xFCF688D675EB41F0ULL,
		0x90A1753478E4758DULL,
		0x120F456BC75E5C2DULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9731D98A28E07B53ULL,
		0x81C2242CDD73300EULL,
		0xC19FB9C1C0EDC33AULL,
		0x4D3DF6D17312B5D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x72F2B805C676F79BULL,
		0x547BE9BEF93FBE89ULL,
		0x357BD4CC1E7C3FD7ULL,
		0x4C155CAA98552754ULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE05CD463B3D208FDULL,
		0xF861E28F766CE580ULL,
		0x8FC5471AA8ADE892ULL,
		0x71DC365188B913D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5BE99B561F217A3ULL,
		0x2C0B97B796E59A7BULL,
		0xA92D950DDDDF9321ULL,
		0x59DA3493C11AEE01ULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x195E33CF63678741ULL,
		0x1D10D17F57242237ULL,
		0xAABC0B5279ADDBE8ULL,
		0x33119609196EA2B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x195E33CF63678741ULL,
		0x1D10D17F57242237ULL,
		0xAABC0B5279ADDBE8ULL,
		0x33119609196EA2B0ULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F55B8D00F1DAABDULL,
		0x1A9453ECDB2FC959ULL,
		0x2061EC820144C732ULL,
		0x6A2F8E4AF5C9BAD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x160DFF80A9F52BCCULL,
		0xB886502379ED4F92ULL,
		0x01523BAF7090584BULL,
		0x78138FE7E6207CE9ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x481DB1ADA9189FBEULL,
		0xAE1E9C88B5EA60DEULL,
		0x49C6EF683DD0D603ULL,
		0x5DA08273D66C6F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5697814ED3944AAULL,
		0x8F94B4DD64B74966ULL,
		0xF78ACAC946CAEE57ULL,
		0x5FD520CD93BB1346ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x366A3D9D26999F42ULL,
		0x784E239976CC1F83ULL,
		0x2FDA50633E16EC40ULL,
		0x7B6ED7C74073395DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9086147E2C4E13C4ULL,
		0xC12CAE7BA339E314ULL,
		0xC4D0EF7B0E9744D1ULL,
		0x26E2F1077018CB56ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53026BECE92BF13CULL,
		0x8BACBCD5E10DA445ULL,
		0x63E040F4E2784796ULL,
		0x30BB1CC41C8030C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53026BECE92BF13CULL,
		0x8BACBCD5E10DA445ULL,
		0x63E040F4E2784796ULL,
		0x30BB1CC41C8030C9ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x289AD3D5038D4C3BULL,
		0x758A5BD4B3D6B936ULL,
		0x9D82C7080A3145DAULL,
		0x1B04B72D85674BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x81026A88F5B2F770ULL,
		0x42CCBB3E73164ECFULL,
		0xF7F2BD2E1EEC7CBBULL,
		0x3505B11300F7434BULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x74968D9489CFAA58ULL,
		0x46D3FAEF5ED86BD2ULL,
		0xC467864638DE195DULL,
		0x06F0D27380E1C726ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB52223037A13EE33ULL,
		0x2C8D56A6375C07B4ULL,
		0xA41CB15CCC8BE8CCULL,
		0x4D63C2018406F3D3ULL
	}};
	t = -1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA4766E0C21E0678EULL,
		0xE3091A704C717657ULL,
		0x018F4AEA64416B71ULL,
		0x5CD4C846C2515B4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x060AE3B51BAA4EB9ULL,
		0xC3C57FE79C96A8E5ULL,
		0xA79F1A07F195CF3BULL,
		0x57645275D0234FA0ULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA904D490E19684AULL,
		0x7EC3337C1297A95DULL,
		0xEBCAC47E357E9D64ULL,
		0x36AA4F2C40F3D7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA904D490E19684AULL,
		0x7EC3337C1297A95DULL,
		0xEBCAC47E357E9D64ULL,
		0x36AA4F2C40F3D7BFULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4C7E491EF1F2C42CULL,
		0x0D0A5D06B8C5FFECULL,
		0x3D837683482AD968ULL,
		0x491FC10C0F603E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D52B51EB90DF070ULL,
		0xE7CD37D582FFEC48ULL,
		0xA6A5608E4E580573ULL,
		0x3C5A89F18C2ADBBCULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x81B2560F7C5BA84CULL,
		0x95FE5F9776347955ULL,
		0x9C560649E215D6C7ULL,
		0x76E8A090AE096070ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2F03F8DA3A82834DULL,
		0xC7196E7AC673ACFDULL,
		0x814024E75A1E58B1ULL,
		0x3D7F64F931062213ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x72741D2B543E5B3CULL,
		0x9A359E9D0C130B66ULL,
		0xDA3DB831A1B829A8ULL,
		0x241E6B5452E472ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE01DC3F79A8FFDADULL,
		0x6503939F231B3E26ULL,
		0x2C1035419E62D099ULL,
		0x4DC9C5D12CB3C3D6ULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD968C5CC9DC6729CULL,
		0xFFC971EC4C947260ULL,
		0xBF12A84898BD29D8ULL,
		0x069D46738A5BDA9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD968C5CC9DC6729CULL,
		0xFFC971EC4C947260ULL,
		0xBF12A84898BD29D8ULL,
		0x069D46738A5BDA9EULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEAB3F74F6EE643BCULL,
		0x5A4E76D48273157DULL,
		0x53482A5C674CDC06ULL,
		0x56CA6556E085CAA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x799E5AB457F9023FULL,
		0x6ECE835C857BAD62ULL,
		0xBDC767BC0D40B5CEULL,
		0x2C3E2462191EF029ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44E38076F401BC6AULL,
		0x4B86FB44512E4EB6ULL,
		0xED0B05828F49D19CULL,
		0x45A56AAE9B84802CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F5E3CE54A3D91D2ULL,
		0x7F382F81802248BAULL,
		0x35CF89A00614C2B8ULL,
		0x3122D448626DF28AULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x629BDC2E8E325850ULL,
		0xA6AB16ED839C855CULL,
		0x28C7AF2A06F3C667ULL,
		0x6A94645A05757E61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5FBB0FFE1250DEABULL,
		0x543C4753042D78A3ULL,
		0x4959CFE9E1D24B94ULL,
		0x64B6D22A3EAC26F7ULL
	}};
	t = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x536E3D6A5AC4E047ULL,
		0x2C8658EC7EE5E98DULL,
		0x58CCCE97B5ED48EFULL,
		0x6FB2F5410CC3035CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x536E3D6A5AC4E047ULL,
		0x2C8658EC7EE5E98DULL,
		0x58CCCE97B5ED48EFULL,
		0x6FB2F5410CC3035CULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC8DD20F97295092EULL,
		0x8AE51CB9A587D056ULL,
		0xCDE345DC00919EDAULL,
		0x68116FD52E907938ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD0396A6E9F31B43ULL,
		0xA154E12A8E0368B1ULL,
		0xF7E62BDB16B1E3B1ULL,
		0x254146EFE32C1E52ULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A55619EF2BE080AULL,
		0x7D88D9595F0074FBULL,
		0x8A3793E22854458AULL,
		0x16C878FAF9E4C5F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A13DBE9F9CD22C2ULL,
		0x5BF8A6BD348FBC02ULL,
		0x1006656B11DC783EULL,
		0x46428E1B8A8615CAULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7E84F48709F7211ULL,
		0xF3BBF0DE002F778CULL,
		0x29BBE2C2E1635E45ULL,
		0x7C69EDF3C890E86FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6C393FD7865D81A2ULL,
		0x006629AAFECFDF0AULL,
		0x288D136844AC6474ULL,
		0x2CDB84FA8E61EF6FULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0E3111DA34BC0337ULL,
		0x9F0926B39EC55A30ULL,
		0x36F3284A1818BB15ULL,
		0x12E128438A8FEECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0E3111DA34BC0337ULL,
		0x9F0926B39EC55A30ULL,
		0x36F3284A1818BB15ULL,
		0x12E128438A8FEECCULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BB23B53E0B7800BULL,
		0x091C7ADBC85226B1ULL,
		0x4100288711D1E1B4ULL,
		0x440F2F653CFAF9B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D0436612AF15DD0ULL,
		0xEB4F0772CB6A1186ULL,
		0xDFC925A34B5B2DDAULL,
		0x21FDB43048E32A0CULL
	}};
	t = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83A3EE435907E9D3ULL,
		0xC619779CFD1E4A37ULL,
		0xD11363C248C51C8BULL,
		0x0905685B40BD3980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x987C4C630E341276ULL,
		0x541BFFEA33E1759AULL,
		0xCD05766B23FAC996ULL,
		0x3DCFEF5EC9F1B110ULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F8FDF88FE66B80CULL,
		0x708B44928C928A47ULL,
		0xCF6FE93DE54C6C70ULL,
		0x546651C50C41AF2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x38DFCB460ADE3064ULL,
		0x14E23C10E39ACC27ULL,
		0x04DECF318E9B407EULL,
		0x7B9B6A3127A68F41ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58C231A8C32A926CULL,
		0xDE8E75D1E65F35E9ULL,
		0x8D3034A99D0FBD8DULL,
		0x4394E7A052CED392ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58C231A8C32A926CULL,
		0xDE8E75D1E65F35E9ULL,
		0x8D3034A99D0FBD8DULL,
		0x4394E7A052CED392ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x76913FAD3DA82B0CULL,
		0x86E3E0475C131861ULL,
		0x5100FDD6BD74AFB3ULL,
		0x414F4F6A6F39AF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x136B6FCCEACB0922ULL,
		0xE326B981225AE606ULL,
		0x3AFE0842CAE588C8ULL,
		0x2E216014CF84738CULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBBB4D4940BB2577FULL,
		0xE4EA0F4B0EDC5163ULL,
		0x414CB3CB155CCBBFULL,
		0x2F656753FB424DB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67A4876425834114ULL,
		0x57FDBBBF17B06DAAULL,
		0xE011314076FFD9E6ULL,
		0x09D0ED6300A881A0ULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0A2C98910C2EB674ULL,
		0xC79C6BD31579AEF1ULL,
		0xD30196DC99B28619ULL,
		0x7414262FE558D7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x219974A2172C324EULL,
		0x2936AE86414996A9ULL,
		0xCBAFEF0D058BF7EEULL,
		0x7E8CCE2BC7B10BDDULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDEC65D48EE849B7BULL,
		0xF62A8FCA4084165EULL,
		0xA891AA15F4156FB1ULL,
		0x7024DB2E4E95B6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDEC65D48EE849B7BULL,
		0xF62A8FCA4084165EULL,
		0xA891AA15F4156FB1ULL,
		0x7024DB2E4E95B6C5ULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x94D18546AEC52196ULL,
		0xDA989706FE531CE1ULL,
		0xE714B5C2998A5BC5ULL,
		0x409C2BCE9664F0A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BFB816C6AA70851ULL,
		0x1712B349DE456A77ULL,
		0x6FCF9F8D8526CDB3ULL,
		0x3885BFA4A7C92BD1ULL
	}};
	t = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4FB8A6F3DE326344ULL,
		0x4E9E806E266B7A13ULL,
		0x8C9820C8965FB82EULL,
		0x463946C0A2763EE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA45AA2C7BA3682B3ULL,
		0x2ACE3D8BEF1820E0ULL,
		0x0D2B3FD7F635B007ULL,
		0x26E0A7BFA3AB8ABEULL
	}};
	t = 1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F287DF935FDEEBFULL,
		0x559876C76679060EULL,
		0x7A719E994A64C0F8ULL,
		0x66C041F4E15DF287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x450A2E50A20779F3ULL,
		0x7F646E70381A4978ULL,
		0x8DF782A1F223CA4AULL,
		0x5E8C76A2D94A39BEULL
	}};
	t = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5F65E7F1CCF55A0ULL,
		0x16E727368CE27179ULL,
		0xAC63672438960CA1ULL,
		0x30342119EEB891F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5F65E7F1CCF55A0ULL,
		0x16E727368CE27179ULL,
		0xAC63672438960CA1ULL,
		0x30342119EEB891F6ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE74D3C39A30CEF0CULL,
		0xF05A73E3903DD319ULL,
		0xFA997FB3D31D1CFDULL,
		0x055F95A1ADE35E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1EF30442D9D0FBA1ULL,
		0x738CE1EA63E9588CULL,
		0x294744FDE17EF9F2ULL,
		0x4765A69A2C9C278AULL
	}};
	t = -1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01BE94BA67534814ULL,
		0xE54D380A46C10719ULL,
		0x19B5A83218D80C08ULL,
		0x46CB7986BBD73C9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD72A45ED394E6D5ULL,
		0xD687F2270A5766CEULL,
		0xF62288787B53EB7AULL,
		0x619D15B8DAB1ECF6ULL
	}};
	t = -1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4568FE4EE43E20F7ULL,
		0xC87BC6994B28897DULL,
		0x1263A7B9E71E26F0ULL,
		0x5FE483F13E7E5AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00CE60AE129E4920ULL,
		0x34405E79790100F1ULL,
		0x1581BA0F2384B0EAULL,
		0x4229074B2F5C57B1ULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD035462E45F719F5ULL,
		0x34F691552D21972EULL,
		0x1937E01B65319EBEULL,
		0x12C285AD8B23C599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD035462E45F719F5ULL,
		0x34F691552D21972EULL,
		0x1937E01B65319EBEULL,
		0x12C285AD8B23C599ULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x671398C8EB71452FULL,
		0xB33032991C342547ULL,
		0x5FA48F447B9377DCULL,
		0x01DA331F80CF3A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD598BDF1810571F2ULL,
		0x94EA1BCD9B4E6116ULL,
		0xD2A8308B2B3B92BFULL,
		0x7228BD94A3043AB7ULL
	}};
	t = -1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6969117632CFA98FULL,
		0x6E0516E612F49BE1ULL,
		0xBEB0B1BB81A4B8E3ULL,
		0x05B2189FF731BA7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8258F7C5136DD9E3ULL,
		0x82BF90DE0CE8F9DDULL,
		0x1F31555192A85858ULL,
		0x167AE24F4C558C1CULL
	}};
	t = -1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x72080294B8428BD9ULL,
		0xF720876473C77F6EULL,
		0xCA18BF2818E3E4BFULL,
		0x66082B57E315C534ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x08490574331B9BAFULL,
		0x354D9CEF623CD522ULL,
		0xD4B2444030182AAEULL,
		0x109AC323523A8CA9ULL
	}};
	t = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4713475D92205AD1ULL,
		0xBC1DA9D85363B29AULL,
		0xA437CEF281E3FFC8ULL,
		0x157AC2B1DF3C19BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4713475D92205AD1ULL,
		0xBC1DA9D85363B29AULL,
		0xA437CEF281E3FFC8ULL,
		0x157AC2B1DF3C19BEULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x51690F4B02D86601ULL,
		0x4336619548B13235ULL,
		0xC4934301F9F66BE2ULL,
		0x4C0D5584FAAF8F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF3549FD3D7EE60C0ULL,
		0x43D201B6D1F228CAULL,
		0x4DB3B30A1F2BBD12ULL,
		0x7641CC27C647978FULL
	}};
	t = -1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x914CC6330C4BE737ULL,
		0xA0C958D755C64FF5ULL,
		0x6BEC3F092ED435ADULL,
		0x16F572CBDCC34020ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x28AAC791A7355605ULL,
		0xD0526A67461727E0ULL,
		0x82BC19780C52E243ULL,
		0x4E597EC23F8CCC3CULL
	}};
	t = -1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC405CE1CC1C70A5AULL,
		0xA004BA0C4618A8C4ULL,
		0xDF54EB9A9720F2F3ULL,
		0x54F5F5EB3157380AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1816C9F348913DFCULL,
		0x738171F33EBAA391ULL,
		0x6125061B1818A092ULL,
		0x750D92556620DAB9ULL
	}};
	t = -1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D251CB640B306B9ULL,
		0x1952D7F9885C41DFULL,
		0x38293C5ED577CA65ULL,
		0x59B7827B0EB52B75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D251CB640B306B9ULL,
		0x1952D7F9885C41DFULL,
		0x38293C5ED577CA65ULL,
		0x59B7827B0EB52B75ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4BDC9791A4EC51D1ULL,
		0xADCD4EDC59F0CC5FULL,
		0xB7EB512CE9EEE627ULL,
		0x3DB808949326AA06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x983604652C3ABCEEULL,
		0xEE89FEA76E225907ULL,
		0x0D4ACC8C1C7240E3ULL,
		0x692B73BAF071D159ULL
	}};
	t = -1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E3ADA07FC48D919ULL,
		0xBE73497C0BEB0B6BULL,
		0x9C45CD2C4302EDDAULL,
		0x2AF420015749525DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x48C89699D7604B47ULL,
		0x9478DBA2E6A6E43BULL,
		0x0C5184817F165C7EULL,
		0x3D00928B8F7C4B86ULL
	}};
	t = -1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDEA5481D43A767B9ULL,
		0xE6F4CA04D8D5F337ULL,
		0xDFAF9FC19FC85F0BULL,
		0x763AD152598FD429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x153EDACB4D7DE3B5ULL,
		0x1393ADEC001AC6DFULL,
		0x8DD7154BC902BAB1ULL,
		0x1839AF8B54AF3DA8ULL
	}};
	t = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA077C1C85C6B2DBCULL,
		0xC006255DA566CFFEULL,
		0x418D25E3BC6B714BULL,
		0x08058DCBFAFC76C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA077C1C85C6B2DBCULL,
		0xC006255DA566CFFEULL,
		0x418D25E3BC6B714BULL,
		0x08058DCBFAFC76C3ULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D100E3B58AC7563ULL,
		0x7FD134E4825FDD75ULL,
		0xF34A7E1CC7594E25ULL,
		0x4C812E5A896DC0C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A6A306838161029ULL,
		0x97D197A1D84F60C5ULL,
		0xDDDBFF27BA9C94E8ULL,
		0x67D75A24E4837353ULL
	}};
	t = -1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5C08029C49CEC05AULL,
		0xD4C10C4E798A04E2ULL,
		0x7FFE671665C47B65ULL,
		0x5EA3BD0F9777B37AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x416252C422A87C03ULL,
		0xA06E3B53563AEF65ULL,
		0xF7BE7974812E7C0AULL,
		0x1785065132DDB607ULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF78A618E27D16E84ULL,
		0xAAD70221541F9C1EULL,
		0xDEDAFA4C49679BDDULL,
		0x3756C2129A88E288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xED13B559C95DB6B1ULL,
		0x49A34CA93E69BE7CULL,
		0x96D99E77011F7F5FULL,
		0x2454496FC0160D51ULL
	}};
	t = 1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x27234567CF839B71ULL,
		0x1898A5D1F91E7203ULL,
		0xD296ACF585084337ULL,
		0x03C0C4373533D3CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x27234567CF839B71ULL,
		0x1898A5D1F91E7203ULL,
		0xD296ACF585084337ULL,
		0x03C0C4373533D3CBULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD3EA4E84BC3E320FULL,
		0x4008883A67BD16E5ULL,
		0xAA040B385537A43BULL,
		0x2F57A8F5C91EB181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2AE2EF901379D27CULL,
		0xFAA37065265AE7EDULL,
		0x21BBC1C2A1F52CFBULL,
		0x17AE4BAD40F938CBULL
	}};
	t = 1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6DB89D54D8E8505BULL,
		0xFFC232E2E61C30E1ULL,
		0x4E51253B264264F9ULL,
		0x7FDB5F44E8D28333ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x254131D502E4A50FULL,
		0x16613A311C940401ULL,
		0xD3AD064E13E0F17EULL,
		0x25FDD39EF2A5AE35ULL
	}};
	t = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5EE5C33A50611D78ULL,
		0x1C0D293F350AE24FULL,
		0x76F4C197E43569D7ULL,
		0x07D112907FFFB694ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF07FAE7CC38A1A5FULL,
		0xF03DBEFEB0FF321EULL,
		0x36855D68B3AE1FF6ULL,
		0x2E83836EC00F8A1EULL
	}};
	t = -1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA4C845B8D237A93ULL,
		0xC9D74EBA51A7AF29ULL,
		0x6BA53B803C061462ULL,
		0x281457B7FE8D9BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA4C845B8D237A93ULL,
		0xC9D74EBA51A7AF29ULL,
		0x6BA53B803C061462ULL,
		0x281457B7FE8D9BCFULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53D75F3E4C4328CBULL,
		0xE69A6182196EF19BULL,
		0x44F895FCDB70BDFFULL,
		0x2FE05EDBC372DC75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E374E4BEEFE7019ULL,
		0x7FE2EB0DED79B369ULL,
		0x21B6126EE6CD9E70ULL,
		0x3F7EBEAEB66A4F8CULL
	}};
	t = -1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCBC60BC3E0B53BB9ULL,
		0xD7F7C2BD65F1A93BULL,
		0x801037F6F3232CD5ULL,
		0x775CE1BBBECCA958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5AFE489C2B94A70DULL,
		0xEE3FB723EC7B4BF9ULL,
		0x123B9CFDB031EF96ULL,
		0x03BDF8C15333B6CEULL
	}};
	t = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x31E10F92EB0BD340ULL,
		0xEAFD32EBC5064A07ULL,
		0xF801AFDE39941A72ULL,
		0x08292813A58B9DEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA27658D2B8B6CE63ULL,
		0xCF40BE79A6B727E6ULL,
		0x728E81DBE3BAF5FDULL,
		0x5A5D71B2A79F665FULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7DE6C91155CFA5F1ULL,
		0x8E4E83F935F1D150ULL,
		0x99506ADCF930078FULL,
		0x039009966B6ADEC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7DE6C91155CFA5F1ULL,
		0x8E4E83F935F1D150ULL,
		0x99506ADCF930078FULL,
		0x039009966B6ADEC8ULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC46F3FFA31CDB13AULL,
		0x182C0FD08F583990ULL,
		0xFB77F381EA5A5A28ULL,
		0x26B625694FB79490ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE12D1E3050869435ULL,
		0x8FA73EFE98BC0685ULL,
		0x65549273C1E405E8ULL,
		0x2B2351FA05D5712BULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB11428B79C6F1EACULL,
		0xA083FCD4E5DA10ABULL,
		0xC66443A635974895ULL,
		0x780E434EB0B582FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x36E02AEDA3130704ULL,
		0x80150A1326C394C3ULL,
		0x9EB27F1624E3866EULL,
		0x46A48305FB3E8438ULL
	}};
	t = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7B9554F84ACBAA3ULL,
		0x7E5D2C319B32515EULL,
		0x63C59A2772CD8382ULL,
		0x3A0804F8A7B70CEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE585404CF497083AULL,
		0x2B4AE819781A1EC5ULL,
		0x5488482420D36C74ULL,
		0x200199FCF3AD4115ULL
	}};
	t = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA54B39F4DF94BF1AULL,
		0x6F735CB7C398AAE5ULL,
		0xD16E028FEC2FB2E0ULL,
		0x58C0F5F89151F7D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA54B39F4DF94BF1AULL,
		0x6F735CB7C398AAE5ULL,
		0xD16E028FEC2FB2E0ULL,
		0x58C0F5F89151F7D2ULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6A9EBC7D79421BCAULL,
		0x0AE2EFF5B5642991ULL,
		0x37B8310CFF30566CULL,
		0x442424FD52906FBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A943A65C09C6692ULL,
		0x7E8E4D294A8A1A45ULL,
		0xB7F26916CE87BD57ULL,
		0x25E8745790BBADEDULL
	}};
	t = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62E9B9F9AE3E0C9DULL,
		0x044FD679ED1A8E6FULL,
		0x88BF084E9EA7F628ULL,
		0x72146E96E33CEF4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6B6374C7C01F6BFULL,
		0xFE50982578BCCAE9ULL,
		0x51D0E9682C37D0D1ULL,
		0x22E4F32F75497328ULL
	}};
	t = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC803D26ACAA6708CULL,
		0xA08041B472407698ULL,
		0xC8F1F3949711458DULL,
		0x327DDDCD8239E5ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5F967F95D0D93CB3ULL,
		0x54C9929690E2EE38ULL,
		0x62307C478409FD3BULL,
		0x5A5B6B8A434F9104ULL
	}};
	t = -1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC10C8B7EC4ED7394ULL,
		0x01B1EED42BD31040ULL,
		0xDB209C3DF6DC0FC4ULL,
		0x7B4CCC4BFD2A8961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC10C8B7EC4ED7394ULL,
		0x01B1EED42BD31040ULL,
		0xDB209C3DF6DC0FC4ULL,
		0x7B4CCC4BFD2A8961ULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62B7A6FCE5D3E169ULL,
		0xBAC0A54CFE3ADCCBULL,
		0x04622CE15B4F6F6EULL,
		0x729D132B8A40E68BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5AF0D5A8D5FEED5ULL,
		0x89C2AE8850AD859AULL,
		0x6187C26AD2D2E890ULL,
		0x669B5ADB88A11353ULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6E929F380FC293A9ULL,
		0x0DB64A9C2877FB43ULL,
		0xFF0675578762F7DFULL,
		0x45C3957B222F3373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F2DD7B902E81D79ULL,
		0xCC657479AC26A423ULL,
		0x6F260B368A2239AEULL,
		0x60A79482E706C087ULL
	}};
	t = -1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFE8E5A47153DC217ULL,
		0x153453B543A7B50DULL,
		0x5F819C0CFD21D2BCULL,
		0x7C7CCCFC522A426BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B8BE72BC7441B6EULL,
		0x199BB8D456E50554ULL,
		0xA49C3575E899C0FEULL,
		0x213FE011B7685FECULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BF2E0E52694E23BULL,
		0x95257589B7B0EF44ULL,
		0x5989ACDA63611DE4ULL,
		0x39383534FEF51870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BF2E0E52694E23BULL,
		0x95257589B7B0EF44ULL,
		0x5989ACDA63611DE4ULL,
		0x39383534FEF51870ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8FECD7A4C961F514ULL,
		0x3528EC3ACD071F83ULL,
		0xFABB00167E44FE94ULL,
		0x3FA0AE65020FB1CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x626C2AFB9ACF6B25ULL,
		0xBCDE5C1D3834531EULL,
		0xA90608EED16CB7A5ULL,
		0x6C13A6EB347E96D0ULL
	}};
	t = -1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09DB989C7D0DB0C4ULL,
		0x3826F4939C264EE6ULL,
		0x557D3F84D9E7B4B7ULL,
		0x026587B087EDDA42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF1195F0D909D623FULL,
		0x8F77EFB536D486A4ULL,
		0xAC0CC09C575565CAULL,
		0x02EEA2D2D77A4E14ULL
	}};
	t = -1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x91E8D075974F68CAULL,
		0x80A931577CD369CCULL,
		0x2182D47DCFE0B981ULL,
		0x37843C526E6159CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAAD3AF3330B285E8ULL,
		0x20DDE213616F62ABULL,
		0xD116464E7E4BDF42ULL,
		0x79E13140717B2487ULL
	}};
	t = -1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x38340730C378D636ULL,
		0xFF30E074339C7311ULL,
		0x7C0C96CBA533F100ULL,
		0x7DBEFAEE94641A00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x38340730C378D636ULL,
		0xFF30E074339C7311ULL,
		0x7C0C96CBA533F100ULL,
		0x7DBEFAEE94641A00ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B63B2811A0D92AFULL,
		0x972CD2B59FF54A22ULL,
		0x90A6DC232D9E190DULL,
		0x1E4D3A3E3DF5B9ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x36984C16488D8FAFULL,
		0xB8AD19D004741A56ULL,
		0x53956EABEF20EEEBULL,
		0x1A2765A26E7C0BB5ULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA2C6E33545497D1ULL,
		0x7B23975EC382F54AULL,
		0xCAEF6EEDB446B6C7ULL,
		0x2DAE9093B40C9AEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45EDC44F8EC0F875ULL,
		0xE4375FF2F920F855ULL,
		0x297EF58FFA8B4FB2ULL,
		0x578CD63323008820ULL
	}};
	t = -1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC58FACBD373F9F9CULL,
		0xB482C6D413C6FC01ULL,
		0x8BEB3113612A565BULL,
		0x662E5B47EFFCDCFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x555E78A7D585A68FULL,
		0x4D741379826FE3C0ULL,
		0x230A2B5D8C52B9EBULL,
		0x1060390B737DA12BULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB2A50DB832E3E3A6ULL,
		0x210A089117AADA91ULL,
		0xFBEDE9FBA686E6F3ULL,
		0x62B3382209BAD58DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB2A50DB832E3E3A6ULL,
		0x210A089117AADA91ULL,
		0xFBEDE9FBA686E6F3ULL,
		0x62B3382209BAD58DULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF7968A94E2D979E6ULL,
		0x84C278EC1E268864ULL,
		0x8E2263419A89A8B1ULL,
		0x23A98747B6387768ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E34A59400ED3EDAULL,
		0xB01521EB6F0D2C21ULL,
		0xA379D6F19230D09EULL,
		0x03AF9C4ED6F251B2ULL
	}};
	t = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3FBE57507D15E140ULL,
		0x034B029A32F7CCAEULL,
		0x34132134951B6BE7ULL,
		0x0C3F011A387E0FCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4793F7D45540F49AULL,
		0x2E6BEA36C47202B7ULL,
		0x1270C6B9C347C50CULL,
		0x71FF0A42E1CF8189ULL
	}};
	t = -1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x37F8BB1E196FEF95ULL,
		0x300E87BC26222FDBULL,
		0x4E2696F748BF95A7ULL,
		0x527933AFEB6498DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF84EBBECCB08084DULL,
		0x885A5C08313AD71DULL,
		0xC4C900EF4BB6A6F6ULL,
		0x1C97E6032CF4584EULL
	}};
	t = 1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD4CF2E4C719D5FC5ULL,
		0x0FB3B5593E31DD0CULL,
		0x0FAADE6B9BD011A0ULL,
		0x02ACB8CE5F5E984FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD4CF2E4C719D5FC5ULL,
		0x0FB3B5593E31DD0CULL,
		0x0FAADE6B9BD011A0ULL,
		0x02ACB8CE5F5E984FULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC355091B5C3EF450ULL,
		0x72D534BAED3E3C94ULL,
		0x65E58BD3C3145836ULL,
		0x782500C2FFE69416ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC1BF6CC70032143CULL,
		0x9C3B609910D070C0ULL,
		0x6ACADF7A91318246ULL,
		0x411CF5B14BC6772FULL
	}};
	t = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84E5244721E9C6F2ULL,
		0xA5BAE924D2CE1C38ULL,
		0xCED329DA1DABD2ABULL,
		0x0CE6EA7DC3703DEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D1460D2041F8C8AULL,
		0x21046EBD3F206DB2ULL,
		0xB99AAD06594BBB9DULL,
		0x424522F69CA53722ULL
	}};
	t = -1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC89133FDB67470DCULL,
		0x74E5C1F647B7BA4BULL,
		0x76D6EA8D60332D86ULL,
		0x199756F94EF01AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75FA03EADC17A82AULL,
		0x75E31ECF7726C3EAULL,
		0x0A5D66BA45050CA8ULL,
		0x0F22C1924D8EC72CULL
	}};
	t = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7427785B98BC2B20ULL,
		0xCCA819D599B06D2FULL,
		0xD95324BCACCD4D59ULL,
		0x0890E36839BFE2E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7427785B98BC2B20ULL,
		0xCCA819D599B06D2FULL,
		0xD95324BCACCD4D59ULL,
		0x0890E36839BFE2E6ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A0D58094BE24361ULL,
		0x9027882E9EC144E6ULL,
		0xCC3E522DFDA5EF52ULL,
		0x2DE8EC2E82A4280EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD31DDE4569ECE07ULL,
		0x68A78D8DE5ACA435ULL,
		0x0E805D4151F8B774ULL,
		0x7320C6E928B4C898ULL
	}};
	t = -1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBAC2B6A54EDF83C3ULL,
		0x0DCB795958A25D13ULL,
		0xE398332B60B3A6E3ULL,
		0x58A5797740D73241ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x229B0CD5AFEB960EULL,
		0x46FED987C79DFA67ULL,
		0x0D8FE276D65AB10BULL,
		0x2D63B0F85BD120B8ULL
	}};
	t = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2019AF68F5E4F7C9ULL,
		0x35CE94C71DA1E18FULL,
		0xB99535B975B64E53ULL,
		0x1680CE15D2A73026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x657E4DE27F5B9D02ULL,
		0x22934C28A44C1885ULL,
		0x27A12969E9E2F6A9ULL,
		0x534E07009783A4F1ULL
	}};
	t = -1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B500F898AB99125ULL,
		0x9B435EC1A2D3D023ULL,
		0x1E7348BB31B3548EULL,
		0x16FF7FDF07A494FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B500F898AB99125ULL,
		0x9B435EC1A2D3D023ULL,
		0x1E7348BB31B3548EULL,
		0x16FF7FDF07A494FCULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC2DA382C98C6968FULL,
		0x3C0306FB5FA3B631ULL,
		0xA2C3384A9159FE56ULL,
		0x3161012B9D8B404FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x02BFAF3C12608A86ULL,
		0x663C912281349515ULL,
		0x51B7EE3127A9F408ULL,
		0x5F6871950990E770ULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x975B8EE4E1BF244BULL,
		0xD62E0444ABF658B9ULL,
		0xC07D58A27F60918BULL,
		0x234301DF19D19ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9D4230A05E26C7C9ULL,
		0x3F3E4963768E5747ULL,
		0x3C12283123D791C0ULL,
		0x1CED1120AE98DE92ULL
	}};
	t = 1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC0CE98029A4D1B71ULL,
		0x280B7FFEE7E5069AULL,
		0xC7F89D3C9E4C99E3ULL,
		0x76BA4F59612F1C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x82D622BA4489EBC6ULL,
		0xF634760050B11426ULL,
		0x906AD8CE7369937EULL,
		0x14FF38004A714D2BULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x632A25885E7E3798ULL,
		0xBBF9995CDFCC8795ULL,
		0xED05E928959AEE97ULL,
		0x437D04070868D74EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x632A25885E7E3798ULL,
		0xBBF9995CDFCC8795ULL,
		0xED05E928959AEE97ULL,
		0x437D04070868D74EULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x414E404A495D807EULL,
		0x5FFC8621072B691EULL,
		0xCB939A4B331B1816ULL,
		0x1202D0C7809BDCAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7537CBB41B0C5125ULL,
		0x4ACB7839B0F5C45AULL,
		0x504B1EC0F8AD4B2DULL,
		0x6077D478206046D8ULL
	}};
	t = -1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x823BCA97F349F47AULL,
		0xA09FC6D431EE7C77ULL,
		0x79DFA8526066D1DCULL,
		0x6A765894B480671BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8400652055426E1AULL,
		0xF5AE7C801CDA291CULL,
		0x8A583BCAFEB9E324ULL,
		0x04E94A4E83945C82ULL
	}};
	t = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3B6D41D58352A55AULL,
		0xAC45BA52B8424C46ULL,
		0x706A45CC6B4045F1ULL,
		0x1DE56BD58E3C7FB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE12D74B2AD391FACULL,
		0xF157B10D5175B76AULL,
		0x5B06D1F5A3A2A74DULL,
		0x067AFC39C62AEB6DULL
	}};
	t = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29C9EADFC68E5179ULL,
		0x375E0B662BE208F7ULL,
		0x43000A5C9DD54CF1ULL,
		0x45199581F9DC6CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29C9EADFC68E5179ULL,
		0x375E0B662BE208F7ULL,
		0x43000A5C9DD54CF1ULL,
		0x45199581F9DC6CDBULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EE7721C86FB4981ULL,
		0x3B845804E21628D1ULL,
		0x49BA5B23A5EE3C7DULL,
		0x4000E26AFD61AC71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CF079069BB3B751ULL,
		0x35810059AD451E0FULL,
		0x24E942EB7C450158ULL,
		0x0C82EA9DF83F88A7ULL
	}};
	t = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x52644AD624240C90ULL,
		0xB81E0346DB7D24D6ULL,
		0xEC61707743B32CF0ULL,
		0x7A1C6E8B0A0A92BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA052D55B0E156A75ULL,
		0x72D266FF4612F4F9ULL,
		0x0101887C95AFFA73ULL,
		0x3BFBFEF3D12A6E02ULL
	}};
	t = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x202EB89157DFDD1FULL,
		0xF53F2EB56ED38A90ULL,
		0x0A98AEC58507E0D6ULL,
		0x4C3DBFC5D31679C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x621A7DE09C62E7E9ULL,
		0x67D488DAB1991047ULL,
		0x5F4502CC563BC94CULL,
		0x3927233939CF8833ULL
	}};
	t = 1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06E6EB375775E139ULL,
		0xD07770E7999595B7ULL,
		0x8A95A84DE6822726ULL,
		0x144B2604C09E7A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06E6EB375775E139ULL,
		0xD07770E7999595B7ULL,
		0x8A95A84DE6822726ULL,
		0x144B2604C09E7A80ULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC73EECDCA8B73D6ULL,
		0xD92754067F23E214ULL,
		0x0967CFBFA4D4232BULL,
		0x597E2937271F48F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x592F9C6E016600B5ULL,
		0x00C71A0B3F3B2EAAULL,
		0x5CBE8D0465A97659ULL,
		0x3D8A0392B131A5C2ULL
	}};
	t = 1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66B9ADBB9458ED35ULL,
		0x9EA02874AC296913ULL,
		0x71F660129707AF73ULL,
		0x084DA7351DF779E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2874BA52E381E524ULL,
		0x189377F3DD453587ULL,
		0x94269DFCAB302134ULL,
		0x6A121F48D8F9B5A1ULL
	}};
	t = -1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D40D7239DB8ABA1ULL,
		0xF861F7A0F53789F0ULL,
		0x1263E73F2E99E7EDULL,
		0x5DC190AE8E3D2205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB54A3F6C2F7A2C0DULL,
		0xF85A95043DB7F942ULL,
		0x4ECE0077C4B703CDULL,
		0x50B22D5FC99EF786ULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x408B0C022634D168ULL,
		0x32FCBBED15A38352ULL,
		0xEB1541153A6BD4AFULL,
		0x3D82EA390D614C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x408B0C022634D168ULL,
		0x32FCBBED15A38352ULL,
		0xEB1541153A6BD4AFULL,
		0x3D82EA390D614C43ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20C18562E659ACB7ULL,
		0x9F1550E40C1FB8EDULL,
		0xC34CEE4C3DAAA790ULL,
		0x7252DCC51B1A91FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEE49E5E0191A4E3DULL,
		0x5EC47C0F010F7C4DULL,
		0x6B56E2B52FA81C5AULL,
		0x7908D7CA6F324B9DULL
	}};
	t = -1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA6A408A534136F7EULL,
		0xECF7BBCD6ED6E4BFULL,
		0x3E43705EBE16FC9DULL,
		0x03DDEA25AEB9D9CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD372F2B0D8117C3ULL,
		0x2C34E27B84C1F5D4ULL,
		0x72BA4D1A45B5E3CFULL,
		0x30407F13080E9147ULL
	}};
	t = -1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2148F823F9AA2760ULL,
		0x94E83AD7CF50C0AAULL,
		0x5D01FB09DC0C1F0AULL,
		0x33D5D9EA5C680F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA2D44821A65B073CULL,
		0x612E557A6D27A227ULL,
		0xD539CAC645ED36DEULL,
		0x7331FE26808ECEDCULL
	}};
	t = -1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CD41747257E6B03ULL,
		0x97A962C2205EEE42ULL,
		0x6F2629C48A627E2FULL,
		0x76616A6B89FB31EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CD41747257E6B03ULL,
		0x97A962C2205EEE42ULL,
		0x6F2629C48A627E2FULL,
		0x76616A6B89FB31EBULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x50E3D021FAF80771ULL,
		0xE7704CB5553C27F6ULL,
		0x02A2D36254B5DB8EULL,
		0x731AC4EBD7471F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDFF9FC381316DC9ULL,
		0xCAD69BAD91E4B6E1ULL,
		0xF0BD0734E0E39187ULL,
		0x409E4030E498DD0AULL
	}};
	t = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFEF66601A9B9A68ULL,
		0x010EF68ED5ACC87BULL,
		0x494913A3954F1760ULL,
		0x3323AFFA678F8EADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF8DC8D2EAC083E87ULL,
		0xE5278DFBEE10575DULL,
		0xD5F9BF5D651D3566ULL,
		0x3CCEBCAEB7A0F0C5ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x301A3A06603BE6C2ULL,
		0xE348C65DE188D607ULL,
		0xCCDAE4ABD6D92EBDULL,
		0x29D084050F2708D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00C0D162F4BF1DCFULL,
		0x6D0EA2FE999EF7D1ULL,
		0xE0FEA3E41DEC5DA5ULL,
		0x736AE1852CC62488ULL
	}};
	t = -1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9FD0A6CAF9EF919ULL,
		0xB77A9336522683B8ULL,
		0x19FB36DF24548DB4ULL,
		0x3694A2DFF7965BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9FD0A6CAF9EF919ULL,
		0xB77A9336522683B8ULL,
		0x19FB36DF24548DB4ULL,
		0x3694A2DFF7965BB2ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE9BCBF3B25398341ULL,
		0x9BBC0325B1B57D2BULL,
		0xC2DDA2274F8E18D2ULL,
		0x01BE2DD85A76349BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x463CCF8EB7C4F354ULL,
		0x9BBB1A97BED32DC1ULL,
		0x809EB13FFABC8568ULL,
		0x444535705389556CULL
	}};
	t = -1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9C3D347EC6559FFAULL,
		0x3497E22806E92430ULL,
		0x74BB26606EF4EF91ULL,
		0x1E60FC42D54C2CD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC3A07D1DD1FD4C30ULL,
		0x5F9BB3BD0EEC4735ULL,
		0xBEABEACBAE8E9522ULL,
		0x54B85A14DB86DD1BULL
	}};
	t = -1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5DA6E18C7FD2BD0ULL,
		0x2F642C8154E2884FULL,
		0x8C87B4495430CD0CULL,
		0x6DD87B74576B9C32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9424774041B6FC0AULL,
		0x524CF21F95170E84ULL,
		0x113E161ABF76DB31ULL,
		0x3CCCB9F25AF07808ULL
	}};
	t = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE39E70406847CE8EULL,
		0xB2E58FC1AF34519CULL,
		0x4172F4444934A19CULL,
		0x0B99F75CF9584DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE39E70406847CE8EULL,
		0xB2E58FC1AF34519CULL,
		0x4172F4444934A19CULL,
		0x0B99F75CF9584DDAULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC66E76CDF4917107ULL,
		0x2818FCBF4EA07209ULL,
		0x44B4D178E058A334ULL,
		0x3179E0700574B9E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB73BB0AA91E36F8ULL,
		0xC0D36AF7777D23D7ULL,
		0x1619869DFE5B65FAULL,
		0x799E8C2B10380942ULL
	}};
	t = -1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA6C41EF01722757CULL,
		0x4C0274B905EDC55EULL,
		0xBC42F529714533D1ULL,
		0x32BC24EF6A8718B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB328F2AA85CFDF8CULL,
		0x75846E003F60E80CULL,
		0x6C9DC8647B5D1A10ULL,
		0x4AA7ABAD034E0E92ULL
	}};
	t = -1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8BE2B3B2318B7F96ULL,
		0x653AB9AA5424F82BULL,
		0x674E0A9B172A4889ULL,
		0x1A9B92445ADC5C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C9D94172A6BF146ULL,
		0x1E60D400AF0E1D88ULL,
		0x75A997E1B699081DULL,
		0x7A43143919A908A6ULL
	}};
	t = -1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4F4D8221D36FED7ULL,
		0x8879E5382D352794ULL,
		0xD3CFA77827DA1F74ULL,
		0x7DDCFFD89168171EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4F4D8221D36FED7ULL,
		0x8879E5382D352794ULL,
		0xD3CFA77827DA1F74ULL,
		0x7DDCFFD89168171EULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6E8B9C63B21A7744ULL,
		0xDFEF947CBD652CFFULL,
		0x616154B79AE2427EULL,
		0x4E327474B22016C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x92AC119A7CFE8590ULL,
		0x2C3DA2825DE53951ULL,
		0xDFB2F30E12B97D8AULL,
		0x76C061BF1D5DFA95ULL
	}};
	t = -1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x598644CD8A5509C4ULL,
		0x64AE731A561808CBULL,
		0xDFED9323795114A0ULL,
		0x53A233ED1BBB9783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6537B1E993D522F0ULL,
		0x404171B147FAD76BULL,
		0x64E771C295F3BE58ULL,
		0x2E337B9AC7CC1376ULL
	}};
	t = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0155497A456C8FA4ULL,
		0x6888C784D878F748ULL,
		0x73ACA1254A6A8110ULL,
		0x423E4574D4AFF983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE6D546430F65363AULL,
		0xED980860FDB61AB6ULL,
		0x7836AFD87CE606F1ULL,
		0x0A3112F633A79457ULL
	}};
	t = 1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84A17800A0462DFDULL,
		0x410BC178C87EC6B6ULL,
		0x3B570E160831536CULL,
		0x214024024595F087ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84A17800A0462DFDULL,
		0x410BC178C87EC6B6ULL,
		0x3B570E160831536CULL,
		0x214024024595F087ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6B3F8EBFE7B80FE1ULL,
		0x7C3EFA408A76F19CULL,
		0x6AF9ADA8C56286B7ULL,
		0x2601188246DAD85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEEBBD62A9DC966DULL,
		0x6080AAF48911E429ULL,
		0x99E8A8A3C535A09CULL,
		0x7A4510E864B2D008ULL
	}};
	t = -1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2047CD1B9193359BULL,
		0x1EEACC183785242DULL,
		0x0ED36FB1A1478538ULL,
		0x4C6A30F364E3E02AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA540AECC9C4729B7ULL,
		0xC0F990E846522DD1ULL,
		0xC5C4D7C1460DB990ULL,
		0x4D22D3984FA62561ULL
	}};
	t = -1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x282E1AE3BC9E528FULL,
		0x9635A6FFC3E8C1BFULL,
		0xA114372DD629009EULL,
		0x739AAED20598A4E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD6C8EE3F43FD36DBULL,
		0x66F753FC3B064E77ULL,
		0xE2A3C05E9459E00DULL,
		0x2466FBB8D256ADDCULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x31F21B5B33BD71E1ULL,
		0xE16BC66442E2533DULL,
		0x74116E00405B6084ULL,
		0x508E1149FB6E8867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x31F21B5B33BD71E1ULL,
		0xE16BC66442E2533DULL,
		0x74116E00405B6084ULL,
		0x508E1149FB6E8867ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF3732A4D8AE87EC2ULL,
		0x59A4AA8B8F4625CCULL,
		0xA48381421ED3E9C4ULL,
		0x2093A8043C810876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE487ACBBE89ADAB6ULL,
		0x587D8EEB4C798C03ULL,
		0x7A6E02C0DC2FCED1ULL,
		0x2ABDCD7B8E6E6ADAULL
	}};
	t = -1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE3CF647F5170AB2BULL,
		0x255622F737FBA988ULL,
		0x4D8D18A3A50FD89AULL,
		0x095F62142BCA15B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0F8ECB869EC6C69ULL,
		0x0E7FAC6EC8677E53ULL,
		0x3D7B971482BBF62AULL,
		0x20C2DEE4FBD2BB9AULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD2D3898E3F6CF0FDULL,
		0xE304A104B220DF7CULL,
		0xB759C83B6064F4C5ULL,
		0x693C40A9BB64A6BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7641D986E7440B3ULL,
		0xF2D2CCFA06D55ECAULL,
		0xA3E3FC136F469A3AULL,
		0x344F6628E351CC7BULL
	}};
	t = 1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E0909298C450E14ULL,
		0x80C025CC0D239E8DULL,
		0x08E527C4EC6C81DBULL,
		0x286C17C1358B7438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E0909298C450E14ULL,
		0x80C025CC0D239E8DULL,
		0x08E527C4EC6C81DBULL,
		0x286C17C1358B7438ULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE9BFD86171261E59ULL,
		0x392B4809A6A9AE5EULL,
		0x1E2AE3756CBC7837ULL,
		0x62D3E8D55081B580ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C735677F75604A0ULL,
		0x117D313308B4CEFAULL,
		0x3E873E1943B6C273ULL,
		0x16E12344BF0314E2ULL
	}};
	t = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF9C2C15E8B4C4E72ULL,
		0x39255C9E9711B70CULL,
		0x75B7B7359C0CAC5DULL,
		0x54F77A4FC436E48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2CD76D72B3D1B0BCULL,
		0xC1FB123FBB86694DULL,
		0x7F6492FAE8CAE1B7ULL,
		0x46C44306B89FCE12ULL
	}};
	t = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CF984B34D544120ULL,
		0xB9729AF6BCBE86A2ULL,
		0x9D63CA23C985593EULL,
		0x03D6B597B21E82ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7208060A52037443ULL,
		0x34A896E328A6B780ULL,
		0xB32202B6E31B25B9ULL,
		0x7EFD13BA50F86E10ULL
	}};
	t = -1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7CBBAF979C38148ULL,
		0x88724E192D74E684ULL,
		0xDBEAD6720E755A91ULL,
		0x6AE4FE279808BB74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7CBBAF979C38148ULL,
		0x88724E192D74E684ULL,
		0xDBEAD6720E755A91ULL,
		0x6AE4FE279808BB74ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A6285597C09BC6AULL,
		0xD2ADE41390A612DFULL,
		0xA61F584727B149FDULL,
		0x2D4670234597E5C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7894083A7FF97831ULL,
		0x8C9B6800870AAC95ULL,
		0xF72EF07D9CE54498ULL,
		0x70142CF039CCE433ULL
	}};
	t = -1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4EF8DFDB4C6A0B4BULL,
		0x721ADC1A72CD2CFDULL,
		0xE1B905E0330CB77CULL,
		0x181A8AFD79FE75FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E86B4DF39DE408EULL,
		0x4299CBABA7756250ULL,
		0x35A6FFA95F1EA121ULL,
		0x56D403B7C389FE29ULL
	}};
	t = -1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x644F987F27D0651FULL,
		0xC602B49B20EA3E73ULL,
		0x715ED2536543035FULL,
		0x3FD97B6B91D19811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x81D391BD4ED6252DULL,
		0xCD66A1B7D6D69A4AULL,
		0x17323A7B10BB7782ULL,
		0x1EE56BD2ECFF88A9ULL
	}};
	t = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBFF065F26F789FDULL,
		0x11DDD19B1FC78585ULL,
		0xAE99B2A448E5F070ULL,
		0x4B16F3CCC18AAACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBFF065F26F789FDULL,
		0x11DDD19B1FC78585ULL,
		0xAE99B2A448E5F070ULL,
		0x4B16F3CCC18AAACCULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2295A07C232FC3FULL,
		0xA3CBBC7038459C2FULL,
		0x54EC5EF12B89C8B4ULL,
		0x36685F7F59E5CB51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA04F397967576F5AULL,
		0xAA53755FDF2E48D4ULL,
		0x4CA002D874C352CEULL,
		0x439FAB8C98D8DAD8ULL
	}};
	t = -1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x764053C76E6FB5A7ULL,
		0x5AB4B4D456CF9A87ULL,
		0x97C419E846ABB9D2ULL,
		0x73035717C67ED482ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5F43C073FECDC483ULL,
		0x7EC11687EC458181ULL,
		0x0BBD7BDABB2C410EULL,
		0x1C6CC75A22EC86FCULL
	}};
	t = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8530BE0CF6A1DB46ULL,
		0x6A4757AEB7545B52ULL,
		0x86CFA46A9E022B15ULL,
		0x3F4D61D8198FA0ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x73B4D42679DBE54DULL,
		0x8A97D726F01E4647ULL,
		0x52109D9D3123503AULL,
		0x65F0B3F6CF8F78B2ULL
	}};
	t = -1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4809678A33D7F48CULL,
		0xB49BE99A65C5D424ULL,
		0x19ED831091E984CCULL,
		0x75E4964314F1AE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4809678A33D7F48CULL,
		0xB49BE99A65C5D424ULL,
		0x19ED831091E984CCULL,
		0x75E4964314F1AE09ULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6743A3BB0620C857ULL,
		0x50D3C69E5F251D65ULL,
		0x0DC2E5BF0586A775ULL,
		0x32C442FCC43BAC6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA50572546A0B64DCULL,
		0xBF71707975CEBBE7ULL,
		0x2F7B4C03E00384D2ULL,
		0x3048E8AA80BA8921ULL
	}};
	t = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x591B139FB363BC5EULL,
		0xD1268F5A94103889ULL,
		0x28AD5D0768A0506AULL,
		0x421165879B0BA218ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4492B849F9EAC46BULL,
		0x3D0D2D9D6B24F8ABULL,
		0x742C3F388C9FA648ULL,
		0x2385DDFF848F3863ULL
	}};
	t = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFDEA76479EC7DE2FULL,
		0xF352B670D63F1C60ULL,
		0x1DBE5F28F9D9C82DULL,
		0x4401A37FD7CCCD93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC50BD688D39319EBULL,
		0xE19822A5D81F0DF2ULL,
		0x907BF10A0BE6BA9DULL,
		0x236F6BFCA2A62FB5ULL
	}};
	t = 1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CD09BF8AA40ACF2ULL,
		0xEF6F3E8C8E3A7C70ULL,
		0xD0FB08847BDF81FDULL,
		0x02DEFCC200E6EAFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CD09BF8AA40ACF2ULL,
		0xEF6F3E8C8E3A7C70ULL,
		0xD0FB08847BDF81FDULL,
		0x02DEFCC200E6EAFAULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD6E03A4CBB654A0AULL,
		0x9E27C025C6DA0927ULL,
		0xE3900B4E7CE6B145ULL,
		0x37CC1197840718B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7DB746639B31F67BULL,
		0xAC97F5C5D406A3F3ULL,
		0x835D9AA8F3111ED4ULL,
		0x660326A6B2D56EBBULL
	}};
	t = -1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75172919E7AF0CA8ULL,
		0xB64EE5A657024742ULL,
		0xBCB155D48EBC3880ULL,
		0x6063ABDBE8B53172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E43E806CB1B6752ULL,
		0x52C54652035CA7D4ULL,
		0x52B1A2E91C72953AULL,
		0x0A0C611165B7BB4EULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0069DF6459429DDBULL,
		0x45EF5C66EC5565ABULL,
		0x03E70BED955A3D2FULL,
		0x022CC12C4F7AB38AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x71AF1A5A662805CAULL,
		0x1444FDA8CEF6DAF2ULL,
		0x119B5A93405E4351ULL,
		0x7DCC74AB0C289658ULL
	}};
	t = -1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFA02E9789285566FULL,
		0xCE54A40695510BD3ULL,
		0x174F5A50F86581EBULL,
		0x2C52764BFBA35F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFA02E9789285566FULL,
		0xCE54A40695510BD3ULL,
		0x174F5A50F86581EBULL,
		0x2C52764BFBA35F95ULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEB85066FE83BE87FULL,
		0x660CD337F13CBC8BULL,
		0x2B2E70878446B913ULL,
		0x72615E398FE36AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44C6AE9307266151ULL,
		0x7F8CA3326F7F5CE6ULL,
		0x9AD38036DCB1C95CULL,
		0x2F0FC5CEABF30646ULL
	}};
	t = 1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC3E6655D70918500ULL,
		0x626746E8C5CCCFFDULL,
		0xC53023261547D42FULL,
		0x5290F4679A95C20EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01699CA579121652ULL,
		0x2DC5C8501862C041ULL,
		0x510759262662D01BULL,
		0x50B713E0742C568EULL
	}};
	t = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5925E2132155DC9ULL,
		0xAE995C04A584A0D6ULL,
		0xD8F9A6C1F6EE48C3ULL,
		0x2DCDCED9ECBC102FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA79E2DE1F47B4D4ULL,
		0x36C9769565A11378ULL,
		0x5AAB317375DDAF58ULL,
		0x5DC1F65F304400CEULL
	}};
	t = -1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4CA432BC4A0BA6DULL,
		0x0B7B4D2B4C90C552ULL,
		0x34C5354E0FA4A44EULL,
		0x448F9EF50EA752B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4CA432BC4A0BA6DULL,
		0x0B7B4D2B4C90C552ULL,
		0x34C5354E0FA4A44EULL,
		0x448F9EF50EA752B8ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x61335D596FCF0926ULL,
		0xDCA6F33BD3D9AB2BULL,
		0x7F141943A320239DULL,
		0x493AFC644B8C8EB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF4329D697AF63930ULL,
		0x758BA0B30A18D834ULL,
		0x91B4BC048605A562ULL,
		0x0B569F17FBF883B6ULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE1789857969E61D2ULL,
		0x613FC05CB96B38EBULL,
		0x6A361676CE035359ULL,
		0x7A919D33F871DE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33139DA287AA2BEBULL,
		0x13FF229B8D78C7B6ULL,
		0x772A66F9DA0053C4ULL,
		0x2718F8D7C710686CULL
	}};
	t = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x735A77A9ECD3B5BBULL,
		0xE0BB85CEE613B8B1ULL,
		0x2D09BCA9D0999A93ULL,
		0x66DB87EF182E7E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF18F5C63FD5F688ULL,
		0xFD1E6AD82C1E1A10ULL,
		0x77EC268452B513F4ULL,
		0x54E4D48AE351CBAFULL
	}};
	t = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2AF31172F678C936ULL,
		0x713AC6B7959B30AAULL,
		0x2F5FB29D1F142110ULL,
		0x77BE64127AB9E6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2AF31172F678C936ULL,
		0x713AC6B7959B30AAULL,
		0x2F5FB29D1F142110ULL,
		0x77BE64127AB9E6FEULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x03986640A2D9DF9AULL,
		0x91CFB0ED4B54FE93ULL,
		0x8ECC6EE396088AD3ULL,
		0x1CACAF2D008D3D0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1A334DAF71BEB97AULL,
		0xE8C193AD6086A787ULL,
		0x0E47FD2F228647D6ULL,
		0x201FE2DC2654BEDDULL
	}};
	t = -1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9C70C062C905FF5EULL,
		0x51B7CADC3460696CULL,
		0xEB8CB0BF013C0116ULL,
		0x7581191A54383567ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x963C64234DCF0602ULL,
		0xC51E1EA5AE7722BDULL,
		0x403EAE2EC54E8435ULL,
		0x519B292E213B99A4ULL
	}};
	t = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x95D92C1ED49B32CEULL,
		0xA092E8066974F95BULL,
		0x6BA0BC270182B8B8ULL,
		0x0274F517812D1343ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x40378EE32F4D09B7ULL,
		0xA33908C966B581D4ULL,
		0x2B1BC10C976B393CULL,
		0x0EC512B12B71D695ULL
	}};
	t = -1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49831600E9CD66C1ULL,
		0x948DEC72FAA11448ULL,
		0xBC2970D24AB18A16ULL,
		0x579D837EC0661CCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49831600E9CD66C1ULL,
		0x948DEC72FAA11448ULL,
		0xBC2970D24AB18A16ULL,
		0x579D837EC0661CCFULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B46451498FDE736ULL,
		0xC0CCC0050A249903ULL,
		0x73D2FA43B414B070ULL,
		0x1FDE959434E5CCD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x815F7A28765A304CULL,
		0xCD50DFDDE6051DCDULL,
		0xCD0A34008E417AF9ULL,
		0x29D7135E0ECE6A2BULL
	}};
	t = -1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4DF58FCD61A3A3A0ULL,
		0x2BCC0F65DBB2C00DULL,
		0xC9E187219D50B6CAULL,
		0x56298A7CB45B1885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x584C904F67D7C0F7ULL,
		0x3DC5FBF201196DC1ULL,
		0x795FD97D0C9C1524ULL,
		0x42926D51B3680F10ULL
	}};
	t = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x55AA95DD8946829DULL,
		0xCCE506C7FBF46BD2ULL,
		0x6262DD02018F0CA7ULL,
		0x5A5484D977D61384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4BCC5DBC30E28EFULL,
		0xFDE7C347CA2382B6ULL,
		0x1E5536F280DF6717ULL,
		0x15D3E9383B0BE826ULL
	}};
	t = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7009872E7D387620ULL,
		0xB0C3AC268826C6F9ULL,
		0x8F486422191F751CULL,
		0x7DF1C85D2B018A42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7009872E7D387620ULL,
		0xB0C3AC268826C6F9ULL,
		0x8F486422191F751CULL,
		0x7DF1C85D2B018A42ULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83A3719F8FD434B0ULL,
		0x8606DC1E9679AA4BULL,
		0xCDAAE4FE9D6EBDFEULL,
		0x4819552861F6FF3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8555BCF09ECCF4A2ULL,
		0xE00C94180C7C6D0DULL,
		0xDD36F3235C261FECULL,
		0x4018B43AB62518C4ULL
	}};
	t = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1CEF11FCD2C86A2ULL,
		0x257F2DEA68D713F1ULL,
		0x27D96D3B459AEBE7ULL,
		0x1F027C23D7D48A18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58C14CE8D6041914ULL,
		0x675C5FD9795BDC16ULL,
		0x5EF6E715D67C687AULL,
		0x3C4EBADF080D51E2ULL
	}};
	t = -1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9ACFC8F3E0B89A8BULL,
		0xB200E45A1D7D354AULL,
		0x7796CF3897401A38ULL,
		0x2786203FF36A0015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4809C4BF34ED5B61ULL,
		0xB24DB31A646F88CFULL,
		0x189CE1F16AFAA02CULL,
		0x40D0615970540EE0ULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0CE345DB45C7D012ULL,
		0x9C2BB4BEBAB1BBC4ULL,
		0x05ACE5DBAC7B9BEDULL,
		0x3E1288CF91B2BC76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0CE345DB45C7D012ULL,
		0x9C2BB4BEBAB1BBC4ULL,
		0x05ACE5DBAC7B9BEDULL,
		0x3E1288CF91B2BC76ULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD175EC0A73064FBULL,
		0xB12D67B172FF7105ULL,
		0x191F58FB30B07336ULL,
		0x175B5547A6166F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD9D3D1C1BEA31AB3ULL,
		0x7E2BCA8854BE0A16ULL,
		0xD5632C5C0C473209ULL,
		0x7F122CE7379EA9AAULL
	}};
	t = -1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3C1A3CB2A00654C4ULL,
		0x3533195E8585B207ULL,
		0xD614FB82E9B92406ULL,
		0x6CE2C847A46F6D13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E42FDEB626504B7ULL,
		0xEB223D0A52FCCBB1ULL,
		0x77B43CB6893AE676ULL,
		0x1C47F5986EC0A342ULL
	}};
	t = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x352F6F45EA3A4BC3ULL,
		0x00EE717BB2B6A32EULL,
		0xFD976AA84DC1FA93ULL,
		0x6FCDFF095C0F4777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE52926C9614C250FULL,
		0x519F5CF42F8961EFULL,
		0xFB7A470A28461176ULL,
		0x06203F5C4FF6FDAFULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E4A0C906D0C6AACULL,
		0x8212192C7C800200ULL,
		0xB0AB402ACF64792EULL,
		0x027278DB62312254ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E4A0C906D0C6AACULL,
		0x8212192C7C800200ULL,
		0xB0AB402ACF64792EULL,
		0x027278DB62312254ULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF28BF1A654F62127ULL,
		0x0ACDC0781784A8AEULL,
		0x15FE66719976D072ULL,
		0x42DB93520CCE4CE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3A4FF67820E8286ULL,
		0xAD849EAC931B7D8AULL,
		0xB7BC977A23F30A3BULL,
		0x52F906ED618CE6ACULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6E94EC88DB0AB20AULL,
		0xA18B3DABF0A7FE2DULL,
		0xF32EE7F82A5A275AULL,
		0x6F4E7B81A406A146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x05AA1B61150B36ACULL,
		0x34A6546B519CDDA0ULL,
		0xA30BBE698362A3EAULL,
		0x4D7F413062228A65ULL
	}};
	t = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1CAB9C6F50CA637ULL,
		0xB118339E8A893103ULL,
		0x9C207F093B7CBEB1ULL,
		0x789276BA271B163FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C3CCF9C559D4393ULL,
		0x5608F93C29310BD9ULL,
		0xD41B759D89E6214EULL,
		0x1011C2BD66EC20BFULL
	}};
	t = 1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE00357DC99919654ULL,
		0x5FC6C1C5FDFA5FADULL,
		0xE5A9C653BEBF0842ULL,
		0x1EC7123C7BF04F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE00357DC99919654ULL,
		0x5FC6C1C5FDFA5FADULL,
		0xE5A9C653BEBF0842ULL,
		0x1EC7123C7BF04F0AULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEEA892FA37AF0D76ULL,
		0x5622A826116BC19AULL,
		0xF46E7FFAB9C141C2ULL,
		0x4ABB934BAC042B9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF3751EAD038CB334ULL,
		0x82348B792AFC84E1ULL,
		0xFBB92D7A99650B77ULL,
		0x30D39C99F4F18162ULL
	}};
	t = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0147097F0978F9E3ULL,
		0x7F68355A3FA8DDB0ULL,
		0xC1896A19ABB163FDULL,
		0x064E29DB1C3D2672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEE8C45ABBBDEA7D1ULL,
		0x84E82FA4F982D41EULL,
		0xD36F01C3BF3F942FULL,
		0x0AC10A5230FE2CA5ULL
	}};
	t = -1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDE7735475B574CEULL,
		0x1004FDE1DE479265ULL,
		0xF769A023D0EA03B5ULL,
		0x39B481FDF797FDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87A48009BE11F79DULL,
		0x586538FEAF4E56EAULL,
		0x01A403E875D33AA4ULL,
		0x733D01CCAB908FE2ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20A6C18EC1549C52ULL,
		0xF7DBFB9F7181A111ULL,
		0x13FDF3F8885E5B28ULL,
		0x719E5842A47C314DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20A6C18EC1549C52ULL,
		0xF7DBFB9F7181A111ULL,
		0x13FDF3F8885E5B28ULL,
		0x719E5842A47C314DULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8AB9EB800FD725F1ULL,
		0x37254F843C23A38DULL,
		0x73B30D5DB88822F4ULL,
		0x244F436A1FDFD025ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5180411E7364E405ULL,
		0x20C4305517EA5D82ULL,
		0x303D943287DC1FDAULL,
		0x180229041FFA2778ULL
	}};
	t = 1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x50371E86FE7944F2ULL,
		0x441AB6050475C96BULL,
		0xDA40A9CAFA3AF596ULL,
		0x68A202D98F363382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBAC13320EA761799ULL,
		0x949FBE9B131FE45AULL,
		0x8967F1BF5CF42B1DULL,
		0x5453A31D645D52F0ULL
	}};
	t = 1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA15D5D2B7A486A2ULL,
		0x740DDC6F84F9ED16ULL,
		0x8D5E8D6D4D69D73EULL,
		0x7CE132C5299801CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8DEC37DD27F3EF6FULL,
		0x36A6B7A4DD31B0B6ULL,
		0x801F5A9F47CF91D2ULL,
		0x413B0E08897C716EULL
	}};
	t = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6B27FC71658BEF3EULL,
		0x91E1AD5EF2231887ULL,
		0xB1588696D00CE3CEULL,
		0x5A28358D4B7F1647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6B27FC71658BEF3EULL,
		0x91E1AD5EF2231887ULL,
		0xB1588696D00CE3CEULL,
		0x5A28358D4B7F1647ULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD3E4B35C9BA9C2EULL,
		0x8A3737E43F50614EULL,
		0x29B375802D59E824ULL,
		0x05F83E212488340AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x22D16B81F3EE3C47ULL,
		0x810B88C4E5489950ULL,
		0x68355C98B0DF0C9FULL,
		0x202D36690B6ADA49ULL
	}};
	t = -1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x94249CCDD739FE38ULL,
		0x12580ABD3BC726A2ULL,
		0x3A5D653AF419B976ULL,
		0x14C1148E9209919AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD1C54BD764600077ULL,
		0x9E6DFB2B1FD4BD40ULL,
		0x94F8263705A77518ULL,
		0x1B398437734DB1DEULL
	}};
	t = -1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CA79E5DC05CAD66ULL,
		0xF3B9A46B0D53A397ULL,
		0xA1B91BC65841159FULL,
		0x2CCAA0B37D92F7B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F0DDA967DE4BEC2ULL,
		0xA2FDFC7FFE2A662EULL,
		0xA1D8698D1CF93FB1ULL,
		0x35DD0F81A1FD0394ULL
	}};
	t = -1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x753D5AD4470828E9ULL,
		0x52FA11143819D135ULL,
		0x760CBBD08413C8CEULL,
		0x1BB78CB2788A9126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x753D5AD4470828E9ULL,
		0x52FA11143819D135ULL,
		0x760CBBD08413C8CEULL,
		0x1BB78CB2788A9126ULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA71830A5F351E9C0ULL,
		0x2BC5F1F3C855064BULL,
		0x8D93CA508A1AA287ULL,
		0x4F2BBB5914086A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x648651B4D4DBBE9BULL,
		0x357E77B90D58E218ULL,
		0x4F83A3BE8E74347DULL,
		0x593F24688AF20CA4ULL
	}};
	t = -1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7EFEFAE9075907AFULL,
		0x1A53002557A2F549ULL,
		0x1A2175AB25B071D4ULL,
		0x6AEE4EE6C2B4E59BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5B17A269CDE14C77ULL,
		0x390E4EB1C425CE43ULL,
		0xAEBF58D338F2A64CULL,
		0x6F81E1C4D24F6BF0ULL
	}};
	t = -1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x08548818A41C8981ULL,
		0xCAD79D4E9EAB5761ULL,
		0xB02EEBF5BF38F443ULL,
		0x0C68A0D8C9704C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD031422BB61AA375ULL,
		0xFB179714B4B97671ULL,
		0xA2BCBF7084D777F3ULL,
		0x5BB052A154A41CB6ULL
	}};
	t = -1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC7757B907B6E7ADULL,
		0xA3947B1D71924BCDULL,
		0xF454D9CFEB6430A5ULL,
		0x1562748BD906C3F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC7757B907B6E7ADULL,
		0xA3947B1D71924BCDULL,
		0xF454D9CFEB6430A5ULL,
		0x1562748BD906C3F7ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x92705657BCE36A64ULL,
		0x5108D9CD28B8EA05ULL,
		0xEE5F4E23CB8DB93AULL,
		0x6E66F0C65B016B2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6423937102010C4AULL,
		0x6700A27B9F5DF73CULL,
		0x6CEC22D685F7D1C4ULL,
		0x7BB20E3B075AF6B0ULL
	}};
	t = -1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x82BBFD3B245997B4ULL,
		0xCD2EC8CA30F2B7CFULL,
		0x14E3A10D2B4010FEULL,
		0x431613CE5B06CB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC8CC7DABF35832A9ULL,
		0x7C8D918104A5EB41ULL,
		0xE34D00DFD49049B5ULL,
		0x3B33F5C41A6A29A3ULL
	}};
	t = 1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2554BD7E58C3C1E3ULL,
		0x26586B25A0DC2CE3ULL,
		0x4F43134F6043C442ULL,
		0x2436878C2F5B9AAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x163CFCF272AE2447ULL,
		0xAFC3D2F12ED3E5B8ULL,
		0x471F74DE77C5C4AAULL,
		0x071E78350C339F9FULL
	}};
	t = 1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x43AE36F7E09B6A2DULL,
		0x87F2568376CDB4CCULL,
		0xC8820C5058B20C2AULL,
		0x37934288FBD991AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x43AE36F7E09B6A2DULL,
		0x87F2568376CDB4CCULL,
		0xC8820C5058B20C2AULL,
		0x37934288FBD991AEULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC4E780AD1CB52FBDULL,
		0x65B113AF8081A078ULL,
		0x556A244F6C6B712AULL,
		0x561A271A8F896C33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4C29D43118FE34ADULL,
		0x4C2A23E3AE9C492BULL,
		0xC8E3D0FEA3494B24ULL,
		0x5C2771A6C07691FDULL
	}};
	t = -1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAA289CF1B6F18B90ULL,
		0x7DECC1A0838A5635ULL,
		0x48819718FBC4C013ULL,
		0x02C62BE27CA823E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00BAE3723A376E4CULL,
		0xDB52A22707269EB0ULL,
		0x532E3BE9506067C5ULL,
		0x37EB089D931CA028ULL
	}};
	t = -1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCDF803621A032D6EULL,
		0x4932937FE7AB9EA4ULL,
		0xFF525454B71FF326ULL,
		0x428848FECF6A362BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EE2B3E047FAF435ULL,
		0x04E8E128B390A353ULL,
		0xF91368E496E39D61ULL,
		0x5E8197CCB4C15ABAULL
	}};
	t = -1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x650A2F7CCDAA1D84ULL,
		0x71D504B46E7B5C24ULL,
		0xDB8209D0DD801BE7ULL,
		0x03E4F96CC1C3DDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x650A2F7CCDAA1D84ULL,
		0x71D504B46E7B5C24ULL,
		0xDB8209D0DD801BE7ULL,
		0x03E4F96CC1C3DDDCULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDA0CF8BE8A8316B8ULL,
		0x6BA9AAD42FAACE58ULL,
		0xC3059B42196B15C2ULL,
		0x4958BDD865FA3380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xECFAF1A12F25BB06ULL,
		0x00655F2A53EF90B2ULL,
		0x40EE28FAEDCD9C7AULL,
		0x6009B1691E946596ULL
	}};
	t = -1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x784676ADDDC83B25ULL,
		0xC77983EE35D2E8FDULL,
		0xBA1ABABEBE617331ULL,
		0x72571B18CA5F644CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1EE8BBB5DF5FAABFULL,
		0x986821E85D38E4A6ULL,
		0x9B8AE6EA0F4EA53BULL,
		0x3BE50992D0A0C6A4ULL
	}};
	t = 1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EDE55CDBFC6E4A4ULL,
		0x2FABEDBDEBB70043ULL,
		0x033D9AA816DF81C6ULL,
		0x3A4216EFE19F83D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAF08DF8AA92B92A1ULL,
		0xD40FA6997B38869FULL,
		0x7217C843590E012EULL,
		0x0B0993DFEBAEC3DDULL
	}};
	t = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x48DCF4883880FAA4ULL,
		0x47CEA69493960275ULL,
		0xC7B1F009EB7DF5C4ULL,
		0x55E263A35A2F1967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x48DCF4883880FAA4ULL,
		0x47CEA69493960275ULL,
		0xC7B1F009EB7DF5C4ULL,
		0x55E263A35A2F1967ULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x740862CA5DE353C5ULL,
		0xF5D435BA880CB274ULL,
		0x5442636D7616E1E7ULL,
		0x0808CFCF16330A0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC1FA6A277EF79466ULL,
		0x671FE091470845CEULL,
		0x9B878C0EE7CA1F81ULL,
		0x688214F449A9805DULL
	}};
	t = -1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8107959429697AA5ULL,
		0x1237B7274CFE279FULL,
		0xF022E58BC4446BCFULL,
		0x3F9E9BA797CBCFF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA43214BA4F8FA945ULL,
		0x838A6A22455EAC12ULL,
		0x380A98D80FE3B07EULL,
		0x164E021822FD1AB1ULL
	}};
	t = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF293600C89FA153ULL,
		0xC9707D5BC7BBD1C8ULL,
		0x628E1130592BC45CULL,
		0x043AB1591784E114ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F71F48308491971ULL,
		0x6E6706A3EE79A152ULL,
		0xA9F56752576E14B3ULL,
		0x1FEB6D986766544EULL
	}};
	t = -1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x54CFAB047E08D077ULL,
		0xF3603B620CF38A36ULL,
		0xA344749695F6A767ULL,
		0x4A3D5C46DD4B0DE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x54CFAB047E08D077ULL,
		0xF3603B620CF38A36ULL,
		0xA344749695F6A767ULL,
		0x4A3D5C46DD4B0DE8ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5C992783B62975AULL,
		0x188293BD216E7DDAULL,
		0x4EEC60229A35D465ULL,
		0x04327AC973CC7A3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA75696AE758E5014ULL,
		0x658F4FE0D7C03D59ULL,
		0x247252A0312D4412ULL,
		0x3F05838581E7F535ULL
	}};
	t = -1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B3D48144751C44AULL,
		0x52B5EF3B9866C202ULL,
		0x65AA4C9B2E51B717ULL,
		0x3CEE3CB6B9E9A82EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7777AE52120121E9ULL,
		0x76FCEE8EC7696D81ULL,
		0xD7C0FF267723A777ULL,
		0x4EB339A551D54960ULL
	}};
	t = -1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC685D6CB5508DECULL,
		0x85CE614863D1EC14ULL,
		0x4269724FBEA30383ULL,
		0x4616C291D0DB53E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA5CE69FE0109559ULL,
		0x233B02D06BA95CA2ULL,
		0x0BB2C90CF579992CULL,
		0x2F69A3E83C4FF750ULL
	}};
	t = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x772909EE418D4A68ULL,
		0x5DB83245660D3976ULL,
		0xCC24179EBBF440E2ULL,
		0x65C7B13F60722106ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x772909EE418D4A68ULL,
		0x5DB83245660D3976ULL,
		0xCC24179EBBF440E2ULL,
		0x65C7B13F60722106ULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEF65B5062D2F009ULL,
		0xD302AD811A86D962ULL,
		0xF953ECF9C0890167ULL,
		0x0A7E1153C9D652A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF768D841795D5825ULL,
		0xC8300F801896F711ULL,
		0x5F00C8414CAF40E6ULL,
		0x7ED5429F209668C0ULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x43ADA6F1CD634022ULL,
		0x1BF8737E3C3BD48EULL,
		0xE21D80C2A038D198ULL,
		0x2A38AA2BD5A2DCB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0F2926CAA62300EULL,
		0xBC8C6D633416658EULL,
		0x25061379CEF3A10FULL,
		0x65B29E49F4C1DAEDULL
	}};
	t = -1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6C76F7C4A9C5EDAFULL,
		0x6094D23AEE27BD6DULL,
		0xE98343AD39BCD528ULL,
		0x270D3E408446AF4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x756CC64515A36C05ULL,
		0x40DB6A4FDB912A39ULL,
		0x5072C52E660840C1ULL,
		0x5E35C5899B387732ULL
	}};
	t = -1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x464615E5A83BE647ULL,
		0xE8AE7854C35A3FA1ULL,
		0x772F258CAB9EAF6BULL,
		0x49267DAF77171E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x464615E5A83BE647ULL,
		0xE8AE7854C35A3FA1ULL,
		0x772F258CAB9EAF6BULL,
		0x49267DAF77171E68ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x54009A21A8E2273AULL,
		0x5D101CEC71FCFB1DULL,
		0xFD233D51B654CA12ULL,
		0x4A1D575B370EFFB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x333E0A8D97FE55E8ULL,
		0x802E3D1006D6CE4CULL,
		0xEFB39770C6ACCE26ULL,
		0x733902FBAC8AC100ULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5186F8A9E6D781EULL,
		0x710B236027019C2DULL,
		0x5C81FF4E7F7B31D0ULL,
		0x0B17D45CA5A948C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x47B86ADD4CEC0D55ULL,
		0x24DD1A6EDE253055ULL,
		0x2A3F3F1C792EB974ULL,
		0x7FC0BE025A0A4FA4ULL
	}};
	t = -1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFCBCEAA0185E9DCULL,
		0x962E21C9E2066E3DULL,
		0x7E13C5F77BDBB3A5ULL,
		0x345873FE4042A3ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9CD9F08D85DB830ULL,
		0xE98035AD7A4D282AULL,
		0x4B785E7B6565D943ULL,
		0x073F60F774C63A7CULL
	}};
	t = 1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90A8FE1DE7B79751ULL,
		0x69E543C0BFFFBE8DULL,
		0xC452BD92791BC2AEULL,
		0x2B4AA1FD9497FC2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90A8FE1DE7B79751ULL,
		0x69E543C0BFFFBE8DULL,
		0xC452BD92791BC2AEULL,
		0x2B4AA1FD9497FC2EULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA8B8C19B7F64D9CFULL,
		0x3FAB6848E02CD988ULL,
		0xB46621919E67397EULL,
		0x509391B09418BF70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD696245EA4471F16ULL,
		0xFE3132D0FFEA0F73ULL,
		0x242C6FF416037AACULL,
		0x5048EC005FF6F183ULL
	}};
	t = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1288BC96E90D4E0ULL,
		0x41C4FC6559DCE5A3ULL,
		0xD27B6568261DAA68ULL,
		0x78296301289FE16AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4FF3EB08ECC2943CULL,
		0x485F35A14F71AF30ULL,
		0x2941C682DB6611A2ULL,
		0x39EA5AFBA4A9657AULL
	}};
	t = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x68E7A3DDA64A4FFEULL,
		0xB4FBC23CA2217C86ULL,
		0x501EF55F3D44A389ULL,
		0x07CFED36DBEA825EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFD933F2649646BE8ULL,
		0x71916BA07BA1C83EULL,
		0x72CBB25702770FCFULL,
		0x524F16B0D45DD69EULL
	}};
	t = -1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BBA09721CC78E1AULL,
		0x86D6BC8863B8DEA0ULL,
		0x9502119240580593ULL,
		0x0A72D05F5237A544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BBA09721CC78E1AULL,
		0x86D6BC8863B8DEA0ULL,
		0x9502119240580593ULL,
		0x0A72D05F5237A544ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE47711A86FC9FCC6ULL,
		0x05707FE9ED5AEBC3ULL,
		0x45F17B10C875B8FDULL,
		0x7294613064DBAC52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x913E1382A8774BE5ULL,
		0x4FD0ED9827B9EDEBULL,
		0x53AB302D97389802ULL,
		0x13FE673CBDA3E84AULL
	}};
	t = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00B1ED8751D1897AULL,
		0x0F548696FD298F33ULL,
		0x3A4FD8B3BFB48DF7ULL,
		0x58B0EC4DCB4CD3A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2CAE28D0FA345692ULL,
		0x879AE6571BB69A5EULL,
		0x1399E926A62694D9ULL,
		0x7C32A73A8823BBD8ULL
	}};
	t = -1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x011FF1505E492777ULL,
		0x9C808D758932F791ULL,
		0x0EAA8CA16218C2ABULL,
		0x495F5747F2D64D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x64B4FAA763B92D4EULL,
		0xDB9EF4C782FB5927ULL,
		0x39E72C8673854BDAULL,
		0x5A23D3B94E1CDEE4ULL
	}};
	t = -1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EE03E086876562EULL,
		0x80685689D8FB4721ULL,
		0xAFE9507D46DE6648ULL,
		0x1643085F6D5D2C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EE03E086876562EULL,
		0x80685689D8FB4721ULL,
		0xAFE9507D46DE6648ULL,
		0x1643085F6D5D2C8DULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD188ABAF811BC81CULL,
		0xF533EACED6A0C8DCULL,
		0x7808BFFD27B1E12DULL,
		0x735B3D1F5F66C2A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAFB1DFDF220E5751ULL,
		0x987C074A0EF1FD8FULL,
		0xA6EB375FD6AE0A0BULL,
		0x55C0E8B9D8B77D0FULL
	}};
	t = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD19DCD3E3BFC6EC2ULL,
		0xA91B3EA9DA986F9FULL,
		0x9C658A3D64E422DCULL,
		0x67C8E345A6BD0ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6B6DE4081BC728EULL,
		0x75B94BC441FAE51EULL,
		0xE4F8A20FAD5D310CULL,
		0x3049199CEAE8AEEAULL
	}};
	t = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEE078F770085C257ULL,
		0x0FF8D8B3A872D948ULL,
		0xA4119B4886EDACC6ULL,
		0x64379DAA5D92C0A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2E7F9A78C8B9A978ULL,
		0xFB4356C4CB64D7B0ULL,
		0x3F07022A9F50677BULL,
		0x4DDFEE1DC4F49546ULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCAC076EFE226299BULL,
		0x6E1C24ABBC461DDCULL,
		0x41EEE0DDD2ED0A3EULL,
		0x6E457E3585E92F88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCAC076EFE226299BULL,
		0x6E1C24ABBC461DDCULL,
		0x41EEE0DDD2ED0A3EULL,
		0x6E457E3585E92F88ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5BD6170F26A77CAULL,
		0x046EEC248F5A4AEDULL,
		0xD8C883F279071443ULL,
		0x22B74A4861EAB834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBBDB12E15C44987ULL,
		0x81B4410B5E4CA6AAULL,
		0x377195F0E5680927ULL,
		0x318C5F8970347B0DULL
	}};
	t = -1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29951A4285AA1F2DULL,
		0x69E0326070F095D4ULL,
		0x85112A482A77CA27ULL,
		0x5255891EDC54F648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2ED3022DC6E49B8EULL,
		0xCBA4D171E8DFEB7CULL,
		0x52BF9A1DB134F5FFULL,
		0x7F69212142841961ULL
	}};
	t = -1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x78DBA79833559FDBULL,
		0xB29EAB29F1D5334EULL,
		0xCA5090B3388D470FULL,
		0x017D6234B8AA9985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2696EFE59D3C3DC9ULL,
		0x354AE28A70AFDFC0ULL,
		0xF6208EAD4BCED579ULL,
		0x0267CFFD61F43EDEULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF671D9BB994259AULL,
		0xCB0B51B589945F5AULL,
		0x8CDAB72A7B4B26C5ULL,
		0x25A8014EA4B5A40CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF671D9BB994259AULL,
		0xCB0B51B589945F5AULL,
		0x8CDAB72A7B4B26C5ULL,
		0x25A8014EA4B5A40CULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3994A1DC7BE4F89ULL,
		0x757DE98BD842193CULL,
		0xB680A242E9830D18ULL,
		0x61E7148179D14556ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x37CF8AAB65F6DC9EULL,
		0x6AF6DAD61A3569B8ULL,
		0xAE6EA6FA8251AA8EULL,
		0x798DDD4652BD9818ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC06951B435A56BDEULL,
		0x43B34794ACB5F01EULL,
		0xDF9F37EF8222B3C9ULL,
		0x793FB18C0CD242BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC691BA463AFDE01CULL,
		0x533055CB974FFC7EULL,
		0xC2B02DA7ED046EC4ULL,
		0x247531A7AEBF7FA4ULL
	}};
	t = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14FD47AED7C9DB15ULL,
		0x8DC748CEA3DEA27CULL,
		0x8300EE715661EDBCULL,
		0x227691B060447F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA00A523BFAB9425DULL,
		0x6543BA554454F0A0ULL,
		0x034CAE49A9EE9B67ULL,
		0x1BF5253D3E35D86BULL
	}};
	t = 1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3C031C1F58EDA094ULL,
		0x36EAD661845BED67ULL,
		0x372759EA887B0DC5ULL,
		0x51C8B71293E44F3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3C031C1F58EDA094ULL,
		0x36EAD661845BED67ULL,
		0x372759EA887B0DC5ULL,
		0x51C8B71293E44F3DULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x55C56B6CCC82130AULL,
		0x154B93A37D35A72AULL,
		0x887E9D2699B69166ULL,
		0x761D711E379DA07DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41DDB539633A3D4BULL,
		0xE48E67F7EB1F00AEULL,
		0x9F35D35B3AC18D3EULL,
		0x06DC6B3CF83C075AULL
	}};
	t = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE234413940CBC04CULL,
		0x37055849E784EF72ULL,
		0x0D1D73B6E183F690ULL,
		0x3A84E5940120328DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6596014DC68DCBFBULL,
		0x14F7EE847451E190ULL,
		0xEB4CAF9E06B512B7ULL,
		0x04F737F41C460905ULL
	}};
	t = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x515EB0B4C8406E1AULL,
		0x4EBFA4963DB5BB57ULL,
		0xDFE49D5E8847E975ULL,
		0x35EDB3A2C8E10D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33863B91BCAC2515ULL,
		0x88412BC667451A6BULL,
		0x5E551750E278751FULL,
		0x25B7842855EEDECAULL
	}};
	t = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14280D1D8C814234ULL,
		0x248574CC582F90DEULL,
		0x5FCCD301D229CE99ULL,
		0x52035E2DDE475351ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14280D1D8C814234ULL,
		0x248574CC582F90DEULL,
		0x5FCCD301D229CE99ULL,
		0x52035E2DDE475351ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x832F86CB55F601E6ULL,
		0x05570E857B1D4F55ULL,
		0x13E2F720CF5B7E68ULL,
		0x7BF96750DD9FB60AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7111312E49F7D36AULL,
		0x21992B6E2A589B51ULL,
		0x70C4A49693311F8FULL,
		0x2E712E09E81BC45EULL
	}};
	t = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BD0431CDD741D9AULL,
		0xF10C80B872BB52CEULL,
		0xCDAE902AE41FCBF9ULL,
		0x13BD595F4E4DA044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9EF0E497FF24CE91ULL,
		0x0B869E0EA6FC7349ULL,
		0xB90A7F8447EE4FBAULL,
		0x36E34BCA6C3B9993ULL
	}};
	t = -1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B9DF509BA3ABEA4ULL,
		0xE3C659CD6DD6AF21ULL,
		0xFC85FA33985CADA7ULL,
		0x2F483FA35071E4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x97710197D0C7A663ULL,
		0x3744D1E33A7B2326ULL,
		0x0280D50D8AC363DBULL,
		0x181E3F755907054AULL
	}};
	t = 1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7196D12CDFD3CACCULL,
		0x87741B86A1623E52ULL,
		0xBC0A90A6F0D2A03AULL,
		0x67D14F09AE92DA57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7196D12CDFD3CACCULL,
		0x87741B86A1623E52ULL,
		0xBC0A90A6F0D2A03AULL,
		0x67D14F09AE92DA57ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00535F19A8C0C279ULL,
		0x2F3746513A74A82DULL,
		0x4F9B1FBE22B2C7BAULL,
		0x68024C913AD704F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6FCFE3F8A5B5C604ULL,
		0xC6F52EED572F4278ULL,
		0xC2DDEDDFACAE48C9ULL,
		0x66F85A7B1A895C3EULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x401CF4D45ADE5673ULL,
		0xBA414B70824CE32AULL,
		0x276AA242DB0C75F2ULL,
		0x6337C56A098548B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x252FBF7CBDA5946BULL,
		0xEBD32AE6F4910E56ULL,
		0xEDC65FE6A53C1AFDULL,
		0x1828A21203D1BB1AULL
	}};
	t = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF52964C304EB82FFULL,
		0xC37C7F2A7921D0D1ULL,
		0x81D1C145A346EF90ULL,
		0x63857A4B9A7E30ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59F2C0644F1D1F37ULL,
		0x49DC100718FCA5DBULL,
		0x96CA128A0AB0927FULL,
		0x6BAFE9EF41F605B1ULL
	}};
	t = -1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F247BDA23E0EBC7ULL,
		0x741B0B03E71CC9C2ULL,
		0x80BDD0B034947C0EULL,
		0x56F6504C0100B752ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F247BDA23E0EBC7ULL,
		0x741B0B03E71CC9C2ULL,
		0x80BDD0B034947C0EULL,
		0x56F6504C0100B752ULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1120DD83E90AF8D7ULL,
		0x2892FD9F51A17612ULL,
		0xEFC8B01661C0B783ULL,
		0x3988AC3780DA129BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D2295D206DF8641ULL,
		0x65937547E328B0C7ULL,
		0xB7B6BFBFCF909D88ULL,
		0x074906A103BC4C71ULL
	}};
	t = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE820C2D566E9D50CULL,
		0x093F70B5FCD05C3BULL,
		0xCC0402FB5EC0336DULL,
		0x1FBC67FA943E8ED1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB44C0539AA754F5DULL,
		0x96A3CF66A413168CULL,
		0x1A754A5B4851F05BULL,
		0x795F5A550AC13169ULL
	}};
	t = -1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9EA68E736523A1D5ULL,
		0xEB3B9D721233EF9DULL,
		0xCA1177A231891938ULL,
		0x170944ADDDE824C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD37836760C47765BULL,
		0xBAF3FDB666109CABULL,
		0x223DFA70BA912609ULL,
		0x66F82C3622FE1818ULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBD5378CDF425493ULL,
		0xB65F3C0099458729ULL,
		0x4179440248D0F952ULL,
		0x45323CD7A07471FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBD5378CDF425493ULL,
		0xB65F3C0099458729ULL,
		0x4179440248D0F952ULL,
		0x45323CD7A07471FEULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6CFA0116A7E4110ULL,
		0xA93EE0DFE9270ED8ULL,
		0x47115DEF13FA98E3ULL,
		0x0DB00E3DC3A878DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE35124CF057EFAB4ULL,
		0xD051D52BDD975450ULL,
		0x0304B321DD75DE24ULL,
		0x0DB0F2391BF53352ULL
	}};
	t = -1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9CDF3F91749B6619ULL,
		0x4A4934B32560B6BCULL,
		0xADFDF7CFCBB40884ULL,
		0x3AFBEA03140B14FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFE0E9BD6B7F319B9ULL,
		0x02D05071C62518AEULL,
		0xD6DDD184A4A70E2CULL,
		0x7DA2006319868710ULL
	}};
	t = -1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC3E9F84E89BBB3B5ULL,
		0x934679AC1E24DCE7ULL,
		0xB15912829E4B0436ULL,
		0x211F9FA76B84E9D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x051BC15B8AD991C8ULL,
		0x3FF0189F383D973DULL,
		0x93F1397E6C7C84FFULL,
		0x5569BDDB3258C680ULL
	}};
	t = -1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x828F5E39D801C17CULL,
		0x3221DEE07835455AULL,
		0x736DFDDB8A9BCF32ULL,
		0x730AA16824DCFD51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x828F5E39D801C17CULL,
		0x3221DEE07835455AULL,
		0x736DFDDB8A9BCF32ULL,
		0x730AA16824DCFD51ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB3D8A28197DE6530ULL,
		0xD9752E75D8362375ULL,
		0x0A32323E1A4D0406ULL,
		0x529E89912390B79DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x494DD0CFF264EDB8ULL,
		0x49A8EF452092E20EULL,
		0x0FAE4932A6000A6BULL,
		0x62E8A6AEC596121EULL
	}};
	t = -1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB468E5DA8F78F2BULL,
		0xF6D48DB92D918517ULL,
		0xEB2C15FD7F1FF3A2ULL,
		0x6B462ABCE75BF4B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF1D7B6246D360075ULL,
		0x20262618768369C9ULL,
		0x0BCB703549701127ULL,
		0x465DA210B783AE6AULL
	}};
	t = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3E03B286217A1B57ULL,
		0x924BF4DB90895DA8ULL,
		0x4E8BE603D0767C3AULL,
		0x25B4BF67E443A4B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x94725DFA1564B899ULL,
		0x1B2F776962499894ULL,
		0x48B4CD3ACB253162ULL,
		0x0BE02AC9278BBA5AULL
	}};
	t = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7EE753649B54C7FEULL,
		0x4622855F00E49BA8ULL,
		0x98B8BE4D1A1B3312ULL,
		0x02356C3F6343ACAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7EE753649B54C7FEULL,
		0x4622855F00E49BA8ULL,
		0x98B8BE4D1A1B3312ULL,
		0x02356C3F6343ACAAULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6EEBB60F95B31B0ULL,
		0xD15DE20CE6F28FC5ULL,
		0xBEE3ED5C91294B9AULL,
		0x0513F7CAF2062604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFF4BE19216AA469ULL,
		0x0237D39C46DC7C85ULL,
		0xE173235033345C35ULL,
		0x1D2AE3E2C2B5B60FULL
	}};
	t = -1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xECFA115C133F7C08ULL,
		0x1E1430CDE2D8ABD8ULL,
		0x0FB66D58EA147B1FULL,
		0x66B54AC5F4CB54FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x95FEF26D01B0EEC6ULL,
		0x96F9D4E6CDF25B4FULL,
		0xB878C06AD9AD1B8EULL,
		0x7D76B2C75339595AULL
	}};
	t = -1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x21CE77B475CF0577ULL,
		0x533AAB6C22B2B2A4ULL,
		0xAF2B6990FA153270ULL,
		0x1120AC388A13E236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8362CF3A35113144ULL,
		0xEBD20E1BDD575FC0ULL,
		0x77FA7A9E63AD6272ULL,
		0x6174A3D54A51B990ULL
	}};
	t = -1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66B7B4E37F2F2DA1ULL,
		0x3B901CF4A29F2D58ULL,
		0xC40536D1A89A943EULL,
		0x1FAAF8FB0A51C6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66B7B4E37F2F2DA1ULL,
		0x3B901CF4A29F2D58ULL,
		0xC40536D1A89A943EULL,
		0x1FAAF8FB0A51C6FEULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD38B47E7459DD560ULL,
		0xB772D1E4F233EB39ULL,
		0x56E6DE29EAB70CE5ULL,
		0x664A00C28580F647ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x253AED0F57D37864ULL,
		0xFB202726902A13F9ULL,
		0xB3DF22B92AA5FC90ULL,
		0x27A6FDFF8BAE0AA6ULL
	}};
	t = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE8EDD37FF87CFE65ULL,
		0x10D1B1C5B3B8D0C9ULL,
		0x1E373B724A0C1D88ULL,
		0x2D889FB6BDFDD3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B234F131111061DULL,
		0x790C81CDA805B027ULL,
		0x6F43D455A5232B4DULL,
		0x3CE1052FBB4A8970ULL
	}};
	t = -1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x133952997D17400FULL,
		0xDD56683CF6B840CFULL,
		0xE9B07AFF89623DBBULL,
		0x4725C1DDFAEFF5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x21B59D37E934619CULL,
		0xE4235CF4EB229446ULL,
		0xAA8A2727D8677BD1ULL,
		0x49DEAAA6185A3CFBULL
	}};
	t = -1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x871104E09CB6BB74ULL,
		0x505A052D0970AFD2ULL,
		0x07275B6EF1955D26ULL,
		0x5D6BE62E8EE9F743ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x871104E09CB6BB74ULL,
		0x505A052D0970AFD2ULL,
		0x07275B6EF1955D26ULL,
		0x5D6BE62E8EE9F743ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5734590FDD9AFDFULL,
		0x8C4C7E0257541AD2ULL,
		0xDE23F908DBFDEF84ULL,
		0x5BD998C0D126F731ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB3034794809EDE7FULL,
		0xF00D8F5990565370ULL,
		0xE545D483FE9A1462ULL,
		0x41EB2354402284D6ULL
	}};
	t = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x457BE55C3BD8736AULL,
		0x62D2751F00607F97ULL,
		0x8047198B8C0C9589ULL,
		0x4423932ED6521015ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45C8663F8DBC8BF0ULL,
		0x0F26F7F081D34EEFULL,
		0x7D388AC12B3191CDULL,
		0x444E09145DA17BB2ULL
	}};
	t = -1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7ABFC38F9E8D2D3ULL,
		0x317413FE0B0A1146ULL,
		0x291FF97679BAC28AULL,
		0x3CFD70DB0FFE058DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5815FA23BD4B9841ULL,
		0xEA8987013B498AD6ULL,
		0x90F260C6261A515DULL,
		0x2D93DB752CE83E4EULL
	}};
	t = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x12461324B2F0416FULL,
		0xFE78E53C10DD6CAFULL,
		0x770D7778E0CD59DBULL,
		0x225D45741B56655FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x12461324B2F0416FULL,
		0xFE78E53C10DD6CAFULL,
		0x770D7778E0CD59DBULL,
		0x225D45741B56655FULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x97BF273C96968E48ULL,
		0xF044C3B15C18733DULL,
		0xDDCFFB34174438D3ULL,
		0x555A82E06A818881ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58772E2896996D76ULL,
		0x04DFD76A86F203BCULL,
		0x1B41D95AD778237DULL,
		0x0D501ECEF8FC2A09ULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x35A6FB54ED69940CULL,
		0xDA4287F0F0FCCC11ULL,
		0xD697F7183E2F5305ULL,
		0x224A3787D87EBE6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4030EF03494894EULL,
		0x0F912A1D0F49C44FULL,
		0x0820DEA38888C87BULL,
		0x3CFFFCEEEAE04F8FULL
	}};
	t = -1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF0D68328397FC1ECULL,
		0x4E66126352B3A0F8ULL,
		0xB7F24CAA88D40A80ULL,
		0x4D817B6E37DD2332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x451204F07BA8E508ULL,
		0x45B97E4FE0B8D78DULL,
		0xC59ACDFFCB38E4B2ULL,
		0x23901D37E06C37F3ULL
	}};
	t = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6DEFD0BE3A60032ULL,
		0x798950FA1A5D6F95ULL,
		0x53F31525E9B6E7FDULL,
		0x7C20FA280AE5C664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6DEFD0BE3A60032ULL,
		0x798950FA1A5D6F95ULL,
		0x53F31525E9B6E7FDULL,
		0x7C20FA280AE5C664ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x65A73B74A74D9690ULL,
		0x0C80C04F3E4B9D85ULL,
		0xB4039F2A2674D262ULL,
		0x34FA1DAE3A5FB9EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x15A7CFD0A2FDBBCBULL,
		0x9207D5F962CD295FULL,
		0x01F36AE30AFDD6BBULL,
		0x7C559B0E15966FE7ULL
	}};
	t = -1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9AE75B20A40AD19AULL,
		0x7376F9D2D008CD1FULL,
		0x91577AB904F5E7C3ULL,
		0x7C25C7BFDF441122ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3E7385D682881300ULL,
		0x3D215BA2F0E967ACULL,
		0x3AF622DABA23C7ADULL,
		0x35F85BA689F0978EULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3D0A269F36B14EFDULL,
		0x66EE4BC2E276FF2EULL,
		0xB2460824CA68CD2EULL,
		0x6A68295B13D7C8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x341A0C0BD9ADDC43ULL,
		0xA1A19C316FA41046ULL,
		0x2EA1BE3B5598AFDEULL,
		0x3A250374A20D5832ULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A0F2E3B3E62281BULL,
		0xBFDBC0CE964C40C3ULL,
		0x7429B949BB023688ULL,
		0x0BF2045A7A8E83EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A0F2E3B3E62281BULL,
		0xBFDBC0CE964C40C3ULL,
		0x7429B949BB023688ULL,
		0x0BF2045A7A8E83EEULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE112F59F94166950ULL,
		0xF14A72AE2BB6970EULL,
		0x484C36102CC9A9CCULL,
		0x1DA50D91F4A6A098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F690D0405A048C1ULL,
		0xFCD6AED8E1B26A86ULL,
		0x8CBA49AEAF4E32A3ULL,
		0x3C10DA4AC5192E4AULL
	}};
	t = -1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x018BA0ECFF92755FULL,
		0x723ADA30EE3F0B89ULL,
		0x14083F99053F1FFDULL,
		0x1BBB3C4839F513EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x99B797EBE603B082ULL,
		0xB61769A93A7A98DCULL,
		0x7DBC8EED63401E62ULL,
		0x4FFEB968020484CAULL
	}};
	t = -1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87DEC23C257CF295ULL,
		0xC538105F83EB75E8ULL,
		0x79ED580C4B3FDE44ULL,
		0x5EA27C4FAFC366C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2CC01684DF4AEFB6ULL,
		0x6A14AB5A33A27E7AULL,
		0xA1C37B2C56954823ULL,
		0x6985500EE247E8BCULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5C39D59604D53123ULL,
		0x809414AF1B575F5BULL,
		0xCAB8D47B4F9CD21EULL,
		0x613C63ACBCF47EEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5C39D59604D53123ULL,
		0x809414AF1B575F5BULL,
		0xCAB8D47B4F9CD21EULL,
		0x613C63ACBCF47EEFULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1404910EDC6AC43CULL,
		0x99F55245AF46D926ULL,
		0x81A7A306321739D2ULL,
		0x4D5E7E6B96AB5853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x13FAC7B50CEAD399ULL,
		0x68360D0EE34F1EF7ULL,
		0xA06DDD214F941D01ULL,
		0x08B2EE9C63B1E343ULL
	}};
	t = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6CF9180F30CB7118ULL,
		0x2515FDC1F612972FULL,
		0xAD7689703FF0EEC9ULL,
		0x42E40D3CB28F1295ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD869C1D1A7F1F8EEULL,
		0x2FEC3A81755C2638ULL,
		0xDA9725DB5E3082ECULL,
		0x6789A40572167EA5ULL
	}};
	t = -1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB089A4435329D8F1ULL,
		0xFC5277F5FCF72AD3ULL,
		0xB279BAEA09D85445ULL,
		0x191AEEAB7549DFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEB1218665861EA6ULL,
		0x4E0CDE4F9559EDEBULL,
		0x6A16278C967CE025ULL,
		0x1BA385C1648F748FULL
	}};
	t = -1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xABD9C7C15D45677BULL,
		0x2FE8149B0F49A216ULL,
		0x8FF0E7AEA63C57D6ULL,
		0x122CD0407A69D81AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xABD9C7C15D45677BULL,
		0x2FE8149B0F49A216ULL,
		0x8FF0E7AEA63C57D6ULL,
		0x122CD0407A69D81AULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79C93B0242B87075ULL,
		0x6FAD063FC613B2E1ULL,
		0x2D7B9F655E3F19A6ULL,
		0x6CC6D164A622E871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B66D7D8B49650E6ULL,
		0xDEE90CBF82138C6DULL,
		0xFA63C9DE2AD45DABULL,
		0x63733265C05928FFULL
	}};
	t = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x96D3BB94BD1FF3C6ULL,
		0xCB81B8C6D30F4A87ULL,
		0x2A54A990EB0DB281ULL,
		0x3588DEF90FD98EFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB05592066CC41359ULL,
		0x52527410213E661BULL,
		0x365CB04FD39D1CE4ULL,
		0x44D185CE63CD2CAFULL
	}};
	t = -1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7F03AD7270DF4284ULL,
		0xBDAF0D14AD3CF0C6ULL,
		0x95CDA87A0E532A58ULL,
		0x55DE5E69758DD7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC46D19C8E60BC07ULL,
		0x21EEB74FF6AF1579ULL,
		0x0E85467C849181FAULL,
		0x7518FCF33CEF6907ULL
	}};
	t = -1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x369D22C70A3623F8ULL,
		0x778B7218BD686AB3ULL,
		0xEBE56731307672EEULL,
		0x4163F9A43D4B931BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x369D22C70A3623F8ULL,
		0x778B7218BD686AB3ULL,
		0xEBE56731307672EEULL,
		0x4163F9A43D4B931BULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44C45778C8F56ED3ULL,
		0x927942BB88CCEFBBULL,
		0xAF58CDD041652E95ULL,
		0x07007516D2915C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E9E36E1326B9A1FULL,
		0x9CF0EAECCFA6EC43ULL,
		0x3044EE0F1410DAD0ULL,
		0x1643F387B9AAF576ULL
	}};
	t = -1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6EFB8A71E2CD9133ULL,
		0x9A7C03036296B3EFULL,
		0x815D32710ADF4CD9ULL,
		0x2D845688CE219B6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F36FB72A6E6A939ULL,
		0x5CD1D20E2EBAF29FULL,
		0xCA1F375CAE122034ULL,
		0x7B975117D2651FA1ULL
	}};
	t = -1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5C460BAD832946AULL,
		0xBDFA2D7438149ED0ULL,
		0x68AB7CF568E483E2ULL,
		0x77F419BDE21AA7E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x34F348E682E59F8AULL,
		0x6962C0541D8DDCAFULL,
		0x0E3AE79E237063CBULL,
		0x41C7CDEB3F81A858ULL
	}};
	t = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49D1A738A4A3D7FDULL,
		0x426BD04001042DB0ULL,
		0x06F22FCA6D494EB1ULL,
		0x724158601C4C1935ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49D1A738A4A3D7FDULL,
		0x426BD04001042DB0ULL,
		0x06F22FCA6D494EB1ULL,
		0x724158601C4C1935ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDB248DE251330C9ULL,
		0x4E58272E542213D0ULL,
		0x263A16A2E290543DULL,
		0x1C7FAFC324020967ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB9524E1612F7A30ULL,
		0xC6A694B0442F49A4ULL,
		0xE7243F570343608EULL,
		0x73B008AE92E4C82CULL
	}};
	t = -1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6613DF06BBE03F9ULL,
		0x691734822D089949ULL,
		0x22347E7CD9D96F60ULL,
		0x3F5AB79E3F53DE8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7B577841E43C88CULL,
		0x932FDDC8B5141123ULL,
		0x8B991BFD4804DAD2ULL,
		0x617BB257EEE5F222ULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D254AFDE876B87AULL,
		0xF6AA73BECAF811E3ULL,
		0x12757B3B65E71757ULL,
		0x695FE756BE1895D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6DF49C6A5631919ULL,
		0x81C5DA5132823E37ULL,
		0xBB951B3550D4A38FULL,
		0x1DD3DEB56942878AULL
	}};
	t = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBB77AC2FD9DA4B8ULL,
		0x8ED833A448C47735ULL,
		0xF9C93B85DE5B0CDBULL,
		0x10EEB70F9A6E88FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBB77AC2FD9DA4B8ULL,
		0x8ED833A448C47735ULL,
		0xF9C93B85DE5B0CDBULL,
		0x10EEB70F9A6E88FCULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC28C97FD7D280198ULL,
		0x7AD043A48A8BF4E1ULL,
		0xCEA737EA0172676EULL,
		0x35C8CCA77B10B791ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x24E1061021ED644FULL,
		0xC3EC2DC7CBC583F9ULL,
		0x1DE20C0FE1BA4C7EULL,
		0x44D3A80CEDF601B5ULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x81EBC59BCA0A61BBULL,
		0xD8AE4EBE89EC9603ULL,
		0x8D971072CB313EEAULL,
		0x08599EEAC7EE18E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC03891470D4BEC2EULL,
		0x5D320B30ADC4F3C4ULL,
		0x134A31948A2B7144ULL,
		0x7D78209982D7C759ULL
	}};
	t = -1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD6031A594FE5052ULL,
		0x4148F2EF8ABE2802ULL,
		0x171B85A16ACC0DB1ULL,
		0x636897465216DB8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D803DA68554E713ULL,
		0x50EAE7BC710AFB1FULL,
		0x76DC9EA27CC7EC91ULL,
		0x18629B932A922A69ULL
	}};
	t = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3728C7FB90FE1013ULL,
		0x9D252D2BF46BBBF6ULL,
		0xA77262EEF279142AULL,
		0x218A71075C740812ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3728C7FB90FE1013ULL,
		0x9D252D2BF46BBBF6ULL,
		0xA77262EEF279142AULL,
		0x218A71075C740812ULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA57A4AD1E419218FULL,
		0x368B34A19422C203ULL,
		0xDF1BF3EF9960C21CULL,
		0x7358753F07E199A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F73DCB6C43D9B62ULL,
		0x66FFF32BDC037259ULL,
		0x03DA1375BE7C6790ULL,
		0x7B5794671656CF23ULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x34B12DE023CB068DULL,
		0x0F8A4D54CCAE5023ULL,
		0xBC8076C50A0DD280ULL,
		0x7194B3CB7778B64BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBBFADFDE1A6D68F1ULL,
		0xA5380B8BA0310173ULL,
		0xF7EE7C24AEEC9610ULL,
		0x2A6FC0BF99E211AAULL
	}};
	t = 1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3475BB7C6D384352ULL,
		0x8269F4C4E1E8C93BULL,
		0xE36F1E9AA27BBBD2ULL,
		0x4688550203760855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00E58A1942D92D35ULL,
		0xC57EB2E11EF13737ULL,
		0x2F59F70967695946ULL,
		0x1763EF51286FB738ULL
	}};
	t = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6383F2F0D1DC13C5ULL,
		0x6E18FFFB73E6CC3DULL,
		0x2DE158EF5545A2CEULL,
		0x334EA9E4F972FE38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6383F2F0D1DC13C5ULL,
		0x6E18FFFB73E6CC3DULL,
		0x2DE158EF5545A2CEULL,
		0x334EA9E4F972FE38ULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC267E365AC53CA2ULL,
		0xFCF333D6700C0DE4ULL,
		0x010A175EB686496EULL,
		0x7064FD1BD90AFCDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF80D12ED6F4E37FDULL,
		0x70470E1F54549240ULL,
		0xF133656D7F265114ULL,
		0x479624E6A90118C6ULL
	}};
	t = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7422073B81BC8D72ULL,
		0x43E082B87D1FA5CCULL,
		0xA304936B943A2C2FULL,
		0x00A0DE7FDBC43EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB41F2BA0552F2C7EULL,
		0x47C702C06DB44657ULL,
		0xD9E2897A1844ADA0ULL,
		0x147B5A4F3A91D77FULL
	}};
	t = -1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x02AF2EFB30C890CEULL,
		0x682FE8719CE3AF54ULL,
		0x39070B45E8E67DF3ULL,
		0x4C9E3D97EB3DB278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCBD57797B62BA175ULL,
		0x2561A3FA0E9E3BE3ULL,
		0x316C05B1F5F24BACULL,
		0x72964D33EBFA61D6ULL
	}};
	t = -1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9A35339FAA0F3861ULL,
		0xC9002B84B3984AC0ULL,
		0x26B0E71806C01DD5ULL,
		0x4FDF590FCF6E75DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9A35339FAA0F3861ULL,
		0xC9002B84B3984AC0ULL,
		0x26B0E71806C01DD5ULL,
		0x4FDF590FCF6E75DCULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA67544D8B5789752ULL,
		0xB28A211F86655E69ULL,
		0xC2EEBED722FB8D14ULL,
		0x3DC846D3268FE834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB63EE41F46575682ULL,
		0xB1095D6FE42EF9FFULL,
		0xA9BF4FA3880AE5AFULL,
		0x3ABD120C9AB9B46FULL
	}};
	t = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x04BE53DFC4D6EB62ULL,
		0x0691BC295614B039ULL,
		0x77B5A892C0C71C80ULL,
		0x7797C3D7DD75E94CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3D530E06898EE323ULL,
		0x013CEDAE6A38736DULL,
		0x6F5FD46E297BE134ULL,
		0x2F8C4F22A37C66E4ULL
	}};
	t = 1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x64B8C06586EB61B8ULL,
		0xB28549D5D5C6035EULL,
		0xEEC8B9FEDAFCE9B0ULL,
		0x1FD89D204F4843CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC646A4D44D88B75ULL,
		0x75B07B90092A60D3ULL,
		0xAE3DB8E0D82B38C7ULL,
		0x67D82EF843C4375DULL
	}};
	t = -1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_high(&k1, &k2);
	if ((res > 0 && t <= 0) || (res < 0 && t >= 0) || (res == 0 && t != 0)) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}