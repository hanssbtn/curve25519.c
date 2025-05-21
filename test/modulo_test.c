#include "tests.h"

int32_t curve25519_key_modulo_test(void) {
	printf("Modulo Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xE7DC6767897D090DULL,
		0x42B02BD4529B39C3ULL,
		0xA8410E8B48B220A1ULL,
		0x2D96872CD6342AF2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xE7DC6767897D090DULL,
		0x42B02BD4529B39C3ULL,
		0xA8410E8B48B220A1ULL,
		0x2D96872CD6342AF2ULL
	}};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4D7CB6D48D04361ULL,
		0x594442F203BDA061ULL,
		0x6478964B42075D21ULL,
		0x6477605D247D42EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4D7CB6D48D04361ULL,
		0x594442F203BDA061ULL,
		0x6478964B42075D21ULL,
		0x6477605D247D42EFULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x72026EC0011FE899ULL,
		0x5F61242776E26A44ULL,
		0x919D3B304B42AC77ULL,
		0x5E5316456C154558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72026EC0011FE899ULL,
		0x5F61242776E26A44ULL,
		0x919D3B304B42AC77ULL,
		0x5E5316456C154558ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x950CBB63D8AEA398ULL,
		0xC8D72CDB9D733EC8ULL,
		0x2191D9259E6D4F49ULL,
		0x506D8ECA5D51CD30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x950CBB63D8AEA398ULL,
		0xC8D72CDB9D733EC8ULL,
		0x2191D9259E6D4F49ULL,
		0x506D8ECA5D51CD30ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE913FE795233CA47ULL,
		0x6195A5D9AF2E8823ULL,
		0x81DDFBFCD405CB86ULL,
		0x6193DBA8E12AA8A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE913FE795233CA47ULL,
		0x6195A5D9AF2E8823ULL,
		0x81DDFBFCD405CB86ULL,
		0x6193DBA8E12AA8A8ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9AC5F4D708162F8ULL,
		0x4CCD4EFD99821B32ULL,
		0x0B5607DCF588A769ULL,
		0xF3B46282099C9730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9AC5F4D7081630BULL,
		0x4CCD4EFD99821B32ULL,
		0x0B5607DCF588A769ULL,
		0x73B46282099C9730ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5047180C3EF6BF82ULL,
		0x5BD7D19F13529A2CULL,
		0x7A7751A6B6411790ULL,
		0x04946F1A4CAE52CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5047180C3EF6BF82ULL,
		0x5BD7D19F13529A2CULL,
		0x7A7751A6B6411790ULL,
		0x04946F1A4CAE52CDULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7F26D4BC1E42BB6ULL,
		0xDA50D8F72E1E7BFAULL,
		0xEFFC286A33EACCC6ULL,
		0x0C7AC11DADCDFF83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7F26D4BC1E42BB6ULL,
		0xDA50D8F72E1E7BFAULL,
		0xEFFC286A33EACCC6ULL,
		0x0C7AC11DADCDFF83ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x24D768F46B07D20DULL,
		0xF818C1F53C78BCDDULL,
		0xA2F477629CF8CAEAULL,
		0x387EA7BB8C50F6FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24D768F46B07D20DULL,
		0xF818C1F53C78BCDDULL,
		0xA2F477629CF8CAEAULL,
		0x387EA7BB8C50F6FEULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48860ECD950AA5ECULL,
		0x06C54F50C8986278ULL,
		0x136E0576D0428061ULL,
		0x96DA0B4A53B89327ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48860ECD950AA5FFULL,
		0x06C54F50C8986278ULL,
		0x136E0576D0428061ULL,
		0x16DA0B4A53B89327ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B00AA6E9D10D504ULL,
		0xD876FC46B8223A34ULL,
		0x5B0F63343509981AULL,
		0x27227011ABD90B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B00AA6E9D10D504ULL,
		0xD876FC46B8223A34ULL,
		0x5B0F63343509981AULL,
		0x27227011ABD90B4AULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3484D314EE51A650ULL,
		0xDFE2BCF3BE6B6E9CULL,
		0x8F2A0B2806843385ULL,
		0xEAAF8A32C4017424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3484D314EE51A663ULL,
		0xDFE2BCF3BE6B6E9CULL,
		0x8F2A0B2806843385ULL,
		0x6AAF8A32C4017424ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B24047639D19F86ULL,
		0x31A5575A07B0CD11ULL,
		0x3C5491FB48DA0463ULL,
		0xB6F8B93008B8DE95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B24047639D19F99ULL,
		0x31A5575A07B0CD11ULL,
		0x3C5491FB48DA0463ULL,
		0x36F8B93008B8DE95ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA84F4839AF41DDD6ULL,
		0xD38627F26639C8C4ULL,
		0xA841BDA06E802308ULL,
		0x5E41CB5D8559DD71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84F4839AF41DDD6ULL,
		0xD38627F26639C8C4ULL,
		0xA841BDA06E802308ULL,
		0x5E41CB5D8559DD71ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68FFF6F8B0840282ULL,
		0x5A0366A4A8831580ULL,
		0x16C3100EB1498D6CULL,
		0xEFC63F1226C33DBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68FFF6F8B0840295ULL,
		0x5A0366A4A8831580ULL,
		0x16C3100EB1498D6CULL,
		0x6FC63F1226C33DBCULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6436035ABE4DFB69ULL,
		0xF3D7633DE57427AFULL,
		0x0E9E16BCAB1DF025ULL,
		0x1C0B552A94AA16C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6436035ABE4DFB69ULL,
		0xF3D7633DE57427AFULL,
		0x0E9E16BCAB1DF025ULL,
		0x1C0B552A94AA16C8ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F98AC9E084A4550ULL,
		0x43B5857F594BFB6AULL,
		0x782FB082F1742E73ULL,
		0xD3FFB36B97BC5054ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F98AC9E084A4563ULL,
		0x43B5857F594BFB6AULL,
		0x782FB082F1742E73ULL,
		0x53FFB36B97BC5054ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9541224BB9A739CDULL,
		0x4D7A70328F0B0171ULL,
		0x75DB4F2862A1BF18ULL,
		0x9F1EB79180968F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9541224BB9A739E0ULL,
		0x4D7A70328F0B0171ULL,
		0x75DB4F2862A1BF18ULL,
		0x1F1EB79180968F23ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49D882E34D80CC8AULL,
		0x282F78796899D9AFULL,
		0x6CF9CAD2F2845AE4ULL,
		0xBE986672A3F1B113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D882E34D80CC9DULL,
		0x282F78796899D9AFULL,
		0x6CF9CAD2F2845AE4ULL,
		0x3E986672A3F1B113ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x68378FEE41B6CF6AULL,
		0x68EAD89CB3C4D2E1ULL,
		0x87173683C4C703C5ULL,
		0x42500718ACE7F244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68378FEE41B6CF6AULL,
		0x68EAD89CB3C4D2E1ULL,
		0x87173683C4C703C5ULL,
		0x42500718ACE7F244ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1FF269DBD06977FULL,
		0xEC65D539EC1CA6F1ULL,
		0x33F4D6994B074919ULL,
		0x63E9B31987FA3EFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1FF269DBD06977FULL,
		0xEC65D539EC1CA6F1ULL,
		0x33F4D6994B074919ULL,
		0x63E9B31987FA3EFAULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5ECC19E1D68EC164ULL,
		0x6C908400AF3A9960ULL,
		0x97225BCC5D1AEE18ULL,
		0xBC442B30E554941EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ECC19E1D68EC177ULL,
		0x6C908400AF3A9960ULL,
		0x97225BCC5D1AEE18ULL,
		0x3C442B30E554941EULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7B640116F51EA28ULL,
		0x0A4FDA94DF075162ULL,
		0x1DEEE4CD372F4761ULL,
		0x99CD4F5186EC81B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7B640116F51EA3BULL,
		0x0A4FDA94DF075162ULL,
		0x1DEEE4CD372F4761ULL,
		0x19CD4F5186EC81B4ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBAC079699A1BE290ULL,
		0x4BAEBE321D911D3AULL,
		0x15B7195AA9ADAF29ULL,
		0xAE220F6103D72AE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC079699A1BE2A3ULL,
		0x4BAEBE321D911D3AULL,
		0x15B7195AA9ADAF29ULL,
		0x2E220F6103D72AE3ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x565D2138217A3018ULL,
		0x1E6CB68EAFD66FC1ULL,
		0x78C7E0C8182F9FC6ULL,
		0xBF0AC275B3C8D479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x565D2138217A302BULL,
		0x1E6CB68EAFD66FC1ULL,
		0x78C7E0C8182F9FC6ULL,
		0x3F0AC275B3C8D479ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF0A7B05020EBD30ULL,
		0x76584EDF0B89CD61ULL,
		0xD409D9C40207AB76ULL,
		0x882C2AC5E9181EFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF0A7B05020EBD43ULL,
		0x76584EDF0B89CD61ULL,
		0xD409D9C40207AB76ULL,
		0x082C2AC5E9181EFFULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x731ECC7E55B8AE2CULL,
		0x45B6251C68533AC9ULL,
		0x3E8E49354E378738ULL,
		0xB9DFF3B037D8D4FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x731ECC7E55B8AE3FULL,
		0x45B6251C68533AC9ULL,
		0x3E8E49354E378738ULL,
		0x39DFF3B037D8D4FDULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3CE0037F1CB7246BULL,
		0x32CF23BD7AB020A7ULL,
		0xE3DA5A7C45FE4E99ULL,
		0x58F1CC7EBA1FD51EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE0037F1CB7246BULL,
		0x32CF23BD7AB020A7ULL,
		0xE3DA5A7C45FE4E99ULL,
		0x58F1CC7EBA1FD51EULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E1CAA78463D27BEULL,
		0x3577EAE2104C1611ULL,
		0xD3D1427491588BF7ULL,
		0xD1B881936A267925ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E1CAA78463D27D1ULL,
		0x3577EAE2104C1611ULL,
		0xD3D1427491588BF7ULL,
		0x51B881936A267925ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFD070838CE819C89ULL,
		0x34CB96422D174E5EULL,
		0x189D75D8A3752A00ULL,
		0x1E9C1C99D086EC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD070838CE819C89ULL,
		0x34CB96422D174E5EULL,
		0x189D75D8A3752A00ULL,
		0x1E9C1C99D086EC85ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x192BEFE8462A8E3EULL,
		0x661AFD4F6BD469F3ULL,
		0xD72A8ADB16468144ULL,
		0x0DE7C332E24A8B5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x192BEFE8462A8E3EULL,
		0x661AFD4F6BD469F3ULL,
		0xD72A8ADB16468144ULL,
		0x0DE7C332E24A8B5BULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x994BB71011D22543ULL,
		0x9A44864C8C3DBAC4ULL,
		0xCC6C3C9476B46A03ULL,
		0xE4358200C7119DD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994BB71011D22556ULL,
		0x9A44864C8C3DBAC4ULL,
		0xCC6C3C9476B46A03ULL,
		0x64358200C7119DD8ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11828224839D09F4ULL,
		0xB4397A5A8C692936ULL,
		0x34532F33095D3DFAULL,
		0xB665CBAE8471E33BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11828224839D0A07ULL,
		0xB4397A5A8C692936ULL,
		0x34532F33095D3DFAULL,
		0x3665CBAE8471E33BULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE634EBB1A6A4AE0FULL,
		0xE39CC0471FDDA8E7ULL,
		0x2CE16202DC91A445ULL,
		0xD1FBC65A6492ECAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE634EBB1A6A4AE22ULL,
		0xE39CC0471FDDA8E7ULL,
		0x2CE16202DC91A445ULL,
		0x51FBC65A6492ECAEULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9D54DAA901F0638ULL,
		0xD2033D4C764B9939ULL,
		0x8FAF361BF8ED77A4ULL,
		0xF729F9BF6E3D1ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9D54DAA901F064BULL,
		0xD2033D4C764B9939ULL,
		0x8FAF361BF8ED77A4ULL,
		0x7729F9BF6E3D1ABEULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCECB7A1F9CE9AEABULL,
		0x8AF49338620A2F71ULL,
		0x825B3D1727027827ULL,
		0xC729CC4875ED60F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCECB7A1F9CE9AEBEULL,
		0x8AF49338620A2F71ULL,
		0x825B3D1727027827ULL,
		0x4729CC4875ED60F1ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5639B98D8B3E1A8FULL,
		0xBD4224DA0F7697B6ULL,
		0xF6FDA3E099AA679FULL,
		0xC959E36B97A5A133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5639B98D8B3E1AA2ULL,
		0xBD4224DA0F7697B6ULL,
		0xF6FDA3E099AA679FULL,
		0x4959E36B97A5A133ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21BA84AE1292E103ULL,
		0x7BC7B61CBB93A6F1ULL,
		0x9AFCB52185A84C5EULL,
		0x32488DC815F446D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21BA84AE1292E103ULL,
		0x7BC7B61CBB93A6F1ULL,
		0x9AFCB52185A84C5EULL,
		0x32488DC815F446D3ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93C4333CE7FD639CULL,
		0x31E64873225DFDC3ULL,
		0x51EB89E924A2299EULL,
		0x7985A6D09CF2F2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93C4333CE7FD639CULL,
		0x31E64873225DFDC3ULL,
		0x51EB89E924A2299EULL,
		0x7985A6D09CF2F2B3ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC925E22796996599ULL,
		0x3DA610BF771017BFULL,
		0xA17424C92D30A535ULL,
		0xFF9761D97991915AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC925E227969965ACULL,
		0x3DA610BF771017BFULL,
		0xA17424C92D30A535ULL,
		0x7F9761D97991915AULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA1D58291571E49EULL,
		0x6CB96B2748F84ACBULL,
		0x4D2FA12A77349BB1ULL,
		0xFB7936C20DBA5C44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA1D58291571E4B1ULL,
		0x6CB96B2748F84ACBULL,
		0x4D2FA12A77349BB1ULL,
		0x7B7936C20DBA5C44ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2773EB4EEAC99AE2ULL,
		0x83CED5CE4CF9EA19ULL,
		0xA7A58F6B1F50FB4EULL,
		0x7E584F2243F21E9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2773EB4EEAC99AE2ULL,
		0x83CED5CE4CF9EA19ULL,
		0xA7A58F6B1F50FB4EULL,
		0x7E584F2243F21E9CULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA960BB76AC7771C0ULL,
		0x7405E4553F62AB68ULL,
		0x6888284F9DEBC20FULL,
		0x8AF8B506A62C4206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA960BB76AC7771D3ULL,
		0x7405E4553F62AB68ULL,
		0x6888284F9DEBC20FULL,
		0x0AF8B506A62C4206ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6021EBF5D2E0E329ULL,
		0x9B9393AD2CC11F85ULL,
		0x6DB42DA5D79F4AD8ULL,
		0x4819D8882309FCA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6021EBF5D2E0E329ULL,
		0x9B9393AD2CC11F85ULL,
		0x6DB42DA5D79F4AD8ULL,
		0x4819D8882309FCA3ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37F252EA60415471ULL,
		0x98799D31FAB235B4ULL,
		0x0C044D32D0FBB8EFULL,
		0xA49D60CA838714BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F252EA60415484ULL,
		0x98799D31FAB235B4ULL,
		0x0C044D32D0FBB8EFULL,
		0x249D60CA838714BCULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90343024E8B18D51ULL,
		0x0D2B079D77B7ADC4ULL,
		0x784A54FE53826B18ULL,
		0xB0EBB94C4963C156ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90343024E8B18D64ULL,
		0x0D2B079D77B7ADC4ULL,
		0x784A54FE53826B18ULL,
		0x30EBB94C4963C156ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93B273F31B18A80AULL,
		0xA995207247282966ULL,
		0x0727FB2647EDFBBAULL,
		0x8174EF16CE8CEBA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93B273F31B18A81DULL,
		0xA995207247282966ULL,
		0x0727FB2647EDFBBAULL,
		0x0174EF16CE8CEBA2ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39EE7181A9826119ULL,
		0x7CA89F323F60E67CULL,
		0xD7CAF0C26FB17979ULL,
		0xFBDFDFDF619477CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39EE7181A982612CULL,
		0x7CA89F323F60E67CULL,
		0xD7CAF0C26FB17979ULL,
		0x7BDFDFDF619477CEULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2FC056AED8542BB4ULL,
		0x389183C9C39A91BBULL,
		0x06669CFF8A53D410ULL,
		0x2584F31A432517CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC056AED8542BB4ULL,
		0x389183C9C39A91BBULL,
		0x06669CFF8A53D410ULL,
		0x2584F31A432517CFULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49AD89BA3F35727CULL,
		0xD2A3AE4A1FB7CBA8ULL,
		0xE7BEC6AE71E19072ULL,
		0xE8065871BCC05247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49AD89BA3F35728FULL,
		0xD2A3AE4A1FB7CBA8ULL,
		0xE7BEC6AE71E19072ULL,
		0x68065871BCC05247ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15E4D800BA4A5C74ULL,
		0x4DEA402C8B2068E0ULL,
		0x15B0C3AC6AF32BA9ULL,
		0xAD3DDD086A262FEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15E4D800BA4A5C87ULL,
		0x4DEA402C8B2068E0ULL,
		0x15B0C3AC6AF32BA9ULL,
		0x2D3DDD086A262FEDULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50BC91649F0E19D2ULL,
		0xB98DB603B708D2DBULL,
		0xEE6C58FC976CAA28ULL,
		0x8764902891EF4F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50BC91649F0E19E5ULL,
		0xB98DB603B708D2DBULL,
		0xEE6C58FC976CAA28ULL,
		0x0764902891EF4F91ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA5BAE90462DB7776ULL,
		0x4A9222CE9F8A4D1FULL,
		0xBE04CC1D50A21A6FULL,
		0x38EFD223B6F468C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5BAE90462DB7776ULL,
		0x4A9222CE9F8A4D1FULL,
		0xBE04CC1D50A21A6FULL,
		0x38EFD223B6F468C7ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F1283637FAE87BBULL,
		0x3485E48A4DDAF6CBULL,
		0x04E77ABB3C5026D9ULL,
		0x253D731CE541B13AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F1283637FAE87BBULL,
		0x3485E48A4DDAF6CBULL,
		0x04E77ABB3C5026D9ULL,
		0x253D731CE541B13AULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x906303C40ACCF008ULL,
		0x949E27E5008A4626ULL,
		0x13067D7BF8AA484FULL,
		0xBF282BAC50F50C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x906303C40ACCF01BULL,
		0x949E27E5008A4626ULL,
		0x13067D7BF8AA484FULL,
		0x3F282BAC50F50C3BULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x305F444202C7FC1CULL,
		0x60BDB95B197A55DFULL,
		0xCB3CA879B1BBC7C5ULL,
		0x3D17A896CC5C1C49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x305F444202C7FC1CULL,
		0x60BDB95B197A55DFULL,
		0xCB3CA879B1BBC7C5ULL,
		0x3D17A896CC5C1C49ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DCDFB05FADCDE9EULL,
		0x2F6705335B03FF21ULL,
		0x3003767A227C8718ULL,
		0x306A09F1B759D8C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DCDFB05FADCDE9EULL,
		0x2F6705335B03FF21ULL,
		0x3003767A227C8718ULL,
		0x306A09F1B759D8C3ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF540B01168FB6929ULL,
		0x1A5820639D6E7C66ULL,
		0x8D4C33DFAA7CFEBCULL,
		0xD6CD52EAB52A75AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF540B01168FB693CULL,
		0x1A5820639D6E7C66ULL,
		0x8D4C33DFAA7CFEBCULL,
		0x56CD52EAB52A75AAULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9CA36C2060540A4ULL,
		0xA5893DA8C88B6569ULL,
		0xB6D1228CDAAFF936ULL,
		0x5C5DC1EE86B69E2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CA36C2060540A4ULL,
		0xA5893DA8C88B6569ULL,
		0xB6D1228CDAAFF936ULL,
		0x5C5DC1EE86B69E2DULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCED179F11BD2EE81ULL,
		0x9A47F5824D5FABB2ULL,
		0xAFD290569AEBD3FCULL,
		0x5BF06F093870AAD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED179F11BD2EE81ULL,
		0x9A47F5824D5FABB2ULL,
		0xAFD290569AEBD3FCULL,
		0x5BF06F093870AAD3ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FFD005BA45CAADEULL,
		0x240BB3560F49EFD7ULL,
		0xCC7464E989A09C2EULL,
		0xF1F1F3807440EFE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FFD005BA45CAAF1ULL,
		0x240BB3560F49EFD7ULL,
		0xCC7464E989A09C2EULL,
		0x71F1F3807440EFE1ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x069A9A31B67EFF09ULL,
		0x27E5F947B3A10477ULL,
		0xD53D01E46E31F21EULL,
		0x87994B8EEE61FA20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x069A9A31B67EFF1CULL,
		0x27E5F947B3A10477ULL,
		0xD53D01E46E31F21EULL,
		0x07994B8EEE61FA20ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15C659F342B399B7ULL,
		0xFB512605144EBD09ULL,
		0x42B59CC63AAB370CULL,
		0x99E857913415F813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C659F342B399CAULL,
		0xFB512605144EBD09ULL,
		0x42B59CC63AAB370CULL,
		0x19E857913415F813ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x174BDB486C4EDD1AULL,
		0xDC65EEB4BD7CA0F0ULL,
		0xABF67FBB51560A55ULL,
		0x662F19586AED6CD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174BDB486C4EDD1AULL,
		0xDC65EEB4BD7CA0F0ULL,
		0xABF67FBB51560A55ULL,
		0x662F19586AED6CD1ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC21A23FEF14C345ULL,
		0x2FEAB24F49B37587ULL,
		0xA2E1835599FAC75BULL,
		0x62A83C1E179C89DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC21A23FEF14C345ULL,
		0x2FEAB24F49B37587ULL,
		0xA2E1835599FAC75BULL,
		0x62A83C1E179C89DFULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA16BC7543CC8CFA1ULL,
		0x7790D4C3BC76CEE3ULL,
		0x1533D6B728B2F10BULL,
		0x9DCB8E20F3738454ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA16BC7543CC8CFB4ULL,
		0x7790D4C3BC76CEE3ULL,
		0x1533D6B728B2F10BULL,
		0x1DCB8E20F3738454ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7896C92B113B766ULL,
		0xF4B4751A278AA4AFULL,
		0x45459B34330670E9ULL,
		0xBF428DD297E0340CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7896C92B113B779ULL,
		0xF4B4751A278AA4AFULL,
		0x45459B34330670E9ULL,
		0x3F428DD297E0340CULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA98D21F7D4E4DE4ULL,
		0x1EA66B8654CBC4C7ULL,
		0xDE44429A64E1330DULL,
		0x9F08E5AE7AAB3354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA98D21F7D4E4DF7ULL,
		0x1EA66B8654CBC4C7ULL,
		0xDE44429A64E1330DULL,
		0x1F08E5AE7AAB3354ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8B09410F6E924DDULL,
		0x8ED6B09035EA0089ULL,
		0xD3148A0A39AFFE26ULL,
		0x1B818CD1437A3C18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B09410F6E924DDULL,
		0x8ED6B09035EA0089ULL,
		0xD3148A0A39AFFE26ULL,
		0x1B818CD1437A3C18ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8E136DFD9FCA02DULL,
		0x24D79A5AD14ECC0BULL,
		0xCCDACFB871E582A7ULL,
		0x30CF52477FD9032FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8E136DFD9FCA02DULL,
		0x24D79A5AD14ECC0BULL,
		0xCCDACFB871E582A7ULL,
		0x30CF52477FD9032FULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x854EA37CB2F3205FULL,
		0x7B9FFCDC03D901F6ULL,
		0x3EF0707D667D5981ULL,
		0xCC3B24845BE5541CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x854EA37CB2F32072ULL,
		0x7B9FFCDC03D901F6ULL,
		0x3EF0707D667D5981ULL,
		0x4C3B24845BE5541CULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x301E6E5AF4B17F30ULL,
		0x440409C0812823A2ULL,
		0xED24ACC005ED9611ULL,
		0xEE954A5DCA53E75FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x301E6E5AF4B17F43ULL,
		0x440409C0812823A2ULL,
		0xED24ACC005ED9611ULL,
		0x6E954A5DCA53E75FULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3EB517A20D60DEFULL,
		0x879119650A4BCCDCULL,
		0x427263C0A173FB34ULL,
		0xC7E83CB7C2ED5BEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3EB517A20D60E02ULL,
		0x879119650A4BCCDCULL,
		0x427263C0A173FB34ULL,
		0x47E83CB7C2ED5BEAULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x64175548695187CBULL,
		0x779B84D74C6478B7ULL,
		0x83D528859C571CAAULL,
		0x15C07EC436B3E175ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x64175548695187CBULL,
		0x779B84D74C6478B7ULL,
		0x83D528859C571CAAULL,
		0x15C07EC436B3E175ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02A33299092BA9DCULL,
		0xE3FBD0D722708E88ULL,
		0x91A11F782C9C96D8ULL,
		0x7CD78AFA3E9DFC56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A33299092BA9DCULL,
		0xE3FBD0D722708E88ULL,
		0x91A11F782C9C96D8ULL,
		0x7CD78AFA3E9DFC56ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C2CEE4EC13B9DAAULL,
		0xA7615E688915B081ULL,
		0x8E7BF558FD350DABULL,
		0xFF7988126F427919ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2CEE4EC13B9DBDULL,
		0xA7615E688915B081ULL,
		0x8E7BF558FD350DABULL,
		0x7F7988126F427919ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD0F5536181EB8353ULL,
		0x6134DA41641B0074ULL,
		0x52D757E23E104969ULL,
		0x9113B50FC97C9F66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0F5536181EB8366ULL,
		0x6134DA41641B0074ULL,
		0x52D757E23E104969ULL,
		0x1113B50FC97C9F66ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07142BCCD37D2502ULL,
		0xF31CA6CDD5B363CAULL,
		0xAAE719AA0CE1A228ULL,
		0x41195D654D8B04F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07142BCCD37D2502ULL,
		0xF31CA6CDD5B363CAULL,
		0xAAE719AA0CE1A228ULL,
		0x41195D654D8B04F6ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB016BE803CE92E7AULL,
		0xC5BA5B8ED1C7C2F4ULL,
		0x0B653A8E703782B0ULL,
		0xE296545A169B2094ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB016BE803CE92E8DULL,
		0xC5BA5B8ED1C7C2F4ULL,
		0x0B653A8E703782B0ULL,
		0x6296545A169B2094ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB3E23255DF8E9DBULL,
		0x1CA7F7E8AA782B01ULL,
		0x2587FAC9A5204BA0ULL,
		0xD62C7B97692C6E8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB3E23255DF8E9EEULL,
		0x1CA7F7E8AA782B01ULL,
		0x2587FAC9A5204BA0ULL,
		0x562C7B97692C6E8BULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x993B0B5AC5F57B3AULL,
		0x4AB12BFF7526BDCEULL,
		0xB087DCB2C32B0ACBULL,
		0x49311A12B5801CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993B0B5AC5F57B3AULL,
		0x4AB12BFF7526BDCEULL,
		0xB087DCB2C32B0ACBULL,
		0x49311A12B5801CEBULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x676D6022C83F43CAULL,
		0x1A69CB6A6FE0A45EULL,
		0xAE413A1F8B6DEBD5ULL,
		0x25040A6056B5252EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x676D6022C83F43CAULL,
		0x1A69CB6A6FE0A45EULL,
		0xAE413A1F8B6DEBD5ULL,
		0x25040A6056B5252EULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CD16BE35B5C7742ULL,
		0xD00AED736EE0D235ULL,
		0x5450F6A8E1DFB2AEULL,
		0x44CCEC3A73415BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CD16BE35B5C7742ULL,
		0xD00AED736EE0D235ULL,
		0x5450F6A8E1DFB2AEULL,
		0x44CCEC3A73415BBDULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC36DB7BDF114EFA5ULL,
		0x3C799E765AB218E4ULL,
		0xC8568BB6C16C1ACAULL,
		0x303D927BC424868AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC36DB7BDF114EFA5ULL,
		0x3C799E765AB218E4ULL,
		0xC8568BB6C16C1ACAULL,
		0x303D927BC424868AULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5F4B416CA17DE34ULL,
		0x3EFE72964493D88BULL,
		0xEA2A5F51EBA7FC8BULL,
		0xA9EDF9DB3062182DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F4B416CA17DE47ULL,
		0x3EFE72964493D88BULL,
		0xEA2A5F51EBA7FC8BULL,
		0x29EDF9DB3062182DULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA4C17B1419892CEULL,
		0x0C24C849E4BFA67CULL,
		0x528499E45B040243ULL,
		0x567C14DADA8D5197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4C17B1419892CEULL,
		0x0C24C849E4BFA67CULL,
		0x528499E45B040243ULL,
		0x567C14DADA8D5197ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71C198F890080167ULL,
		0xC7E1A67EF500AC69ULL,
		0x33E349C655CF67ECULL,
		0x3B6C7DD82FB2F7BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C198F890080167ULL,
		0xC7E1A67EF500AC69ULL,
		0x33E349C655CF67ECULL,
		0x3B6C7DD82FB2F7BDULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39AF8C440F213B86ULL,
		0x254F875E010D698AULL,
		0x1B8BADA39958F0CCULL,
		0x8253BCF269023664ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39AF8C440F213B99ULL,
		0x254F875E010D698AULL,
		0x1B8BADA39958F0CCULL,
		0x0253BCF269023664ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7EC8A2A5A01DAF5ULL,
		0x11F4191842BAEDFFULL,
		0x75980CBD1787F57EULL,
		0xAF04FF2CE9B33DDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7EC8A2A5A01DB08ULL,
		0x11F4191842BAEDFFULL,
		0x75980CBD1787F57EULL,
		0x2F04FF2CE9B33DDDULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7733DB77841934A8ULL,
		0xB835EC8910653BE9ULL,
		0xA7B0EAE110FDB359ULL,
		0x58854BCA083E2EBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7733DB77841934A8ULL,
		0xB835EC8910653BE9ULL,
		0xA7B0EAE110FDB359ULL,
		0x58854BCA083E2EBDULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB3159038D57C028ULL,
		0xBC4B9863ED059070ULL,
		0x6AD3157ABC20D034ULL,
		0x1DED1117617C6B49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3159038D57C028ULL,
		0xBC4B9863ED059070ULL,
		0x6AD3157ABC20D034ULL,
		0x1DED1117617C6B49ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA7173AF20D5E882ULL,
		0xC734C3902B60C333ULL,
		0x4A249FBCE177411FULL,
		0x29E9DEA229562CDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA7173AF20D5E882ULL,
		0xC734C3902B60C333ULL,
		0x4A249FBCE177411FULL,
		0x29E9DEA229562CDEULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x471E907D495AA0B3ULL,
		0xB2429C4693BF952EULL,
		0xBFCC0657A4BD5F47ULL,
		0x9E90107C297E7C12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x471E907D495AA0C6ULL,
		0xB2429C4693BF952EULL,
		0xBFCC0657A4BD5F47ULL,
		0x1E90107C297E7C12ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15C76FF99C25B40FULL,
		0xA30C3DA11E762984ULL,
		0xBE4C7A55FE6F6B91ULL,
		0xBCD87279EE0553B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C76FF99C25B422ULL,
		0xA30C3DA11E762984ULL,
		0xBE4C7A55FE6F6B91ULL,
		0x3CD87279EE0553B2ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5602F4C07D3D5B3ULL,
		0xE37F762377DACFA4ULL,
		0x4420CA586A8B499FULL,
		0x24F3428FBCDEC1CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5602F4C07D3D5B3ULL,
		0xE37F762377DACFA4ULL,
		0x4420CA586A8B499FULL,
		0x24F3428FBCDEC1CAULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCA81BECDBCB14204ULL,
		0xCE950B8306F91E43ULL,
		0x46F40302713F9910ULL,
		0xEE6306D89ACC1737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA81BECDBCB14217ULL,
		0xCE950B8306F91E43ULL,
		0x46F40302713F9910ULL,
		0x6E6306D89ACC1737ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DF78707863ACCC6ULL,
		0xE035F6415ACB7167ULL,
		0x48518AD045C526BBULL,
		0xAB97D4EBB8BDECE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DF78707863ACCD9ULL,
		0xE035F6415ACB7167ULL,
		0x48518AD045C526BBULL,
		0x2B97D4EBB8BDECE0ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x56AE42659ACF0A4DULL,
		0xFC220D207B35DC2FULL,
		0x560DA96CC4A3E7ECULL,
		0x9E1E3D8FA6CED01AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AE42659ACF0A60ULL,
		0xFC220D207B35DC2FULL,
		0x560DA96CC4A3E7ECULL,
		0x1E1E3D8FA6CED01AULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x318823C0A7DD6688ULL,
		0xBADEFBB8CCCF9257ULL,
		0x71A753EB948FD33EULL,
		0x0CE32885EF2154C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x318823C0A7DD6688ULL,
		0xBADEFBB8CCCF9257ULL,
		0x71A753EB948FD33EULL,
		0x0CE32885EF2154C2ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D36FC3649D07E1CULL,
		0x125CBAED65CFDD22ULL,
		0xB867DEDD9E83AEB6ULL,
		0x054813C6C93E00DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D36FC3649D07E1CULL,
		0x125CBAED65CFDD22ULL,
		0xB867DEDD9E83AEB6ULL,
		0x054813C6C93E00DEULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k2, B64);
	compute_modulo_25519(&k1);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}