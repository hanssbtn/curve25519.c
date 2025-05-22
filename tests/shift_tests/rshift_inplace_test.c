#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Inplace Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5922F516C8ECD3DEULL,
		0xD1B5C3DCA6F84166ULL,
		0xD331AA21B9475176ULL,
		0xE161D2C71846BCCAULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9A7BC0000000000ULL,
		0xF082CCB245EA2D91ULL,
		0x8EA2EDA36B87B94DULL,
		0x8D7995A663544372ULL,
		0x000001C2C3A58E30ULL,
		0x0000000000000000ULL
	}};
	int shift = 87;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	int32_t res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x986E572ADBABC2A6ULL,
		0x61CD271729E69531ULL,
		0x67B638C476A571FBULL,
		0xBBD3A77D11B963F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xABC2A60000000000ULL,
		0xE69531986E572ADBULL,
		0xA571FB61CD271729ULL,
		0xB963F867B638C476ULL,
		0x000000BBD3A77D11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57BA08CA989A8A90ULL,
		0x7C012EF344B1440DULL,
		0xD92259795E17C423ULL,
		0x8016154A3C25C498ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA2A4000000000000ULL,
		0x510355EE8232A626ULL,
		0xF108DF004BBCD12CULL,
		0x71263648965E5785ULL,
		0x0000200585528F09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73FF3238AA25DA5AULL,
		0x8663A96E67739EA3ULL,
		0x54AD896D8E160172ULL,
		0x5DACDAD2466A399AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9769680000000000ULL,
		0xCE7A8DCFFCC8E2A8ULL,
		0x5805CA198EA5B99DULL,
		0xA8E66952B625B638ULL,
		0x00000176B36B4919ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE44638352BA96FDULL,
		0x72F73E3A439752A3ULL,
		0xA6103A19815F9D36ULL,
		0x097CC6AD08CF0099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD000000000000000ULL,
		0x3FE44638352BA96FULL,
		0x672F73E3A439752AULL,
		0x9A6103A19815F9D3ULL,
		0x0097CC6AD08CF009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3593D00B42F6619ULL,
		0x8A0C43239E83B6CEULL,
		0x646A33B365DCC8D8ULL,
		0xFADB1867A3D92287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B42F66190000000ULL,
		0x39E83B6CEB3593D0ULL,
		0x365DCC8D88A0C432ULL,
		0x7A3D92287646A33BULL,
		0x000000000FADB186ULL
	}};
	shift = 36;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB53C175CDC65BC09ULL,
		0x85ED16CBC72FB298ULL,
		0x404DC02B43F454DCULL,
		0x3067FFCF214632BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F05D737196F024ULL,
		0x17B45B2F1CBECA62ULL,
		0x013700AD0FD15372ULL,
		0xC19FFF3C8518CAEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD6F858CD4FF0C77ULL,
		0x867B2BB2F5FED271ULL,
		0xBE21A33A22E5CA99ULL,
		0x25955DE9AF20E907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FE18EE000000000ULL,
		0xBFDA4E3BADF0B19AULL,
		0x5CB95330CF65765EULL,
		0xE41D20F7C4346744ULL,
		0x00000004B2ABBD35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DB06F3E1B63F5B1ULL,
		0xC7EEC1E0E0E8DACEULL,
		0x2DDD6E0311280FA6ULL,
		0xB6FB95F15E579F71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB06F3E1B63F5B100ULL,
		0xEEC1E0E0E8DACE2DULL,
		0xDD6E0311280FA6C7ULL,
		0xFB95F15E579F712DULL,
		0x00000000000000B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72F306FC0D4F03C8ULL,
		0x6CC439A6F96B4464ULL,
		0x8447D84FCB136461ULL,
		0x050030ECA16A4F74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x781E400000000000ULL,
		0x5A2323979837E06AULL,
		0x9B230B6621CD37CBULL,
		0x527BA4223EC27E58ULL,
		0x000000280187650BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x462DA56D5F135768ULL,
		0x108CA34A8C2D7985ULL,
		0x54A6EC6B0B42C6B0ULL,
		0x63CAB704F600250AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2B6AF89ABB40000ULL,
		0x51A54616BCC2A316ULL,
		0x763585A163580846ULL,
		0x5B827B0012852A53ULL,
		0x00000000000031E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB23D82B661513CD3ULL,
		0x8FB7934A0F658002ULL,
		0xEC37A43BE46BEE27ULL,
		0xA1C82A393AE4ADFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15B30A89E6980000ULL,
		0x9A507B2C001591ECULL,
		0x21DF235F713C7DBCULL,
		0x51C9D7256FEF61BDULL,
		0x0000000000050E41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E2C9993F2D0555AULL,
		0x3374365F03688ACAULL,
		0x7FE9096AC305A30BULL,
		0x3591991AEF5AA9A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47164CC9F9682AADULL,
		0x99BA1B2F81B44565ULL,
		0xBFF484B56182D185ULL,
		0x1AC8CC8D77AD54D1ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x066EAF3B60AC6859ULL,
		0xC0ED50AB28EBE344ULL,
		0x91F70DD1581EB4EEULL,
		0x5E8A6AC1960BB45BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBCED82B1A1640000ULL,
		0x42ACA3AF8D1019BAULL,
		0x3745607AD3BB03B5ULL,
		0xAB06582ED16E47DCULL,
		0x0000000000017A29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x098CA458B6F88C09ULL,
		0xBD875CF5CA76D032ULL,
		0x0910389B10FAA6D6ULL,
		0xA2C9F82820CAC5B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6329162DBE230240ULL,
		0x61D73D729DB40C82ULL,
		0x440E26C43EA9B5AFULL,
		0xB27E0A0832B16C42ULL,
		0x0000000000000028ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3087DDD46F80938ULL,
		0xEC56255F18FF2EEEULL,
		0x7896D00B4B1EE675ULL,
		0xDB230639A5D261A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDA610FBBA8DF0127ULL,
		0xBD8AC4ABE31FE5DDULL,
		0xCF12DA016963DCCEULL,
		0x1B6460C734BA4C34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F16E9617E84F1F5ULL,
		0x59F6569B061D456DULL,
		0x2C01AD5581EB8291ULL,
		0xEC9B728B22B6904AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74B0BF4278FA8000ULL,
		0x2B4D830EA2B69F8BULL,
		0xD6AAC0F5C148ACFBULL,
		0xB945915B48251600ULL,
		0x000000000000764DULL
	}};
	shift = 49;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE05DFCDCCC657C96ULL,
		0xD55783CB3795778CULL,
		0xFA768566AD7FAE76ULL,
		0xE58A3799F1B9DFDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BE4B00000000000ULL,
		0xABBC6702EFE6E663ULL,
		0xFD73B6AABC1E59BCULL,
		0xCEFEFFD3B42B356BULL,
		0x0000072C51BCCF8DULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E4ABC1971202937ULL,
		0xDAC4D6CE575F67E6ULL,
		0x5F0E44A7846341E5ULL,
		0xB4BA81DCC7575D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CB890149B800000ULL,
		0x672BAFB3F30F255EULL,
		0x53C231A0F2ED626BULL,
		0xEE63ABAE92AF8722ULL,
		0x00000000005A5D40ULL
	}};
	shift = 41;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97CFF6F5E9F74AD2ULL,
		0xF6998DBE7CC1F266ULL,
		0x370EBB24B677557CULL,
		0x9F409590C8EA6D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4800000000000000ULL,
		0x9A5F3FDBD7A7DD2BULL,
		0xF3DA6636F9F307C9ULL,
		0x3CDC3AEC92D9DD55ULL,
		0x027D02564323A9B6ULL
	}};
	shift = 6;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x686AF54360B45941ULL,
		0x99E157EFEEB44010ULL,
		0xC95DBE46AF05D31CULL,
		0xB26457A6A1C5B1D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9410000000000000ULL,
		0x010686AF54360B45ULL,
		0x31C99E157EFEEB44ULL,
		0x1D9C95DBE46AF05DULL,
		0x000B26457A6A1C5BULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3430E9877C140997ULL,
		0x64680BD0B3A6BF01ULL,
		0x0311110BD7FB94ADULL,
		0x84BF942DF0209B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x828132E000000000ULL,
		0x74D7E026861D30EFULL,
		0xFF7295AC8D017A16ULL,
		0x04136D606222217AULL,
		0x0000001097F285BEULL
	}};
	shift = 27;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78DC03BDCF135AD5ULL,
		0xBA046E97DB1475A3ULL,
		0x8A68AB75506F56DAULL,
		0xE14183E8083852E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26B5AA0000000000ULL,
		0x28EB46F1B8077B9EULL,
		0xDEADB57408DD2FB6ULL,
		0x70A5D314D156EAA0ULL,
		0x000001C28307D010ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1B7C5977BBABB282ULL,
		0xBD668AAD13652B9AULL,
		0x5098840881CB965DULL,
		0xB35CBA5335B85F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF775765040000000ULL,
		0xA26CA573436F8B2EULL,
		0x103972CBB7ACD155ULL,
		0x66B70BE5AA131081ULL,
		0x00000000166B974AULL
	}};
	shift = 35;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6ED379459AFE0944ULL,
		0x67D73A7F11CF46A4ULL,
		0x8BFEA18420443DEAULL,
		0xD771DF5DFEBA3C9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x769BCA2CD7F04A20ULL,
		0x3EB9D3F88E7A3523ULL,
		0x5FF50C210221EF53ULL,
		0xBB8EFAEFF5D1E4ECULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0CE9BD474CDB5E3ULL,
		0xD21736A40F24A70BULL,
		0x02C0A522717CD969ULL,
		0x91F073FFDE97055EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74DEA3A66DAF1800ULL,
		0xB9B5207925385E86ULL,
		0x0529138BE6CB4E90ULL,
		0x839FFEF4B82AF016ULL,
		0x000000000000048FULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C5E2F2805490489ULL,
		0x7CD48E6C6535945FULL,
		0x7FAB0E2B3F056FFDULL,
		0xD0D5B98E1D360F68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E500A9209120000ULL,
		0x1CD8CA6B28BEB8BCULL,
		0x1C567E0ADFFAF9A9ULL,
		0x731C3A6C1ED0FF56ULL,
		0x000000000001A1ABULL
	}};
	shift = 47;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43C8C102267F6993ULL,
		0x32A1ED02F10639D4ULL,
		0xA783C29A471ED5A8ULL,
		0xF79025688EF008D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x044CFED326000000ULL,
		0x05E20C73A8879182ULL,
		0x348E3DAB506543DAULL,
		0xD11DE011A34F0785ULL,
		0x0000000001EF204AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AADD2DB2CE200F7ULL,
		0x75585A0B005F9DD9ULL,
		0x7ABD636497EA6B06ULL,
		0x48EE149A06D24B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE200F70000000000ULL,
		0x5F9DD92AADD2DB2CULL,
		0xEA6B0675585A0B00ULL,
		0xD24B907ABD636497ULL,
		0x00000048EE149A06ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9901CED014D269D1ULL,
		0xE03B6D0C476DEC30ULL,
		0xFBD27D466A9A6649ULL,
		0x33D04CFC37653B8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5349A74400000000ULL,
		0x1DB7B0C264073B40ULL,
		0xAA69992780EDB431ULL,
		0xDD94EE3FEF49F519ULL,
		0x00000000CF4133F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x193275899CCF5C25ULL,
		0x4A0CFAAA68C74FC7ULL,
		0x42C74600A4C36E57ULL,
		0x720DCC8ED0959CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3D70940000000000ULL,
		0x1D3F1C64C9D62673ULL,
		0x0DB95D2833EAA9A3ULL,
		0x5672E10B1D180293ULL,
		0x000001C837323B42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E58863BB0A21E31ULL,
		0x6FE189FA32DDB9D4ULL,
		0xB5F971DDE0C7BB3EULL,
		0x93DFBDAB268506F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB0A21E3100000000ULL,
		0x32DDB9D48E58863BULL,
		0xE0C7BB3E6FE189FAULL,
		0x268506F3B5F971DDULL,
		0x0000000093DFBDABULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89EE481FAFAFC031ULL,
		0x759EECD1BFF51EE3ULL,
		0x2828C5454AB4E21AULL,
		0x937A84A49230EDBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF7240FD7D7E01880ULL,
		0xCF7668DFFA8F71C4ULL,
		0x1462A2A55A710D3AULL,
		0xBD4252491876DF14ULL,
		0x0000000000000049ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE1B2D2F11B80EADEULL,
		0xD04EA25BD1445D85ULL,
		0x83473FF746B8BE2FULL,
		0xA3C86586C45031E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0756F00000000000ULL,
		0x22EC2F0D969788DCULL,
		0xC5F17E827512DE8AULL,
		0x818F1C1A39FFBA35ULL,
		0x0000051E432C3622ULL
	}};
	shift = 21;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBB621BA6E27A040DULL,
		0xEFFD3B4E98216C7BULL,
		0x98650D5C56C20DA1ULL,
		0x143ACC4E5DA27593ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD3713D0206800000ULL,
		0xA74C10B63DDDB10DULL,
		0xAE2B6106D0F7FE9DULL,
		0x272ED13AC9CC3286ULL,
		0x00000000000A1D66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B5DDD26BC5F3C3BULL,
		0x2678F4B97D261297ULL,
		0x71AC5544C8B04119ULL,
		0x3E2DF1E524F91543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8BE7876000000000ULL,
		0xA4C252F16BBBA4D7ULL,
		0x16082324CF1E972FULL,
		0x9F22A86E358AA899ULL,
		0x00000007C5BE3CA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F0B2F53CF7554A3ULL,
		0xA7937F43BE147383ULL,
		0xA56E039DA22F5987ULL,
		0x88D5396BDDB8AB60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53CF7554A3000000ULL,
		0x43BE1473830F0B2FULL,
		0x9DA22F5987A7937FULL,
		0x6BDDB8AB60A56E03ULL,
		0x000000000088D539ULL
	}};
	shift = 40;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3102FBABDB55A926ULL,
		0xA0D85C5E4E5A0E2EULL,
		0x0F6B297A90410BD4ULL,
		0x13F44AFBB59A33A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDAAD49300000000ULL,
		0x272D071718817DD5ULL,
		0x482085EA506C2E2FULL,
		0xDACD19D307B594BDULL,
		0x0000000009FA257DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9E10DAD08A570DBULL,
		0xB045B117B65DC063ULL,
		0x762F505218C42786ULL,
		0x653F57FCF2D10100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8452B86D80000000ULL,
		0xDB2EE031D4F086D6ULL,
		0x0C6213C35822D88BULL,
		0x796880803B17A829ULL,
		0x00000000329FABFEULL
	}};
	shift = 33;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B7091B90906C599ULL,
		0x2C1CAB1BF88D4178ULL,
		0xEACE624468E0BF0BULL,
		0x6ED582B1289829C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC80000000000000ULL,
		0xBC1DB848DC848362ULL,
		0x85960E558DFC46A0ULL,
		0xE17567312234705FULL,
		0x00376AC158944C14ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDBB31C5236A33B1DULL,
		0x9E23912E439C4435ULL,
		0xC1967DFD9F640A9AULL,
		0x1F0E2B7D260073D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48DA8CEC74000000ULL,
		0xB90E7110D76ECC71ULL,
		0xF67D902A6A788E44ULL,
		0xF49801CF630659F7ULL,
		0x00000000007C38ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x13A4794A410EB53BULL,
		0x450EA987B3BEA049ULL,
		0xE3AE7991B9D57C13ULL,
		0x65EB245CEC6D1104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9D23CA520875A9D8ULL,
		0x28754C3D9DF50248ULL,
		0x1D73CC8DCEABE09AULL,
		0x2F5922E763688827ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DD9A012B7259BCDULL,
		0x8A1CDD6497D15ECCULL,
		0x4770A73CD487530EULL,
		0x14D45059C3AEC902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE68000000000000ULL,
		0xF6616ECD0095B92CULL,
		0x987450E6EB24BE8AULL,
		0x48123B8539E6A43AULL,
		0x0000A6A282CE1D76ULL
	}};
	shift = 13;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8844ED7ECFE3B71ULL,
		0x2A7BDD00431B6779ULL,
		0xC46BF1FE4C352FB9ULL,
		0x299C6E7552D9DC3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x722113B5FB3F8EDCULL,
		0x4A9EF74010C6D9DEULL,
		0xF11AFC7F930D4BEEULL,
		0x0A671B9D54B6770FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB714613B84A90EC7ULL,
		0xA91B124DB1AF7FFDULL,
		0x42C61E0F5CD95832ULL,
		0xCCDDBCB5B3DA7D3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4613B84A90EC7000ULL,
		0xB124DB1AF7FFDB71ULL,
		0x61E0F5CD95832A91ULL,
		0xDBCB5B3DA7D3D42CULL,
		0x0000000000000CCDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x20339572C9FF2B37ULL,
		0xA449F0098FC18C10ULL,
		0x4835A303DB858F12ULL,
		0x9F1B12749D187822ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55CB27FCACDC000ULL,
		0x7C0263F06304080CULL,
		0x68C0F6E163C4A912ULL,
		0xC49D27461E08920DULL,
		0x00000000000027C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB378E053E7983FFFULL,
		0xE07EBD6C549E50FEULL,
		0x4A3E6B802C4C8109ULL,
		0x4D97E55086AFD453ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB378E053E7983FFFULL,
		0xE07EBD6C549E50FEULL,
		0x4A3E6B802C4C8109ULL,
		0x4D97E55086AFD453ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7635DA16E41415A4ULL,
		0x34560ADFF38F9188ULL,
		0x414C513E7A998479ULL,
		0x216D49AB52755250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5056900000000000ULL,
		0x3E4621D8D7685B90ULL,
		0x6611E4D1582B7FCEULL,
		0xD54941053144F9EAULL,
		0x00000085B526AD49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5B2B6017F3EF83BULL,
		0xED726A124AEEB30AULL,
		0x4BA7CFD51172E9EBULL,
		0x2988F39CB7919655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD95B00BF9F7C1D80ULL,
		0xB93509257759857AULL,
		0xD3E7EA88B974F5F6ULL,
		0xC479CE5BC8CB2AA5ULL,
		0x0000000000000014ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF15C5DCD07C05C56ULL,
		0xF6A51C3B736BBA60ULL,
		0x21B967C9869F1562ULL,
		0x2B948759E17AC6C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE683E02E2B0000ULL,
		0x8E1DB9B5DD3078AEULL,
		0xB3E4C34F8AB17B52ULL,
		0x43ACF0BD636110DCULL,
		0x00000000000015CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A46749CF88A3447ULL,
		0xC6990CB2B935C76BULL,
		0x9A351D53C8A30F89ULL,
		0xE6ADCE140DA94E04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C451A2380000000ULL,
		0x5C9AE3B595233A4EULL,
		0xE45187C4E34C8659ULL,
		0x06D4A7024D1A8EA9ULL,
		0x000000007356E70AULL
	}};
	shift = 33;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02BA2D20F622225BULL,
		0x4D84A17DA497CE4CULL,
		0x36662F7021C0F82DULL,
		0x27CA0B9BAB0885A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44B6000000000000ULL,
		0x9C9805745A41EC44ULL,
		0xF05A9B0942FB492FULL,
		0x0B426CCC5EE04381ULL,
		0x00004F9417375611ULL
	}};
	shift = 15;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40BD7799E389EF30ULL,
		0x7739AEF727975F14ULL,
		0xBB9D47442D38A5C9ULL,
		0xB1F20BC42CAAF867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE600000000000000ULL,
		0xE28817AEF33C713DULL,
		0xB92EE735DEE4F2EBULL,
		0x0CF773A8E885A714ULL,
		0x00163E417885955FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA5CE1D75AD5C431ULL,
		0xBAD1A6BC489E134FULL,
		0x3B36DAE27345DD3EULL,
		0xD2CA37F8A941A8DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6AE218800000000ULL,
		0x44F09A7DD2E70EBAULL,
		0x9A2EE9F5D68D35E2ULL,
		0x4A0D46D1D9B6D713ULL,
		0x000000069651BFC5ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF85C78458CB1E66ULL,
		0x92660C2159AFE321ULL,
		0xE6CAB6A3C3C400DBULL,
		0x9D1E7AEBA4AE5B70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3000000000000000ULL,
		0x0F7C2E3C22C658F3ULL,
		0xDC9330610ACD7F19ULL,
		0x873655B51E1E2006ULL,
		0x04E8F3D75D2572DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2654586B5879B165ULL,
		0xFA0B8A9B27EE328DULL,
		0x5796D6F2C6D01E69ULL,
		0xEDEFDF4BD9841A5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x586B5879B1650000ULL,
		0x8A9B27EE328D2654ULL,
		0xD6F2C6D01E69FA0BULL,
		0xDF4BD9841A5B5796ULL,
		0x000000000000EDEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA308B21E80EF0A3ULL,
		0xCF113BAF4DCAA75DULL,
		0x72E1C86109AE25C5ULL,
		0x53E8B02D140D3C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11643D01DE146000ULL,
		0x2775E9B954EBBF46ULL,
		0x390C2135C4B8B9E2ULL,
		0x1605A281A7886E5CULL,
		0x0000000000000A7DULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9C37B2F60CAD770ULL,
		0x024D15E9441CC447ULL,
		0xDA6A9A25EE1ADA76ULL,
		0x8A50D221092699B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE00000000000000ULL,
		0x88F7386F65EC195AULL,
		0x4EC049A2BD288398ULL,
		0x36FB4D5344BDC35BULL,
		0x00114A1A442124D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x161FF09275C27C9BULL,
		0x47B0C5104708D2FCULL,
		0x6E61AAC694953262ULL,
		0xBCFAD377CFA35D5FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE124EB84F9360000ULL,
		0x8A208E11A5F82C3FULL,
		0x558D292A64C48F61ULL,
		0xA6EF9F46BABEDCC3ULL,
		0x00000000000179F5ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98E591ACDFF6D738ULL,
		0x2F269183B305C27FULL,
		0x142B4EBF130F2A67ULL,
		0x7862B89675B23856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B9C000000000000ULL,
		0xE13FCC72C8D66FFBULL,
		0x9533979348C1D982ULL,
		0x1C2B0A15A75F8987ULL,
		0x00003C315C4B3AD9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCEEBFDAF5B967CD0ULL,
		0x3A5E71B7484486C7ULL,
		0x7173A31D69839299ULL,
		0x6A06A11046833DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7ADCB3E680000000ULL,
		0xBA4224363E775FEDULL,
		0xEB4C1C94C9D2F38DULL,
		0x823419EDFB8B9D18ULL,
		0x0000000003503508ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BA312D1BB81CACDULL,
		0xC1F9B0966F268721ULL,
		0xAFB74A9C559BA208ULL,
		0x722E62A82B5229D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6680000000000000ULL,
		0x908DD18968DDC0E5ULL,
		0x0460FCD84B379343ULL,
		0xEBD7DBA54E2ACDD1ULL,
		0x003917315415A914ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBA55FAD1CF114A0ULL,
		0x7C12AA65C2DF06D6ULL,
		0xFD670D048D39A7CFULL,
		0xC1F647C82B771AD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBA55FAD1CF114A0ULL,
		0x7C12AA65C2DF06D6ULL,
		0xFD670D048D39A7CFULL,
		0xC1F647C82B771AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x548876BC9E779117ULL,
		0x55D1604DE7E1628CULL,
		0xE43162E1EB2E2860ULL,
		0xA730F965279C297CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B80000000000000ULL,
		0x462A443B5E4F3BC8ULL,
		0x302AE8B026F3F0B1ULL,
		0xBE7218B170F59714ULL,
		0x0053987CB293CE14ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FF0A008BA856EF5ULL,
		0xB43D1FE87B90FC9AULL,
		0xB59320DCC373BBF6ULL,
		0x101D2548B8D2AF17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA800000000000000ULL,
		0xD3FF850045D42B77ULL,
		0xB5A1E8FF43DC87E4ULL,
		0xBDAC9906E61B9DDFULL,
		0x0080E92A45C69578ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF7C717EE2424FE74ULL,
		0xEBC2BFB3D11A71B9ULL,
		0x74F47BC39C38580BULL,
		0xEF6833F0BC391F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFBE38BF712127F3AULL,
		0xF5E15FD9E88D38DCULL,
		0xBA7A3DE1CE1C2C05ULL,
		0x77B419F85E1C8F94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF500440007979674ULL,
		0x33099690DACBEEE2ULL,
		0x88767D9B5148E100ULL,
		0xDBA9C9713A268AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x5EA0088000F2F2CEULL,
		0x066132D21B597DDCULL,
		0xD10ECFB36A291C20ULL,
		0x1B75392E2744D154ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB14D5B6D063A93B4ULL,
		0x7C716F5B77490BEFULL,
		0xA11E3FEC18D48B76ULL,
		0xC1D9B914F5FBA80FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC5356DB418EA4ED0ULL,
		0xF1C5BD6DDD242FBEULL,
		0x8478FFB063522DD9ULL,
		0x0766E453D7EEA03EULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC965D6F1FB2421E8ULL,
		0x2F00B9AFBD4D2318ULL,
		0xE16BE408A066B790ULL,
		0xE4FC3482F2FD4763ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x6325975BC7EC9087ULL,
		0x40BC02E6BEF5348CULL,
		0x8F85AF9022819ADEULL,
		0x0393F0D20BCBF51DULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC556786994FBF3CULL,
		0xBCC1FE1E8B45A2EBULL,
		0xBDE9109836DAA50AULL,
		0xCC56C5B0A39ECDBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF000000000000000ULL,
		0xAFF1559E1A653EFCULL,
		0x2AF307F87A2D168BULL,
		0xFAF7A44260DB6A94ULL,
		0x03315B16C28E7B36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFBA9AD127B8B5735ULL,
		0x11117DAADF3278C4ULL,
		0xE9676D2E214AC23EULL,
		0x4E6061363ED9DB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD400000000000000ULL,
		0x13EEA6B449EE2D5CULL,
		0xF84445F6AB7CC9E3ULL,
		0x93A59DB4B8852B08ULL,
		0x01398184D8FB676CULL
	}};
	shift = 6;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C4F912D2D421F0CULL,
		0xA73524DAFA1582F3ULL,
		0xD5CA08743B6E14DBULL,
		0x2011C7CB846173AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C4F912D2D421F0CULL,
		0xA73524DAFA1582F3ULL,
		0xD5CA08743B6E14DBULL,
		0x2011C7CB846173AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BB747B192432AF7ULL,
		0xD039BEA97B769616ULL,
		0x8D3DD90B1554AD6FULL,
		0x44588D7268D3DEB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC921957B80000000ULL,
		0xBDBB4B0B15DBA3D8ULL,
		0x8AAA56B7E81CDF54ULL,
		0x3469EF5BC69EEC85ULL,
		0x00000000222C46B9ULL
	}};
	shift = 33;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83B9B0B4B156A299ULL,
		0xAD4950B8C263E92AULL,
		0xFD26859438B49899ULL,
		0x5540D8B04335346EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62AD453200000000ULL,
		0x84C7D25507736169ULL,
		0x716931335A92A171ULL,
		0x866A68DDFA4D0B28ULL,
		0x00000000AA81B160ULL
	}};
	shift = 31;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C27ED1ECCD4F656ULL,
		0xF981742D849B2FF1ULL,
		0x3B0161CF5A87F640ULL,
		0x5BA45FA962C1B913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF666A7B2B0000000ULL,
		0x6C24D97F89E13F68ULL,
		0x7AD43FB207CC0BA1ULL,
		0x4B160DC899D80B0EULL,
		0x0000000002DD22FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 229;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C98269BAC74D867ULL,
		0x9106882349A14753ULL,
		0x92B42950EC35DD3AULL,
		0xC2A51BAEAD58173FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x79304D3758E9B0CEULL,
		0x220D104693428EA6ULL,
		0x256852A1D86BBA75ULL,
		0x854A375D5AB02E7FULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x41FD0BBA2B0F2268ULL,
		0x3C4A71A994B76EB9ULL,
		0xAFF13303B1CD8A8DULL,
		0xDBD39A45BD936286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x941FD0BBA2B0F226ULL,
		0xD3C4A71A994B76EBULL,
		0x6AFF13303B1CD8A8ULL,
		0x0DBD39A45BD93628ULL
	}};
	shift = 4;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x941333C64DB46E7DULL,
		0xB3478CD76A4D50EDULL,
		0x370AB7D6684A8EEAULL,
		0x1DC8E798293FC529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D1B9F4000000000ULL,
		0x93543B6504CCF193ULL,
		0x12A3BAACD1E335DAULL,
		0x4FF14A4DC2ADF59AULL,
		0x000000077239E60AULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8873CAED10FB30E6ULL,
		0xDE515C220132695EULL,
		0x51B61FA5F769C876ULL,
		0x9F13495666935537ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC398000000000000ULL,
		0xA57A21CF2BB443ECULL,
		0x21DB7945708804C9ULL,
		0x54DD46D87E97DDA7ULL,
		0x00027C4D25599A4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDD239BA332B723FULL,
		0x7AE0596FA35F13E3ULL,
		0x094BCA777AB420F0ULL,
		0x64EF3D16FEA735CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FC0000000000000ULL,
		0xF8FB748E6E8CCADCULL,
		0x3C1EB8165BE8D7C4ULL,
		0x728252F29DDEAD08ULL,
		0x00193BCF45BFA9CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8EEE4A84A2D453A8ULL,
		0x7423F5A66EF724DEULL,
		0xE2621317730BCCE9ULL,
		0xF0E7DCF46042A7BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29D4000000000000ULL,
		0x926F47772542516AULL,
		0xE674BA11FAD3377BULL,
		0x53DF7131098BB985ULL,
		0x00007873EE7A3021ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECC8E602756A9BC8ULL,
		0x8948253515766996ULL,
		0xCB3331A4B5C61BF0ULL,
		0xDAD95FA7E84C49A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66473013AB54DE40ULL,
		0x4A4129A8ABB34CB7ULL,
		0x59998D25AE30DF84ULL,
		0xD6CAFD3F42624D0EULL,
		0x0000000000000006ULL
	}};
	shift = 61;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08F3C51B76ED8509ULL,
		0x22A5F81ABA979F2AULL,
		0xA8015CC12B4C2A65ULL,
		0xD67CD8B99B9D0C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB614240000000000ULL,
		0x5E7CA823CF146DDBULL,
		0x30A9948A97E06AEAULL,
		0x743176A0057304ADULL,
		0x00000359F362E66EULL
	}};
	shift = 22;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB82466D393F449C3ULL,
		0x21C5C23B71D7C765ULL,
		0x2194B813E0B1E5F7ULL,
		0x17CAC05E7E155824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x727E893860000000ULL,
		0x6E3AF8ECB7048CDAULL,
		0x7C163CBEE438B847ULL,
		0xCFC2AB0484329702ULL,
		0x0000000002F9580BULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DDC1A48B5A7EFF5ULL,
		0xFD91B46D8FEB8B50ULL,
		0xE0356A93A1B07E1CULL,
		0x18BA6ED6FAC4C584ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x69FBFD4000000000ULL,
		0xFAE2D4237706922DULL,
		0x6C1F873F646D1B63ULL,
		0xB13161380D5AA4E8ULL,
		0x000000062E9BB5BEULL
	}};
	shift = 26;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x190BD49E3CED18FAULL,
		0x92300464435E9C53ULL,
		0x0F80EDD78386CB9BULL,
		0x18D21559AE49C626ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5278F3B463E80000ULL,
		0x11910D7A714C642FULL,
		0xB75E0E1B2E6E48C0ULL,
		0x5566B92718983E03ULL,
		0x0000000000006348ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B864653F53A1E09ULL,
		0x894E6489E2364E4FULL,
		0x4311A4F8A9F93B56ULL,
		0x4D78B33DA895F94CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC32329FA9D0F048ULL,
		0x4A73244F11B2727AULL,
		0x188D27C54FC9DAB4ULL,
		0x6BC599ED44AFCA62ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84B6ECA9FC87B2FDULL,
		0x6856D0A86B21DAF8ULL,
		0x206DE37A0D90C274ULL,
		0x168CBCDBBA0C21BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC87B2FD000000000ULL,
		0xB21DAF884B6ECA9FULL,
		0xD90C2746856D0A86ULL,
		0xA0C21BE206DE37A0ULL,
		0x0000000168CBCDBBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D275EFD5759D617ULL,
		0xBF1E96AC3B3F08F7ULL,
		0x08D43F66EA114206ULL,
		0x473029902A9280A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF7EABACEB0B8000ULL,
		0x4B561D9F847BC693ULL,
		0x1FB37508A1035F8FULL,
		0x14C815494050846AULL,
		0x0000000000002398ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C9921B327CC0FEAULL,
		0x145C8605D393DF6CULL,
		0x4AAE0D44F1F7D264ULL,
		0x325FE3E5115F4F4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0FEA000000000000ULL,
		0xDF6C8C9921B327CCULL,
		0xD264145C8605D393ULL,
		0x4F4D4AAE0D44F1F7ULL,
		0x0000325FE3E5115FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15C0C3A55E9EC9D9ULL,
		0x7C2A8CA257658487ULL,
		0x7A2F522059225735ULL,
		0xA66BE6915F43278DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x64EC800000000000ULL,
		0xC2438AE061D2AF4FULL,
		0x2B9ABE1546512BB2ULL,
		0x93C6BD17A9102C91ULL,
		0x00005335F348AFA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD81D4D69CB065181ULL,
		0x726357591485F571ULL,
		0x219F19502387F792ULL,
		0x7D09DD2138C3AE16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9460400000000000ULL,
		0x7D5C7607535A72C1ULL,
		0xFDE49C98D5D64521ULL,
		0xEB858867C65408E1ULL,
		0x00001F4277484E30ULL
	}};
	shift = 18;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7DDF4BF4DC41434ULL,
		0xDC2EDD1F8BA25F0AULL,
		0x9D1F40CCEF68BC1AULL,
		0x6764D0925F5A1358ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD2FD371050D00000ULL,
		0x747E2E897C2B9F77ULL,
		0x0333BDA2F06B70BBULL,
		0x42497D684D62747DULL,
		0x0000000000019D93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D28593F0EE11C55ULL,
		0xB82F6DBBA2514E71ULL,
		0x55D4869ACFD6DAC8ULL,
		0xE06A2234A863128AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x08E2A80000000000ULL,
		0x8A738AE942C9F877ULL,
		0xB6D645C17B6DDD12ULL,
		0x189452AEA434D67EULL,
		0x000007035111A543ULL
	}};
	shift = 21;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA79807222C078CE2ULL,
		0x3CFF710AD342152FULL,
		0x68BBC042903DF0DBULL,
		0x2D62EC2DC74A7786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80F19C4000000000ULL,
		0x6842A5F4F300E445ULL,
		0x07BE1B679FEE215AULL,
		0xE94EF0CD17780852ULL,
		0x00000005AC5D85B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07A50CCA5713BA08ULL,
		0x3B0D8D40F911D826ULL,
		0x8B3EB4A011682EE0ULL,
		0x00B35CF915C60D0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0x981E9433295C4EE8ULL,
		0x80EC363503E44760ULL,
		0x322CFAD28045A0BBULL,
		0x0002CD73E4571834ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF13A9EB026AE8753ULL,
		0x2FFE125F5E918FB8ULL,
		0x52CB9461C74E3FA2ULL,
		0xE3F385ABBBD76978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0x8F13A9EB026AE875ULL,
		0x22FFE125F5E918FBULL,
		0x852CB9461C74E3FAULL,
		0x0E3F385ABBBD7697ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C98ADCF84AA3AC5ULL,
		0x42C45BBF2BCC2F36ULL,
		0xB5F3E5B89AE60667ULL,
		0xE07CA344A95BA8E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x758A000000000000ULL,
		0x5E6C19315B9F0954ULL,
		0x0CCE8588B77E5798ULL,
		0x51D36BE7CB7135CCULL,
		0x0001C0F9468952B7ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB8F8FA82E23992A5ULL,
		0x3E238E570F176755ULL,
		0x83D4A197E30D3F1DULL,
		0x50942AFDFFAAD325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x992A500000000000ULL,
		0x76755B8F8FA82E23ULL,
		0xD3F1D3E238E570F1ULL,
		0xAD32583D4A197E30ULL,
		0x0000050942AFDFFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x433DC910AA63715CULL,
		0xF5D70E99B075E61AULL,
		0x9D030C410131C085ULL,
		0xF60EF38CFBC57491ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5531B8AE00000000ULL,
		0xD83AF30D219EE488ULL,
		0x8098E042FAEB874CULL,
		0x7DE2BA48CE818620ULL,
		0x000000007B0779C6ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D8BA7D6F4AF6CA8ULL,
		0x81C44D0FE47F3B8AULL,
		0xB9177BEDDDD97CC8ULL,
		0x1D899432A4ED11FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2BDB2A000000000ULL,
		0x91FCEE29762E9F5BULL,
		0x7765F3220711343FULL,
		0x93B447FAE45DEFB7ULL,
		0x00000000762650CAULL
	}};
	shift = 30;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5317B32461AF8AFDULL,
		0x3C3ED188B122E78CULL,
		0x24EDCF3CF7B2A127ULL,
		0x65EC6A88E52E5A9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x230D7C57E8000000ULL,
		0x4589173C6298BD99ULL,
		0xE7BD950939E1F68CULL,
		0x472972D4D1276E79ULL,
		0x00000000032F6354ULL
	}};
	shift = 37;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96F2E18E7311D60FULL,
		0x58917145069236B4ULL,
		0x6D1CA5EDE0FB5698ULL,
		0x85EC04502CB3FD8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x92DE5C31CE623AC1ULL,
		0x0B122E28A0D246D6ULL,
		0x6DA394BDBC1F6AD3ULL,
		0x10BD808A05967FB1ULL
	}};
	shift = 3;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB827F8FEB0D44658ULL,
		0xF888A816DE93D634ULL,
		0x19A1710D250B3B6EULL,
		0x2AB4E7788D5EA46AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FE3FAC351196000ULL,
		0x22A05B7A4F58D2E0ULL,
		0x85C434942CEDBBE2ULL,
		0xD39DE2357A91A866ULL,
		0x00000000000000AAULL
	}};
	shift = 54;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF01D09BDC5FB3332ULL,
		0x28FF9A91EBADA517ULL,
		0xCFD5705BD9300AF4ULL,
		0x6BD8BC01C72DD7BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE03A137B8BF66664ULL,
		0x51FF3523D75B4A2FULL,
		0x9FAAE0B7B26015E8ULL,
		0xD7B178038E5BAF7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5BBE11B3EE7A5FCULL,
		0x7EBA5A9E6DA697E7ULL,
		0x76BEF9AF653FB89DULL,
		0x5DD4F9A702CF3797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEE7A5FC000000000ULL,
		0xDA697E7D5BBE11B3ULL,
		0x53FB89D7EBA5A9E6ULL,
		0x2CF379776BEF9AF6ULL,
		0x00000005DD4F9A70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x127FBCFFB6312AC8ULL,
		0x785D6533DD170CF2ULL,
		0xA834A942DD32B3A4ULL,
		0x79BA75EA71EFDA2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x9093FDE7FDB18956ULL,
		0x23C2EB299EE8B867ULL,
		0x6541A54A16E9959DULL,
		0x03CDD3AF538F7ED1ULL
	}};
	shift = 5;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30056FA06C227BF1ULL,
		0xD45A46112F113823ULL,
		0xFD4031939FFDD51CULL,
		0x0A29688CC55C5F4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BF1000000000000ULL,
		0x382330056FA06C22ULL,
		0xD51CD45A46112F11ULL,
		0x5F4EFD4031939FFDULL,
		0x00000A29688CC55CULL
	}};
	shift = 16;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x752B81751D0C4155ULL,
		0xC5AFFEA27C47A7F8ULL,
		0xED669972821900B2ULL,
		0x7A951B677BEF60B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4155000000000000ULL,
		0xA7F8752B81751D0CULL,
		0x00B2C5AFFEA27C47ULL,
		0x60B8ED6699728219ULL,
		0x00007A951B677BEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA41F1B3F4646F4B0ULL,
		0x60D23958AE2D74B1ULL,
		0x3C75AB7886D7E6D0ULL,
		0x87FEADF6B7449E74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFD191BD2C000000ULL,
		0x562B8B5D2C6907C6ULL,
		0xDE21B5F9B418348EULL,
		0x7DADD1279D0F1D6AULL,
		0x000000000021FFABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89AE7E5D4A61D09BULL,
		0x043B732F5EA2B286ULL,
		0x8B644F6D5349F560ULL,
		0xA6AB2274BFFC212EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCBA94C3A1360000ULL,
		0xE65EBD45650D135CULL,
		0x9EDAA693EAC00876ULL,
		0x44E97FF8425D16C8ULL,
		0x0000000000014D56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x234EE978E185278CULL,
		0xE5BDDA80A594D30BULL,
		0x93A0EB2068B423DDULL,
		0x62FDC82C2B6EA420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8D3BA5E386149E3ULL,
		0x796F76A0296534C2ULL,
		0x24E83AC81A2D08F7ULL,
		0x18BF720B0ADBA908ULL
	}};
	shift = 2;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E5C9DA4004F7078ULL,
		0x69DCAA29E3A901E2ULL,
		0xDA125CA32ECC1339ULL,
		0xBB9635662A82C90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF707800000000000ULL,
		0x901E25E5C9DA4004ULL,
		0xC133969DCAA29E3AULL,
		0x2C90CDA125CA32ECULL,
		0x00000BB9635662A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA9C898FA39FFDEAULL,
		0x41695C596D1A2824ULL,
		0x93282AE8F2A96B16ULL,
		0x32188CA0E7236283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEF5000000000000ULL,
		0x14125D4E44C7D1CFULL,
		0xB58B20B4AE2CB68DULL,
		0xB141C99415747954ULL,
		0x0000190C46507391ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 209;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA11D96F3E8D8FF53ULL,
		0xFA4D703DE04C231CULL,
		0xCF69AC1ED2C8F6EBULL,
		0xEE68F62522DE77CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x284765BCFA363FD4ULL,
		0xFE935C0F781308C7ULL,
		0xF3DA6B07B4B23DBAULL,
		0x3B9A3D8948B79DF3ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9C191A6BE9BB947ULL,
		0x937E0951D200C450ULL,
		0xA5456AB68676F659ULL,
		0x64AFAE4A1AF44407ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6EE51C000000000ULL,
		0x80311436706469AFULL,
		0x9DBD9664DF825474ULL,
		0xBD1101E9515AADA1ULL,
		0x000000192BEB9286ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x556E5A7278074EB9ULL,
		0x8A8302A7B6A0FAD6ULL,
		0xD3D112699406AFC2ULL,
		0x7FE9E458142E6F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9D7200000000000ULL,
		0x1F5ACAADCB4E4F00ULL,
		0xD5F851506054F6D4ULL,
		0xCDE37A7A224D3280ULL,
		0x00000FFD3C8B0285ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE3E0140487890C6ULL,
		0x041F5EFDE24C686BULL,
		0xD94D851EAE2146A2ULL,
		0x40A67C8B06332A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3E0140487890C60ULL,
		0x41F5EFDE24C686BBULL,
		0x94D851EAE2146A20ULL,
		0x0A67C8B06332A82DULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27EAA73B0F5A090BULL,
		0x2D70AC46FF1F568FULL,
		0xB13722ED0E29027DULL,
		0x89C0904C965F7770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x90B0000000000000ULL,
		0x68F27EAA73B0F5A0ULL,
		0x27D2D70AC46FF1F5ULL,
		0x770B13722ED0E290ULL,
		0x00089C0904C965F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E6496960839EDD1ULL,
		0xC385BCEA30BB4C65ULL,
		0xF8C92D527E631BC1ULL,
		0x13E609F465C4B02EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6E8800000000000ULL,
		0xA632C7324B4B041CULL,
		0x8DE0E1C2DE75185DULL,
		0x58177C6496A93F31ULL,
		0x000009F304FA32E2ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06AFA626416FA1FBULL,
		0xC82C63B80DFB9AE4ULL,
		0x3EDEA2D2DAA942F1ULL,
		0xDCB1C1D9BC21F6FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0FD800000000000ULL,
		0xCD720357D31320B7ULL,
		0xA178E41631DC06FDULL,
		0xFB7D9F6F51696D54ULL,
		0x00006E58E0ECDE10ULL
	}};
	shift = 17;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE17163B8616E4465ULL,
		0xBB30D0C71520257DULL,
		0x5A6CF5366DE69EB5ULL,
		0xE193D7B59222EA02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x616E446500000000ULL,
		0x1520257DE17163B8ULL,
		0x6DE69EB5BB30D0C7ULL,
		0x9222EA025A6CF536ULL,
		0x00000000E193D7B5ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C5B5EE4C3F880D6ULL,
		0x70FEF08438A021EEULL,
		0x7377833EF8E10B32ULL,
		0xDCB44F26A28BF5EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF880D60000000000ULL,
		0xA021EE4C5B5EE4C3ULL,
		0xE10B3270FEF08438ULL,
		0x8BF5EA7377833EF8ULL,
		0x000000DCB44F26A2ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD5F425B91893CE3CULL,
		0x7B56AEB08BE5277EULL,
		0x4E3ACE0DFE357771ULL,
		0xBB445E612FEB4DABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7800000000000000ULL,
		0xFDABE84B7231279CULL,
		0xE2F6AD5D6117CA4EULL,
		0x569C759C1BFC6AEEULL,
		0x017688BCC25FD69BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC703E19C25162F0ULL,
		0x6FB9F1F0731B9A9DULL,
		0xE6D1EC51208AF325ULL,
		0xAB3CB8E4078500EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC25162F000000000ULL,
		0x731B9A9DAC703E19ULL,
		0x208AF3256FB9F1F0ULL,
		0x078500EBE6D1EC51ULL,
		0x00000000AB3CB8E4ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x590944AAC17629FDULL,
		0x9B50F1B63138B0FFULL,
		0x77229F71FE2FFFE4ULL,
		0xE3DAF4F5F78B6FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAAC17629FD000000ULL,
		0xB63138B0FF590944ULL,
		0x71FE2FFFE49B50F1ULL,
		0xF5F78B6FDA77229FULL,
		0x0000000000E3DAF4ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D1A131E68EB42C5ULL,
		0x7962AB51AD4E45A0ULL,
		0x02887AD0B8FE3CD6ULL,
		0xDB15414573A90803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79A3AD0B14000000ULL,
		0x46B5391680F4684CULL,
		0x42E3F8F359E58AADULL,
		0x15CEA4200C0A21EBULL,
		0x00000000036C5505ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA461FF6D2F69CB6CULL,
		0xE5411D8607986459ULL,
		0x52C3BFFA204CC7D0ULL,
		0x09AD1999E4BF87C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBDA72DB000000000ULL,
		0x1E6191669187FDB4ULL,
		0x81331F4395047618ULL,
		0x92FE1F014B0EFFE8ULL,
		0x0000000026B46667ULL
	}};
	shift = 30;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE53102FD5C649783ULL,
		0x58AE7F405587CC6DULL,
		0xD4EACA56B93A08E1ULL,
		0xE958FA817E0AAB02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD5C649783000000ULL,
		0x405587CC6DE53102ULL,
		0x56B93A08E158AE7FULL,
		0x817E0AAB02D4EACAULL,
		0x0000000000E958FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1129E94138473467ULL,
		0x3B4B20CB630BFA4DULL,
		0x5F403BEB193369C9ULL,
		0x48689E3F0D2EFB70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7346700000000000ULL,
		0xBFA4D1129E941384ULL,
		0x369C93B4B20CB630ULL,
		0xEFB705F403BEB193ULL,
		0x0000048689E3F0D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7697B273764CC8CAULL,
		0x8275B5AEA9F171B8ULL,
		0xBE3F223A47FAC569ULL,
		0x7B82CE1AA647F629ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x87697B273764CC8CULL,
		0x98275B5AEA9F171BULL,
		0x9BE3F223A47FAC56ULL,
		0x07B82CE1AA647F62ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x691EE930C1EDB1E3ULL,
		0xCA5345A634755161ULL,
		0x51BBC2A464ADDB3EULL,
		0x2DCB90E951CC0865ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C78C00000000000ULL,
		0x54585A47BA4C307BULL,
		0x76CFB294D1698D1DULL,
		0x0219546EF0A9192BULL,
		0x00000B72E43A5473ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF5D1B1EBA30628C1ULL,
		0xFEEE346461FF9E48ULL,
		0x9DE1B0BFD5E7A400ULL,
		0xD2611B22B9A9C2D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA30628C10000000ULL,
		0x461FF9E48F5D1B1EULL,
		0xFD5E7A400FEEE346ULL,
		0x2B9A9C2D69DE1B0BULL,
		0x000000000D2611B2ULL
	}};
	shift = 36;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x17826E0752D89EFBULL,
		0xE0DCFB5F7A6A7C6CULL,
		0xFDA12A6FBAD78966ULL,
		0xC274334BA75134F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BEC000000000000ULL,
		0xF1B05E09B81D4B62ULL,
		0x259B8373ED7DE9A9ULL,
		0xD3E3F684A9BEEB5EULL,
		0x000309D0CD2E9D44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 206;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x120AE948DE218759ULL,
		0xB62EDBFF8703E481ULL,
		0xE86E8909C8DE9357ULL,
		0xB388E168E9E97C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA52378861D64000ULL,
		0xB6FFE1C0F9204482ULL,
		0xA2427237A4D5ED8BULL,
		0x385A3A7A5F1DFA1BULL,
		0x0000000000002CE2ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7C2173B2266836EULL,
		0xA474ED3A027B13EFULL,
		0xF0D3EFA4327233ABULL,
		0x594502514E4EBB03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE10B9D913341B700ULL,
		0x3A769D013D89F7F3ULL,
		0x69F7D2193919D5D2ULL,
		0xA28128A7275D81F8ULL,
		0x000000000000002CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9D995729BA9C620ULL,
		0x176284236FBABFDDULL,
		0xCC74C9BFB69F6EDDULL,
		0xE27769767AE3BF8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB94DD4E310000000ULL,
		0x11B7DD5FEEE4ECCAULL,
		0xDFDB4FB76E8BB142ULL,
		0xBB3D71DFC5E63A64ULL,
		0x0000000000713BB4ULL
	}};
	shift = 41;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98226AA62BA54FD5ULL,
		0x6BD791CEB14840ABULL,
		0x5F8011816ECCA2A4ULL,
		0xD26F62B0AD9169D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF540000000000000ULL,
		0x2AE6089AA98AE953ULL,
		0xA91AF5E473AC5210ULL,
		0x7657E004605BB328ULL,
		0x00349BD8AC2B645AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00F4189D13B35B64ULL,
		0x067EE998C761C080ULL,
		0xCF1192C62BB3410FULL,
		0x86F5C004A0368549ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC800000000000000ULL,
		0x0001E8313A2766B6ULL,
		0x1E0CFDD3318EC381ULL,
		0x939E23258C576682ULL,
		0x010DEB8009406D0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6256B287C9E2C21EULL,
		0xDD19C07AED49A12EULL,
		0x2223CBB9F41E6408ULL,
		0x80E944568975B1F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x943E4F1610F00000ULL,
		0x03D76A4D097312B5ULL,
		0x5DCFA0F32046E8CEULL,
		0x22B44BAD8FC1111EULL,
		0x000000000004074AULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D7D5D904615C06DULL,
		0x58F2881AA9EF57D5ULL,
		0x54E211405637AC5FULL,
		0x0EA61512B26C0702ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB400000000000000ULL,
		0x5535F57641185701ULL,
		0x7D63CA206AA7BD5FULL,
		0x095388450158DEB1ULL,
		0x003A98544AC9B01CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8ECB41EA21A84901ULL,
		0x4D8D6110984B1F0BULL,
		0xAE913A61F75F6C0BULL,
		0x03A14AA9251B4E21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D44350920200000ULL,
		0x22130963E171D968ULL,
		0x4C3EEBED8169B1ACULL,
		0x5524A369C435D227ULL,
		0x0000000000007429ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB24D1AE9D04B1FAAULL,
		0x619793A509FB54BDULL,
		0x336D346784D482B5ULL,
		0x2C2C026C46AE5A7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1FAA000000000000ULL,
		0x54BDB24D1AE9D04BULL,
		0x82B5619793A509FBULL,
		0x5A7E336D346784D4ULL,
		0x00002C2C026C46AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x58863066BF40FDDAULL,
		0xB7610D7265D2FC21ULL,
		0xDF9E5923AA6D3383ULL,
		0x278AF5B4DC0563D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED00000000000000ULL,
		0x10AC4318335FA07EULL,
		0xC1DBB086B932E97EULL,
		0xEC6FCF2C91D53699ULL,
		0x0013C57ADA6E02B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC01A822A2EEF61FDULL,
		0xD316CD134B132F74ULL,
		0x64BCDB3A163B50B3ULL,
		0xCACB932373351D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F40000000000000ULL,
		0xDD3006A08A8BBBD8ULL,
		0x2CF4C5B344D2C4CBULL,
		0x43992F36CE858ED4ULL,
		0x0032B2E4C8DCCD47ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9702F925296A186ULL,
		0xA5B13280C67D873CULL,
		0xF2126491CE84BCDDULL,
		0x6873338D003D0635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0BE494A5A8618000ULL,
		0x4CA0319F61CF2A5CULL,
		0x992473A12F37696CULL,
		0xCCE3400F418D7C84ULL,
		0x0000000000001A1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x46BFEA6C352785F7ULL,
		0xF8CE91851B342716ULL,
		0xDCCE6E220B9E6BD6ULL,
		0x767443679D4A5DA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DC0000000000000ULL,
		0xC591AFFA9B0D49E1ULL,
		0xF5BE33A46146CD09ULL,
		0x6977339B8882E79AULL,
		0x001D9D10D9E75297ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E9B7D8F67E82C25ULL,
		0xAFA49D8C8F42914CULL,
		0x1C31ECBA7A52B55EULL,
		0xAE1C2A48E8A90DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FA0B09400000000ULL,
		0x3D0A45313A6DF63DULL,
		0xE94AD57ABE927632ULL,
		0xA2A4368470C7B2E9ULL,
		0x00000002B870A923ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x83EE7DFDE6C3254DULL,
		0x3CE7F9D61DE5FBD6ULL,
		0xDA2901741928FF23ULL,
		0x8FC368E7442930D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3254D00000000000ULL,
		0x5FBD683EE7DFDE6CULL,
		0x8FF233CE7F9D61DEULL,
		0x930D0DA290174192ULL,
		0x000008FC368E7442ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F549032B4CB89BEULL,
		0x450D60A3B6540CDEULL,
		0xA8B479844BD8E637ULL,
		0xA7B78DA0F9E2041CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48195A65C4DF0000ULL,
		0xB051DB2A066F27AAULL,
		0x3CC225EC731BA286ULL,
		0xC6D07CF1020E545AULL,
		0x00000000000053DBULL
	}};
	shift = 49;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05625D99BEBCD7BAULL,
		0x9A5096F1F00FDCEBULL,
		0xFF7940141D9E8A47ULL,
		0xD1A831BA5C39B3B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x625D99BEBCD7BA00ULL,
		0x5096F1F00FDCEB05ULL,
		0x7940141D9E8A479AULL,
		0xA831BA5C39B3B4FFULL,
		0x00000000000000D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDFB8E2BB180BCDBULL,
		0x4D5CA9643467A562ULL,
		0xD19679D6CF5A1011ULL,
		0x55BDC8069DCF883AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC602F36C0000000ULL,
		0x0D19E958B77EE38AULL,
		0xB3D6840453572A59ULL,
		0xA773E20EB4659E75ULL,
		0x00000000156F7201ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x816B054C302682D3ULL,
		0x2423EC0217A1FC2FULL,
		0xD1C66665C80C0DA6ULL,
		0x120526281ED510BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1530C09A0B4C000ULL,
		0xFB0085E87F0BE05AULL,
		0x9999720303698908ULL,
		0x498A07B5442EB471ULL,
		0x0000000000000481ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x85B0D66A027CB0CDULL,
		0x813B36791B85D6EDULL,
		0x6DF3358C33820F7BULL,
		0x748B50D65CE0604DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1ACD404F9619A000ULL,
		0x66CF2370BADDB0B6ULL,
		0x66B1867041EF7027ULL,
		0x6A1ACB9C0C09ADBEULL,
		0x0000000000000E91ULL
	}};
	shift = 51;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4F192D5400ABA38ULL,
		0xA5A3A91DE857F159ULL,
		0x2F0B5E75B9263915ULL,
		0x7184C401D7A49F2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0ABA380000000000ULL,
		0x57F159C4F192D540ULL,
		0x263915A5A3A91DE8ULL,
		0xA49F2E2F0B5E75B9ULL,
		0x0000007184C401D7ULL
	}};
	shift = 24;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55B77C9C8A8A7CADULL,
		0xB7249CD1F8D4E8FBULL,
		0xD778C4BE8335FD15ULL,
		0x202EB6D96644F970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F2B40000000000ULL,
		0x53A3ED56DDF2722AULL,
		0xD7F456DC927347E3ULL,
		0x13E5C35DE312FA0CULL,
		0x00000080BADB6599ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F11BBFAF139ACD4ULL,
		0xFEAED10AFF553139ULL,
		0x5CC1712AB06E39C3ULL,
		0x72D1C2A39C37A6DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC4E6B3500000000ULL,
		0xBFD54C4E57C46EFEULL,
		0xAC1B8E70FFABB442ULL,
		0xE70DE9B6D7305C4AULL,
		0x000000001CB470A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x59CF38A84B8D1D29ULL,
		0xC14044EDB0A96B8BULL,
		0x6DFA528FC13BDE45ULL,
		0x6DC6C44940A5A4ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE3474A4000000000ULL,
		0x2A5AE2D673CE2A12ULL,
		0x4EF7917050113B6CULL,
		0x29692B1B7E94A3F0ULL,
		0x0000001B71B11250ULL
	}};
	shift = 26;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18CE1F6AE950CD0EULL,
		0xA2B6320DCEB9FBBAULL,
		0xC62A81D8AAACE096ULL,
		0x5E28F4C04441E734ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4334380000000000ULL,
		0xE7EEE863387DABA5ULL,
		0xB3825A8AD8C8373AULL,
		0x079CD318AA0762AAULL,
		0x00000178A3D30111ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07E3E07147120A25ULL,
		0xE9B971C25692E9C6ULL,
		0xFC5E67A87DDA3E88ULL,
		0x0D03EA3F0A3A901AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1F038A389051280ULL,
		0xDCB8E12B4974E303ULL,
		0x2F33D43EED1F4474ULL,
		0x81F51F851D480D7EULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5FBF2C2C63882C7ULL,
		0x1265ABEF5926F415ULL,
		0xA0A11132511C8E35ULL,
		0xE65CDDE4736F93E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC700000000000000ULL,
		0x15B5FBF2C2C63882ULL,
		0x351265ABEF5926F4ULL,
		0xE6A0A11132511C8EULL,
		0x00E65CDDE4736F93ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2952D9C92FEDDC67ULL,
		0xD3DA3ADB2690024EULL,
		0xE96BE898A8512AACULL,
		0x6C7BB052F1CB958BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3380000000000000ULL,
		0x2714A96CE497F6EEULL,
		0x5669ED1D6D934801ULL,
		0xC5F4B5F44C542895ULL,
		0x00363DD82978E5CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 201;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D7A162355C34534ULL,
		0x03D52E2C1EADDDFCULL,
		0x96A408EF66E8BC71ULL,
		0x13A86A3D4CBF3972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D570D14D0000000ULL,
		0xB07AB777F175E858ULL,
		0xBD9BA2F1C40F54B8ULL,
		0xF532FCE5CA5A9023ULL,
		0x00000000004EA1A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66EEE950727A8D42ULL,
		0x211A9AD3F205996EULL,
		0x5C1FB29EF0DBCD8CULL,
		0xBE21113C875369BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A8393D46A100000ULL,
		0xD69F902CCB733777ULL,
		0x94F786DE6C6108D4ULL,
		0x89E43A9B4DFAE0FDULL,
		0x000000000005F108ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8535B61825525E33ULL,
		0xE85EB5AF73103BB5ULL,
		0x2B62156B462D41B7ULL,
		0x3B21567AD4931BD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8535B61825525E33ULL,
		0xE85EB5AF73103BB5ULL,
		0x2B62156B462D41B7ULL,
		0x3B21567AD4931BD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC48DA3AE16274337ULL,
		0xA729AA1CD1EA2882ULL,
		0xA2689BF037C29B27ULL,
		0x04ED542ED79BBD4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D70B13A19B80000ULL,
		0x50E68F514416246DULL,
		0xDF81BE14D93D394DULL,
		0xA176BCDDEA651344ULL,
		0x000000000000276AULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5639F3C9735BDA51ULL,
		0xAB9477683177794DULL,
		0x167B09D3E04CBA48ULL,
		0x12CA3D6DDBB37F95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5639F3C9735BDA51ULL,
		0xAB9477683177794DULL,
		0x167B09D3E04CBA48ULL,
		0x12CA3D6DDBB37F95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2348B0DC73A813F0ULL,
		0x67263F7F06291906ULL,
		0x737AB46284D602B7ULL,
		0x1F254DC0FC708276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x409F800000000000ULL,
		0x48C8311A4586E39DULL,
		0xB015BB3931FBF831ULL,
		0x8413B39BD5A31426ULL,
		0x000000F92A6E07E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC1F1830E74CA1F4AULL,
		0x2E7D6AAE88583657ULL,
		0x30F26651163FCF26ULL,
		0x83D81FD5614CC26FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE940000000000000ULL,
		0xCAF83E3061CE9943ULL,
		0xE4C5CFAD55D10B06ULL,
		0x4DE61E4CCA22C7F9ULL,
		0x00107B03FAAC2998ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD7BC52E41E261BEULL,
		0xF87C9B52CC400F1FULL,
		0x2CF41585D1F06FD9ULL,
		0x39FCE2EC1BDF3283ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDF00000000000000ULL,
		0x8FEEBDE29720F130ULL,
		0xECFC3E4DA9662007ULL,
		0x41967A0AC2E8F837ULL,
		0x001CFE71760DEF99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC3193BDF69356C65ULL,
		0x4158D539519702DEULL,
		0x3D619355A5257404ULL,
		0xAF6C6831B305B077ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BDF69356C650000ULL,
		0xD539519702DEC319ULL,
		0x9355A52574044158ULL,
		0x6831B305B0773D61ULL,
		0x000000000000AF6CULL
	}};
	shift = 48;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA2062A9DEC1C1DDULL,
		0x42AA723ECA17CC1CULL,
		0x070B5FBA0609B9DDULL,
		0x8702B81A23E2B1FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2062A9DEC1C1DD00ULL,
		0xAA723ECA17CC1CAAULL,
		0x0B5FBA0609B9DD42ULL,
		0x02B81A23E2B1FB07ULL,
		0x0000000000000087ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44106A6D316727C8ULL,
		0x62FF4CCDD179B6CCULL,
		0xDA9B34E8DDFD2274ULL,
		0x0E1DF2D38561DA24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE400000000000000ULL,
		0x662208353698B393ULL,
		0x3A317FA666E8BCDBULL,
		0x126D4D9A746EFE91ULL,
		0x00070EF969C2B0EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA7054FEDD9F5B3AULL,
		0x211C3565D8FBEE8BULL,
		0xC5B693CAF912BBF0ULL,
		0x72BE1F927CFE451EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBB3EB6740000000ULL,
		0xBB1F7DD1754E0A9FULL,
		0x5F22577E042386ACULL,
		0x4F9FC8A3D8B6D279ULL,
		0x000000000E57C3F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5449784A9F7EE9FULL,
		0x66699BB82517A959ULL,
		0x237738C003CF4B58ULL,
		0x66BC533BAB7815B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xD2A24BC254FBF74FULL,
		0x3334CDDC128BD4ACULL,
		0x11BB9C6001E7A5ACULL,
		0x335E299DD5BC0ADAULL
	}};
	shift = 1;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x237441C1FD3DD798ULL,
		0x1AE540A3FDDBDE9AULL,
		0xDD32F0FDE7AF81DFULL,
		0xEDEE4C95757BC986ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAF30000000000000ULL,
		0xBD3446E88383FA7BULL,
		0x03BE35CA8147FBB7ULL,
		0x930DBA65E1FBCF5FULL,
		0x0001DBDC992AEAF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09A341EBA92DD83DULL,
		0x11467107DE06B792ULL,
		0xCB53456B85BB158FULL,
		0x49EE088E8EE19A02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD7525BB07A000000ULL,
		0x0FBC0D6F24134683ULL,
		0xD70B762B1E228CE2ULL,
		0x1D1DC3340596A68AULL,
		0x000000000093DC11ULL
	}};
	shift = 39;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00E286F2102C072BULL,
		0xA9135AC204718087ULL,
		0x99C40501ACE5A4D9ULL,
		0x018A33830E18CBFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE286F2102C072B00ULL,
		0x135AC20471808700ULL,
		0xC40501ACE5A4D9A9ULL,
		0x8A33830E18CBFF99ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81A52B9C06F4AA08ULL,
		0xE97C827DFD052109ULL,
		0xC828CE3EF62A4DBDULL,
		0x63266B99BEF2E608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9541000000000000ULL,
		0xA4213034A57380DEULL,
		0x49B7BD2F904FBFA0ULL,
		0x5CC1190519C7DEC5ULL,
		0x00000C64CD7337DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DAAB3096413411CULL,
		0x3F41AAD82F10CE6BULL,
		0x8283DC726117ECD9ULL,
		0x122CFF7833B3B6E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C82682380000000ULL,
		0x05E219CD67B55661ULL,
		0x4C22FD9B27E8355BULL,
		0x067676DC50507B8EULL,
		0x0000000002459FEFULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34205A2A81D943EEULL,
		0x51E8B598B237C33DULL,
		0xB3A4C037435FFB97ULL,
		0x648BA9BDA68E8E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA07650FB8000000ULL,
		0x62C8DF0CF4D08168ULL,
		0xDD0D7FEE5D47A2D6ULL,
		0xF69A3A3A12CE9300ULL,
		0x0000000001922EA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56B26428F2538427ULL,
		0x148B8F46926BA84AULL,
		0xA1667B562382E847ULL,
		0x983E4BF5320B9AC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA3C94E109C000000ULL,
		0x1A49AEA1295AC990ULL,
		0x588E0BA11C522E3DULL,
		0xD4C82E6B268599EDULL,
		0x000000000260F92FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF405173690EE8630ULL,
		0xC25F45A38DA3079CULL,
		0x9123546390EB9F14ULL,
		0x5746F12E770741A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8774318000000000ULL,
		0x6D183CE7A028B9B4ULL,
		0x875CF8A612FA2D1CULL,
		0xB83A0D04891AA31CULL,
		0x00000002BA378973ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E03A6E70994671DULL,
		0x4FE1AC8E8ED8302EULL,
		0x14CEE8FA9D713A67ULL,
		0x2CF8E6FA97FD46A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9B9C26519C740000ULL,
		0xB23A3B60C0B9780EULL,
		0xA3EA75C4E99D3F86ULL,
		0x9BEA5FF51A90533BULL,
		0x000000000000B3E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CAA5FD0FBD67FEAULL,
		0x30FC7374776751B8ULL,
		0x36A6F8320F4DBE82ULL,
		0xE22BDDB2BE26B370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1F7ACFFD4000000ULL,
		0xE8EECEA3701954BFULL,
		0x641E9B7D0461F8E6ULL,
		0x657C4D66E06D4DF0ULL,
		0x0000000001C457BBULL
	}};
	shift = 39;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD720B1C8FA10C42ULL,
		0x508617C959B4888AULL,
		0x937A79A4DEDBC9D4ULL,
		0xE8C61DF120EB5774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8FA10C4200000000ULL,
		0x59B4888AAD720B1CULL,
		0xDEDBC9D4508617C9ULL,
		0x20EB5774937A79A4ULL,
		0x00000000E8C61DF1ULL
	}};
	shift = 32;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF4277323A882D79CULL,
		0xCCF95A8F4E295E61ULL,
		0xC03113ACED5BC8CEULL,
		0xDBB82AA74FB9E499ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x277323A882D79C00ULL,
		0xF95A8F4E295E61F4ULL,
		0x3113ACED5BC8CECCULL,
		0xB82AA74FB9E499C0ULL,
		0x00000000000000DBULL
	}};
	shift = 56;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9272EB6A6623EE33ULL,
		0x8E6131AE75DB225FULL,
		0x597D650E23148278ULL,
		0xBDD5BFD44866E2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x975B53311F719800ULL,
		0x098D73AED912FC93ULL,
		0xEB287118A413C473ULL,
		0xADFEA24337165ACBULL,
		0x00000000000005EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD386BE2DB9C332FULL,
		0x0333F867724432E0ULL,
		0xBED07B9278E3C943ULL,
		0xDDCC81FCD20A1080ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1997800000000000ULL,
		0x19707E9C35F16DCEULL,
		0xE4A18199FC33B922ULL,
		0x08405F683DC93C71ULL,
		0x00006EE640FE6905ULL
	}};
	shift = 17;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CDEC3CF08F86D74ULL,
		0x23AA1428294CD6D6ULL,
		0x320B990ABDD4E6CBULL,
		0x6A96A31AB1B42DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAE8000000000000ULL,
		0xADAD19BD879E11F0ULL,
		0xCD96475428505299ULL,
		0x5B7E641732157BA9ULL,
		0x0000D52D46356368ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21222E2D258448E3ULL,
		0x60C11A48D73AC4CEULL,
		0x6B5AE04CFD564FA8ULL,
		0xC2784ECBFCE50E27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C5A4B0891C60000ULL,
		0x3491AE75899C4244ULL,
		0xC099FAAC9F50C182ULL,
		0x9D97F9CA1C4ED6B5ULL,
		0x00000000000184F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03D2E5783C091E35ULL,
		0x1E751C303833B624ULL,
		0xEE3246B13719B2F5ULL,
		0xCC705D737BBA0063ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2E5783C091E35000ULL,
		0x51C303833B62403DULL,
		0x246B13719B2F51E7ULL,
		0x05D737BBA0063EE3ULL,
		0x0000000000000CC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x22B3627F365B91A5ULL,
		0x374D435DF0A2186AULL,
		0x0F84CDD5B8D21DEDULL,
		0x6CDE164B96299F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x365B91A500000000ULL,
		0xF0A2186A22B3627FULL,
		0xB8D21DED374D435DULL,
		0x96299F8A0F84CDD5ULL,
		0x000000006CDE164BULL
	}};
	shift = 32;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA75B2294FF2B0A9ULL,
		0x84F03FCC48254644ULL,
		0xACFFDE85D0E27197ULL,
		0x673DF799B5993D71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9D6C8A53FCAC2A40ULL,
		0x3C0FF31209519132ULL,
		0x3FF7A174389C65E1ULL,
		0xCF7DE66D664F5C6BULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x13F92DB9B3B6278CULL,
		0x8BEEF14BDA7029D1ULL,
		0xC23FF61CF6C421B3ULL,
		0x82A30FD4112BB983ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC96DCD9DB13C600ULL,
		0xF778A5ED3814E889ULL,
		0x1FFB0E7B6210D9C5ULL,
		0x5187EA0895DCC1E1ULL,
		0x0000000000000041ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0B6E62FE19EC525ULL,
		0xDEAA8B2A53A7DD84ULL,
		0xEE4F8D0CB162C288ULL,
		0x057DA476474964EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB6E62FE19EC52500ULL,
		0xAA8B2A53A7DD84A0ULL,
		0x4F8D0CB162C288DEULL,
		0x7DA476474964EAEEULL,
		0x0000000000000005ULL
	}};
	shift = 56;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E46B3596091995FULL,
		0x22676C6838C2E4CEULL,
		0x784F89D46626470FULL,
		0x6365F607BB2439C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D66B2C12332BE00ULL,
		0xCED8D07185C99C9CULL,
		0x9F13A8CC4C8E1E44ULL,
		0xCBEC0F76487382F0ULL,
		0x00000000000000C6ULL
	}};
	shift = 55;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD265352D29178BAULL,
		0x888891EAD43AD2BBULL,
		0xE636D5CED59EA5A1ULL,
		0xE458CF78482819CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2D29178BA0000000ULL,
		0xAD43AD2BBFD26535ULL,
		0xED59EA5A1888891EULL,
		0x8482819CFE636D5CULL,
		0x000000000E458CF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5C8A97BD9AB8E6FULL,
		0x6313888829AECCFBULL,
		0x7B5C18E416DA5206ULL,
		0x82FB1CC1A817343EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD9AB8E6F0000000ULL,
		0x829AECCFBC5C8A97ULL,
		0x416DA52066313888ULL,
		0x1A817343E7B5C18EULL,
		0x00000000082FB1CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E06FF2AE1D4727DULL,
		0x7F757F7CEB23838BULL,
		0xA524C17A51C4D734ULL,
		0x96CE2D0DA765E312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFF2AE1D4727D0000ULL,
		0x7F7CEB23838B0E06ULL,
		0xC17A51C4D7347F75ULL,
		0x2D0DA765E312A524ULL,
		0x00000000000096CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000100000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000002000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000040000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000004000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000040000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000001000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}