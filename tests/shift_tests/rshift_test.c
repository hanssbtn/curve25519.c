#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DA0D3DEB663C8E1ULL,
		0x966F8CE8B8048B66ULL,
		0x1B49595E22F6979CULL,
		0x1F973A4AE03E6082ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6CC791C20000000ULL,
		0x1700916CD1B41A7BULL,
		0xC45ED2F392CDF19DULL,
		0x5C07CC1043692B2BULL,
		0x0000000003F2E749ULL
	}};
	int shift = 35;
	curve25519_key_t r = {};
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA42EDAF1FE4C43ADULL,
		0x130BE270FCCA9875ULL,
		0xDDD01BB00B81450BULL,
		0xC69C3F402CAA9720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6800000000000000ULL,
		0xAD2176D78FF2621DULL,
		0x58985F1387E654C3ULL,
		0x06EE80DD805C0A28ULL,
		0x0634E1FA016554B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EFD7ACBC027B51BULL,
		0xAB256CDBD3AE2FCDULL,
		0x7BEED59B19B6330EULL,
		0x8A078E9D8DC50F29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77EBD65E013DA8D8ULL,
		0x592B66DE9D717E68ULL,
		0xDF76ACD8CDB19875ULL,
		0x503C74EC6E28794BULL,
		0x0000000000000004ULL
	}};
	shift = 61;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x04003D8C71B4CE92ULL,
		0x7585EB4AF30F2778ULL,
		0x9D699E6060034A7FULL,
		0x4ED547C075C7701DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x003D8C71B4CE9200ULL,
		0x85EB4AF30F277804ULL,
		0x699E6060034A7F75ULL,
		0xD547C075C7701D9DULL,
		0x000000000000004EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCFB084A4D49EC92EULL,
		0xC4EA7186BCEB1515ULL,
		0xA47DBF2D947096BEULL,
		0x5A2AE3073237E86BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x84A4D49EC92E0000ULL,
		0x7186BCEB1515CFB0ULL,
		0xBF2D947096BEC4EAULL,
		0xE3073237E86BA47DULL,
		0x0000000000005A2AULL
	}};
	shift = 48;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x527B84A107D1EFD5ULL,
		0x3DDBE1DC11B43C7FULL,
		0x61CE9E60E4189026ULL,
		0x2FF6F363302C566CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F47BF540000000ULL,
		0x046D0F1FD49EE128ULL,
		0x390624098F76F877ULL,
		0xCC0B159B1873A798ULL,
		0x000000000BFDBCD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 226;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA4A3739A8627AFCULL,
		0xA7DF6A407C60E229ULL,
		0xA8CBFC5D38D72DD1ULL,
		0xAD41DD3E7D7A890BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9CD4313D7E00000ULL,
		0x5203E307114E5251ULL,
		0xE2E9C6B96E8D3EFBULL,
		0xE9F3EBD4485D465FULL,
		0x0000000000056A0EULL
	}};
	shift = 45;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA49A0AF4CFAE8563ULL,
		0x49EE93F49F99827CULL,
		0xBB6BBDDE3964E01AULL,
		0xD07C5078D3D66E11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x158C000000000000ULL,
		0x09F292682BD33EBAULL,
		0x806927BA4FD27E66ULL,
		0xB846EDAEF778E593ULL,
		0x000341F141E34F59ULL
	}};
	shift = 14;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE668F0027F211E7FULL,
		0x0477CBCD6F8DBE3AULL,
		0xC7B1D317D9C965E7ULL,
		0xBA82CD192AF48A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7F0000000000000ULL,
		0xE3AE668F0027F211ULL,
		0x5E70477CBCD6F8DBULL,
		0xA3EC7B1D317D9C96ULL,
		0x000BA82CD192AF48ULL
	}};
	shift = 12;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFCB1F93C0173DD65ULL,
		0xA8BA019DA5AA1C8AULL,
		0x6597586ABF350333ULL,
		0x8D006CD16606AA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA00000000000000ULL,
		0x15F963F27802E7BAULL,
		0x675174033B4B5439ULL,
		0x64CB2EB0D57E6A06ULL,
		0x011A00D9A2CC0D54ULL
	}};
	shift = 7;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DF2007A4F6DDD70ULL,
		0x93CD79F7878545A2ULL,
		0xBA6964B85817CA5CULL,
		0x390694DEC3E72E12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF2007A4F6DDD700ULL,
		0x3CD79F7878545A28ULL,
		0xA6964B85817CA5C9ULL,
		0x90694DEC3E72E12BULL,
		0x0000000000000003ULL
	}};
	shift = 60;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7B7BA7845C009B6DULL,
		0x7C3722AF1E3B8397ULL,
		0x1787052330CB781EULL,
		0xC8D6B2F23A2D5C65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB680000000000000ULL,
		0xCBBDBDD3C22E004DULL,
		0x0F3E1B91578F1DC1ULL,
		0x328BC382919865BCULL,
		0x00646B59791D16AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC888C7F882B2D9BULL,
		0x524B0475FF891CA1ULL,
		0x3246597C61C84D69ULL,
		0xE914FEC9E74D00E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7F882B2D9B00000ULL,
		0x475FF891CA1AC888ULL,
		0x97C61C84D69524B0ULL,
		0xEC9E74D00E732465ULL,
		0x00000000000E914FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 236;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11D7658B36C9F018ULL,
		0xE455052C293A8D32ULL,
		0x94CC7FB0192BD36AULL,
		0x34C32A42068856E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0300000000000000ULL,
		0xA6423AECB166D93EULL,
		0x6D5C8AA0A5852751ULL,
		0xDD12998FF603257AULL,
		0x000698654840D10AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE92D7B2C6993DC43ULL,
		0x888A079BD6AD1998ULL,
		0x123B3662959D6ABFULL,
		0x6CE5C363BC8C01F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x710C000000000000ULL,
		0x6663A4B5ECB1A64FULL,
		0xAAFE22281E6F5AB4ULL,
		0x07D448ECD98A5675ULL,
		0x0001B3970D8EF230ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x956CA20190DD6AD9ULL,
		0x8CF9CDE881F249F9ULL,
		0x9FC14CAD1D695CC0ULL,
		0x930C987F4A013B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x56CA20190DD6AD90ULL,
		0xCF9CDE881F249F99ULL,
		0xFC14CAD1D695CC08ULL,
		0x30C987F4A013B249ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78E18E926249BEDDULL,
		0x7E9883B405C3F205ULL,
		0xA0777C5991FBD150ULL,
		0xF960E87E5BCC41ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEDD0000000000000ULL,
		0x20578E18E926249BULL,
		0x1507E9883B405C3FULL,
		0x1ADA0777C5991FBDULL,
		0x000F960E87E5BCC4ULL
	}};
	shift = 12;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAE27D25C30DACD4ULL,
		0xBBAD2015F0A96E79ULL,
		0x88E341F719826A3EULL,
		0x39AC4521DDAB5146ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59A800000000000ULL,
		0x2DCF3D5C4FA4B861ULL,
		0x4D47D775A402BE15ULL,
		0x6A28D11C683EE330ULL,
		0x0000073588A43BB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6D3BD04E048EAD9ULL,
		0x45B041CC70E6E720ULL,
		0xDADF41C744223395ULL,
		0xA68910F4590211A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91D5B20000000000ULL,
		0xCDCE414DA77A09C0ULL,
		0x44672A8B608398E1ULL,
		0x042341B5BE838E88ULL,
		0x0000014D1221E8B2ULL
	}};
	shift = 23;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD6DF1F5FD72D7DFULL,
		0x0112C16110762FEAULL,
		0xD88A4597750BCDF6ULL,
		0x199D3C4EE2F2F17DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7DF0000000000000ULL,
		0xFEAFD6DF1F5FD72DULL,
		0xDF60112C16110762ULL,
		0x17DD88A4597750BCULL,
		0x000199D3C4EE2F2FULL
	}};
	shift = 12;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAE531FF205E6AA6ULL,
		0xC32264D34F74F0EAULL,
		0x035BAD1E43C705E1ULL,
		0x9678D85DFF466044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA63FE40BCD54C000ULL,
		0x4C9A69EE9E1D5D5CULL,
		0x75A3C878E0BC3864ULL,
		0x1B0BBFE8CC08806BULL,
		0x00000000000012CFULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC892FAEA778469D1ULL,
		0x1E63D54A4D573A85ULL,
		0x343FD12A0B99A6F8ULL,
		0x1A7B43EB2327F9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A74400000000000ULL,
		0xCEA17224BEBA9DE1ULL,
		0x69BE0798F5529355ULL,
		0xFE7C0D0FF44A82E6ULL,
		0x0000069ED0FAC8C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2E1FE32506D7E5EULL,
		0x7D19579EFCC7F904ULL,
		0xFC6ED69AC7413623ULL,
		0x715B97D4FA522652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF978000000000000ULL,
		0xE413CB87F8C941B5ULL,
		0xD88DF4655E7BF31FULL,
		0x994BF1BB5A6B1D04ULL,
		0x0001C56E5F53E948ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12AEDCAD25E80CFBULL,
		0xE3567B9F1E3FE53FULL,
		0x5F3786F1CFEDB919ULL,
		0x00C61ED5F53A8C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F4067D800000000ULL,
		0xF1FF29F89576E569ULL,
		0x7F6DC8CF1AB3DCF8ULL,
		0xA9D46492F9BC378EULL,
		0x000000000630F6AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 221;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0AD3373E36C72233ULL,
		0x936082E11C922147ULL,
		0x16D25DA46EF67087ULL,
		0xB20225D2BA8C9410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE446600000000000ULL,
		0x4428E15A66E7C6D8ULL,
		0xCE10F26C105C2392ULL,
		0x928202DA4BB48DDEULL,
		0x0000164044BA5751ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x948AB84D4216246AULL,
		0x1FF0402ADBAA0D4BULL,
		0x82BDACCFB3FF8375ULL,
		0x711E9E9E0949247DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4D4216246A000000ULL,
		0x2ADBAA0D4B948AB8ULL,
		0xCFB3FF83751FF040ULL,
		0x9E0949247D82BDACULL,
		0x0000000000711E9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6EB6DB3C1C9AA69AULL,
		0x2399576C06B7A030ULL,
		0x92A602A7CF632A8FULL,
		0x1F107329C31CE8F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4D34000000000000ULL,
		0x4060DD6DB6783935ULL,
		0x551E4732AED80D6FULL,
		0xD1ED254C054F9EC6ULL,
		0x00003E20E6538639ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED00507339A5973BULL,
		0x12502D430C973EBCULL,
		0x54DED21231CD9D31ULL,
		0x9BD5D943BDA8577BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99CD2CB9D8000000ULL,
		0x1864B9F5E7680283ULL,
		0x918E6CE98892816AULL,
		0x1DED42BBDAA6F690ULL,
		0x0000000004DEAECAULL
	}};
	shift = 37;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C364C5F9B5F988DULL,
		0x16E38E624370D3D9ULL,
		0x11ED311D2B24BB05ULL,
		0xAC4D136634D9F016ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x186C98BF36BF311AULL,
		0x2DC71CC486E1A7B2ULL,
		0x23DA623A5649760AULL,
		0x589A26CC69B3E02CULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53FCEFD3972AFAFCULL,
		0xE450DE13C616217AULL,
		0x3F447BB1B190FD82ULL,
		0xF64551D3B4320695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77E9CB957D7E0000ULL,
		0x6F09E30B10BD29FEULL,
		0x3DD8D8C87EC17228ULL,
		0xA8E9DA19034A9FA2ULL,
		0x0000000000007B22ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x04E959543BFE201EULL,
		0x5BDEA259199FE557ULL,
		0xB6FFC4B2954B002BULL,
		0x1080054FF357F62BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC403C0000000000ULL,
		0x3FCAAE09D2B2A877ULL,
		0x960056B7BD44B233ULL,
		0xAFEC576DFF89652AULL,
		0x00000021000A9FE6ULL
	}};
	shift = 23;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65C2055D96F60263ULL,
		0x84274FC9CD4AF477ULL,
		0xFC40F69E06759DE0ULL,
		0x0FEC8F91DBB0748BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x098C000000000000ULL,
		0xD1DD970815765BD8ULL,
		0x7782109D3F27352BULL,
		0xD22FF103DA7819D6ULL,
		0x00003FB23E476EC1ULL
	}};
	shift = 14;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03537867A28DC3F0ULL,
		0xA5BD330C72E194A3ULL,
		0x5E01A5AFDAB589AEULL,
		0x3632B16ACF0E0961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A370FC000000000ULL,
		0xCB86528C0D4DE19EULL,
		0x6AD626BA96F4CC31ULL,
		0x3C382585780696BFULL,
		0x00000000D8CAC5ABULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF3CD4C9B60C6365ULL,
		0x7B4058B08B04AC34ULL,
		0xBC5F67F7C873C846ULL,
		0xD40F1EA1A88935DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6D8318D940000000ULL,
		0x22C12B0D2BCF3532ULL,
		0xF21CF2119ED0162CULL,
		0x6A224D772F17D9FDULL,
		0x000000003503C7A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70D91FFFC766C5F1ULL,
		0xE7A67729029C2088ULL,
		0x4EEA46751C67489AULL,
		0x29C8986AEEE0C338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8ECD8BE200000000ULL,
		0x05384110E1B23FFFULL,
		0x38CE9135CF4CEE52ULL,
		0xDDC186709DD48CEAULL,
		0x00000000539130D5ULL
	}};
	shift = 31;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BE801C9929343D6ULL,
		0xCC0AFD684390AE6EULL,
		0x574DBD6C5F646490ULL,
		0xDB43CF4031F1A87CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C949A1EB0000000ULL,
		0x421C8573735F400EULL,
		0x62FB2324866057EBULL,
		0x018F8D43E2BA6DEBULL,
		0x0000000006DA1E7AULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECBC411083343CDCULL,
		0x903FCDE7DB1BF8FEULL,
		0x26F6E46E678D5406ULL,
		0x2142EE4E30F9D79DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A1E6E0000000000ULL,
		0x8DFC7F765E208841ULL,
		0xC6AA03481FE6F3EDULL,
		0x7CEBCE937B723733ULL,
		0x00000010A1772718ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09DB00C377536502ULL,
		0x1061F8CB96AD5EF7ULL,
		0xB2E45E65EBF2646BULL,
		0xCBAA6C671EB9667EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9B2810000000000ULL,
		0x56AF7B84ED8061BBULL,
		0xF932358830FC65CBULL,
		0x5CB33F59722F32F5ULL,
		0x00000065D536338FULL
	}};
	shift = 25;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0641AFCAB908755ULL,
		0xF1913F45832EFA58ULL,
		0xE8FC17DFE2476992ULL,
		0x5EFA70FE7D8709B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF957210EAA000000ULL,
		0x8B065DF4B140C835ULL,
		0xBFC48ED325E3227EULL,
		0xFCFB0E1369D1F82FULL,
		0x0000000000BDF4E1ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E02D5A0D1DCDCDBULL,
		0x0EE7BE5573DFFFC6ULL,
		0x7F9E5CF739B816F9ULL,
		0xE3728B0213A3A56BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x016AD068EE6E6D80ULL,
		0x73DF2AB9EFFFE307ULL,
		0xCF2E7B9CDC0B7C87ULL,
		0xB9458109D1D2B5BFULL,
		0x0000000000000071ULL
	}};
	shift = 57;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEF068A5E24D64CAULL,
		0x290C12B47A9F9669ULL,
		0x9F1C49B589162815ULL,
		0x6BE44C37913822E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEF068A5E24D64CA0ULL,
		0x90C12B47A9F9669DULL,
		0xF1C49B5891628152ULL,
		0xBE44C37913822E79ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x232E5F7807161AF8ULL,
		0x6AE3DADC92D1C56AULL,
		0x99CF3B22A491DA61ULL,
		0x44596BCB79998150ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E5F7807161AF800ULL,
		0xE3DADC92D1C56A23ULL,
		0xCF3B22A491DA616AULL,
		0x596BCB7999815099ULL,
		0x0000000000000044ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11AD65CB201E0B58ULL,
		0x0A005451689CB909ULL,
		0x8B7F87E42753E871ULL,
		0x3032490CC3CAE6FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03C16B0000000000ULL,
		0x1397212235ACB964ULL,
		0xEA7D0E21400A8A2DULL,
		0x795CDF916FF0FC84ULL,
		0x0000000606492198ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F037535D8242752ULL,
		0x0630C1014B0DD871ULL,
		0x025012E97A9F7F2EULL,
		0x656298D11789E475ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EA6BB0484EA4000ULL,
		0x18202961BB0E25E0ULL,
		0x025D2F53EFE5C0C6ULL,
		0x531A22F13C8EA04AULL,
		0x0000000000000CACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x963E6A71C4E9B33FULL,
		0x4C48CFEE52B3201FULL,
		0x10DB6300971516DAULL,
		0x1D956501D04FF5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4E389D3667E000ULL,
		0x19FDCA566403F2C7ULL,
		0x6C6012E2A2DB4989ULL,
		0xACA03A09FEBA021BULL,
		0x00000000000003B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x562575D754A80752ULL,
		0x202601B97FE9B0BDULL,
		0x02F9F2EE21B457F4ULL,
		0x4A4C71FF9B2A3B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBAEA9500EA400000ULL,
		0x372FFD3617AAC4AEULL,
		0x5DC4368AFE8404C0ULL,
		0x3FF3654773205F3EULL,
		0x000000000009498EULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD49BCB40509F55FULL,
		0x7EDC23DFCB0BE67DULL,
		0x272D5C35298C68AFULL,
		0xE2537B8C246DE8DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x509F55F000000000ULL,
		0xB0BE67DAD49BCB40ULL,
		0x98C68AF7EDC23DFCULL,
		0x46DE8DF272D5C352ULL,
		0x0000000E2537B8C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89DACAF094B47967ULL,
		0x1EC2D9CAD13E61CAULL,
		0xE9D7369FB3D7EF4EULL,
		0x6DABD65137DE51D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4ED65784A5A3CB38ULL,
		0xF616CE5689F30E54ULL,
		0x4EB9B4FD9EBF7A70ULL,
		0x6D5EB289BEF28E8FULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA4E7B2C9C52BEA11ULL,
		0xA8DB03C5B326D6D6ULL,
		0x54556B12F08E7481ULL,
		0x53EC0413CB768797ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x5273D964E295F508ULL,
		0xD46D81E2D9936B6BULL,
		0xAA2AB58978473A40ULL,
		0x29F60209E5BB43CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD10E864022B474E2ULL,
		0xE593D6CB83BDFF9DULL,
		0xA6D6C78273C7E162ULL,
		0x3E906F41FA0F99A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3A19008AD1D38800ULL,
		0x4F5B2E0EF7FE7744ULL,
		0x5B1E09CF1F858B96ULL,
		0x41BD07E83E668E9BULL,
		0x00000000000000FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC2F3721B784F60F1ULL,
		0x34944434FEC09045ULL,
		0x3C7D12BD71115F50ULL,
		0x717A48375010C0CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E436F09EC1E2000ULL,
		0x88869FD81208B85EULL,
		0xA257AE222BEA0692ULL,
		0x4906EA021819878FULL,
		0x0000000000000E2FULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2DB7FDCA0D28693CULL,
		0x5A99F8E00CB49274ULL,
		0x811DA1437A95E0E3ULL,
		0x0F8F7A6D9F9F60DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA50D278000000000ULL,
		0x96924E85B6FFB941ULL,
		0x52BC1C6B533F1C01ULL,
		0xF3EC1B7023B4286FULL,
		0x00000001F1EF4DB3ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5C30AB8ED36A069ULL,
		0xDA2ECAF6E3A8BA8EULL,
		0xFADE7D3F8F729235ULL,
		0x2CDF4853BB8CBC72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6D40D20000000000ULL,
		0x51751D4B861571DAULL,
		0xE5246BB45D95EDC7ULL,
		0x1978E5F5BCFA7F1EULL,
		0x00000059BE90A777ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F192F977B3C3778ULL,
		0x57E346E60DD70389ULL,
		0x9FB62C9ABFA204EFULL,
		0x88502FB0C6332BB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C97CBBD9E1BBC0ULL,
		0xBF1A37306EB81C4AULL,
		0xFDB164D5FD10277AULL,
		0x42817D8631995D9CULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE720671E5649E15FULL,
		0x879D5BFAC9C7347AULL,
		0x937A90F4A057AEB6ULL,
		0x5F9015FED49D8815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7857C00000000000ULL,
		0xCD1EB9C819C79592ULL,
		0xEBADA1E756FEB271ULL,
		0x620564DEA43D2815ULL,
		0x000017E4057FB527ULL
	}};
	shift = 18;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F9560DF23D10BFDULL,
		0x4606C6A6CAF668F4ULL,
		0x59E6DD4DA229A22FULL,
		0x4B7D41F32354DA15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0DF23D10BFD00000ULL,
		0x6A6CAF668F45F956ULL,
		0xD4DA229A22F4606CULL,
		0x1F32354DA1559E6DULL,
		0x000000000004B7D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6687BBE6DEB00381ULL,
		0x43442A41F4D1882EULL,
		0xCA4A2BC314D1B8D7ULL,
		0x60D09D889AE3B82BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0038100000000000ULL,
		0x1882E6687BBE6DEBULL,
		0x1B8D743442A41F4DULL,
		0x3B82BCA4A2BC314DULL,
		0x0000060D09D889AEULL
	}};
	shift = 20;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD806D2485BFAC09ULL,
		0x0D91B755FED4F0DCULL,
		0xBB27393FDB8F3B67ULL,
		0x2B42FEA979F1F2CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x16FEB02400000000ULL,
		0xFB53C373F601B492ULL,
		0x6E3CED9C3646DD57ULL,
		0xE7C7CB2AEC9CE4FFULL,
		0x00000000AD0BFAA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9ED2FCB87159BA3CULL,
		0xC649AC7A91AAFF51ULL,
		0xEC611CD64BD2DD45ULL,
		0xB11451B6B22E0D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DA5F970E2B37478ULL,
		0x8C9358F52355FEA3ULL,
		0xD8C239AC97A5BA8BULL,
		0x6228A36D645C1A07ULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5DD9858B7A0BB579ULL,
		0xC3199726C925E56AULL,
		0x43207034401310A9ULL,
		0xEF97D79A492AE479ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05DABC8000000000ULL,
		0x92F2B52EECC2C5BDULL,
		0x098854E18CCB9364ULL,
		0x95723CA190381A20ULL,
		0x00000077CBEBCD24ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0BF5AFB8E6A40ACDULL,
		0x01219E48F8A53DCAULL,
		0x527EC5A3531B80CBULL,
		0xE84CDD87A22CB2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x902B340000000000ULL,
		0x94F7282FD6BEE39AULL,
		0x6E032C04867923E2ULL,
		0xB2CB2149FB168D4CULL,
		0x000003A133761E88ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A78C2CC9D8C876CULL,
		0xDF80EA9D2FC3C4F5ULL,
		0x68F0FDEEC31AA8EFULL,
		0xB48AF70A68CAAD25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6321DB0000000000ULL,
		0xF0F13D429E30B327ULL,
		0xC6AA3BF7E03AA74BULL,
		0x32AB495A3C3F7BB0ULL,
		0x0000002D22BDC29AULL
	}};
	shift = 26;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6588E24B8EC3545ULL,
		0x4B982FD19D9200EFULL,
		0xEB914EB19BE9D4ABULL,
		0xAE09A7EFAEB2E4B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE24B8EC354500000ULL,
		0xFD19D9200EFC6588ULL,
		0xEB19BE9D4AB4B982ULL,
		0x7EFAEB2E4B4EB914ULL,
		0x00000000000AE09AULL
	}};
	shift = 44;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47B4F22F4341928EULL,
		0x373CF8711852FE6FULL,
		0x620BC1189082E973ULL,
		0x5DB0846D11313BF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47B4F22F4341928EULL,
		0x373CF8711852FE6FULL,
		0x620BC1189082E973ULL,
		0x5DB0846D11313BF9ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x901F625056A5D340ULL,
		0xB1DCE282BD775801ULL,
		0x8DAABA1B0C239C75ULL,
		0x3FD4F94DC4BA7733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x00C80FB1282B52E9ULL,
		0x3AD8EE71415EBBACULL,
		0x99C6D55D0D8611CEULL,
		0x001FEA7CA6E25D3BULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE7222CD7EAAFFFECULL,
		0xF8F67CB830A79041ULL,
		0x5E24F3047F6EF8E2ULL,
		0xA94280E6B5186B55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFFEC000000000000ULL,
		0x9041E7222CD7EAAFULL,
		0xF8E2F8F67CB830A7ULL,
		0x6B555E24F3047F6EULL,
		0x0000A94280E6B518ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02A819730D723C91ULL,
		0x10B288FBE9B0BA65ULL,
		0xBCCE6EBF8DE75185ULL,
		0x846D989899A6AAEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F24400000000000ULL,
		0x2E9940AA065CC35CULL,
		0xD461442CA23EFA6CULL,
		0xAABAAF339BAFE379ULL,
		0x0000211B66262669ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x35F60567E86357B2ULL,
		0x6F24EBE07C861A8CULL,
		0x0ACC0241A2D18885ULL,
		0x6C7FE41D58301506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE86357B200000000ULL,
		0x7C861A8C35F60567ULL,
		0xA2D188856F24EBE0ULL,
		0x583015060ACC0241ULL,
		0x000000006C7FE41DULL
	}};
	shift = 32;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A66A1F23AAB3E48ULL,
		0x7B2A7DF3DD7517FAULL,
		0xF4BB443EE30A6C50ULL,
		0x5D2753747402A0FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9200000000000000ULL,
		0xFE9699A87C8EAACFULL,
		0x141ECA9F7CF75D45ULL,
		0x3EFD2ED10FB8C29BULL,
		0x001749D4DD1D00A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x589BB8E673AA1C1BULL,
		0x68FA8EFB3A0F3184ULL,
		0x2ABEA2DF4D12F973ULL,
		0xEAEF3E13782CE60CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8360000000000000ULL,
		0x308B13771CCE7543ULL,
		0x2E6D1F51DF6741E6ULL,
		0xC18557D45BE9A25FULL,
		0x001D5DE7C26F059CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A184CACA911A38BULL,
		0x7E84F818F31C6D63ULL,
		0x837AB9FC115B2A50ULL,
		0x59EE7FBA030B6178ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C58000000000000ULL,
		0x6B1C50C26565488DULL,
		0x5283F427C0C798E3ULL,
		0x0BC41BD5CFE08AD9ULL,
		0x0002CF73FDD0185BULL
	}};
	shift = 13;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FD17B16F297D773ULL,
		0x3DCB5E92B1C33BD0ULL,
		0xFC4162AB144638ECULL,
		0xDB4778610B7CCA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16F297D773000000ULL,
		0x92B1C33BD05FD17BULL,
		0xAB144638EC3DCB5EULL,
		0x610B7CCA19FC4162ULL,
		0x0000000000DB4778ULL
	}};
	shift = 40;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE7719B61F1923E4ULL,
		0xA213D181721F5A36ULL,
		0x2E403B603D13EAEFULL,
		0xAFA97BE8903E11CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC91F200000000000ULL,
		0xFAD1B6F3B8CDB0F8ULL,
		0x9F577D109E8C0B90ULL,
		0xF08E617201DB01E8ULL,
		0x0000057D4BDF4481ULL
	}};
	shift = 21;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC41BA0DD4DD42993ULL,
		0x5D6BFD2A97214057ULL,
		0x9EF3F73F566DE383ULL,
		0x052771583BC7CFCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20DD06EA6EA14C98ULL,
		0xEB5FE954B90A02BEULL,
		0xF79FB9FAB36F1C1AULL,
		0x293B8AC1DE3E7E6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9DDE16B67D73ADCBULL,
		0xAAA06D9F6B661FADULL,
		0xE29BD8C00F46C0FEULL,
		0x3D9AD508C15252AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B96000000000000ULL,
		0x3F5B3BBC2D6CFAE7ULL,
		0x81FD5540DB3ED6CCULL,
		0xA555C537B1801E8DULL,
		0x00007B35AA1182A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0092E1E752BDDBE6ULL,
		0xE3AE1F604026B81DULL,
		0x3A726E48D30A60C2ULL,
		0x6116FA86DBA679F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A95EEDF30000000ULL,
		0x020135C0E804970FULL,
		0x46985306171D70FBULL,
		0x36DD33CF91D39372ULL,
		0x000000000308B7D4ULL
	}};
	shift = 37;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA054A339BA06AA6ULL,
		0x7E9F136113A62722ULL,
		0x844B548932EBE57DULL,
		0xE60056807C5EC78CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA980000000000000ULL,
		0xC8AA81528CE6E81AULL,
		0x5F5FA7C4D844E989ULL,
		0xE32112D5224CBAF9ULL,
		0x00398015A01F17B1ULL
	}};
	shift = 10;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAF6DB769FDD38007ULL,
		0x2E396631B48D5EAAULL,
		0x4002B18D261A9321ULL,
		0xCF014284CAAE724BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C00000000000000ULL,
		0xAABDB6DDA7F74E00ULL,
		0x84B8E598C6D2357AULL,
		0x2D000AC634986A4CULL,
		0x033C050A132AB9C9ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB9B72F53F75846F0ULL,
		0xA93E2A8723A59849ULL,
		0x5EFDBFD06821164FULL,
		0xB78ECACFDDCBF792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD611BC0000000000ULL,
		0xE966126E6DCBD4FDULL,
		0x084593EA4F8AA1C8ULL,
		0x72FDE497BF6FF41AULL,
		0x0000002DE3B2B3F7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 218;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA170E7A518BFF11ULL,
		0xD3F22F70DB0757C6ULL,
		0xFE39FD45D4AC6AB4ULL,
		0x43951FE9AD98BC4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42E1CF4A317FE220ULL,
		0x7E45EE1B60EAF8D7ULL,
		0xC73FA8BA958D569AULL,
		0x72A3FD35B31789FFULL,
		0x0000000000000008ULL
	}};
	shift = 59;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B925BDD4B166A0EULL,
		0xFC03A668D615B8B9ULL,
		0x167A644E8FEC434EULL,
		0xC322C566C30D9890ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x925BDD4B166A0E00ULL,
		0x03A668D615B8B94BULL,
		0x7A644E8FEC434EFCULL,
		0x22C566C30D989016ULL,
		0x00000000000000C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4796ADA7AC93DC0CULL,
		0xB5C69B08C7980DF9ULL,
		0x9941C9CB9E2A881CULL,
		0x53F22482819508D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAB69EB24F7030000ULL,
		0xA6C231E6037E51E5ULL,
		0x7272E78AA2072D71ULL,
		0x8920A06542366650ULL,
		0x00000000000014FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F07506B00292C82ULL,
		0xC7FAFA8610E842E4ULL,
		0x2EE310D4CDDB4F12ULL,
		0x063E9D361E8014F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0052590400000000ULL,
		0x21D085C89E0EA0D6ULL,
		0x9BB69E258FF5F50CULL,
		0x3D0029E25DC621A9ULL,
		0x000000000C7D3A6CULL
	}};
	shift = 31;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A2E44080C3B4549ULL,
		0xEF50E5DE717784B9ULL,
		0xDFA764B68D806AEFULL,
		0x819465DC83D6B05CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4080C3B454900000ULL,
		0x5DE717784B98A2E4ULL,
		0x4B68D806AEFEF50EULL,
		0x5DC83D6B05CDFA76ULL,
		0x0000000000081946ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC5BC59DA34C9CA8ULL,
		0x8B2AAE9CB6775964ULL,
		0xD3361D456B2A4326ULL,
		0x05D9D12E5A6831E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC9CA800000000000ULL,
		0x75964FC5BC59DA34ULL,
		0xA43268B2AAE9CB67ULL,
		0x831E1D3361D456B2ULL,
		0x0000005D9D12E5A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD90C5D3541573550ULL,
		0x5151D6F96A1482FEULL,
		0xD1A251F05735598CULL,
		0x14BEC226C8AAFEB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AE6AA0000000000ULL,
		0x42905FDB218BA6A8ULL,
		0xE6AB318A2A3ADF2DULL,
		0x155FD6BA344A3E0AULL,
		0x0000000297D844D9ULL
	}};
	shift = 27;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A7F255F03575517ULL,
		0x6E1D00C7B023376DULL,
		0xDD8CD8383CC362EFULL,
		0xE737F8C0C89211FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD5D545C000000000ULL,
		0x08CDDB629FC957C0ULL,
		0x30D8BBDB874031ECULL,
		0x24847EF763360E0FULL,
		0x00000039CDFE3032ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5852F8F57ED29C2EULL,
		0x7127EE75AB88E865ULL,
		0xD75A15391E78B8DDULL,
		0xC0C134C9FE9382A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29C2E00000000000ULL,
		0x8E8655852F8F57EDULL,
		0x8B8DD7127EE75AB8ULL,
		0x382A9D75A15391E7ULL,
		0x00000C0C134C9FE9ULL
	}};
	shift = 20;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x424F550D844C1798ULL,
		0x7C15E16156B756D9ULL,
		0x2693544A0F154A39ULL,
		0x269DB69DFA278F28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7980000000000000ULL,
		0x6D9424F550D844C1ULL,
		0xA397C15E16156B75ULL,
		0xF282693544A0F154ULL,
		0x000269DB69DFA278ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x24EA4954B52BE6D0ULL,
		0x83C1F7AFACA952B7ULL,
		0xB8DA51A30DF9F63BULL,
		0x27EC55D9881918E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x492A96A57CDA0000ULL,
		0x3EF5F5952A56E49DULL,
		0x4A3461BF3EC77078ULL,
		0x8ABB3103231D371BULL,
		0x00000000000004FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 243;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F74E336B7E9E052ULL,
		0xE1341EAF6C95C466ULL,
		0x00E55AB7F9BA405FULL,
		0xB3A482937622BB8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38CDADFA78148000ULL,
		0x07ABDB25711997DDULL,
		0x56ADFE6E9017F84DULL,
		0x20A4DD88AEE3C039ULL,
		0x0000000000002CE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3FC5536FB014B808ULL,
		0xED668EC38FEC3573ULL,
		0xF2F2040510D18F05ULL,
		0x505CE3D4428625B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0xE67F8AA6DF602970ULL,
		0x0BDACD1D871FD86AULL,
		0x69E5E4080A21A31EULL,
		0x00A0B9C7A8850C4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x89EC8A3FB27E6119ULL,
		0x6F502B0C076657A7ULL,
		0x46BB3BABD787C269ULL,
		0x123D5347057F98F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9147F64FCC232000ULL,
		0x056180ECCAF4F13DULL,
		0x67757AF0F84D2DEAULL,
		0xAA68E0AFF31F28D7ULL,
		0x0000000000000247ULL
	}};
	shift = 51;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9020433B42A1028AULL,
		0xE9E7666B845B0FB3ULL,
		0x86E9A73A230A4345ULL,
		0x3A2C563451FA82FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3B42A1028A000000ULL,
		0x6B845B0FB3902043ULL,
		0x3A230A4345E9E766ULL,
		0x3451FA82FB86E9A7ULL,
		0x00000000003A2C56ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3093ED205A489384ULL,
		0x935915415960FDDAULL,
		0xD948C6154D3F92A1ULL,
		0xCCAFD88FE2DD3BB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ED205A489384000ULL,
		0x915415960FDDA309ULL,
		0x8C6154D3F92A1935ULL,
		0xFD88FE2DD3BB9D94ULL,
		0x0000000000000CCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A8803040A23D74DULL,
		0x3137F5BDC6F3AA66ULL,
		0x4066C0637EFDC324ULL,
		0x2A7F281A20825F23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBA68000000000000ULL,
		0x533254401820511EULL,
		0x192189BFADEE379DULL,
		0xF91A0336031BF7EEULL,
		0x000153F940D10412ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD1614EC9DEB913BBULL,
		0x904C201AF033D6E0ULL,
		0xA6E1B002B2AA331FULL,
		0xD3DAB9B617FC36BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6000000000000000ULL,
		0x1A2C29D93BD72277ULL,
		0xF20984035E067ADCULL,
		0x94DC360056554663ULL,
		0x1A7B5736C2FF86D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 195;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3EF2AD95A27E15F7ULL,
		0xF8CE118243735306ULL,
		0xBB9BAB191DE2F07EULL,
		0x312B3FFF99815260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x1F7956CAD13F0AFBULL,
		0x7C6708C121B9A983ULL,
		0x5DCDD58C8EF1783FULL,
		0x18959FFFCCC0A930ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD3FCB5F5A33DE3EULL,
		0x1BCEE31401E01F69ULL,
		0xFC30306FA8A4810EULL,
		0x4F28E15BFEBCD9FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFF2D7D68CF78F800ULL,
		0x3B8C5007807DA6B4ULL,
		0xC0C1BEA29204386FULL,
		0xA3856FFAF367FBF0ULL,
		0x000000000000013CULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE529662A9F7E42ECULL,
		0xCD26F9589DFBDDCCULL,
		0xB2661F2DE7AAB563ULL,
		0x4504F76155AD94EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC85D8000000000ULL,
		0xBF7BB99CA52CC553ULL,
		0xF556AC79A4DF2B13ULL,
		0xB5B29DB64CC3E5BCULL,
		0x00000008A09EEC2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A3755B969EB835AULL,
		0x11E5B4556F458D18ULL,
		0xD39FC9AC515FAFF8ULL,
		0x0F32EFF96B9A7E67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD680000000000000ULL,
		0x46128DD56E5A7AE0ULL,
		0xFE04796D155BD163ULL,
		0x99F4E7F26B1457EBULL,
		0x0003CCBBFE5AE69FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A7B0AFED633E1C9ULL,
		0x3ECACBB409713E0DULL,
		0x7AAD4061702E0FDDULL,
		0x6C78671C80F471F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19F0E48000000000ULL,
		0xB89F06CD3D857F6BULL,
		0x1707EE9F6565DA04ULL,
		0x7A38FC3D56A030B8ULL,
		0x000000363C338E40ULL
	}};
	shift = 25;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CDB3E1685B1A738ULL,
		0xA7CBDB53CB1D2CCEULL,
		0x4A33A41F728C83AEULL,
		0xDD16CDDD6EB0E1E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D39C0000000000ULL,
		0x8E9667266D9F0B42ULL,
		0x4641D753E5EDA9E5ULL,
		0x5870F32519D20FB9ULL,
		0x0000006E8B66EEB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C9EB993CBC65835ULL,
		0x3B7872645C0A1334ULL,
		0xF7FDE6A4088F95D5ULL,
		0xF091A626FDBD861FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7978CB06A0000000ULL,
		0x8B8142668593D732ULL,
		0x8111F2BAA76F0E4CULL,
		0xDFB7B0C3FEFFBCD4ULL,
		0x000000001E1234C4ULL
	}};
	shift = 35;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA7E9B1AA26A97644ULL,
		0x520F1D88CD486010ULL,
		0xDF4816C3DF6A37DBULL,
		0x19D47F83D7206E75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D51354BB2200000ULL,
		0xEC466A4300853F4DULL,
		0xB61EFB51BEDA9078ULL,
		0xFC1EB90373AEFA40ULL,
		0x000000000000CEA3ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76096C53F46899B8ULL,
		0x2F2060B2A44511DCULL,
		0xAFFBA460E143F78AULL,
		0x628870C2C827358CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFA344CDC00000000ULL,
		0x522288EE3B04B629ULL,
		0x70A1FBC517903059ULL,
		0x64139AC657FDD230ULL,
		0x0000000031443861ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03ACE243FA8487B6ULL,
		0x87B4CFE9A60A3C80ULL,
		0x76CBEF7C0BEE6EE9ULL,
		0x37057F7F566AB0CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4243DB000000000ULL,
		0x3051E4001D67121FULL,
		0x5F73774C3DA67F4DULL,
		0xB3558653B65F7BE0ULL,
		0x00000001B82BFBFAULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE5C51DDAB7C03DAULL,
		0x6349A95557532800ULL,
		0xDAD1EDE9F798197FULL,
		0xB6F590DDF57DC9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x76ADF00F68000000ULL,
		0x555D4CA002F97147ULL,
		0xA7DE6065FD8D26A5ULL,
		0x77D5F726876B47B7ULL,
		0x0000000002DBD643ULL
	}};
	shift = 38;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C938D6456E8BC89ULL,
		0xA4E2DFC8B1E0C517ULL,
		0xE80357BFA653EAAFULL,
		0x5742A77FD2F887E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC8ADD1791200000ULL,
		0xF9163C18A2E39271ULL,
		0xF7F4CA7D55F49C5BULL,
		0xEFFA5F10FC3D006AULL,
		0x00000000000AE854ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77BDCB6072E3BCDDULL,
		0x9D96AA3E41566711ULL,
		0x5B7B74D345CA4C45ULL,
		0x95ADBB085684DC88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5C779BA000000000ULL,
		0x2ACCE22EF7B96C0EULL,
		0xB94988B3B2D547C8ULL,
		0xD09B910B6F6E9A68ULL,
		0x00000012B5B7610AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x856D87AABE142461ULL,
		0x474E973A6407FE2AULL,
		0xD1C7930CBF5ACB48ULL,
		0x81714D63E5FD6ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xA15B61EAAF850918ULL,
		0x11D3A5CE9901FF8AULL,
		0xB471E4C32FD6B2D2ULL,
		0x205C5358F97F5AAEULL
	}};
	shift = 2;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72DC6B165B3133DBULL,
		0xBC3A6BDDFA6F45E2ULL,
		0x135817ABFC4D30C3ULL,
		0x3F3DD412D4BF3D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x267B600000000000ULL,
		0xE8BC4E5B8D62CB66ULL,
		0xA61877874D7BBF4DULL,
		0xE7A3226B02F57F89ULL,
		0x000007E7BA825A97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A896E25155340F3ULL,
		0x967BBC3B3D1660C3ULL,
		0xE5E577E4DA5B9178ULL,
		0x29D2C29306298D9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0798000000000000ULL,
		0x061BD44B7128AA9AULL,
		0x8BC4B3DDE1D9E8B3ULL,
		0x6CEF2F2BBF26D2DCULL,
		0x00014E961498314CULL
	}};
	shift = 13;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x325994BC8FF82B02ULL,
		0xF0B67AF715D9C972ULL,
		0xBB8BF2B1E94AB16BULL,
		0xF5E2F6997B283899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CCA5E47FC158100ULL,
		0x5B3D7B8AECE4B919ULL,
		0xC5F958F4A558B5F8ULL,
		0xF17B4CBD941C4CDDULL,
		0x000000000000007AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x349CA0152E8D1F15ULL,
		0x3EC10F08F82CD88FULL,
		0x72B92813D8FDA2F4ULL,
		0xE0C9BCFF6D46F030ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A5D1A3E2A000000ULL,
		0x11F059B11E693940ULL,
		0x27B1FB45E87D821EULL,
		0xFEDA8DE060E57250ULL,
		0x0000000001C19379ULL
	}};
	shift = 39;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB2F6C24370E3EEFBULL,
		0xADE49E4C9FE2DF98ULL,
		0xB11DFD8181765255ULL,
		0x29AE21175DCAC29FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBDB090DC38FBBEC0ULL,
		0x79279327F8B7E62CULL,
		0x477F60605D94956BULL,
		0x6B8845D772B0A7ECULL,
		0x000000000000000AULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0FA91E3CC189586BULL,
		0x06D0893DA0654461ULL,
		0x04D2CFB3A6AFF9E3ULL,
		0xBB4DC61A95A2D0FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAC00000000000000ULL,
		0x843EA478F3062561ULL,
		0x8C1B4224F6819511ULL,
		0xE8134B3ECE9ABFE7ULL,
		0x02ED37186A568B43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 134;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4E437AACB222649ULL,
		0x573A27053B70B5CEULL,
		0x7914B3CE4ED7FF8DULL,
		0x98080A910EBBF019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37AACB2226490000ULL,
		0x27053B70B5CEB4E4ULL,
		0xB3CE4ED7FF8D573AULL,
		0x0A910EBBF0197914ULL,
		0x0000000000009808ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DCA8A811BD9AA93ULL,
		0xD887D50ECB04599EULL,
		0xF575EC345C237E3CULL,
		0xE75FD7ACD5D8116EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x811BD9AA93000000ULL,
		0x0ECB04599E4DCA8AULL,
		0x345C237E3CD887D5ULL,
		0xACD5D8116EF575ECULL,
		0x0000000000E75FD7ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81BE758B0C97DBFDULL,
		0xD1F23FEB8D221D32ULL,
		0x9FE6BAAB013D9DFEULL,
		0x82CACB327BF05EA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x58B0C97DBFD00000ULL,
		0xFEB8D221D3281BE7ULL,
		0xAAB013D9DFED1F23ULL,
		0xB327BF05EA69FE6BULL,
		0x0000000000082CACULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B43E33CD7E56C94ULL,
		0x15E2269DBFFF9A24ULL,
		0xFC89AE0E428FF7AFULL,
		0x98B3FB1D237E3BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE6BF2B64A0000000ULL,
		0xEDFFFCD1205A1F19ULL,
		0x72147FBD78AF1134ULL,
		0xE91BF1DF97E44D70ULL,
		0x0000000004C59FD8ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB4ED359FCDCBB53ULL,
		0xBC5F71006A2223CFULL,
		0x6625AD21B29E800DULL,
		0x2C44E092940A209DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED4C000000000000ULL,
		0x8F3F2D3B4D67F372ULL,
		0x0036F17DC401A888ULL,
		0x82759896B486CA7AULL,
		0x0000B113824A5028ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 206;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9D82AB9307493F6ULL,
		0x2413ED665864119FULL,
		0x2C7AAAF812D76DA8ULL,
		0x18879277013CC30BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7493F60000000000ULL,
		0x64119FF9D82AB930ULL,
		0xD76DA82413ED6658ULL,
		0x3CC30B2C7AAAF812ULL,
		0x0000001887927701ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 216;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE45BB1F8D6284552ULL,
		0xB217BB083EA69218ULL,
		0x1D923DFAA1C9285AULL,
		0xA2E06AF146C0471CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1AC508AA4000000ULL,
		0x107D4D2431C8B763ULL,
		0xF5439250B5642F76ULL,
		0xE28D808E383B247BULL,
		0x000000000145C0D5ULL
	}};
	shift = 39;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6480CF4B567BEDD7ULL,
		0xFC3C7203F836F53DULL,
		0xBD547D302F588A2CULL,
		0x31C000FF5161F8E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDD70000000000000ULL,
		0x53D6480CF4B567BEULL,
		0xA2CFC3C7203F836FULL,
		0x8E8BD547D302F588ULL,
		0x00031C000FF5161FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D54B66DD29BB0D5ULL,
		0xFCC1F78D986EBBFDULL,
		0xF86146B561EF4428ULL,
		0xD52A36AF7F5D252EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2D54B66DD29BB0D5ULL,
		0xFCC1F78D986EBBFDULL,
		0xF86146B561EF4428ULL,
		0xD52A36AF7F5D252EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6E8CF6892BF04C0ULL,
		0xC22DB88CB4288CEFULL,
		0x89C26D66F9014C84ULL,
		0xCCAE3735AEAE60FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57E0980000000000ULL,
		0x85119DFADD19ED12ULL,
		0x2029909845B71196ULL,
		0xD5CC1F91384DACDFULL,
		0x0000001995C6E6B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x339B97F16F4B5DF9ULL,
		0xCA89BE1F7C4647D1ULL,
		0xD193855B0546B92EULL,
		0xD1E0E83BC037462FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF16F4B5DF9000000ULL,
		0x1F7C4647D1339B97ULL,
		0x5B0546B92ECA89BEULL,
		0x3BC037462FD19385ULL,
		0x0000000000D1E0E8ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC44B47145C3E48FULL,
		0x829206629AD2A250ULL,
		0x216E41D2B4884AB3ULL,
		0x00FEFC7E9B0026B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1E00000000000000ULL,
		0xA1D88968E28B87C9ULL,
		0x6705240CC535A544ULL,
		0x6042DC83A5691095ULL,
		0x0001FDF8FD36004DULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8741587279A104DEULL,
		0x4F51D70B376B41B7ULL,
		0xA7A9E09C9704B669ULL,
		0xB70C128C216E1DA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x209BC00000000000ULL,
		0x6836F0E82B0E4F34ULL,
		0x96CD29EA3AE166EDULL,
		0xC3B4F4F53C1392E0ULL,
		0x000016E18251842DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06AA508B46817485ULL,
		0xEA3982AA431AE8EEULL,
		0xBBBB60904E732669ULL,
		0x0E3FA740E5107630ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x168D02E90A000000ULL,
		0x548635D1DC0D54A1ULL,
		0x209CE64CD3D47305ULL,
		0x81CA20EC617776C1ULL,
		0x00000000001C7F4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BE298807387F723ULL,
		0x95362DFECA3F3C80ULL,
		0xD36501BDE438745EULL,
		0xB33FC3A33B9620CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4039C3FB91800000ULL,
		0xFF651F9E401DF14CULL,
		0xDEF21C3A2F4A9B16ULL,
		0xD19DCB1065E9B280ULL,
		0x0000000000599FE1ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x67B30D2DE92C9F73ULL,
		0x938D66F795226FF1ULL,
		0x0EF0186412084C5AULL,
		0x8B8549F8339555C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE92C9F730000000ULL,
		0x795226FF167B30D2ULL,
		0x412084C5A938D66FULL,
		0x8339555C30EF0186ULL,
		0x0000000008B8549FULL
	}};
	shift = 36;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CFD80040984AD50ULL,
		0x02AC37AEC40407C1ULL,
		0x85D004223C02C6A6ULL,
		0x86F7D95D5F7E9C91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE7EC00204C256A8ULL,
		0x01561BD7620203E0ULL,
		0xC2E802111E016353ULL,
		0x437BECAEAFBF4E48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B7402B8B12CA249ULL,
		0xF428EA204B57DCD2ULL,
		0x62C67787D40A5CAFULL,
		0x3F797DAFB150F374ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4920000000000000ULL,
		0x9A456E8057162594ULL,
		0x95FE851D44096AFBULL,
		0x6E8C58CEF0FA814BULL,
		0x0007EF2FB5F62A1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 203;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DB4EE63B7BDC99DULL,
		0xCEFDAAB7A0A0D9B0ULL,
		0x5B092F44569A28D6ULL,
		0x5E9887C11A919552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8EDEF72674000000ULL,
		0xDE828366C0F6D3B9ULL,
		0x115A68A35B3BF6AAULL,
		0x046A4655496C24BDULL,
		0x00000000017A621FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC98F39619AB116FULL,
		0x378E32C52EEAE759ULL,
		0x72B621903559A454ULL,
		0x542F73F047A54A09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CE5866AC45BC000ULL,
		0x8CB14BBAB9D67326ULL,
		0x88640D5669150DE3ULL,
		0xDCFC11E952825CADULL,
		0x000000000000150BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6353DDE30B4837BULL,
		0xE297BA7C3E7EC114ULL,
		0x21F973329BD653E2ULL,
		0x1BB0C895EB76BD9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9EEF185A41BD8000ULL,
		0xDD3E1F3F608A631AULL,
		0xB9994DEB29F1714BULL,
		0x644AF5BB5ECE10FCULL,
		0x0000000000000DD8ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0FB7A11C1DA5D13AULL,
		0x8605770EDDFAF296ULL,
		0xB7ADF46CB91FF9A5ULL,
		0x2F6751705F0F91B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x769744E800000000ULL,
		0x77EBCA583EDE8470ULL,
		0xE47FE6961815DC3BULL,
		0x7C3E46C2DEB7D1B2ULL,
		0x00000000BD9D45C1ULL
	}};
	shift = 30;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71F89072827566C2ULL,
		0xD0B0719CFDE54287ULL,
		0xE8CB0C18F3360527ULL,
		0xAFBAB7347C13B924ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E241CA09D59B080ULL,
		0x2C1C673F7950A1DCULL,
		0x32C3063CCD8149F4ULL,
		0xEEADCD1F04EE493AULL,
		0x000000000000002BULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DAF8E1BBF92DE48ULL,
		0xA55FC3ECBFE2AC54ULL,
		0xA897EA446DA1CDC6ULL,
		0x51EEB557D1904EAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70DDFC96F2400000ULL,
		0x1F65FF1562A46D7CULL,
		0x52236D0E6E352AFEULL,
		0xAABE8C82755544BFULL,
		0x0000000000028F75ULL
	}};
	shift = 45;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA7C182A2E041E6BULL,
		0xD7EC20497F488528ULL,
		0xCD56C70B26757366ULL,
		0xD4864CC493FF5243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F830545C083CD60ULL,
		0xFD84092FE910A51FULL,
		0xAAD8E164CEAE6CDAULL,
		0x90C998927FEA4879ULL,
		0x000000000000001AULL
	}};
	shift = 59;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE11647C2B50C2670ULL,
		0x7AACC7F277AEFE2FULL,
		0xCD37B5093E1E723CULL,
		0x5DE64A6F09A5A592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xBF84591F0AD43099ULL,
		0xF1EAB31FC9DEBBF8ULL,
		0x4B34DED424F879C8ULL,
		0x01779929BC269696ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x217C202DB471791DULL,
		0xD7E4F63267D5FA2EULL,
		0x0529E934CD96BE36ULL,
		0x91DE012C15685294ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8405B68E2F23A00ULL,
		0xC9EC64CFABF45C42ULL,
		0x53D2699B2D7C6DAFULL,
		0xBC02582AD0A5280AULL,
		0x0000000000000123ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF45BB92718F5F41ULL,
		0x7D03D4BF183A0A37ULL,
		0xD28300A7DB936581ULL,
		0x23050E59EAA4FEF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x92718F5F41000000ULL,
		0xBF183A0A37BF45BBULL,
		0xA7DB9365817D03D4ULL,
		0x59EAA4FEF0D28300ULL,
		0x000000000023050EULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE77338D76CB5D14FULL,
		0x3663515F76A0E2E0ULL,
		0xE181D673E22037B9ULL,
		0x850FC5BBD8515620ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE35DB2D7453C0000ULL,
		0x457DDA838B839DCCULL,
		0x59CF8880DEE4D98DULL,
		0x16EF614558838607ULL,
		0x000000000002143FULL
	}};
	shift = 46;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16E127D082AC4FC3ULL,
		0x4FF9A370F8881316ULL,
		0x8F492859949CE2CEULL,
		0x424AAB5F00CE6B2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7093E8415627E180ULL,
		0xFCD1B87C44098B0BULL,
		0xA4942CCA4E716727ULL,
		0x2555AF8067359547ULL,
		0x0000000000000021ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B7448AB44B6C0CDULL,
		0xE45A5DF1B3A0F6EAULL,
		0x87D36F2C2CD85524ULL,
		0x9952E600E9E4536DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x819A000000000000ULL,
		0xEDD496E89156896DULL,
		0xAA49C8B4BBE36741ULL,
		0xA6DB0FA6DE5859B0ULL,
		0x000132A5CC01D3C8ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC8F6C492CF175EAULL,
		0x5CD6590DB8BAED73ULL,
		0xC17DAA0EA90C651CULL,
		0x42FC6290D60E6078ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E2EBD4000000000ULL,
		0x175DAE7D91ED8925ULL,
		0x218CA38B9ACB21B7ULL,
		0xC1CC0F182FB541D5ULL,
		0x000000085F8C521AULL
	}};
	shift = 27;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3A818FC4191ABC7FULL,
		0xECE85081A15D4FFAULL,
		0x3AEC61B3E0246D4AULL,
		0x04883154D10815EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x91ABC7F000000000ULL,
		0x15D4FFA3A818FC41ULL,
		0x0246D4AECE85081AULL,
		0x10815ED3AEC61B3EULL,
		0x000000004883154DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4337C9F5911A647BULL,
		0xBC07200744C1003FULL,
		0x987810716148441EULL,
		0xB21D81EC30C26328ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93EB2234C8F60000ULL,
		0x400E8982007E866FULL,
		0x20E2C290883D780EULL,
		0x03D86184C65130F0ULL,
		0x000000000001643BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 239;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D0B3DBD344327EDULL,
		0xB1855C57323E062BULL,
		0x502F5733468A8465ULL,
		0x9540F7C90A3EDCA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4FDA000000000000ULL,
		0x0C561A167B7A6886ULL,
		0x08CB630AB8AE647CULL,
		0xB94EA05EAE668D15ULL,
		0x00012A81EF92147DULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93B3B31C73A8314DULL,
		0xE9633B5A66A82712ULL,
		0x7156696C8E57DDD1ULL,
		0x20F30E7CF0E3C79AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x98E39D418A680000ULL,
		0xDAD3354138949D9DULL,
		0x4B6472BEEE8F4B19ULL,
		0x73E7871E3CD38AB3ULL,
		0x0000000000010798ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3453D06AE9DCD5E9ULL,
		0xE465919AD8E2D7D5ULL,
		0x443EC9FAC11BF7E8ULL,
		0x0FCD7B5A66F1A3F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7A0D5D3B9ABD200ULL,
		0xCB2335B1C5AFAA68ULL,
		0x7D93F58237EFD1C8ULL,
		0x9AF6B4CDE347E288ULL,
		0x000000000000001FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6E5863513D1CC2CDULL,
		0xAAA07125AE980E12ULL,
		0x2D78958F483436A4ULL,
		0xA3A0C0755EACC300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x72C31A89E8E61668ULL,
		0x5503892D74C07093ULL,
		0x6BC4AC7A41A1B525ULL,
		0x1D0603AAF5661801ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2176CE304B9CEA7FULL,
		0x0A1D1410697B8591ULL,
		0x297414EE75BE5FC3ULL,
		0x595228D6D3986BD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76CE304B9CEA7F00ULL,
		0x1D1410697B859121ULL,
		0x7414EE75BE5FC30AULL,
		0x5228D6D3986BD529ULL,
		0x0000000000000059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02564BD911AA13F6ULL,
		0xED20932ADD37D923ULL,
		0xD169BCC7401CF221ULL,
		0xE4784FC0677F3D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAA13F60000000000ULL,
		0x37D92302564BD911ULL,
		0x1CF221ED20932ADDULL,
		0x7F3D55D169BCC740ULL,
		0x000000E4784FC067ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7F3EA3742C73ACCULL,
		0xBDE2F8124FF5A3AEULL,
		0xCD271B4D50023EF5ULL,
		0x36CD6BF8E782FAAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73ACC00000000000ULL,
		0x5A3AEB7F3EA3742CULL,
		0x23EF5BDE2F8124FFULL,
		0x2FAAACD271B4D500ULL,
		0x0000036CD6BF8E78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5385A9DB6D3E67FCULL,
		0xDA59ADBE43F6D295ULL,
		0x518EB47A307D0FB6ULL,
		0x568EFC04A3813BE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CCFF80000000000ULL,
		0xEDA52AA70B53B6DAULL,
		0xFA1F6DB4B35B7C87ULL,
		0x0277C4A31D68F460ULL,
		0x000000AD1DF80947ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0916FA1E1C634097ULL,
		0x203674AE710F6C49ULL,
		0xF4BB391361FF513BULL,
		0xB6389EFF3B931B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C6812E000000000ULL,
		0x21ED892122DF43C3ULL,
		0x3FEA276406CE95CEULL,
		0x7263709E9767226CULL,
		0x00000016C713DFE7ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC20326AB019170AULL,
		0x1D648EE28778EAD8ULL,
		0x76A39F4BC0B4CB53ULL,
		0xF9D02B22DF5A2C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8500000000000000ULL,
		0x6C56101935580C8BULL,
		0xA98EB2477143BC75ULL,
		0x1BBB51CFA5E05A65ULL,
		0x007CE815916FAD16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x17F0DD31B48CAF7DULL,
		0xC8256D366C2E7744ULL,
		0xF6C5BFD096F38D79ULL,
		0xD7D4E45297A95C4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD232BDF400000000ULL,
		0xB0B9DD105FC374C6ULL,
		0x5BCE35E72095B4D9ULL,
		0x5EA5712FDB16FF42ULL,
		0x000000035F53914AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x622DE5F157BE11C5ULL,
		0x29A8A6278B7779BCULL,
		0xD0ABBAA7E199D9CCULL,
		0x469F3B296EAC0011ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11C5000000000000ULL,
		0x79BC622DE5F157BEULL,
		0xD9CC29A8A6278B77ULL,
		0x0011D0ABBAA7E199ULL,
		0x0000469F3B296EACULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x829FF67B17F1FB1CULL,
		0xAFC898AF91D5BC60ULL,
		0xE593C14126F9CA7EULL,
		0x600E29E81BD4334BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D8BF8FD8E000000ULL,
		0x57C8EADE30414FFBULL,
		0xA0937CE53F57E44CULL,
		0xF40DEA19A5F2C9E0ULL,
		0x0000000000300714ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x378B2D4B884AEC42ULL,
		0xDC8CCCC80D8E2959ULL,
		0x1758B495034D0BCEULL,
		0x357B052C8A4C3F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x26F165A971095D88ULL,
		0xDB91999901B1C52BULL,
		0xA2EB1692A069A179ULL,
		0x06AF60A5914987E6ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1EEB399EF2E85CD5ULL,
		0x06B78E7FA65CA736ULL,
		0xCF6F762B3215C6EAULL,
		0x9443CB152856B289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9AA000000000000ULL,
		0x4E6C3DD6733DE5D0ULL,
		0x8DD40D6F1CFF4CB9ULL,
		0x65139EDEEC56642BULL,
		0x00012887962A50ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3C04C73FC34B59C4ULL,
		0x62EE8837C6D812B0ULL,
		0xA228F3C4E95CE69DULL,
		0xCD9C989FB1A4A7E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34B59C4000000000ULL,
		0x6D812B03C04C73FCULL,
		0x95CE69D62EE8837CULL,
		0x1A4A7E6A228F3C4EULL,
		0x0000000CD9C989FBULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDFBBEA5016BB017ULL,
		0x0339F64B162621EAULL,
		0xD984D8C3F4650039ULL,
		0xB972D6BE8A5DEC7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x405AEC05C0000000ULL,
		0xC589887AB37EEFA9ULL,
		0xFD19400E40CE7D92ULL,
		0xA2977B1F76613630ULL,
		0x000000002E5CB5AFULL
	}};
	shift = 34;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x452AC1902795CFE6ULL,
		0x84F76C6551E55149ULL,
		0x6FA337F7557847E3ULL,
		0x6DDC3589762248A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB9FCC00000000000ULL,
		0xAA2928A5583204F2ULL,
		0x08FC709EED8CAA3CULL,
		0x49146DF466FEEAAFULL,
		0x00000DBB86B12EC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFEC4092537EB972AULL,
		0x5A73BD9C8138E1F9ULL,
		0xF6CBB8DC5AB25210ULL,
		0x3A280F1C5E602B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE540000000000000ULL,
		0x3F3FD88124A6FD72ULL,
		0x420B4E77B390271CULL,
		0x703ED9771B8B564AULL,
		0x00074501E38BCC05ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1721D650DCF06B8EULL,
		0xDD8359EC825097D5ULL,
		0xF3CF11B70D2EBA6EULL,
		0x27C5AA0FB40D9216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B8E000000000000ULL,
		0x97D51721D650DCF0ULL,
		0xBA6EDD8359EC8250ULL,
		0x9216F3CF11B70D2EULL,
		0x000027C5AA0FB40DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9ED3CABFDE4AEDA5ULL,
		0xB5FBE7FF42DF72E0ULL,
		0x8450A56748FD926AULL,
		0x061A46CE506D10EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A00000000000000ULL,
		0xC13DA7957FBC95DBULL,
		0xD56BF7CFFE85BEE5ULL,
		0xD508A14ACE91FB24ULL,
		0x000C348D9CA0DA21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CFEF342C0D88FFFULL,
		0x9CB5360F20AF2400ULL,
		0x284C965979357534ULL,
		0xCF53EB1415F9C659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3FBCD0B03623FFC0ULL,
		0x2D4D83C82BC9000BULL,
		0x1325965E4D5D4D27ULL,
		0xD4FAC5057E71964AULL,
		0x0000000000000033ULL
	}};
	shift = 58;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA9DB30B9C87333EULL,
		0x3C12CC4DF02300C7ULL,
		0xADB7AA16F2B563BEULL,
		0x442689982320034BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xF553B6617390E667ULL,
		0xC7825989BE046018ULL,
		0x75B6F542DE56AC77ULL,
		0x0884D13304640069ULL
	}};
	shift = 3;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96FD76C66475BA60ULL,
		0x8C82AF040EC0CE07ULL,
		0x24D73538EF2D1181ULL,
		0x3233EDB59D0A71D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FD76C66475BA60ULL,
		0x8C82AF040EC0CE07ULL,
		0x24D73538EF2D1181ULL,
		0x3233EDB59D0A71D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6153CCEFE7350934ULL,
		0x25D3C8C706959581ULL,
		0xA59F82128A1699AFULL,
		0xF73DAB3DAF9277AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x16153CCEFE735093ULL,
		0xF25D3C8C70695958ULL,
		0xEA59F82128A1699AULL,
		0x0F73DAB3DAF9277AULL
	}};
	shift = 4;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5C8B0BB1B520362ULL,
		0x3D8C351F669232AFULL,
		0xDCE9632C54CA367BULL,
		0x87610B8D07381C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0D88000000000000ULL,
		0xCABF1722C2EC6D48ULL,
		0xD9ECF630D47D9A48ULL,
		0x722773A58CB15328ULL,
		0x00021D842E341CE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3D8D73A77AB1F30ULL,
		0xF401696134CC84DBULL,
		0x47EE5793AC4598A6ULL,
		0x834D61F89B5EF413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47B1AE74EF563E60ULL,
		0xE802D2C2699909B7ULL,
		0x8FDCAF27588B314DULL,
		0x069AC3F136BDE826ULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6738E231975D7C0CULL,
		0x4502BFA163D239B9ULL,
		0xB87397D0262C5B12ULL,
		0x4838A5A9D0959750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39C7118CBAEBE060ULL,
		0x2815FD0B1E91CDCBULL,
		0xC39CBE813162D892ULL,
		0x41C52D4E84ACBA85ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FD57B4CDC961E03ULL,
		0xD03FEF505E3DF8F9ULL,
		0x1CDB24C2FF2DC26EULL,
		0x7188A5941325DA0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x337258780C000000ULL,
		0x4178F7E3E57F55EDULL,
		0x0BFCB709BB40FFBDULL,
		0x504C97682C736C93ULL,
		0x0000000001C62296ULL
	}};
	shift = 38;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62AF84B42F5DE26EULL,
		0x64F0495D88772697ULL,
		0x23174CEDE704EFE6ULL,
		0x5C68A3F0DB8359A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F09685EBBC4DC00ULL,
		0xE092BB10EE4D2EC5ULL,
		0x2E99DBCE09DFCCC9ULL,
		0xD147E1B706B35246ULL,
		0x00000000000000B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D28CF965AFA68C1ULL,
		0xBBB8F52BB1CE9C0EULL,
		0x5D49D2A4006726BBULL,
		0xA3559B2B5998BFCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CB5F4D18200000ULL,
		0xA57639D381C9A519ULL,
		0x54800CE4D777771EULL,
		0x656B3317F94BA93AULL,
		0x0000000000146AB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x981BA100239704FEULL,
		0x8D6153ED9AD7092FULL,
		0x625B0AB6D21EC1D2ULL,
		0x606DBFFD2674905BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C13F80000000000ULL,
		0x5C24BE606E84008EULL,
		0x7B074A35854FB66BULL,
		0xD2416D896C2ADB48ULL,
		0x00000181B6FFF499ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x526C0A3B6383D187ULL,
		0x35F09A651E2AB6FDULL,
		0xCFA6D7319C1FFC44ULL,
		0xB63ED1B9E6C39D4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E8C380000000000ULL,
		0x55B7EA936051DB1CULL,
		0xFFE221AF84D328F1ULL,
		0x1CEA667D36B98CE0ULL,
		0x000005B1F68DCF36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AB86E3C023052D5ULL,
		0x6898548DF573AE40ULL,
		0x433F811EDD5E4C2DULL,
		0xB234445DDFB8FD68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23052D5000000000ULL,
		0x573AE402AB86E3C0ULL,
		0xD5E4C2D6898548DFULL,
		0xFB8FD68433F811EDULL,
		0x0000000B234445DDULL
	}};
	shift = 28;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x25F8C06A3F077AA9ULL,
		0x4526807583E179A4ULL,
		0xC75D7C46BDEC58A8ULL,
		0x8F81CC649E3C5F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC60351F83BD548ULL,
		0x293403AC1F0BCD21ULL,
		0x3AEBE235EF62C542ULL,
		0x7C0E6324F1E2FCE6ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3A9301E734659ADULL,
		0xDCFE3AA9AC46AC60ULL,
		0x3FA22B2E2DAB4F25ULL,
		0x157D0BC890C9EDE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39A32CD680000000ULL,
		0xD623563069D4980FULL,
		0x16D5A792EE7F1D54ULL,
		0x4864F6F29FD11597ULL,
		0x000000000ABE85E4ULL
	}};
	shift = 33;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F3EEEE83508E435ULL,
		0x4EEA41BCBD2F7716ULL,
		0x31DB51E295709838ULL,
		0xA90073BF77CBCC9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F3EEEE83508E435ULL,
		0x4EEA41BCBD2F7716ULL,
		0x31DB51E295709838ULL,
		0xA90073BF77CBCC9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8028A339C08E4DFULL,
		0x737590D36868FFADULL,
		0xC51D596B049F6ABFULL,
		0xCE61707399883D07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4519CE04726F8000ULL,
		0xC869B4347FD6D401ULL,
		0xACB5824FB55FB9BAULL,
		0xB839CCC41E83E28EULL,
		0x0000000000006730ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA488EBBF78F8479BULL,
		0x4807F99809E36D80ULL,
		0xB5B2094EF457257CULL,
		0x30AEAF8EAEE24CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD80000000000000ULL,
		0xC0524475DFBC7C23ULL,
		0xBE2403FCCC04F1B6ULL,
		0x7DDAD904A77A2B92ULL,
		0x00185757C7577126ULL
	}};
	shift = 9;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6BFC83D55F4ADD58ULL,
		0x38F6EAE72958A038ULL,
		0x5926B862EB26B134ULL,
		0x5DB7A355E72F89A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBAB0000000000000ULL,
		0x4070D7F907AABE95ULL,
		0x626871EDD5CE52B1ULL,
		0x1342B24D70C5D64DULL,
		0x0000BB6F46ABCE5FULL
	}};
	shift = 15;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x698935849D85D291ULL,
		0x3189B454A4528A7AULL,
		0x5704B804FFC1FDF9ULL,
		0xA46703C2E279E460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3126B093B0BA5220ULL,
		0x31368A948A514F4DULL,
		0xE097009FF83FBF26ULL,
		0x8CE0785C4F3C8C0AULL,
		0x0000000000000014ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7AC623ABF562A957ULL,
		0x23F346BDA52FB499ULL,
		0x73580464EEB487C3ULL,
		0x5AE7F7668C5D8E3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x5EB188EAFD58AA55ULL,
		0xC8FCD1AF694BED26ULL,
		0x1CD601193BAD21F0ULL,
		0x16B9FDD9A317638FULL
	}};
	shift = 2;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBD7472348E6F647ULL,
		0xAE48821BF8F7C5CDULL,
		0x8B3178B72748B8ACULL,
		0xBD1CB1961EEA9D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A4737B238000000ULL,
		0xDFC7BE2E6F5EBA39ULL,
		0xB93A45C565724410ULL,
		0xB0F754EAAC598BC5ULL,
		0x0000000005E8E58CULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05F2AED93F6CB186ULL,
		0xF3A12099792F4A93ULL,
		0x975FD82A2671C972ULL,
		0xF90DC6BC2825E7B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD9630C0000000000ULL,
		0x5E95260BE55DB27EULL,
		0xE392E5E7424132F2ULL,
		0x4BCF692EBFB0544CULL,
		0x000001F21B8D7850ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60A713E7A545301DULL,
		0x917CF62F207720F5ULL,
		0x79EF58751BD05748ULL,
		0xF5104DEE0743989BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2980E80000000000ULL,
		0xB907AB05389F3D2AULL,
		0x82BA448BE7B17903ULL,
		0x1CC4DBCF7AC3A8DEULL,
		0x000007A8826F703AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7118B7F2537CA373ULL,
		0x0C62C8A8749DB215ULL,
		0x3E91002451CD565AULL,
		0x43E36AB2648337CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC94DF28DCC00000ULL,
		0x2A1D276C855C462DULL,
		0x09147355968318B2ULL,
		0xAC9920CDF34FA440ULL,
		0x000000000010F8DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 234;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x126A6DFD150F4609ULL,
		0x15BC1AFFE8599A97ULL,
		0xF6D6CF010D8914D4ULL,
		0x610E0743E1E69100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x150F460900000000ULL,
		0xE8599A97126A6DFDULL,
		0x0D8914D415BC1AFFULL,
		0xE1E69100F6D6CF01ULL,
		0x00000000610E0743ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x782192FCF674D211ULL,
		0x8F9AF9C35E1B98ADULL,
		0x6F7FFBA7EE2DA337ULL,
		0x631376E086515C92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECE9A42200000000ULL,
		0xBC37315AF04325F9ULL,
		0xDC5B466F1F35F386ULL,
		0x0CA2B924DEFFF74FULL,
		0x00000000C626EDC1ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x090FD8532532DBD8ULL,
		0x51B19F3CC564884EULL,
		0x0636EA218C2BEB3AULL,
		0xDEB88B9418D110BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF600000000000000ULL,
		0x138243F614C94CB6ULL,
		0xCE946C67CF315922ULL,
		0x2F818DBA88630AFAULL,
		0x0037AE22E5063444ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEEB9F7AB8D3DB086ULL,
		0xD2485CB9BCDB1385ULL,
		0xBD5EBCE74655D0DFULL,
		0xEA1CB6F2217E8AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF571A7B610C0000ULL,
		0xB97379B6270BDD73ULL,
		0x79CE8CABA1BFA490ULL,
		0x6DE442FD15637ABDULL,
		0x000000000001D439ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEB94591F7DFA92EULL,
		0xA83FD839EFA8B3D7ULL,
		0xEA931D6192DE32E3ULL,
		0xF7F204C6A542A142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB94591F7DFA92E0ULL,
		0x83FD839EFA8B3D7DULL,
		0xA931D6192DE32E3AULL,
		0x7F204C6A542A142EULL,
		0x000000000000000FULL
	}};
	shift = 60;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x66B6D1F88C04B3F9ULL,
		0x76E96CA18B781359ULL,
		0xD2EEFF466B9B959DULL,
		0x431100F552EAC609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE400000000000000ULL,
		0x659ADB47E23012CFULL,
		0x75DBA5B2862DE04DULL,
		0x274BBBFD19AE6E56ULL,
		0x010C4403D54BAB18ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB94F42740FA8EBCBULL,
		0xDBE27176193A4DD9ULL,
		0x79AE70D738BF41D4ULL,
		0x2525A25B7B5962D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x29E84E81F51D7960ULL,
		0x7C4E2EC32749BB37ULL,
		0x35CE1AE717E83A9BULL,
		0xA4B44B6F6B2C5A2FULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C8D131888A5FC10ULL,
		0x674E5C2D54F351ADULL,
		0x5FDE6544FC8F5AEEULL,
		0xB85503B3FE061259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF82000000000000ULL,
		0x6A35AD91A2631114ULL,
		0xEB5DCCE9CB85AA9EULL,
		0xC24B2BFBCCA89F91ULL,
		0x0000170AA0767FC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F59E51A1CA2BE2BULL,
		0x5F8CBC0C5217979BULL,
		0xB795AF50EFCABAD6ULL,
		0xE22E9EFFD1555D9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x515F158000000000ULL,
		0x0BCBCDBFACF28D0EULL,
		0xE55D6B2FC65E0629ULL,
		0xAAAECE5BCAD7A877ULL,
		0x00000071174F7FE8ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3A7A56AFAE86C37ULL,
		0x22136C73B5A94497ULL,
		0x28E89E50319F1A6BULL,
		0x67DDF20242B7B4A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D74361B8000000ULL,
		0x9DAD4A24BD1D3D2BULL,
		0x818CF8D359109B63ULL,
		0x1215BDA5094744F2ULL,
		0x00000000033EEF90ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 229;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x020BAF575DA78F69ULL,
		0x736626A490711FD8ULL,
		0x6F0905720E8E4E76ULL,
		0x994B175DCE562948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAED3C7B480000000ULL,
		0x48388FEC0105D7ABULL,
		0x0747273B39B31352ULL,
		0xE72B14A4378482B9ULL,
		0x000000004CA58BAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCD30B5A0D86F40DULL,
		0xB738C3A9625D79C0ULL,
		0x9B0649B42B86419DULL,
		0x560F1DD12438C8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB41B0DE81A000000ULL,
		0x52C4BAF38179A616ULL,
		0x68570C833B6E7187ULL,
		0xA2487191EF360C93ULL,
		0x0000000000AC1E3BULL
	}};
	shift = 39;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x544F016E1CE786CFULL,
		0x0D3EF322A4FC5820ULL,
		0x52D0BBE6C5921B67ULL,
		0x01ACF855C1D3A8D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF016E1CE786CF000ULL,
		0xEF322A4FC5820544ULL,
		0x0BBE6C5921B670D3ULL,
		0xCF855C1D3A8D952DULL,
		0x000000000000001AULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC85B3020C9299787ULL,
		0x726F84C37B543C8DULL,
		0xB88C8E538C3B2B85ULL,
		0x1BFBB31EC4050E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC85B3020C9299787ULL,
		0x726F84C37B543C8DULL,
		0xB88C8E538C3B2B85ULL,
		0x1BFBB31EC4050E52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1F60A3DA7FE3CD0ULL,
		0x1DB36D55464698B5ULL,
		0xAEE28F2AF908E41BULL,
		0xD54578E434FA2D86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3EC147B4FFC79A0ULL,
		0x3B66DAAA8C8D316BULL,
		0x5DC51E55F211C836ULL,
		0xAA8AF1C869F45B0DULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 255;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x325E11459DEA95F4ULL,
		0xAED88335F4FB18F8ULL,
		0x0EEA89C2D1314FFEULL,
		0x00969E980B1FD053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE800000000000000ULL,
		0xF064BC228B3BD52BULL,
		0xFD5DB1066BE9F631ULL,
		0xA61DD51385A2629FULL,
		0x00012D3D30163FA0ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5FAFCE097491A6F9ULL,
		0xF2C7A90144825B8FULL,
		0xB9A1163CB1E76D81ULL,
		0x69DD60DF7542FE9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAFCE097491A6F900ULL,
		0xC7A90144825B8F5FULL,
		0xA1163CB1E76D81F2ULL,
		0xDD60DF7542FE9EB9ULL,
		0x0000000000000069ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x470E09AF1C1523FFULL,
		0x45790A7541BB8DD5ULL,
		0x85E969291EC607FEULL,
		0x8D13CCE65AD6D9C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x382A47FE00000000ULL,
		0x83771BAA8E1C135EULL,
		0x3D8C0FFC8AF214EAULL,
		0xB5ADB3830BD2D252ULL,
		0x000000011A2799CCULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8A0495BCE4EE784ULL,
		0x9BDA23C8C9D195CFULL,
		0x838E8B6E598A6D0AULL,
		0x64972C7B29225B9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5024ADE72773C200ULL,
		0xED11E464E8CAE7E4ULL,
		0xC745B72CC536854DULL,
		0x4B963D94912DCE41ULL,
		0x0000000000000032ULL
	}};
	shift = 57;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD43265669AD51AA3ULL,
		0x4133EDF9BB2AAFA2ULL,
		0x34A616C4C81FB62DULL,
		0xE0D0B8CF46CDF207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x6A1932B34D6A8D51ULL,
		0xA099F6FCDD9557D1ULL,
		0x9A530B62640FDB16ULL,
		0x70685C67A366F903ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE3C2D951BA4DF61ULL,
		0x97EF296F6F5FF972ULL,
		0xFE07614829B34C6BULL,
		0xACC41B930134733BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49BEC20000000000ULL,
		0xBFF2E5BC785B2A37ULL,
		0x6698D72FDE52DEDEULL,
		0x68E677FC0EC29053ULL,
		0x0000015988372602ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40E45EF6E24ED51EULL,
		0xB29FC4890145F04BULL,
		0x65808A0FB90CECC8ULL,
		0x582F7C493DCCA9A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1C8BDEDC49DAA3C0ULL,
		0x53F8912028BE0968ULL,
		0xB01141F7219D9916ULL,
		0x05EF8927B99534ACULL,
		0x000000000000000BULL
	}};
	shift = 59;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC48BD95630AFB7EULL,
		0x5917DCDE25C7C045ULL,
		0xC613725F69AED7B3ULL,
		0x96FCBAE5C1F41DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57DBF00000000000ULL,
		0x3E022E6245ECAB18ULL,
		0x76BD9AC8BEE6F12EULL,
		0xA0ED8E309B92FB4DULL,
		0x000004B7E5D72E0FULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5AF0D9CF1ACDFF1CULL,
		0xC80605750E829BEBULL,
		0x257AF8E898EFD209ULL,
		0x4EEDA65B8D77D33BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF1ACDFF1C000000ULL,
		0x750E829BEB5AF0D9ULL,
		0xE898EFD209C80605ULL,
		0x5B8D77D33B257AF8ULL,
		0x00000000004EEDA6ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0661F655FA00A414ULL,
		0x578EC92ACA2D1562ULL,
		0x4F34A796095DB2D8ULL,
		0x560D64DEC017E9B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D957E802905000ULL,
		0x3B24AB28B4558819ULL,
		0xD29E582576CB615EULL,
		0x35937B005FA6D53CULL,
		0x0000000000000158ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 246;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x242797D78B287A37ULL,
		0x8413B56F7D7784DBULL,
		0x208D2A06DA922838ULL,
		0x6590A7068FC0BC31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E5F5E2CA1E8DC00ULL,
		0x4ED5BDF5DE136C90ULL,
		0x34A81B6A48A0E210ULL,
		0x429C1A3F02F0C482ULL,
		0x0000000000000196ULL
	}};
	shift = 54;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62F1D7134DE65A31ULL,
		0xF70A748E372D135CULL,
		0x613E1314AC2881D0ULL,
		0x463264C9730F0568ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32D1880000000000ULL,
		0x689AE3178EB89A6FULL,
		0x440E87B853A471B9ULL,
		0x782B4309F098A561ULL,
		0x0000023193264B98ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE389FE4F87AB34E7ULL,
		0xEB8C7D2FEE0B6A6DULL,
		0x6DFD91300A467794ULL,
		0xD0FDDC0757F3757FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7380000000000000ULL,
		0x36F1C4FF27C3D59AULL,
		0xCA75C63E97F705B5ULL,
		0xBFB6FEC89805233BULL,
		0x00687EEE03ABF9BAULL
	}};
	shift = 9;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x457007B116C880F0ULL,
		0x0259C598B8746EBEULL,
		0x40150D5DB3B30699ULL,
		0xED0A414F13F1462FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01EC45B2203C0000ULL,
		0x71662E1D1BAF915CULL,
		0x43576CECC1A64096ULL,
		0x9053C4FC518BD005ULL,
		0x0000000000003B42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFA1368104F4F56BULL,
		0x00F15A159F95C71EULL,
		0xD00DA6853571B1FEULL,
		0xB6586E55518FD645ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56B0000000000000ULL,
		0x71EAFA1368104F4FULL,
		0x1FE00F15A159F95CULL,
		0x645D00DA6853571BULL,
		0x000B6586E55518FDULL
	}};
	shift = 12;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2EA48CEABF22DBFBULL,
		0xB69957DA6861ADEAULL,
		0x6293D6B9C6727741ULL,
		0x545C326DE4560ABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5F916DFD80000000ULL,
		0x3430D6F517524675ULL,
		0xE3393BA0DB4CABEDULL,
		0xF22B055F3149EB5CULL,
		0x000000002A2E1936ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x706216F6040DD380ULL,
		0x59B7B829010AD6E6ULL,
		0x5B76977C621DEBA7ULL,
		0xE35895A550B82D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B7B0206E9C00000ULL,
		0xDC1480856B733831ULL,
		0x4BBE310EF5D3ACDBULL,
		0x4AD2A85C16BDADBBULL,
		0x00000000000071ACULL
	}};
	shift = 49;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A6E0DA29E65558CULL,
		0x427BFB6D48781670ULL,
		0x31D6436F822EC2EEULL,
		0xEF3040BD3F900F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58C0000000000000ULL,
		0x6706A6E0DA29E655ULL,
		0x2EE427BFB6D48781ULL,
		0xF1B31D6436F822ECULL,
		0x000EF3040BD3F900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FA49BC837178054ULL,
		0xCF3A6DC05EBC7C7DULL,
		0xD47365EEA1E5151CULL,
		0x35EF3316BB5CBC6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x37906E2F00A80000ULL,
		0xDB80BD78F8FAFF49ULL,
		0xCBDD43CA2A399E74ULL,
		0x662D76B978D7A8E6ULL,
		0x0000000000006BDEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D40C321CB531E21ULL,
		0xA3B3C09D5C78327FULL,
		0x82B4196B9855E64DULL,
		0x8280287A24F74F5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8840000000000000ULL,
		0x9FC75030C872D4C7ULL,
		0x9368ECF027571E0CULL,
		0xD7A0AD065AE61579ULL,
		0x0020A00A1E893DD3ULL
	}};
	shift = 10;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8F95D910CD4F5534ULL,
		0xEE1C7DABB65B3678ULL,
		0xC414E3DC752DAC9FULL,
		0xCF917C54813C0B13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x76443353D54D0000ULL,
		0x1F6AED96CD9E23E5ULL,
		0x38F71D4B6B27FB87ULL,
		0x5F15204F02C4F105ULL,
		0x00000000000033E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4BA143AB28A2D41ULL,
		0x0AC03D2CEDF79602ULL,
		0xBE9626170E4069E2ULL,
		0x6B09AD08472E66AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA28B50400000000ULL,
		0xB7DE580AD2E850EAULL,
		0x3901A7882B00F4B3ULL,
		0x1CB99AAAFA58985CULL,
		0x00000001AC26B421ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75EB580A28918644ULL,
		0x81AFEB727D46D568ULL,
		0xBCFEE2B1DEB0CC39ULL,
		0x359834825AFABB7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x75EB580A28918644ULL,
		0x81AFEB727D46D568ULL,
		0xBCFEE2B1DEB0CC39ULL,
		0x359834825AFABB7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE37E55B192123ECCULL,
		0x3BD8CB10FDB64170ULL,
		0x3768DEAAFD332E19ULL,
		0xC4FA6E7E0C567A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAB6324247D980000ULL,
		0x9621FB6C82E1C6FCULL,
		0xBD55FA665C3277B1ULL,
		0xDCFC18ACF48A6ED1ULL,
		0x00000000000189F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4026E780460B085FULL,
		0x3C9B29BA7D907A80ULL,
		0xC285D6F09392C0BFULL,
		0x43D07A1755BD5523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B9E01182C217C00ULL,
		0x6CA6E9F641EA0100ULL,
		0x175BC24E4B02FCF2ULL,
		0x41E85D56F5548F0AULL,
		0x000000000000010FULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x90275E2A5AB2060BULL,
		0x7A687183C23F5DE0ULL,
		0xE0CFA724F6EAA826ULL,
		0x078A8AA3C72C0250ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x60B0000000000000ULL,
		0xDE090275E2A5AB20ULL,
		0x8267A687183C23F5ULL,
		0x250E0CFA724F6EAAULL,
		0x000078A8AA3C72C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEAF1ADD51B652927ULL,
		0xF3C47A1FFF99EB6CULL,
		0xD290100EA3921BBBULL,
		0x28A1CAFBE485F1C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0xCEAF1ADD51B65292ULL,
		0xBF3C47A1FFF99EB6ULL,
		0x1D290100EA3921BBULL,
		0x028A1CAFBE485F1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF4D70D05E2D8464CULL,
		0x3BD286ACF2297316ULL,
		0xD699170EB6E8C18AULL,
		0x427EA5C9D180EDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4D70D05E2D8464C0ULL,
		0xBD286ACF2297316FULL,
		0x699170EB6E8C18A3ULL,
		0x27EA5C9D180EDD6DULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x755E36D3E728F863ULL,
		0x7BDACCB9CF8AB208ULL,
		0x4082628C9F2C94FEULL,
		0x5753BE6BDD638972ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE18C000000000000ULL,
		0xC821D578DB4F9CA3ULL,
		0x53F9EF6B32E73E2AULL,
		0x25C902098A327CB2ULL,
		0x00015D4EF9AF758EULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26739CBEBAF3F8D6ULL,
		0x1B10E4CD73042BBDULL,
		0x8A1CAC3C3B1899E1ULL,
		0x6CCF3F085B5DB368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26739CBEBAF3F8D6ULL,
		0x1B10E4CD73042BBDULL,
		0x8A1CAC3C3B1899E1ULL,
		0x6CCF3F085B5DB368ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40F48CF32B7F0167ULL,
		0x4ED5B85ADFB02104ULL,
		0x2E7619A431C72A10ULL,
		0x503327B20F806140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F48CF32B7F01670ULL,
		0xED5B85ADFB021044ULL,
		0xE7619A431C72A104ULL,
		0x03327B20F8061402ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2E71B69198B68229ULL,
		0x0284584860BDF1F0ULL,
		0x554DE5C3CD91013BULL,
		0x4CC95B42758B8BA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x1738DB48CC5B4114ULL,
		0x81422C24305EF8F8ULL,
		0xAAA6F2E1E6C8809DULL,
		0x2664ADA13AC5C5D2ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CA949409DC04526ULL,
		0xCC392D28F65AC27CULL,
		0x476F526981EEBC43ULL,
		0x3CCB1F16DD82BA39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CA949409DC04526ULL,
		0xCC392D28F65AC27CULL,
		0x476F526981EEBC43ULL,
		0x3CCB1F16DD82BA39ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD3213E22742FF85ULL,
		0xA44DE6CCC41A757BULL,
		0xCFFD871003ED7CBAULL,
		0x41E212CAEAD14D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FF8500000000000ULL,
		0xA757BAD3213E2274ULL,
		0xD7CBAA44DE6CCC41ULL,
		0x14D6BCFFD871003EULL,
		0x0000041E212CAEADULL
	}};
	shift = 20;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x941C77C9E62A5F0EULL,
		0xC5FE974D68ED9789ULL,
		0xBF7152B05157185DULL,
		0xE19D8EA25584C4EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x152F870000000000ULL,
		0x76CBC4CA0E3BE4F3ULL,
		0xAB8C2EE2FF4BA6B4ULL,
		0xC26277DFB8A95828ULL,
		0x00000070CEC7512AULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x831B23C9B018E141ULL,
		0x03C7FDAD957A5033ULL,
		0x62050F26C06819F3ULL,
		0x2E9A9FE5363E77EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8F26C06385040000ULL,
		0xF6B655E940CE0C6CULL,
		0x3C9B01A067CC0F1FULL,
		0x7F94D8F9DFB98814ULL,
		0x000000000000BA6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA54E54EF59AD9E2ULL,
		0x00ECF888402B08CCULL,
		0x65C3627AFE92A721ULL,
		0x183CAB495087745AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3BD66B6788000000ULL,
		0x2100AC2333695395ULL,
		0xEBFA4A9C8403B3E2ULL,
		0x25421DD169970D89ULL,
		0x000000000060F2ADULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3434470101E75428ULL,
		0x1AEE85E14D8F2379ULL,
		0x26048D09E0121C80ULL,
		0xB70007E243EFA592ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x268688E0203CEA85ULL,
		0x035DD0BC29B1E46FULL,
		0x44C091A13C024390ULL,
		0x16E000FC487DF4B2ULL
	}};
	shift = 3;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BA02D3FC362EF6BULL,
		0x0589389B9BC512E8ULL,
		0x10D8A18C25D9D796ULL,
		0xF0A9EA0B02945364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7BA02D3FC362EF6BULL,
		0x0589389B9BC512E8ULL,
		0x10D8A18C25D9D796ULL,
		0xF0A9EA0B02945364ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF861C0CAAB804113ULL,
		0x5DF5AFB648B96E91ULL,
		0x48B129693DB2098BULL,
		0x8934AC2CD029D1CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAAE01044C0000000ULL,
		0x922E5BA47E187032ULL,
		0x4F6C8262D77D6BEDULL,
		0x340A7472D22C4A5AULL,
		0x00000000224D2B0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0A92669EFB166F6AULL,
		0xFE3F1FD8B61E37CBULL,
		0x52C981B191BAAE49ULL,
		0xDFD6C04790939693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6A0000000000000ULL,
		0x7CB0A92669EFB166ULL,
		0xE49FE3F1FD8B61E3ULL,
		0x69352C981B191BAAULL,
		0x000DFD6C04790939ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7B9BC0ED16EF515CULL,
		0x6179D3077B586656ULL,
		0x2C370FC9A83A792EULL,
		0x2EEF74373807FD7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF73781DA2DDEA2B8ULL,
		0xC2F3A60EF6B0CCACULL,
		0x586E1F935074F25CULL,
		0x5DDEE86E700FFAF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73AE09390BCD25D0ULL,
		0x1C40ABA18737C764ULL,
		0xBFA73E80A7956041ULL,
		0x9871DA5FA8519E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0xC8E75C1272179A4BULL,
		0x82388157430E6F8EULL,
		0x317F4E7D014F2AC0ULL,
		0x0130E3B4BF50A33DULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2895577931EFF3F5ULL,
		0x01997137295CB349ULL,
		0x8599C5C0E3D8CD2FULL,
		0xF4CFC940159B3F70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x512AAEF263DFE7EAULL,
		0x0332E26E52B96692ULL,
		0x0B338B81C7B19A5EULL,
		0xE99F92802B367EE1ULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE3990AC11CA9ABE8ULL,
		0xD4929CCC1937CBDAULL,
		0x91B7BC891F198823ULL,
		0xA6987262E9BDAF69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE800000000000000ULL,
		0xDAE3990AC11CA9ABULL,
		0x23D4929CCC1937CBULL,
		0x6991B7BC891F1988ULL,
		0x00A6987262E9BDAFULL
	}};
	shift = 8;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D10E604E4AF4CDFULL,
		0xDCE2104E68E408DAULL,
		0x76F87B2A27AD5FDDULL,
		0x9946E8819A63E527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD10E604E4AF4CDF0ULL,
		0xCE2104E68E408DA4ULL,
		0x6F87B2A27AD5FDDDULL,
		0x946E8819A63E5277ULL,
		0x0000000000000009ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBAD588C33C96FE35ULL,
		0x73781609A5164C9FULL,
		0x812DD979695398B2ULL,
		0xA8C1C494A8427271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC4619E4B7F1A8000ULL,
		0x0B04D28B264FDD6AULL,
		0xECBCB4A9CC5939BCULL,
		0xE24A54213938C096ULL,
		0x0000000000005460ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBA54225D449F9160ULL,
		0x72B42C0AB1E4CF79ULL,
		0xE407B8579D21192DULL,
		0x41478A84C07F682AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4BA893F22C000000ULL,
		0x81563C99EF374A84ULL,
		0x0AF3A42325AE5685ULL,
		0x50980FED055C80F7ULL,
		0x00000000000828F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8C9CD451792C9D2ULL,
		0x60152C63E84DB0BCULL,
		0x76DFB49795C11D49ULL,
		0x55E306037373DE62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E90000000000000ULL,
		0x85E7C64E6A28BC96ULL,
		0xEA4B00A9631F426DULL,
		0xF313B6FDA4BCAE08ULL,
		0x0002AF18301B9B9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C16985E5B7F960FULL,
		0x9DD632570D00AAD6ULL,
		0xFC81505EA1F41AEBULL,
		0x9A769BE862852FA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82D30BCB6FF2C1E0ULL,
		0xBAC64AE1A0155AD1ULL,
		0x902A0BD43E835D73ULL,
		0x4ED37D0C50A5F4DFULL,
		0x0000000000000013ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94E92854EBBCF6E5ULL,
		0x79F338C9190D1D9EULL,
		0x591CE16892FBFAB3ULL,
		0x11CE6F20C635811EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42A75DE7B7280000ULL,
		0xC648C868ECF4A749ULL,
		0x0B4497DFD59BCF99ULL,
		0x790631AC08F2C8E7ULL,
		0x0000000000008E73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x88374D68877A0C75ULL,
		0x974AEB4BA0BE9494ULL,
		0x992FD333143C1DFFULL,
		0x7122D50B1468AF0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x06E9AD10EF418EA0ULL,
		0xE95D697417D29291ULL,
		0x25FA66628783BFF2ULL,
		0x245AA1628D15E193ULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE423FED906C953A2ULL,
		0x3125F9882776E60DULL,
		0x273B26907EC88A46ULL,
		0xEF2127197E1AFABEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2A74400000000000ULL,
		0xDCC1BC847FDB20D9ULL,
		0x1148C624BF3104EEULL,
		0x5F57C4E764D20FD9ULL,
		0x00001DE424E32FC3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x011C5E2B830AE019ULL,
		0x0BE2F90A1EF751DCULL,
		0x4C7A2A64AAD69396ULL,
		0xAD19BD8C38B4F478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11C5E2B830AE0190ULL,
		0xBE2F90A1EF751DC0ULL,
		0xC7A2A64AAD693960ULL,
		0xD19BD8C38B4F4784ULL,
		0x000000000000000AULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB7F74868C385DC86ULL,
		0x52A29D8A92BCA00BULL,
		0xB6BD0BB8C3ADF8C5ULL,
		0x9ED3E66855C22C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7218000000000000ULL,
		0x802EDFDD21A30E17ULL,
		0xE3154A8A762A4AF2ULL,
		0xB046DAF42EE30EB7ULL,
		0x00027B4F99A15708ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61AF52C332521864ULL,
		0x4CD0A178D4216969ULL,
		0xD3FAF32DB01F75EBULL,
		0xAF122197FAA06ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0CC9486190000000ULL,
		0xE35085A5A586BD4BULL,
		0xB6C07DD7AD334285ULL,
		0x5FEA81AB334FEBCCULL,
		0x0000000002BC4886ULL
	}};
	shift = 38;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE510BC501131C3F9ULL,
		0x5CECB0E0A4784ECFULL,
		0xCB582C7B6CC1343FULL,
		0xA7D703CC47338F39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE40000000000000ULL,
		0xB3F9442F14044C70ULL,
		0x0FD73B2C38291E13ULL,
		0xCE72D60B1EDB304DULL,
		0x0029F5C0F311CCE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 202;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0638BE74C1B0C6CEULL,
		0x222A4922ADC7A564ULL,
		0x23E54ACBDC6E758DULL,
		0xC7561D1408A25BDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7CE983618D9C0000ULL,
		0x92455B8F4AC80C71ULL,
		0x9597B8DCEB1A4454ULL,
		0x3A281144B7B847CAULL,
		0x0000000000018EACULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8106A40928E1403ULL,
		0x7E217EFC23AA4B20ULL,
		0x31DD0D382CD30AC8ULL,
		0xAB2000541F1EFB6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A9024A38500C000ULL,
		0x5FBF08EA92C82A04ULL,
		0x434E0B34C2B21F88ULL,
		0x001507C7BEDB4C77ULL,
		0x0000000000002AC8ULL
	}};
	shift = 50;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CE8A9092B42B255ULL,
		0x00E4A52952F43149ULL,
		0x65F748B896CBC607ULL,
		0x4D3465FD3CE31193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92B42B2550000000ULL,
		0x952F431494CE8A90ULL,
		0x896CBC60700E4A52ULL,
		0xD3CE3119365F748BULL,
		0x0000000004D3465FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05A2389B0284D4C1ULL,
		0x4B3B65A3F55D3F40ULL,
		0x040C068D5B5AF451ULL,
		0x258FAB5ADB848B41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81426A6080000000ULL,
		0xFAAE9FA002D11C4DULL,
		0xADAD7A28A59DB2D1ULL,
		0x6DC245A082060346ULL,
		0x0000000012C7D5ADULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CF4093072496104ULL,
		0x4B977A11ABC3B0E9ULL,
		0xAC63459351CB2C68ULL,
		0x9947BBD4D1578833ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9610400000000000ULL,
		0x3B0E92CF40930724ULL,
		0xB2C684B977A11ABCULL,
		0x78833AC63459351CULL,
		0x000009947BBD4D15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18FDB402098C916BULL,
		0xF7C128284BE27F09ULL,
		0xBB509BB809B61E90ULL,
		0x0994DCC362B3DB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8263245AC0000000ULL,
		0x12F89FC2463F6D00ULL,
		0x026D87A43DF04A0AULL,
		0xD8ACF6E62ED426EEULL,
		0x0000000002653730ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE343D6618940C9DBULL,
		0xCBEE0CC4CF4A61B0ULL,
		0x7A8E54D9623F118FULL,
		0xFF8E5262E17DB901ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC9DB000000000000ULL,
		0x61B0E343D6618940ULL,
		0x118FCBEE0CC4CF4AULL,
		0xB9017A8E54D9623FULL,
		0x0000FF8E5262E17DULL
	}};
	shift = 16;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x336FFFC10F7F5B78ULL,
		0x61524601BFB4107CULL,
		0x613DCDE22B24565EULL,
		0xF639A1236DBBAA93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC10F7F5B78000000ULL,
		0x01BFB4107C336FFFULL,
		0xE22B24565E615246ULL,
		0x236DBBAA93613DCDULL,
		0x0000000000F639A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE98DB4550E8A576BULL,
		0xCB33A6CFB1324F5EULL,
		0xE808C0F1E935D6B9ULL,
		0x568F258B4D9EE5B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xBA636D1543A295DAULL,
		0x72CCE9B3EC4C93D7ULL,
		0xBA02303C7A4D75AEULL,
		0x15A3C962D367B96CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF01409B9755B97BDULL,
		0x5A4004A677D2C75FULL,
		0xDF24660B71F2C9EFULL,
		0xEAF6C79F32B4A501ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCBDE80000000000ULL,
		0x963AFF80A04DCBAAULL,
		0x964F7AD2002533BEULL,
		0xA5280EF923305B8FULL,
		0x00000757B63CF995ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 213;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70DA08CFF5506F25ULL,
		0x87AA37B0BAF3E9A2ULL,
		0xA3C0D17498686D52ULL,
		0xCC4B393F7E23D1AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x506F250000000000ULL,
		0xF3E9A270DA08CFF5ULL,
		0x686D5287AA37B0BAULL,
		0x23D1AFA3C0D17498ULL,
		0x000000CC4B393F7EULL
	}};
	shift = 24;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A89A049D44D9CC1ULL,
		0x280D5F20653E3954ULL,
		0xD81F657AB461BCE8ULL,
		0x5370BEE4C531125FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD024EA26CE608000ULL,
		0xAF90329F1CAA1544ULL,
		0xB2BD5A30DE741406ULL,
		0x5F726298892FEC0FULL,
		0x00000000000029B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFDDE29A34119F38ULL,
		0x122BFDBA793399D7ULL,
		0xD65B1D5ABC4E57F5ULL,
		0x5C169F3CD1B5589CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF778A68D0467CE00ULL,
		0x8AFF6E9E4CE675FFULL,
		0x96C756AF1395FD44ULL,
		0x05A7CF346D562735ULL,
		0x0000000000000017ULL
	}};
	shift = 58;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8CD9CB6CECCC45AAULL,
		0x89F269FE8E2F0B48ULL,
		0x8C5E4407E7FCB4D1ULL,
		0x926571583EC0B1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B396D9D9988B540ULL,
		0x3E4D3FD1C5E16911ULL,
		0x8BC880FCFF969A31ULL,
		0x4CAE2B07D8163D71ULL,
		0x0000000000000012ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B02B641CDFD6212ULL,
		0x7286E4785B1134E4ULL,
		0xD3685E17251FC89BULL,
		0xE44BFD01B0CAD510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x20E6FEB109000000ULL,
		0x3C2D889A724D815BULL,
		0x0B928FE44DB94372ULL,
		0x80D8656A8869B42FULL,
		0x00000000007225FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x57555E4703070610ULL,
		0x77278AFFDE4ACFFCULL,
		0xAE39D424276158DEULL,
		0x340CAA04F63FE1D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE470307061000000ULL,
		0xAFFDE4ACFFC57555ULL,
		0x424276158DE77278ULL,
		0xA04F63FE1D5AE39DULL,
		0x00000000000340CAULL,
		0x0000000000000000ULL
	}};
	shift = 108;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8A479DC21A1E81EBULL,
		0x2FDFC3E8D4E69ED3ULL,
		0x67525EE654697594ULL,
		0x1222CF73E6AE6C3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A07AC0000000000ULL,
		0x9A7B4E291E770868ULL,
		0xA5D650BF7F0FA353ULL,
		0xB9B0F19D497B9951ULL,
		0x000000488B3DCF9AULL
	}};
	shift = 22;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB21F597A6C20E83AULL,
		0xB21C9481E1595A67ULL,
		0x460679FE78DF28D1ULL,
		0x6DD2AF2E1F8FA9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x87D65E9B083A0E80ULL,
		0x87252078565699ECULL,
		0x819E7F9E37CA346CULL,
		0x74ABCB87E3EA7811ULL,
		0x000000000000001BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC2526AE5C3711010ULL,
		0xB4C18E84560C1227ULL,
		0xD7A46661463531A2ULL,
		0x216151C299459097ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x572E1B8880800000ULL,
		0x7422B060913E1293ULL,
		0x330A31A98D15A60CULL,
		0x8E14CA2C84BEBD23ULL,
		0x0000000000010B0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x586A948011A07383ULL,
		0x3A1D5802E8DCA729ULL,
		0x192A6E538C35B06CULL,
		0xEAD8D100AC47F22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD039C18000000000ULL,
		0x6E5394AC354A4008ULL,
		0x1AD8361D0EAC0174ULL,
		0x23F9170C953729C6ULL,
		0x000000756C688056ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x229D9B65851044F0ULL,
		0xE11A94C60DB8940EULL,
		0xFD14F87E4245EB89ULL,
		0xB01429987604A70AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14ECDB2C28822780ULL,
		0x08D4A6306DC4A071ULL,
		0xE8A7C3F2122F5C4FULL,
		0x80A14CC3B0253857ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x68259466E24E5406ULL,
		0x7A2E22EF607728DDULL,
		0xB39F6FCB4166BF64ULL,
		0x5C0CD6C0289C49F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x412CA3371272A030ULL,
		0xD171177B03B946EBULL,
		0x9CFB7E5A0B35FB23ULL,
		0xE066B60144E24FA5ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x879BF9C0C3875A09ULL,
		0x34C9E5A36E255B62ULL,
		0x1CD0260BF24FE33EULL,
		0x43C87DCB4E0757CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F381870EB41200ULL,
		0x93CB46DC4AB6C50FULL,
		0xA04C17E49FC67C69ULL,
		0x90FB969C0EAF9439ULL,
		0x0000000000000087ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB6C2570AD6A461CULL,
		0x4EA3187A32CB9E3DULL,
		0x4AF5FDD167383209ULL,
		0xCF3D6731C7266274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x48C3800000000000ULL,
		0x73C7B96D84AE15ADULL,
		0x064129D4630F4659ULL,
		0xCC4E895EBFBA2CE7ULL,
		0x000019E7ACE638E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE5764111A2FECC5ULL,
		0x5B692208EFF15043ULL,
		0x2A691A7B13A90F13ULL,
		0x97DEAF2972F13FC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCC50000000000000ULL,
		0x043EE5764111A2FEULL,
		0xF135B692208EFF15ULL,
		0xFC82A691A7B13A90ULL,
		0x00097DEAF2972F13ULL
	}};
	shift = 12;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x051914DE33C6531DULL,
		0x5AA4BABD6C92B268ULL,
		0x68576AB6B7B3E423ULL,
		0x21A957D566D61746ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19E3298E80000000ULL,
		0xB6495934028C8A6FULL,
		0x5BD9F211AD525D5EULL,
		0xB36B0BA3342BB55BULL,
		0x0000000010D4ABEAULL
	}};
	shift = 33;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF394E807581CCA08ULL,
		0xE7E5E61F33E2D2CAULL,
		0xCAAB4203E37ECE4DULL,
		0x49091B36EC47FE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCE53A01D6073282ULL,
		0x79F97987CCF8B4B2ULL,
		0x72AAD080F8DFB393ULL,
		0x124246CDBB11FF8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0BA81F84E05E760ULL,
		0xC27C5EF714B38664ULL,
		0x30AACB0E2D3E6461ULL,
		0xFBE4277DB8AB713AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x503F09C0BCEC0000ULL,
		0x8BDEE29670CC9C17ULL,
		0x5961C5A7CC8C384FULL,
		0x84EFB7156E274615ULL,
		0x0000000000001F7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE475D13BBA1869BULL,
		0x04A9FD265B522BAFULL,
		0x295CB6C319EDDBBFULL,
		0x5D07C3FC05C52C3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE89DDD0C34D8000ULL,
		0xFE932DA915D7D723ULL,
		0x5B618CF6EDDF8254ULL,
		0xE1FE02E2961E94AEULL,
		0x0000000000002E83ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81C949948476C34BULL,
		0x5B587CD12D98ABE2ULL,
		0x2D84981E1A34DF53ULL,
		0xFAFF9CD24F41CF77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8476C34B00000000ULL,
		0x2D98ABE281C94994ULL,
		0x1A34DF535B587CD1ULL,
		0x4F41CF772D84981EULL,
		0x00000000FAFF9CD2ULL
	}};
	shift = 32;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42042E83828742AAULL,
		0x7FF08C1CB58BE6E6ULL,
		0x355B93658E98708EULL,
		0xADD50E3B8A3EC120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1550000000000000ULL,
		0x37321021741C143AULL,
		0x8473FF8460E5AC5FULL,
		0x0901AADC9B2C74C3ULL,
		0x00056EA871DC51F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA76875FEED01322DULL,
		0x292EF9338773062BULL,
		0x07154E360B83E2E4ULL,
		0xECA358D5DE28E83EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1D7FBB404C8B400ULL,
		0xBBE4CE1DCC18AE9DULL,
		0x5538D82E0F8B90A4ULL,
		0x8D635778A3A0F81CULL,
		0x00000000000003B2ULL
	}};
	shift = 54;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F89F8EAD04410ACULL,
		0xC77BE12668AA81D0ULL,
		0xCF66180376BD9810ULL,
		0x2571F5257A57DB24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0856000000000000ULL,
		0x40E837C4FC756822ULL,
		0xCC0863BDF0933455ULL,
		0xED9267B30C01BB5EULL,
		0x000012B8FA92BD2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA5C8E64807863E0ULL,
		0x60C05961F1D310ECULL,
		0x76EBF779112E3A85ULL,
		0x8E27B549434A046AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x807863E000000000ULL,
		0xF1D310ECCA5C8E64ULL,
		0x112E3A8560C05961ULL,
		0x434A046A76EBF779ULL,
		0x000000008E27B549ULL
	}};
	shift = 32;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3E2CE900050DE469ULL,
		0x4B1F9564532B2507ULL,
		0x0613725BB2D44D03ULL,
		0x43980525AD2FEDE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0050DE4690000000ULL,
		0x4532B25073E2CE90ULL,
		0xBB2D44D034B1F956ULL,
		0x5AD2FEDE30613725ULL,
		0x0000000004398052ULL
	}};
	shift = 36;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB018DB0F33240AAAULL,
		0x23148AB0DBC90060ULL,
		0x702A1526DA120AF6ULL,
		0xC39D6379F5AD8665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33240AAA00000000ULL,
		0xDBC90060B018DB0FULL,
		0xDA120AF623148AB0ULL,
		0xF5AD8665702A1526ULL,
		0x00000000C39D6379ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDAC6F130D67A9165ULL,
		0x6A3CDEC95DB9BA0BULL,
		0x10868E1845BF4EE0ULL,
		0xDE6E16960FD57834ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA00000000000000ULL,
		0x17B58DE261ACF522ULL,
		0xC0D479BD92BB7374ULL,
		0x68210D1C308B7E9DULL,
		0x01BCDC2D2C1FAAF0ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BDF6CE9A7C7A078ULL,
		0x9C7B7854E48FD076ULL,
		0x7C1785206D33C88EULL,
		0x08A83B3D52670779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x74D3E3D03C000000ULL,
		0x2A7247E83B4DEFB6ULL,
		0x903699E4474E3DBCULL,
		0x9EA93383BCBE0BC2ULL,
		0x000000000004541DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDC3D804DF5746FD7ULL,
		0x6FBAB62522D1285BULL,
		0xA45BE36B346D1277ULL,
		0x1B7513F5B1283A27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0137D5D1BF5C0000ULL,
		0xD8948B44A16F70F6ULL,
		0x8DACD1B449DDBEEAULL,
		0x4FD6C4A0E89E916FULL,
		0x0000000000006DD4ULL
	}};
	shift = 46;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C8C3E0DA0E3A41BULL,
		0x8C84068FBA138431ULL,
		0xACFC242BF1E772CCULL,
		0x0BE53ADB2C99A606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC000000000000000ULL,
		0x43230F836838E906ULL,
		0x232101A3EE84E10CULL,
		0xAB3F090AFC79DCB3ULL,
		0x02F94EB6CB266981ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53C84B6A6F03563FULL,
		0x09EF3B6B7D34592BULL,
		0x18D592E564D175ADULL,
		0x1FB8266B0A708D52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x425B53781AB1F800ULL,
		0x79DB5BE9A2C95A9EULL,
		0xAC972B268BAD684FULL,
		0xC1335853846A90C6ULL,
		0x00000000000000FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D8E1C97B2BBC15BULL,
		0xD931E97BAEB32D8EULL,
		0xA770DC058AEC0707ULL,
		0x4087475EF834DAAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5DE0AD8000000000ULL,
		0x5996C706C70E4BD9ULL,
		0x760383EC98F4BDD7ULL,
		0x1A6D57D3B86E02C5ULL,
		0x0000002043A3AF7CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE4AB320FBC4D94FFULL,
		0x00EF7E6379413753ULL,
		0x5A72CDB28D93A98AULL,
		0x836ED18E3C364079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA7F800000000000ULL,
		0x9BA9F2559907DE26ULL,
		0xD4C50077BF31BCA0ULL,
		0x203CAD3966D946C9ULL,
		0x000041B768C71E1BULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65D432A7444454A3ULL,
		0x957143A3E352C542ULL,
		0x08C0592A5657D2D5ULL,
		0xACD7FA1B0AED0287ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x4CBA8654E8888A94ULL,
		0xB2AE28747C6A58A8ULL,
		0xE1180B254ACAFA5AULL,
		0x159AFF43615DA050ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDF76A3AD2131133ULL,
		0x38C696474C3C063AULL,
		0x5CA35EB99F8846E5ULL,
		0xBDB6D0310B68F9F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDA8EB484C44CC00ULL,
		0x1A591D30F018EB77ULL,
		0x8D7AE67E211B94E3ULL,
		0xDB40C42DA3E7D972ULL,
		0x00000000000002F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 246;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x537140678EB084B9ULL,
		0x44D025F043BF60B4ULL,
		0xBA69B97BE021DA43ULL,
		0x85AA6142C20814DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6109720000000000ULL,
		0x7EC168A6E280CF1DULL,
		0x43B48689A04BE087ULL,
		0x1029B574D372F7C0ULL,
		0x0000010B54C28584ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA44C28867BA2A724ULL,
		0x244F4F07D2788974ULL,
		0x5A8A67F69A8C3A28ULL,
		0x2D373E0AB2669808ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7240000000000000ULL,
		0x974A44C28867BA2AULL,
		0xA28244F4F07D2788ULL,
		0x8085A8A67F69A8C3ULL,
		0x0002D373E0AB2669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFA30650C1FACA0CULL,
		0x9F6A1E75F8A2B5F6ULL,
		0xCB220D953FC035F8ULL,
		0x56DFFE0781F4308DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xACA0C00000000000ULL,
		0x2B5F6AFA30650C1FULL,
		0x035F89F6A1E75F8AULL,
		0x4308DCB220D953FCULL,
		0x0000056DFFE0781FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x14A093E35ED5667FULL,
		0x1B01019EB29D6A17ULL,
		0xF2640CE9DDA01718ULL,
		0x6C6D0FF91B402CBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAACCFE0000000000ULL,
		0x3AD42E294127C6BDULL,
		0x402E303602033D65ULL,
		0x80597FE4C819D3BBULL,
		0x000000D8DA1FF236ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD4B7463D8454828ULL,
		0xD3FE79D11E229ECEULL,
		0x88987CC7A34E2B59ULL,
		0x26E7B3C5AEEC1368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x463D845482800000ULL,
		0x9D11E229ECEDD4B7ULL,
		0xCC7A34E2B59D3FE7ULL,
		0x3C5AEEC136888987ULL,
		0x0000000000026E7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1949FA54E05FB6D0ULL,
		0x7062B41B50822ECBULL,
		0x79D68F8ED6E12A39ULL,
		0xAABB817852C45079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x702FDB6800000000ULL,
		0xA84117658CA4FD2AULL,
		0x6B70951CB8315A0DULL,
		0x2962283CBCEB47C7ULL,
		0x00000000555DC0BCULL
	}};
	shift = 33;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x58B519E37E28E601ULL,
		0xF55A47489174F74FULL,
		0x0DB84964C05475CAULL,
		0xCE515CBC29CA2CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3980400000000000ULL,
		0x3DD3D62D4678DF8AULL,
		0x1D72BD5691D2245DULL,
		0x8B3EC36E12593015ULL,
		0x00003394572F0A72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC7BA79F2132440AEULL,
		0xCD61E1E27E3B0A0AULL,
		0x56E058F4624C214DULL,
		0xD405BBCF8717626CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BA79F2132440AE0ULL,
		0xD61E1E27E3B0A0ACULL,
		0x6E058F4624C214DCULL,
		0x405BBCF8717626C5ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x52AF5D27260F3C8EULL,
		0x7C48EF5860D0EE4AULL,
		0xA6A5A97926399CF5ULL,
		0x8E957CD2298A459DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x91C0000000000000ULL,
		0xC94A55EBA4E4C1E7ULL,
		0x9EAF891DEB0C1A1DULL,
		0xB3B4D4B52F24C733ULL,
		0x0011D2AF9A453148ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3ED3A62FF7D0A9A0ULL,
		0x60E4D13325F3FAC3ULL,
		0xEC76F274490D1553ULL,
		0x1F9C4F0BFEC24108ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFDF42A6800000000ULL,
		0xC97CFEB0CFB4E98BULL,
		0x12434554D839344CULL,
		0xFFB090423B1DBC9DULL,
		0x0000000007E713C2ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0C03787AFA29EC7ULL,
		0x2A34A452EA9A2F1DULL,
		0xAE861DD2F19359F1ULL,
		0x3769C58CBD59DBBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5F453D8E00000000ULL,
		0xD5345E3BE1806F0FULL,
		0xE326B3E2546948A5ULL,
		0x7AB3B7775D0C3BA5ULL,
		0x000000006ED38B19ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C088FE2BFAB5FDBULL,
		0xA365906174027D7AULL,
		0xFE795F45EC3AD270ULL,
		0xF444AE7DC47B152FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF8AFEAD7F6C00000ULL,
		0x185D009F5E8B0223ULL,
		0xD17B0EB49C28D964ULL,
		0x9F711EC54BFF9E57ULL,
		0x00000000003D112BULL
	}};
	shift = 42;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D265CDF065FDA51ULL,
		0xD258113AAD779D5DULL,
		0xC26276EBC759BEEFULL,
		0x3305C9B67048843DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CDF065FDA510000ULL,
		0x113AAD779D5D7D26ULL,
		0x76EBC759BEEFD258ULL,
		0xC9B67048843DC262ULL,
		0x0000000000003305ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x49B899EDB38B3C54ULL,
		0x2761C92B8CA68FEAULL,
		0xE3A58400160C2477ULL,
		0x1C6771B00A33719FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0x524DC4CF6D9C59E2ULL,
		0xB93B0E495C65347FULL,
		0xFF1D2C2000B06123ULL,
		0x00E33B8D80519B8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5AD2667FB2CA2119ULL,
		0xCB42DF8849C834EBULL,
		0x74F46C1EA241A4BCULL,
		0x4FC553A1A813F4D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4423200000000000ULL,
		0x069D6B5A4CCFF659ULL,
		0x349799685BF10939ULL,
		0x7E9A6E9E8D83D448ULL,
		0x000009F8AA743502ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD8690E6C52B3CF27ULL,
		0x69FDAB28D7E62B5CULL,
		0x856379B4B74B044EULL,
		0xB8F036346897D081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA439B14ACF3C9C00ULL,
		0xF6ACA35F98AD7361ULL,
		0x8DE6D2DD2C1139A7ULL,
		0xC0D8D1A25F420615ULL,
		0x00000000000002E3ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC062B6B3543574B5ULL,
		0x0337039C2356115CULL,
		0xBCC457AD20C810D4ULL,
		0xEBD90CD0C58DF56AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B50000000000000ULL,
		0x15CC062B6B354357ULL,
		0x0D40337039C23561ULL,
		0x56ABCC457AD20C81ULL,
		0x000EBD90CD0C58DFULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D5D2A5BFC6E6E20ULL,
		0xA7E8E1D70280DAA4ULL,
		0x52528EB7DBBE1A86ULL,
		0x1AF8DD32C5CF94CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03574A96FF1B9B88ULL,
		0xA9FA3875C0A036A9ULL,
		0x1494A3ADF6EF86A1ULL,
		0x06BE374CB173E533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA3D76C93C36016FULL,
		0x774E6B95397784CBULL,
		0xACD8D7B322E17194ULL,
		0xEA95AF9065104415ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7800000000000000ULL,
		0x5ED1EBB649E1B00BULL,
		0xA3BA735CA9CBBC26ULL,
		0xAD66C6BD99170B8CULL,
		0x0754AD7C83288220ULL
	}};
	shift = 5;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A46B3015528FB5FULL,
		0x87E038A4A875327EULL,
		0x88A3D2D9E2389E96ULL,
		0xABFAAAD3B3E2A75AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xC948D6602AA51F6BULL,
		0xD0FC0714950EA64FULL,
		0x51147A5B3C4713D2ULL,
		0x157F555A767C54EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33512A735BB30E03ULL,
		0xDBD9BC6A70BBC190ULL,
		0x9944A59E3B9555A2ULL,
		0xBB28A16C2590F8EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x380C000000000000ULL,
		0x0640CD44A9CD6ECCULL,
		0x568B6F66F1A9C2EFULL,
		0xE3AE65129678EE55ULL,
		0x0002ECA285B09643ULL
	}};
	shift = 14;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9745625462377EADULL,
		0x8CDD2B1EB1431929ULL,
		0x1EF0AA9E493360FFULL,
		0x8F4800678BA5BFEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B12A311BBF56800ULL,
		0xE958F58A18C94CBAULL,
		0x8554F2499B07FC66ULL,
		0x40033C5D2DFF70F7ULL,
		0x000000000000047AULL,
		0x0000000000000000ULL
	}};
	shift = 117;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x01AB4CC3AA80FBBCULL,
		0xD555E7A445FE2990ULL,
		0xC37FCA88014343AEULL,
		0xD6CA4D6B130BF784ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA80FBBC000000000ULL,
		0x5FE299001AB4CC3AULL,
		0x14343AED555E7A44ULL,
		0x30BF784C37FCA880ULL,
		0x0000000D6CA4D6B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 220;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3768A19164F4B73ULL,
		0x7DCD6DDAF771817DULL,
		0xA0CD6F75FA462BC7ULL,
		0x58B5653CE037334AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50C8B27A5B980000ULL,
		0x6ED7BB8C0BEE9BB4ULL,
		0x7BAFD2315E3BEE6BULL,
		0x29E701B99A55066BULL,
		0x000000000002C5ABULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x70D14F33C960A7F4ULL,
		0xBA1C5948C4351583ULL,
		0xC041BE61F7B687F9ULL,
		0x0A2E9EB72910E63DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF33C960A7F400000ULL,
		0x948C435158370D14ULL,
		0xE61F7B687F9BA1C5ULL,
		0xEB72910E63DC041BULL,
		0x000000000000A2E9ULL
	}};
	shift = 44;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3DAD1A198245FF42ULL,
		0x598DE21718CA2DF0ULL,
		0x1C48CD430320845CULL,
		0x11963BC791FC1905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x198245FF42000000ULL,
		0x1718CA2DF03DAD1AULL,
		0x430320845C598DE2ULL,
		0xC791FC19051C48CDULL,
		0x000000000011963BULL
	}};
	shift = 40;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1CF8D8A602BE1548ULL,
		0x6601C7E91D1688CAULL,
		0x8D228FE4B33C096EULL,
		0x6F2C854FBE7852DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x50E7C6C53015F0AAULL,
		0x73300E3F48E8B446ULL,
		0xFC69147F2599E04BULL,
		0x0379642A7DF3C296ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD48980D97E22BA29ULL,
		0x6A24AC4804AE8681ULL,
		0x12FF662A0482D0D3ULL,
		0xDBDCCF696DE5F207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C06CBF115D14800ULL,
		0x2562402574340EA4ULL,
		0xFB31502416869B51ULL,
		0xE67B4B6F2F903897ULL,
		0x00000000000006DEULL
	}};
	shift = 53;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x82B0ACEF5FF0F3A3ULL,
		0x98A0036186414495ULL,
		0x98D421BD8988E6B3ULL,
		0xCAC350526193BE56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF5FF0F3A3000000ULL,
		0x618641449582B0ACULL,
		0xBD8988E6B398A003ULL,
		0x526193BE5698D421ULL,
		0x0000000000CAC350ULL
	}};
	shift = 40;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6444778E19E69408ULL,
		0xA6B234D79B6DCBB4ULL,
		0xF561D6FA098C8BE4ULL,
		0x37FBEFDCD6B047B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C888EF1C33CD281ULL,
		0x94D6469AF36DB976ULL,
		0x1EAC3ADF4131917CULL,
		0x06FF7DFB9AD608F7ULL
	}};
	shift = 3;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x97F5BDEB76AB94A5ULL,
		0x0BFDB923C8D0C3E9ULL,
		0x21F706E26F98B4B4ULL,
		0x19AFF25AF45F7D84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDEF5BB55CA528000ULL,
		0xDC91E46861F4CBFAULL,
		0x837137CC5A5A05FEULL,
		0xF92D7A2FBEC210FBULL,
		0x0000000000000CD7ULL
	}};
	shift = 49;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F4DB46EF4286A3FULL,
		0xED0C190AB9289786ULL,
		0xEA8DA4A37BED9FF1ULL,
		0x3E57318A6A3C6E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F00000000000000ULL,
		0x863F4DB46EF4286AULL,
		0xF1ED0C190AB92897ULL,
		0x83EA8DA4A37BED9FULL,
		0x003E57318A6A3C6EULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD96B45BC86B34A8BULL,
		0x30BD8EBCFF9CF9F4ULL,
		0x184D06310967B886ULL,
		0x722FD42CB2F09CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B34A8B000000000ULL,
		0xF9CF9F4D96B45BC8ULL,
		0x967B88630BD8EBCFULL,
		0x2F09CD4184D06310ULL,
		0x0000000722FD42CBULL
	}};
	shift = 28;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x344B9A2971C484BFULL,
		0xA364908D567228BCULL,
		0xC99CC1AF32E2A724ULL,
		0xB34DF0DEB13B32B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89097E0000000000ULL,
		0xE4517868973452E3ULL,
		0xC54E4946C9211AACULL,
		0x76656B9339835E65ULL,
		0x000001669BE1BD62ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x322F56FF2D8427FCULL,
		0xB07C235BB882DE1BULL,
		0x49F26DEDCE0640EBULL,
		0xD785D0A94DA54B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27FC000000000000ULL,
		0xDE1B322F56FF2D84ULL,
		0x40EBB07C235BB882ULL,
		0x4B4649F26DEDCE06ULL,
		0x0000D785D0A94DA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x499B4964FF74BDA1ULL,
		0x4339B1F1FEF364ABULL,
		0x2EBAD9DB7C87E45AULL,
		0xDD5C476FC857808DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xD266D2593FDD2F68ULL,
		0x90CE6C7C7FBCD92AULL,
		0x4BAEB676DF21F916ULL,
		0x375711DBF215E023ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4633DDF629BFE629ULL,
		0xEF673575110BF41EULL,
		0x05F2BA66D95C2441ULL,
		0xF1F0788048CC596CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE629000000000000ULL,
		0xF41E4633DDF629BFULL,
		0x2441EF673575110BULL,
		0x596C05F2BA66D95CULL,
		0x0000F1F0788048CCULL
	}};
	shift = 16;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99415A1558B55C9EULL,
		0xEA5176010CD2E226ULL,
		0xEA714EBCBCAD6F1CULL,
		0xCC05DBF5477EAE32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AB16AB93C000000ULL,
		0x0219A5C44D3282B4ULL,
		0x79795ADE39D4A2ECULL,
		0xEA8EFD5C65D4E29DULL,
		0x0000000001980BB7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9D6373289A34DAC8ULL,
		0x25E0D995551BB98DULL,
		0xF81E55C9D36053A0ULL,
		0x495039B8CA1B1193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A34DAC80000000ULL,
		0x5551BB98D9D63732ULL,
		0x9D36053A025E0D99ULL,
		0x8CA1B1193F81E55CULL,
		0x000000000495039BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x930546FA2ED2EFE9ULL,
		0xC55C1545CB3C5109ULL,
		0x4D8700EA4C030A2DULL,
		0xB11730F6C589743BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA2ED2EFE9000000ULL,
		0x45CB3C5109930546ULL,
		0xEA4C030A2DC55C15ULL,
		0xF6C589743B4D8700ULL,
		0x0000000000B11730ULL
	}};
	shift = 40;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x796A5794B20F64F3ULL,
		0xAF771C7C2F48C401ULL,
		0xDBA8D99AC22021EDULL,
		0x3DBFA357CEE3D2F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCA5907B279800000ULL,
		0x3E17A46200BCB52BULL,
		0xCD611010F6D7BB8EULL,
		0xABE771E979EDD46CULL,
		0x00000000001EDFD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x417F0CDE2DFB265FULL,
		0x290D012B53B7B560ULL,
		0xCC061A8C171EF599ULL,
		0xE9BF646838F70CEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6F16FD932F800000ULL,
		0x95A9DBDAB020BF86ULL,
		0x460B8F7ACC948680ULL,
		0x341C7B867566030DULL,
		0x000000000074DFB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C5655E1B9DD5119ULL,
		0x41C46A2E866B2444ULL,
		0x2833617CBC1F87EBULL,
		0x079B0196CCC2A230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA88C80000000000ULL,
		0x592222E2B2AF0DCEULL,
		0xFC3F5A0E23517433ULL,
		0x151181419B0BE5E0ULL,
		0x0000003CD80CB666ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x833B5502535D4B9EULL,
		0xB70F04BEF4393EEBULL,
		0xE8036B76B88B906DULL,
		0xCC2E49B5ED719CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0x5C19DAA8129AEA5CULL,
		0x6DB87825F7A1C9F7ULL,
		0x47401B5BB5C45C83ULL,
		0x0661724DAF6B8CE5ULL
	}};
	shift = 5;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6FD6F5EDD33C25E5ULL,
		0xE1ADABCA65DEDBB9ULL,
		0xFB4B075289220BDAULL,
		0x5CF61D706913CB8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCA0000000000000ULL,
		0x772DFADEBDBA6784ULL,
		0x7B5C35B5794CBBDBULL,
		0x715F6960EA512441ULL,
		0x000B9EC3AE0D2279ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9AF43078086598EULL,
		0xF65576581623C11EULL,
		0x5CC77A68A779406CULL,
		0x9E8CF282B284A7E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F010CB31C000000ULL,
		0xB02C47823D535E86ULL,
		0xD14EF280D9ECAAECULL,
		0x0565094FCEB98EF4ULL,
		0x00000000013D19E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5E68ACCFF3A704EBULL,
		0x4C29FF53D72CB52BULL,
		0x8DEA750BF8763CD5ULL,
		0x0293F7A8C278BD08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xACCFF3A704EB0000ULL,
		0xFF53D72CB52B5E68ULL,
		0x750BF8763CD54C29ULL,
		0xF7A8C278BD088DEAULL,
		0x0000000000000293ULL
	}};
	shift = 48;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1966747DE415930ULL,
		0x80D6243A72B2754EULL,
		0x15001380501E840BULL,
		0xBF0B74D3C79E4AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0AC9800000000000ULL,
		0x93AA778CB33A3EF2ULL,
		0xF4205C06B121D395ULL,
		0xF25598A8009C0280ULL,
		0x000005F85BA69E3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8486434A8D0DE117ULL,
		0xB8DBD412DF753948ULL,
		0xF362CCC184665F94ULL,
		0x9ECE67A1792F3930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0DE117000000000ULL,
		0xF7539488486434A8ULL,
		0x4665F94B8DBD412DULL,
		0x92F3930F362CCC18ULL,
		0x00000009ECE67A17ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C8D1107344614D7ULL,
		0x2E530A4BB3390670ULL,
		0x4025B1FD3286F0DAULL,
		0xEDA605830824ABE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x230A6B8000000000ULL,
		0x9C83382E4688839AULL,
		0x43786D17298525D9ULL,
		0x1255F2A012D8FE99ULL,
		0x00000076D302C184ULL
	}};
	shift = 25;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAA1DA52A13149A5EULL,
		0x33570D2B83940E2EULL,
		0xA455623962A9B2B5ULL,
		0x7776631913C36CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED295098A4D2F000ULL,
		0xB8695C1CA0717550ULL,
		0xAB11CB154D95A99AULL,
		0xB318C89E1B657D22ULL,
		0x00000000000003BBULL
	}};
	shift = 53;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6958C98A087D121ULL,
		0x3DE83BC4B16EA037ULL,
		0xA4FE871CC607CAE1ULL,
		0xAAD20F9BA5D14E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x821F448400000000ULL,
		0xC5BA80DFDA563262ULL,
		0x181F2B84F7A0EF12ULL,
		0x9745392E93FA1C73ULL,
		0x00000002AB483E6EULL
	}};
	shift = 30;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0907B6DBB27A6C13ULL,
		0x53C0B6A7AE9DC0F4ULL,
		0x9C1210E010C77BF7ULL,
		0x76469D0326BF8BD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x8120F6DB764F4D82ULL,
		0xEA7816D4F5D3B81EULL,
		0x3382421C0218EF7EULL,
		0x0EC8D3A064D7F17AULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x142DF7CAD928EEDFULL,
		0x4D2C2C7224CFB5F1ULL,
		0xAFE4885A75100407ULL,
		0xC843E0381D02796FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C94776F80000000ULL,
		0x1267DAF88A16FBE5ULL,
		0x3A880203A6961639ULL,
		0x0E813CB7D7F2442DULL,
		0x000000006421F01CULL
	}};
	shift = 33;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCB1827477EDCD058ULL,
		0x31BEFEE5420A3EF3ULL,
		0x1C6F8C4DB6468650ULL,
		0xF4D361E88611107AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1DFB734160000000ULL,
		0x950828FBCF2C609DULL,
		0x36D91A1940C6FBFBULL,
		0xA2184441E871BE31ULL,
		0x0000000003D34D87ULL
	}};
	shift = 38;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDCDE48C6EC22693CULL,
		0xAFA0BF95B366AC3FULL,
		0xA578009C5A709550ULL,
		0x339FBC02B78DD378ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7379231BB089A4F0ULL,
		0xBE82FE56CD9AB0FFULL,
		0x95E0027169C25542ULL,
		0xCE7EF00ADE374DE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1B807BCBAA2EBC8ULL,
		0xA6F61B43F60DC884ULL,
		0x5DD779CB97CE51F1ULL,
		0x707FB7FD95BF1098ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3700F797545D7900ULL,
		0xDEC3687EC1B91094ULL,
		0xBAEF3972F9CA3E34ULL,
		0x0FF6FFB2B7E2130BULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8DC60680448B94EFULL,
		0x92A00E06448338CDULL,
		0xC1F99DD5237071FCULL,
		0x9491DA8414644C64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8DC60680448B94EFULL,
		0x92A00E06448338CDULL,
		0xC1F99DD5237071FCULL,
		0x9491DA8414644C64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x15FD25D76A1D877EULL,
		0xA8868FA1EE6EEACFULL,
		0x8830BD01C54EDFB2ULL,
		0x17E24CEE54D7F199ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD43B0EFC00000000ULL,
		0xDCDDD59E2BFA4BAEULL,
		0x8A9DBF65510D1F43ULL,
		0xA9AFE33310617A03ULL,
		0x000000002FC499DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8BFB261408D4E66DULL,
		0xFA2311987742D5B5ULL,
		0xC0A116F64F0B24A1ULL,
		0xAE92CC1E8E473EBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8BFB261408D4E66DULL,
		0xFA2311987742D5B5ULL,
		0xC0A116F64F0B24A1ULL,
		0xAE92CC1E8E473EBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x42F7EE07F9723014ULL,
		0xE8A45FB9F21315F4ULL,
		0x73E298A0CF611C46ULL,
		0xF4BC1410ADFA9FABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFDC0FF2E46028000ULL,
		0x8BF73E4262BE885EULL,
		0x531419EC2388DD14ULL,
		0x828215BF53F56E7CULL,
		0x0000000000001E97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDACFAA92BC82798DULL,
		0x1BF9FC502C3F282DULL,
		0x4C050FFC89D4422AULL,
		0x34DF3B0DD1460380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x09E6340000000000ULL,
		0xFCA0B76B3EAA4AF2ULL,
		0x5108A86FE7F140B0ULL,
		0x180E0130143FF227ULL,
		0x000000D37CEC3745ULL
	}};
	shift = 22;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x654A793674446627ULL,
		0xB4DFF00697C064D5ULL,
		0xCBBCB3492435134AULL,
		0xA7CEBBFB2E5117D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4E00000000000000ULL,
		0xAACA94F26CE888CCULL,
		0x9569BFE00D2F80C9ULL,
		0xB197796692486A26ULL,
		0x014F9D77F65CA22FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x444C91C34AAA3001ULL,
		0xFC71359E8C0E49D2ULL,
		0x99A971AACA802B42ULL,
		0xA2651C6F6C555816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0x91132470D2AA8C00ULL,
		0xBF1C4D67A3039274ULL,
		0xA66A5C6AB2A00AD0ULL,
		0x2899471BDB155605ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x60D7AF3E6D80A7B8ULL,
		0x6696466A8D463A00ULL,
		0x96C38164E30994B2ULL,
		0x69AE72D57C92A525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x14F7000000000000ULL,
		0xC7400C1AF5E7CDB0ULL,
		0x32964CD2C8CD51A8ULL,
		0x54A4B2D8702C9C61ULL,
		0x00000D35CE5AAF92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x385839096404AEA9ULL,
		0xAEBC44C7B30CEBFAULL,
		0xF66EA48730AA7FBDULL,
		0xFF792425E15DF0B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4259012BAA40000ULL,
		0x131ECC33AFE8E160ULL,
		0x921CC2A9FEF6BAF1ULL,
		0x90978577C2D3D9BAULL,
		0x000000000003FDE4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 238;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF0215E6422C0908ULL,
		0xFE0162065D83F48FULL,
		0xFE94F9A633CEF3C2ULL,
		0x07A2AA2D6F271AFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF321160484000000ULL,
		0x032EC1FA47F7810AULL,
		0xD319E779E17F00B1ULL,
		0x16B7938D7DFF4A7CULL,
		0x000000000003D155ULL
	}};
	shift = 41;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x40231786600CC1C7ULL,
		0xA77494777FFA3224ULL,
		0x2CB55EFB30209DFAULL,
		0x749538C812442DB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x198033071C000000ULL,
		0xDDFFE8C891008C5EULL,
		0xECC08277EA9DD251ULL,
		0x204910B6C4B2D57BULL,
		0x0000000001D254E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38DF29425ABB7FD4ULL,
		0x9AF1521B72246966ULL,
		0xCD8AF477F91AEC94ULL,
		0x011BFA76652CF31CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFFA8000000000000ULL,
		0xD2CC71BE5284B576ULL,
		0xD92935E2A436E448ULL,
		0xE6399B15E8EFF235ULL,
		0x00000237F4ECCA59ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3CE9B4FC2F141826ULL,
		0xF8469235349F788AULL,
		0x91D509950D5CB4AEULL,
		0xB547772491F75189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD3F0BC5060980000ULL,
		0x48D4D27DE228F3A6ULL,
		0x26543572D2BBE11AULL,
		0xDC9247DD46264754ULL,
		0x000000000002D51DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0B80B9038387D9CULL,
		0x3325B537FA4F8506ULL,
		0xBCA27D7113D06B39ULL,
		0x8A7D080F133D07F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E40E0E1F670000ULL,
		0x6D4DFE93E141A82EULL,
		0x9F5C44F41ACE4CC9ULL,
		0x4203C4CF41FCAF28ULL,
		0x000000000000229FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8321C00A7609EE8ULL,
		0x4890E5643FCA35FFULL,
		0x68B306E47BECF4C8ULL,
		0x4C849D01EAD7F6FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE800000000000000ULL,
		0xFFA8321C00A7609EULL,
		0xC84890E5643FCA35ULL,
		0xFD68B306E47BECF4ULL,
		0x004C849D01EAD7F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1E2D485B8109CE5ULL,
		0xA750AEAE9925B79AULL,
		0x146876C1732FA745ULL,
		0x4BFEAD59D74B6AFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2D485B8109CE5000ULL,
		0x0AEAE9925B79AF1EULL,
		0x876C1732FA745A75ULL,
		0xEAD59D74B6AFD146ULL,
		0x00000000000004BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x16B824DB36499811ULL,
		0x3E1E75C39497CAE3ULL,
		0xB181BB063DBA1B2CULL,
		0xE6553836097AE4A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3302200000000000ULL,
		0xF95C62D7049B66C9ULL,
		0x436587C3CEB87292ULL,
		0x5C94F6303760C7B7ULL,
		0x00001CCAA706C12FULL
	}};
	shift = 19;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9BA12A374DDFE7A0ULL,
		0x0B945A89778C688DULL,
		0xE358C7425CDF4195ULL,
		0x29CC7ED978D271A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDD377F9E80000000ULL,
		0x25DE31A2366E84A8ULL,
		0x09737D06542E516AULL,
		0x65E349C6A38D631DULL,
		0x0000000000A731FBULL
	}};
	shift = 38;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0790BC6797CE7A48ULL,
		0xA1BC65071F051289ULL,
		0x8124C9A5257CD99CULL,
		0x1A4228738646A3CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE7A480000000000ULL,
		0x0512890790BC6797ULL,
		0x7CD99CA1BC65071FULL,
		0x46A3CF8124C9A525ULL,
		0x0000001A42287386ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B9FA837AD56582FULL,
		0x389D33E3CAAFA0F9ULL,
		0x2BC2B88D4F61F044ULL,
		0x61F2EB4CC231EEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5CFD41BD6AB2C178ULL,
		0xC4E99F1E557D07CAULL,
		0x5E15C46A7B0F8221ULL,
		0x0F975A66118F7501ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x64349014913E1FBDULL,
		0xD9F3995FF5678C8DULL,
		0x1F77A8FFE4CEBBF0ULL,
		0x5DE854DF82D230ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80A489F0FDE80000ULL,
		0xCAFFAB3C646B21A4ULL,
		0x47FF2675DF86CF9CULL,
		0xA6FC16918760FBBDULL,
		0x000000000002EF42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 237;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD6A75D55D1F0AA4FULL,
		0x627CA334E654FEA9ULL,
		0x3F8B627D36EF9FDFULL,
		0x9B732F724E203895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAE8F855278000000ULL,
		0xA732A7F54EB53AEAULL,
		0xE9B77CFEFB13E519ULL,
		0x927101C4A9FC5B13ULL,
		0x0000000004DB997BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC0B88F7F27FC96B5ULL,
		0xE215EA992116E334ULL,
		0xE7F8BDAAF79199A2ULL,
		0x61452A269084BA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x96B5000000000000ULL,
		0xE334C0B88F7F27FCULL,
		0x99A2E215EA992116ULL,
		0xBA41E7F8BDAAF791ULL,
		0x000061452A269084ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x327769F66ADE3B4DULL,
		0x50CB3F58BE25987AULL,
		0xE69311618F46BAB2ULL,
		0x8CCB7B33AB6E8CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D9AB78ED3400000ULL,
		0xD62F89661E8C9DDAULL,
		0x5863D1AEAC9432CFULL,
		0xCCEADBA33579A4C4ULL,
		0x00000000002332DEULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x300E0021CE2A1E27ULL,
		0x7D81B416879DFE14ULL,
		0x9CCE1E8BCF70F995ULL,
		0xD18FF5E72B5532EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0E7150F138000000ULL,
		0xB43CEFF0A1807001ULL,
		0x5E7B87CCABEC0DA0ULL,
		0x395AA99774E670F4ULL,
		0x00000000068C7FAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0036BDBE7A963C7ULL,
		0x6253051C2FDDB9C8ULL,
		0xBD7616DEEE8B1C18ULL,
		0x5FF8479369C20236ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3800000000000000ULL,
		0x47801B5EDF3D4B1EULL,
		0xC3129828E17EEDCEULL,
		0xB5EBB0B6F77458E0ULL,
		0x02FFC23C9B4E1011ULL
	}};
	shift = 5;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x94430E0BFF730E53ULL,
		0x423F341B7AE423BFULL,
		0xFBC552912233778AULL,
		0x39D7F2671BDE72A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3000000000000000ULL,
		0xF94430E0BFF730E5ULL,
		0xA423F341B7AE423BULL,
		0x3FBC552912233778ULL,
		0x039D7F2671BDE72AULL
	}};
	shift = 4;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE31E3B94BFDBB660ULL,
		0xD01B49FB62B53E7CULL,
		0xAC9534D8B1719882ULL,
		0xD1FA5B2F436B82C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC78EE52FF6ED9800ULL,
		0x06D27ED8AD4F9F38ULL,
		0x254D362C5C6620B4ULL,
		0x7E96CBD0DAE0B1EBULL,
		0x0000000000000034ULL
	}};
	shift = 58;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA172BF69F0FDE770ULL,
		0x9E44B7B46A96A3C9ULL,
		0x7291F48B0A14A449ULL,
		0x2E89CB5F48078888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE77000000000000ULL,
		0x6A3C9A172BF69F0FULL,
		0x4A4499E44B7B46A9ULL,
		0x788887291F48B0A1ULL,
		0x000002E89CB5F480ULL
	}};
	shift = 20;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x694261752386C976ULL,
		0x88352A0B8654A8ADULL,
		0x3C8803D2D69D6A5BULL,
		0xA45C82451D245778ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x130BA91C364BB000ULL,
		0xA9505C32A5456B4AULL,
		0x401E96B4EB52DC41ULL,
		0xE41228E922BBC1E4ULL,
		0x0000000000000522ULL
	}};
	shift = 53;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3715BC71A6FAFA3BULL,
		0xF838520A13183F4BULL,
		0x0B2662154C4D3F61ULL,
		0x2B06B2AE1CEE6AB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFA3B00000000000ULL,
		0x83F4B3715BC71A6FULL,
		0xD3F61F838520A131ULL,
		0xE6AB40B2662154C4ULL,
		0x000002B06B2AE1CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 212;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A161778D72F281EULL,
		0x721F7A50D65D65E9ULL,
		0xD92CA9F5B6B85AD6ULL,
		0x7F91B72B2712D9FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6B97940F0000000ULL,
		0x86B2EB2F4A50B0BBULL,
		0xADB5C2D6B390FBD2ULL,
		0x593896CFF6C9654FULL,
		0x0000000003FC8DB9ULL
	}};
	shift = 37;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2911657859938816ULL,
		0x4C22F166C711FCF0ULL,
		0x627F430903B2EB44ULL,
		0xCB2538CF18B27572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF0B327102C000000ULL,
		0xCD8E23F9E05222CAULL,
		0x120765D6889845E2ULL,
		0x9E3164EAE4C4FE86ULL,
		0x0000000001964A71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B2EDCA5B722763AULL,
		0x5F3CCBE84C055D6AULL,
		0xDFF3F81869E780FDULL,
		0x37EE560E80039AC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB913B1D000000000ULL,
		0x602AEB505976E52DULL,
		0x4F3C07EAF9E65F42ULL,
		0x001CD62EFF9FC0C3ULL,
		0x00000001BF72B074ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2E39055CFAB3478ULL,
		0xFAC7C5AE42778A57ULL,
		0xF897543C88B6E4A2ULL,
		0x89DA65B458D018EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEACD1E0000000000ULL,
		0x9DE295F4B8E41573ULL,
		0x2DB928BEB1F16B90ULL,
		0x34063BBE25D50F22ULL,
		0x0000002276996D16ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x805C5461139B26E1ULL,
		0x4F54337A6D74190FULL,
		0x83A30A85B774D07EULL,
		0x14257AB62571F60FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB26E100000000000ULL,
		0x4190F805C5461139ULL,
		0x4D07E4F54337A6D7ULL,
		0x1F60F83A30A85B77ULL,
		0x0000014257AB6257ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D29A7A254594C9CULL,
		0x65B8332EB00A0711ULL,
		0xE7C53030BC86A169ULL,
		0x6D00B7360DF045F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA8B2993800000000ULL,
		0x60140E22DA534F44ULL,
		0x790D42D2CB70665DULL,
		0x1BE08BE7CF8A6061ULL,
		0x00000000DA016E6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E56419CE6CDF7E3ULL,
		0x2DA712B2AE3984F8ULL,
		0x3984DAF429E4AFD0ULL,
		0xB0940D52CF25348FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC600000000000000ULL,
		0xF0FCAC8339CD9BEFULL,
		0xA05B4E25655C7309ULL,
		0x1E7309B5E853C95FULL,
		0x0161281AA59E4A69ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x408085F605091E75ULL,
		0x5AA1916497B4E429ULL,
		0x588F55AABB1254EFULL,
		0xAA089C5BF85CAB05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE750000000000000ULL,
		0x429408085F605091ULL,
		0x4EF5AA1916497B4EULL,
		0xB05588F55AABB125ULL,
		0x000AA089C5BF85CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x87FA3C86BF803E3DULL,
		0x69B0CDFD8239F99FULL,
		0xA4F7A7F44BE71021ULL,
		0xC6871C74CBF8B9C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1E8000000000000ULL,
		0xCCFC3FD1E435FC01ULL,
		0x810B4D866FEC11CFULL,
		0xCE0527BD3FA25F38ULL,
		0x00063438E3A65FC5ULL
	}};
	shift = 13;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F2B3DBD443DE969ULL,
		0x3F3BFF2F64001001ULL,
		0x3B973F78B1F82B06ULL,
		0x33AD670C39C268F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x567B7A887BD2D200ULL,
		0x77FE5EC80020025EULL,
		0x2E7EF163F0560C7EULL,
		0x5ACE187384D1F277ULL,
		0x0000000000000067ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 247;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE97E7AC96E97C721ULL,
		0x018EB9165C46FDFEULL,
		0xB8CB4AFD65C6ECF7ULL,
		0xBF0DE9B8760935C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2F8E420000000000ULL,
		0x8DFBFDD2FCF592DDULL,
		0x8DD9EE031D722CB8ULL,
		0x126B8B719695FACBULL,
		0x0000017E1BD370ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD1B012D05B2BAA05ULL,
		0xD93E6270E9442F86ULL,
		0x4A9E55B36AE7789FULL,
		0x7C26798126CDB93CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEA81400000000000ULL,
		0x0BE1B46C04B416CAULL,
		0xDE27F64F989C3A51ULL,
		0x6E4F12A7956CDAB9ULL,
		0x00001F099E6049B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7AFEB0E0CE8F34EDULL,
		0x0B58C27D08BACCE5ULL,
		0xA6159541931EC96AULL,
		0x009F586DF68E436BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBFAC3833A3CD3B4ULL,
		0x2D6309F422EB3395ULL,
		0x985655064C7B25A8ULL,
		0x027D61B7DA390DAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8D02943D4F5037BCULL,
		0xD6DBA37A9008BCBBULL,
		0xC99FCB6655C5B851ULL,
		0x1C4447A01D88B118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD4F5037BC0000000ULL,
		0xA9008BCBB8D02943ULL,
		0x655C5B851D6DBA37ULL,
		0x01D88B118C99FCB6ULL,
		0x0000000001C4447AULL
	}};
	shift = 36;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3D017632B7F2CAAULL,
		0x47ACB9E15634E141ULL,
		0x68D7CCF7466FF677ULL,
		0x26840F6273B5BDB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5400000000000000ULL,
		0x83A7A02EC656FE59ULL,
		0xEE8F5973C2AC69C2ULL,
		0x6ED1AF99EE8CDFECULL,
		0x004D081EC4E76B7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26B37F7CA95502C9ULL,
		0x87D624BCC0EC1704ULL,
		0x98CE7B8F050BE4B0ULL,
		0xACDF20D936E9CC14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDFDF2A5540B24000ULL,
		0x892F303B05C109ACULL,
		0x9EE3C142F92C21F5ULL,
		0xC8364DBA73052633ULL,
		0x0000000000002B37ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD7CD6E32723693E4ULL,
		0xE057EA94FEEDCCD4ULL,
		0x06320915EBDBAD8FULL,
		0xC917A2597B924D01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4F90000000000000ULL,
		0x33535F35B8C9C8DAULL,
		0xB63F815FAA53FBB7ULL,
		0x340418C82457AF6EULL,
		0x0003245E8965EE49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D32B3DAF86545E5ULL,
		0xCCB365A3F9586A8BULL,
		0xD6A9A0D15A1A36C8ULL,
		0xCB6FC5A45EB1AA45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B3DAF86545E5000ULL,
		0x365A3F9586A8B3D3ULL,
		0x9A0D15A1A36C8CCBULL,
		0xFC5A45EB1AA45D6AULL,
		0x0000000000000CB6ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD6E31757031BF01ULL,
		0xB7606DA0275866A9ULL,
		0xB419A8BEBAD83C5BULL,
		0x9BA7C07F1A44A8AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB718BAB818DF8080ULL,
		0xB036D013AC3354DEULL,
		0x0CD45F5D6C1E2DDBULL,
		0xD3E03F8D2254555AULL,
		0x000000000000004DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80A30A6B42051B74ULL,
		0x60F0CFB9BC8C84CEULL,
		0xA30AFC67B078903FULL,
		0x33AEAC0517D6271BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x08146DD000000000ULL,
		0xF232133A028C29ADULL,
		0xC1E240FD83C33EE6ULL,
		0x5F589C6E8C2BF19EULL,
		0x00000000CEBAB014ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 158;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xED9B0FBD076594D5ULL,
		0xCCCFDE0EA436E8C3ULL,
		0xF705B582CC83DA32ULL,
		0x62C555C93BE5FB2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66C3EF41D9653540ULL,
		0x33F783A90DBA30FBULL,
		0xC16D60B320F68CB3ULL,
		0xB155724EF97ECABDULL,
		0x0000000000000018ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 250;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBE8596261D096A4AULL,
		0x91CD3607EBEEA2EDULL,
		0xFC3A68B53F33335CULL,
		0xF9B4B0B3DB227F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF42CB130E84B525ULL,
		0x48E69B03F5F75176ULL,
		0xFE1D345A9F9999AEULL,
		0x7CDA5859ED913FB3ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5C12EF503D05AF9FULL,
		0xB15BE3F11D50EB91ULL,
		0xE9BFA8A89B77B905ULL,
		0xA5956D2C1001D47CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0977A81E82D7CF8ULL,
		0x8ADF1F88EA875C8AULL,
		0x4DFD4544DBBDC82DULL,
		0x2CAB6960800EA3E7ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x65424AA025873737ULL,
		0xE98D032752B8AD1FULL,
		0x65919AF5D3299223ULL,
		0x6645FD147A14F815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0xB2A1255012C39B9BULL,
		0xF4C68193A95C568FULL,
		0xB2C8CD7AE994C911ULL,
		0x3322FE8A3D0A7C0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9879BABF6AF90ADFULL,
		0x7981ED2D0AB323FBULL,
		0x411FF5B43413A277ULL,
		0x87BB2C5C24676533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3757ED5F215BE00ULL,
		0x03DA5A156647F730ULL,
		0x3FEB68682744EEF3ULL,
		0x7658B848CECA6682ULL,
		0x000000000000010FULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28C7EBACED4641E3ULL,
		0xFF4AEDDC74D300CCULL,
		0xF0782E60F533D084ULL,
		0x1CA324A4BDC19CFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBACED4641E30000ULL,
		0xEDDC74D300CC28C7ULL,
		0x2E60F533D084FF4AULL,
		0x24A4BDC19CFDF078ULL,
		0x0000000000001CA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 240;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x90E52DADC17579CAULL,
		0x27AF5847CA676149ULL,
		0x7A470B5811CE4768ULL,
		0xCD91DCDC2C39366EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0E52DADC17579CA0ULL,
		0x7AF5847CA6761499ULL,
		0xA470B5811CE47682ULL,
		0xD91DCDC2C39366E7ULL,
		0x000000000000000CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2F891A27B8723A9FULL,
		0x01F703A3AEF9A731ULL,
		0x293663469F191C8EULL,
		0xCE48E20BE9AC29D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D13DC391D4F8000ULL,
		0x81D1D77CD39897C4ULL,
		0x31A34F8C8E4700FBULL,
		0x7105F4D614E9949BULL,
		0x0000000000006724ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0F30A500169105CFULL,
		0xD51DACADC72FBA23ULL,
		0x3551EF05831A567FULL,
		0x123D20BDDDC0DFC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x05CF000000000000ULL,
		0xBA230F30A5001691ULL,
		0x567FD51DACADC72FULL,
		0xDFC83551EF05831AULL,
		0x0000123D20BDDDC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6ECD70D2DEC6E0FULL,
		0x003681BFB107C360ULL,
		0x22BAE685E3E1E011ULL,
		0x6A8F7E8C9A65C8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9AE1A5BD8DC1E0ULL,
		0x06D037F620F86C14ULL,
		0x575CD0BC7C3C0220ULL,
		0x51EFD1934CB91784ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x28860CDE0D13D904ULL,
		0x1640897C38D3F1C0ULL,
		0x3CBAD5C6EE1B9AECULL,
		0x093B66F4DC3A74BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9BC1A27B20800000ULL,
		0x2F871A7E380510C1ULL,
		0xB8DDC3735D82C811ULL,
		0xDE9B874E97A7975AULL,
		0x000000000001276CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E9BB227D0D1159BULL,
		0x52459AFEE50670C5ULL,
		0xBD8597D003B519F4ULL,
		0x59E23CDC775BDEB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B00000000000000ULL,
		0xC57E9BB227D0D115ULL,
		0xF452459AFEE50670ULL,
		0xB4BD8597D003B519ULL,
		0x0059E23CDC775BDEULL
	}};
	shift = 8;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB86FFFE52220180DULL,
		0x1D18D961523D72BEULL,
		0xD3B1647A051ADD68ULL,
		0x0F64DB5BB4639547ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4888060340000000ULL,
		0x548F5CAFAE1BFFF9ULL,
		0x8146B75A07463658ULL,
		0xED18E551F4EC591EULL,
		0x0000000003D936D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 162;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0297DAE0350E4D01ULL,
		0xD1FCAD36D6B44303ULL,
		0x25DC36E58DA9A880ULL,
		0x52322BEF4A9510BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBED701A872680800ULL,
		0xE569B6B5A2181814ULL,
		0xE1B72C6D4D44068FULL,
		0x915F7A54A885F92EULL,
		0x0000000000000291ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF18EAAD1A2E82900ULL,
		0xFFE62480B3D9E2AAULL,
		0x12CAFE9C3318AFE4ULL,
		0x4357480074C63748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD174148000000000ULL,
		0x59ECF15578C75568ULL,
		0x198C57F27FF31240ULL,
		0x3A631BA409657F4EULL,
		0x0000000021ABA400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4AB22EB0518D3246ULL,
		0x501BF561EBDD3A9AULL,
		0x22B1651693B867F8ULL,
		0x0841264A4D5CF3BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x175828C699230000ULL,
		0xFAB0F5EE9D4D2559ULL,
		0xB28B49DC33FC280DULL,
		0x932526AE79DD9158ULL,
		0x0000000000000420ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x344F685FDCE6053FULL,
		0x817E5C1D69B03FA5ULL,
		0x2AD7F84BF2F028A6ULL,
		0xAFF6FC0B004D520EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x685FDCE6053F0000ULL,
		0x5C1D69B03FA5344FULL,
		0xF84BF2F028A6817EULL,
		0xFC0B004D520E2AD7ULL,
		0x000000000000AFF6ULL
	}};
	shift = 48;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA1F22EDD3FBD186CULL,
		0x16B06E5AA3599E42ULL,
		0xFF0C4F1C1AAFEDAAULL,
		0x0F7A802C4322AD31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD3FBD186C0000000ULL,
		0xAA3599E42A1F22EDULL,
		0xC1AAFEDAA16B06E5ULL,
		0xC4322AD31FF0C4F1ULL,
		0x0000000000F7A802ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF03F6DFA3A3BF2A3ULL,
		0xD85ADB6514042378ULL,
		0xA70B7C3E5A732C51ULL,
		0xC84DBD774F16F2F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF951800000000000ULL,
		0x11BC781FB6FD1D1DULL,
		0x9628EC2D6DB28A02ULL,
		0x797CD385BE1F2D39ULL,
		0x00006426DEBBA78BULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91E0FDDCC7275A01ULL,
		0xA6F420E92628949BULL,
		0xF17DEF9485FBA827ULL,
		0xF286AEEDA1515B81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFDDCC7275A010000ULL,
		0x20E92628949B91E0ULL,
		0xEF9485FBA827A6F4ULL,
		0xAEEDA1515B81F17DULL,
		0x000000000000F286ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 176;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDE6C730B0C45EF46ULL,
		0xAE1F3BCDB6E30323ULL,
		0xA83494E201645CB4ULL,
		0x46CCC9E8D6111CA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC2C3117BD180000ULL,
		0xEF36DB8C0C8F79B1ULL,
		0x5388059172D2B87CULL,
		0x27A358447292A0D2ULL,
		0x0000000000011B33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 238;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x35B182F6620BEB5FULL,
		0xD7C418D1AD6CD9F0ULL,
		0x486C9FE40BB58BC4ULL,
		0xE5BB37DF0CEA1D64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x417D6BE000000000ULL,
		0xAD9B3E06B6305ECCULL,
		0x76B1789AF8831A35ULL,
		0x9D43AC890D93FC81ULL,
		0x0000001CB766FBE1ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0734C728C7581FEULL,
		0xD7D4AD858209B7ECULL,
		0xBD3C5C90A2E8D753ULL,
		0x039DA4BB361ED443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x03FC000000000000ULL,
		0x6FD9A0E698E518EBULL,
		0xAEA7AFA95B0B0413ULL,
		0xA8877A78B92145D1ULL,
		0x0000073B49766C3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B6FA5F3C2A19204ULL,
		0x03207120B8337CFAULL,
		0x0CE05C70709F4B53ULL,
		0xE6B318F9006C6109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA192040000000000ULL,
		0x337CFA5B6FA5F3C2ULL,
		0x9F4B5303207120B8ULL,
		0x6C61090CE05C7070ULL,
		0x000000E6B318F900ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4403FE8A177D432AULL,
		0x891AFFC0C81D6698ULL,
		0x02C6D01405EABBF3ULL,
		0x85D39FC0E4AB1FBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x50CA800000000000ULL,
		0x59A61100FFA285DFULL,
		0xAEFCE246BFF03207ULL,
		0xC7EF00B1B405017AULL,
		0x00002174E7F0392AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4E668E81F0B33E62ULL,
		0x42E572B4C5D4678FULL,
		0xD72FC2A2256174CAULL,
		0xC930872A5BF37AF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x668E81F0B33E6200ULL,
		0xE572B4C5D4678F4EULL,
		0x2FC2A2256174CA42ULL,
		0x30872A5BF37AF4D7ULL,
		0x00000000000000C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F6C367589FB0F09ULL,
		0xE50ED6F4B5DCD955ULL,
		0x1E742DC7D567348CULL,
		0x2CA54748269A4C55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD86CEB13F61E1200ULL,
		0x1DADE96BB9B2AA9EULL,
		0xE85B8FAACE6919CAULL,
		0x4A8E904D3498AA3CULL,
		0x0000000000000059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 183;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A1AADE2CA6CB49BULL,
		0x5AC6A49AD4377C35ULL,
		0x94DEEA0F686D8947ULL,
		0xC21BCF30C03904C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0xAF4355BC594D9693ULL,
		0xEB58D4935A86EF86ULL,
		0xB29BDD41ED0DB128ULL,
		0x184379E618072098ULL
	}};
	shift = 3;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x19043430F94C409CULL,
		0xC044EDEC88B44C34ULL,
		0xD62D04D2C198046CULL,
		0x3B6C2451133F197AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x87CA6204E0000000ULL,
		0x6445A261A0C821A1ULL,
		0x960CC0236602276FULL,
		0x8899F8CBD6B16826ULL,
		0x0000000001DB6122ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x74F4E76CEBEDB38FULL,
		0x9DDE3F48E0BFD6DCULL,
		0x475AF1DF0F60BF5EULL,
		0xF69299535A56CE55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x73B675F6D9C78000ULL,
		0x1FA4705FEB6E3A7AULL,
		0x78EF87B05FAF4EEFULL,
		0x4CA9AD2B672AA3ADULL,
		0x0000000000007B49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D82F75CC04A6134ULL,
		0xAB6A27AFC3A49F6FULL,
		0xAA921BECE2101863ULL,
		0xC4E4A628D78C49C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC268000000000000ULL,
		0x3EDEDB05EEB98094ULL,
		0x30C756D44F5F8749ULL,
		0x9389552437D9C420ULL,
		0x000189C94C51AF18ULL
	}};
	shift = 15;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2ABBEB5E50161F23ULL,
		0x3643E438D22D2989ULL,
		0xBD9A7A05D32B1FFEULL,
		0xF20D6C981D3581A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8C0000000000000ULL,
		0x624AAEFAD7940587ULL,
		0xFF8D90F90E348B4AULL,
		0x68EF669E8174CAC7ULL,
		0x003C835B26074D60ULL
	}};
	shift = 10;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3984C8725D1C4F0ULL,
		0x38AAC74DD8A5CDE4ULL,
		0xF234DC7A0D39F232ULL,
		0x1DA159C733A015C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3984C8725D1C4F0ULL,
		0x38AAC74DD8A5CDE4ULL,
		0xF234DC7A0D39F232ULL,
		0x1DA159C733A015C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x524610174F0E5756ULL,
		0xF6B2244F589E0AD6ULL,
		0x062C7C0679C09AECULL,
		0xD8FFEAFDF1BF1478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05D3C395D5800000ULL,
		0x13D62782B5949184ULL,
		0x019E7026BB3DAC89ULL,
		0xBF7C6FC51E018B1FULL,
		0x0000000000363FFAULL
	}};
	shift = 42;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x46680E46A0698BB7ULL,
		0xEE06F8D6EC140016ULL,
		0xE2345839BC8789B7ULL,
		0x0A38DC8A60C0B08CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x391A81A62EDC0000ULL,
		0xE35BB050005919A0ULL,
		0x60E6F21E26DFB81BULL,
		0x72298302C23388D1ULL,
		0x00000000000028E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE299CBFA088AC236ULL,
		0x1D465C705F16E7CAULL,
		0xC81F8A50F06F81F2ULL,
		0x86B4F11620228954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x672FE8222B08D800ULL,
		0x1971C17C5B9F2B8AULL,
		0x7E2943C1BE07C875ULL,
		0xD3C458808A255320ULL,
		0x000000000000021AULL,
		0x0000000000000000ULL
	}};
	shift = 118;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8080738E0F81040ULL,
		0xB76BDF22D6BD9F8BULL,
		0xC63A4EBBC4015764ULL,
		0x7CBB372008D0062BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x707C082000000000ULL,
		0x6B5ECFC5E404039CULL,
		0xE200ABB25BB5EF91ULL,
		0x04680315E31D275DULL,
		0x000000003E5D9B90ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE345B0B939D3770EULL,
		0xC423E1126D3A4F50ULL,
		0x8EC94D2A5742B78CULL,
		0x63EDCF958D686B0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDDC3800000000000ULL,
		0x93D438D16C2E4E74ULL,
		0xADE33108F8449B4EULL,
		0x1AC3E3B2534A95D0ULL,
		0x000018FB73E5635AULL
	}};
	shift = 18;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCBAFF7CC677104FULL,
		0x60618038583180C0ULL,
		0x80B56B4DF83A3436ULL,
		0x1252419C672329DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF319DC413C000000ULL,
		0xE160C60302F2EBFDULL,
		0x37E0E8D0D9818600ULL,
		0x719C8CA76E02D5ADULL,
		0x0000000000494906ULL
	}};
	shift = 38;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x39517355BBC5C120ULL,
		0x307E7D8C75E9C58DULL,
		0x2C71F2B02D50D5D6ULL,
		0x564C552CE190578BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B9AADDE2E090000ULL,
		0xF3EC63AF4E2C69CAULL,
		0x8F95816A86AEB183ULL,
		0x62A9670C82BC5963ULL,
		0x00000000000002B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 245;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA12F6CAC0F77540ULL,
		0x13F60AC09C08B11AULL,
		0x94D19C3CD997D03BULL,
		0x1C05A6CF9BDDF78EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x46BA84BDB2B03DDDULL,
		0x0EC4FD82B027022CULL,
		0xE3A534670F3665F4ULL,
		0x00070169B3E6F77DULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x37F5A23AEC3C2C8AULL,
		0xAC2D3391D46B0884ULL,
		0x6DA7A8D7B50B58A0ULL,
		0xE1F30528E06494D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEBB0F0B228000000ULL,
		0x4751AC2210DFD688ULL,
		0x5ED42D6282B0B4CEULL,
		0xA381925365B69EA3ULL,
		0x000000000387CC14ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x27EA887D7904155DULL,
		0x5AC31D8E756199E9ULL,
		0x0868F8B7AD1A5449ULL,
		0x8186CDA5BF3504C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D00000000000000ULL,
		0xE927EA887D790415ULL,
		0x495AC31D8E756199ULL,
		0xC60868F8B7AD1A54ULL,
		0x008186CDA5BF3504ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2B369E713BF3D17FULL,
		0x246D9B9FCE06DC51ULL,
		0xD9B00523EB8C16C4ULL,
		0x38E83EF8D758389EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4EFCF45FC000000ULL,
		0x7F381B7144ACDA79ULL,
		0x8FAE305B1091B66EULL,
		0xE35D60E27B66C014ULL,
		0x0000000000E3A0FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36B3848E209751D4ULL,
		0x9B4B4AFA93E42463ULL,
		0x2193C3C48C4CEB5AULL,
		0xA2A0B8EA3D2169D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BA8EA0000000000ULL,
		0xF212319B59C24710ULL,
		0x2675AD4DA5A57D49ULL,
		0x90B4E990C9E1E246ULL,
		0x00000051505C751EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 217;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9F44D2D8C0D1FB2ULL,
		0xBA681BF21C038D4FULL,
		0x30110538428BE54BULL,
		0xC7391170FE6926D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF3E89A5B181A3F64ULL,
		0x74D037E438071A9FULL,
		0x60220A708517CA97ULL,
		0x8E7222E1FCD24DAEULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xECB8474004EF3758ULL,
		0x5F2FEE16ED2DBD38ULL,
		0x1D5B449EA347D86EULL,
		0xB30C81790D1C31B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x009DE6EB00000000ULL,
		0xDDA5B7A71D9708E8ULL,
		0xD468FB0DCBE5FDC2ULL,
		0x21A3863723AB6893ULL,
		0x000000001661902FULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B4262A18BAD79A3ULL,
		0x9FF9EF221E341F58ULL,
		0xBD106D653DBB6479ULL,
		0x771A06F80A16F2BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8B4262A18BAD79A3ULL,
		0x9FF9EF221E341F58ULL,
		0xBD106D653DBB6479ULL,
		0x771A06F80A16F2BEULL
	}};
	shift = 0;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFC892C6421555095ULL,
		0xA31837B37BFACCD9ULL,
		0xEBFBAF3D5E1495DFULL,
		0x968D5DFAAC11C864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4A80000000000000ULL,
		0x6CFE44963210AAA8ULL,
		0xEFD18C1BD9BDFD66ULL,
		0x3275FDD79EAF0A4AULL,
		0x004B46AEFD5608E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0D45AEFA22ECD8D5ULL,
		0x2BD8E970254CEBF4ULL,
		0xE3380D748E8C24A9ULL,
		0x0BDE25C9DB836847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA800000000000000ULL,
		0xA06A2D77D11766C6ULL,
		0x495EC74B812A675FULL,
		0x3F19C06BA4746125ULL,
		0x005EF12E4EDC1B42ULL,
		0x0000000000000000ULL
	}};
	shift = 69;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x313467B6757A3E35ULL,
		0x33FDDEC5F21BD882ULL,
		0x28E6661B3C29045BULL,
		0xBEE1012FE6564E5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6268CF6CEAF47C6AULL,
		0x67FBBD8BE437B104ULL,
		0x51CCCC36785208B6ULL,
		0x7DC2025FCCAC9CB4ULL,
		0x0000000000000001ULL
	}};
	shift = 63;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA5033D38A2925A7CULL,
		0xDA46A2E082395B69ULL,
		0x6702E315C61F9258ULL,
		0xAF36917406372DFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x033D38A2925A7C00ULL,
		0x46A2E082395B69A5ULL,
		0x02E315C61F9258DAULL,
		0x36917406372DFE67ULL,
		0x00000000000000AFULL
	}};
	shift = 56;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A61C5B6AF034351ULL,
		0xBC442447C5B6082BULL,
		0x09F1B45B964718BAULL,
		0xDD23BEABE11F81C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B6AF03435100000ULL,
		0x447C5B6082B9A61CULL,
		0x45B964718BABC442ULL,
		0xEABE11F81C909F1BULL,
		0x00000000000DD23BULL
	}};
	shift = 44;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA59017E9E634040AULL,
		0xC376AB7031A091E5ULL,
		0x584A356CE125B113ULL,
		0x969A4464A2F682F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1400000000000000ULL,
		0xCB4B202FD3CC6808ULL,
		0x2786ED56E0634123ULL,
		0xE0B0946AD9C24B62ULL,
		0x012D3488C945ED05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 199;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBCBB1DDCA28F226AULL,
		0xDE7A09E3B8C80421ULL,
		0x195FF042A972D142ULL,
		0xD1EECDD9D11B578CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51E44D4000000000ULL,
		0x190084379763BB94ULL,
		0x2E5A285BCF413C77ULL,
		0x236AF1832BFE0855ULL,
		0x0000001A3DD9BB3AULL
	}};
	shift = 27;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD3F05CB13BD583AULL,
		0x93F81589B2F1B591ULL,
		0xAABD546E912B0DA0ULL,
		0x98577B3EB9297DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD583A0000000000ULL,
		0xF1B591CD3F05CB13ULL,
		0x2B0DA093F81589B2ULL,
		0x297DDAAABD546E91ULL,
		0x00000098577B3EB9ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51A8AE6DB44FE962ULL,
		0x666B6EB17885D8BFULL,
		0xD343E6A1A4B9C1F6ULL,
		0xC958C485483F505DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9FD2C40000000000ULL,
		0x0BB17EA3515CDB68ULL,
		0x7383ECCCD6DD62F1ULL,
		0x7EA0BBA687CD4349ULL,
		0x00000192B1890A90ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF553137A3E9CE77ULL,
		0xFAAD36473D4E1438ULL,
		0x334C3A405B2EF73DULL,
		0xE5C22D511C1358CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x73B8000000000000ULL,
		0xA1C6FAA989BD1F4EULL,
		0xB9EFD569B239EA70ULL,
		0xC6619A61D202D977ULL,
		0x00072E116A88E09AULL
	}};
	shift = 13;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE1B767FF9113DD6ULL,
		0x18ABA7EF864FFBFFULL,
		0x0948D92FAD15F715ULL,
		0x565E7AB9D89F98C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xECFFF2227BAC0000ULL,
		0x4FDF0C9FF7FFFC36ULL,
		0xB25F5A2BEE2A3157ULL,
		0xF573B13F31861291ULL,
		0x000000000000ACBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x52A84D3A13912194ULL,
		0x51CF901B15EE87EEULL,
		0x2E3ADF1061970C22ULL,
		0x1840A8807B2D16C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0CA0000000000000ULL,
		0x3F72954269D09C89ULL,
		0x61128E7C80D8AF74ULL,
		0xB61171D6F8830CB8ULL,
		0x0000C2054403D968ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C94AC0B87F67444ULL,
		0x8B9BCA01F68FCC02ULL,
		0x4853A0F57E3CA2A3ULL,
		0xB0A640AC4A905C4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1100000000000000ULL,
		0x009F252B02E1FD9DULL,
		0xA8E2E6F2807DA3F3ULL,
		0x139214E83D5F8F28ULL,
		0x002C29902B12A417ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB3D91082EA5EF04ULL,
		0x9CE0BC9AB2F214E4ULL,
		0x61D2DED8CFF325DFULL,
		0xA9C2ED72A0399C06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3D91082EA5EF040ULL,
		0xCE0BC9AB2F214E4EULL,
		0x1D2DED8CFF325DF9ULL,
		0x9C2ED72A0399C066ULL,
		0x000000000000000AULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCD1F147B6883BEDEULL,
		0x7E4CA2034DE7C1F3ULL,
		0x9601F6D1A163F903ULL,
		0x013A1E72F419A6DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB441DF6F0000000ULL,
		0x1A6F3E0F9E68F8A3ULL,
		0x8D0B1FC81BF26510ULL,
		0x97A0CD36E4B00FB6ULL,
		0x000000000009D0F3ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE786CE7E19D22404ULL,
		0xAFF57ED2BCFD9B06ULL,
		0xB440C029F35BFB66ULL,
		0x7B352C0DBBE1709FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9120200000000000ULL,
		0xECD8373C3673F0CEULL,
		0xDFDB357FABF695E7ULL,
		0x0B84FDA206014F9AULL,
		0x000003D9A9606DDFULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCF18DE758EBFD99AULL,
		0xF01E16D067D49EE9ULL,
		0x5E896E51028688F4ULL,
		0x0729B5DDD5A97853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7FB3340000000000ULL,
		0xA93DD39E31BCEB1DULL,
		0x0D11E9E03C2DA0CFULL,
		0x52F0A6BD12DCA205ULL,
		0x0000000E536BBBABULL
	}};
	shift = 23;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE6958997353B51B8ULL,
		0xC541D8A6E868FD66ULL,
		0xABC4EC8DF3EA175EULL,
		0xFBE353DC7C2CAA41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x353B51B800000000ULL,
		0xE868FD66E6958997ULL,
		0xF3EA175EC541D8A6ULL,
		0x7C2CAA41ABC4EC8DULL,
		0x00000000FBE353DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 224;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3888BEC858ED4B35ULL,
		0x9157DC3E147DAF27ULL,
		0x46DEDC5554E58336ULL,
		0xB2C56F61A5F31707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2CD4000000000000ULL,
		0xBC9CE222FB2163B5ULL,
		0x0CDA455F70F851F6ULL,
		0x5C1D1B7B71555396ULL,
		0x0002CB15BD8697CCULL
	}};
	shift = 14;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8862C890AF2E9C0BULL,
		0x064049B7542807D7ULL,
		0xA18FF0D82E0A845AULL,
		0x92D65CFA8C474E60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8160000000000000ULL,
		0xFAF10C591215E5D3ULL,
		0x8B40C80936EA8500ULL,
		0xCC1431FE1B05C150ULL,
		0x00125ACB9F5188E9ULL
	}};
	shift = 11;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFDF78D8D3E7592F8ULL,
		0xA8A6CE0947B035D9ULL,
		0x60002513B1702AD9ULL,
		0x5DCB2D5CB8859062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F8000000000000ULL,
		0x35D9FDF78D8D3E75ULL,
		0x2AD9A8A6CE0947B0ULL,
		0x906260002513B170ULL,
		0x00005DCB2D5CB885ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE0AFA1F82FEB8F7AULL,
		0xB5F711CE8B0BFD90ULL,
		0x1041127468A269D2ULL,
		0x5DBDF594F06B7CB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71EF400000000000ULL,
		0x7FB21C15F43F05FDULL,
		0x4D3A56BEE239D161ULL,
		0x6F968208224E8D14ULL,
		0x00000BB7BEB29E0DULL
	}};
	shift = 19;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC20E4E798D2798BDULL,
		0xBD1D8DC653EC71F3ULL,
		0x23C2AA2F4BC824DDULL,
		0x1EFCF2F3F09D1A2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC5E8000000000000ULL,
		0x8F9E107273CC693CULL,
		0x26EDE8EC6E329F63ULL,
		0xD1791E15517A5E41ULL,
		0x0000F7E7979F84E8ULL
	}};
	shift = 13;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAC496782733ABF25ULL,
		0xE4A4605C95306802ULL,
		0xC5119B2EFB2ABE52ULL,
		0xA63CFA85D0DB9381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5F92800000000000ULL,
		0x34015624B3C1399DULL,
		0x5F297252302E4A98ULL,
		0xC9C0E288CD977D95ULL,
		0x0000531E7D42E86DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4DB568DEA2250DECULL,
		0xC3A8DE0430070504ULL,
		0x6AF873CE4F42579BULL,
		0x602115C9EF9842C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD444A1BD80000000ULL,
		0x8600E0A089B6AD1BULL,
		0xC9E84AF378751BC0ULL,
		0x3DF308584D5F0E79ULL,
		0x000000000C0422B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 227;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FA0D40D0ED81548ULL,
		0x39BE38ABC10161A8ULL,
		0xD16ECD2B3BA92EC7ULL,
		0xA3CD6BDC0E5807C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D06A06876C0AA40ULL,
		0xCDF1C55E080B0D41ULL,
		0x8B766959DD497639ULL,
		0x1E6B5EE072C03E2EULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5186734F7FE523EEULL,
		0x8538AAB84B9AC6D6ULL,
		0xF9D922EAE6268905ULL,
		0xDD3489913F20CFEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC339A7BFF291F700ULL,
		0x9C555C25CD636B28ULL,
		0xEC917573134482C2ULL,
		0x9A44C89F9067F57CULL,
		0x000000000000006EULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x11C9065935166840ULL,
		0x124EE94D5ECF13B6ULL,
		0x83A2DFF4247AB0E5ULL,
		0x3DC9871DFF5A5205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL,
		0x76C23920CB26A2CDULL,
		0x1CA249DD29ABD9E2ULL,
		0x40B0745BFE848F56ULL,
		0x0007B930E3BFEB4AULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3078599D45819E24ULL,
		0xE0AFB4FC6F82C844ULL,
		0xEF5FA19FE6D88C8FULL,
		0x043D0A834697C0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9000000000000000ULL,
		0x10C1E16675160678ULL,
		0x3F82BED3F1BE0B21ULL,
		0xFFBD7E867F9B6232ULL,
		0x0010F42A0D1A5F03ULL
	}};
	shift = 6;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x902B0C48B803D775ULL,
		0x4BED32FCD85DFCA6ULL,
		0x67949FE47EB6AE0EULL,
		0x72475DEBFF78AB38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAEEA000000000000ULL,
		0xF94D205618917007ULL,
		0x5C1C97DA65F9B0BBULL,
		0x5670CF293FC8FD6DULL,
		0x0000E48EBBD7FEF1ULL
	}};
	shift = 15;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
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
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000800ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000001000000000ULL,
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
	shift = 88;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000008ULL,
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
	shift = 12;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000080000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000008000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000004000000000ULL,
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
	shift = 176;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0008000000000000ULL,
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
	shift = 200;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000040000000000ULL,
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
	shift = 152;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000010000ULL,
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
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000001000000ULL,
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
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000400000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0040000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_rshift(&k1, shift, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}