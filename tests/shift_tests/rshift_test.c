#include "../tests.h"

int32_t curve25519_key_rshift_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x833C4E7BA8851700ULL,
		0xDA8D1DAB0C29C78BULL,
		0xAE620C152020F78AULL,
		0x5107AF2735841742ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x139EEA2145C00000ULL,
		0x476AC30A71E2E0CFULL,
		0x830548083DE2B6A3ULL,
		0xEBC9CD6105D0AB98ULL,
		0x0000000000001441ULL
	}};
	int shift = 50;
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
		0x77543BF4FF9D91A9ULL,
		0x807AC6ED1B18A85CULL,
		0x83349345A0D0A284ULL,
		0x36E6B4D474E5CB2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77543BF4FF9D91A9ULL,
		0x807AC6ED1B18A85CULL,
		0x83349345A0D0A284ULL,
		0x36E6B4D474E5CB2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
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
		0x8531BD478DC49FB5ULL,
		0x6130A0F5C42C7365ULL,
		0x79274292D062892AULL,
		0x2C609202857131AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F1B893F6A000000ULL,
		0xEB8858E6CB0A637AULL,
		0x25A0C51254C26141ULL,
		0x050AE2635CF24E85ULL,
		0x000000000058C124ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
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
		0x758CF91E0C425B4DULL,
		0xB721AB52D14F611BULL,
		0x4EEF1555A4B91EAEULL,
		0x1E23047C89C4B49EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x12DA680000000000ULL,
		0x7B08DBAC67C8F062ULL,
		0xC8F575B90D5A968AULL,
		0x25A4F27778AAAD25ULL,
		0x000000F11823E44EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
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
		0xD5F35842403E3381ULL,
		0xB7CDF7A9356FF684ULL,
		0xA4EB5B3EB4D49124ULL,
		0xAB7458441D6EF0E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD5F35842403E3381ULL,
		0xB7CDF7A9356FF684ULL,
		0xA4EB5B3EB4D49124ULL,
		0xAB7458441D6EF0E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0xB46432B3F5A1B594ULL,
		0x363095383F7CF762ULL,
		0x81FE850853A0364EULL,
		0x4CA8AA41393B0929ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2800000000000000ULL,
		0xC568C86567EB436BULL,
		0x9C6C612A707EF9EEULL,
		0x5303FD0A10A7406CULL,
		0x0099515482727612ULL
	}};
	shift = 7;
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
		0x95307EC016D30F0DULL,
		0xCDBD3F4FD7A60AABULL,
		0x131E0FB45DE7DC39ULL,
		0x5BB7D817F33D8D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x983F600B69878680ULL,
		0xDE9FA7EBD30555CAULL,
		0x8F07DA2EF3EE1CE6ULL,
		0xDBEC0BF99EC68789ULL,
		0x000000000000002DULL,
		0x0000000000000000ULL
	}};
	shift = 121;
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
		0x2ACA8CC7C1351AE6ULL,
		0x6525F274576E15CCULL,
		0x24FFEEAC6F738791ULL,
		0xD5CAF3E6F5EAF1F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB2A331F04D46B98ULL,
		0x9497C9D15DB85730ULL,
		0x93FFBAB1BDCE1E45ULL,
		0x572BCF9BD7ABC7C8ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
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
		0x0CF45EBF6CB3DB81ULL,
		0xC577E4853B8DE2D7ULL,
		0x79C1966090D8FCD1ULL,
		0xFDE1CF75E9AC36DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33D17AFDB2CF6E04ULL,
		0x15DF9214EE378B5CULL,
		0xE70659824363F347ULL,
		0xF7873DD7A6B0DB71ULL,
		0x0000000000000003ULL
	}};
	shift = 62;
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
		0x9933D4BCBCEF401EULL,
		0x373E708FA7ACEF56ULL,
		0x24785A5246BD5D79ULL,
		0xF0809DF95C4D7DEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD007800000000000ULL,
		0x3BD5A64CF52F2F3BULL,
		0x575E4DCF9C23E9EBULL,
		0x5F7B891E169491AFULL,
		0x00003C20277E5713ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
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
		0x8BC08F3C86BFE768ULL,
		0xA6FC03CA36BEBB82ULL,
		0x34E8AFB309E6538BULL,
		0x4D0D5E320BD32711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCED0000000000000ULL,
		0x770517811E790D7FULL,
		0xA7174DF807946D7DULL,
		0x4E2269D15F6613CCULL,
		0x00009A1ABC6417A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
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
		0x577C21BDE86C86D7ULL,
		0x7BA34FDD3C6B5E4EULL,
		0x37945B0D43400B13ULL,
		0x2AE5C97DB7699D27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F7A1B21B5C00000ULL,
		0xF74F1AD79395DF08ULL,
		0xC350D002C4DEE8D3ULL,
		0x5F6DDA6749CDE516ULL,
		0x00000000000AB972ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
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
		0xE040CAA061070F35ULL,
		0x4CB7BCEE805B2F0AULL,
		0xAD8F50B7E37CF624ULL,
		0x2A3339B6F35CADDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE040CAA061070F35ULL,
		0x4CB7BCEE805B2F0AULL,
		0xAD8F50B7E37CF624ULL,
		0x2A3339B6F35CADDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 256;
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
		0xC6D743676D8DFA10ULL,
		0x264FC9AA16396712ULL,
		0x071A4C30FFFB31C4ULL,
		0x25FD15BF421CAB62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C6D743676D8DFA1ULL,
		0x4264FC9AA1639671ULL,
		0x2071A4C30FFFB31CULL,
		0x025FD15BF421CAB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 196;
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
		0xF2EACB7C8900B165ULL,
		0xEB1A62EF454664E1ULL,
		0xDD1E72F518055B33ULL,
		0x6A9FFA6D519EBFABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C59400000000000ULL,
		0x99387CBAB2DF2240ULL,
		0x56CCFAC698BBD151ULL,
		0xAFEAF7479CBD4601ULL,
		0x00001AA7FE9B5467ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
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
		0xDA47B08F14FF76F8ULL,
		0xB92256E0A30E5C40ULL,
		0x798D427C9162EEB4ULL,
		0xBA2675340C8E85A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EC23C53FDDBE000ULL,
		0x895B828C39710369ULL,
		0x3509F2458BBAD2E4ULL,
		0x99D4D0323A16A5E6ULL,
		0x00000000000002E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 246;
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
		0x205F7761065896C2ULL,
		0x399A015A24727BCBULL,
		0xE266498CA81E5F7CULL,
		0xE0FC9B5448823CE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05F7761065896C20ULL,
		0x99A015A24727BCB2ULL,
		0x266498CA81E5F7C3ULL,
		0x0FC9B5448823CE1EULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
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
		0x890FDB864E7AAF2FULL,
		0x0ACAA01B2BDAB464ULL,
		0xED2C1B00B96965D0ULL,
		0x926A0CD435320DF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39EABCBC00000000ULL,
		0xAF6AD192243F6E19ULL,
		0xE5A597402B2A806CULL,
		0xD4C837C3B4B06C02ULL,
		0x0000000249A83350ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 222;
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
		0x661706DCCE567671ULL,
		0xA4A4D65B16C0E1A0ULL,
		0xC67B214F235FA535ULL,
		0x1C7B2A57CFC2C1F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x36E672B3B3880000ULL,
		0xB2D8B6070D0330B8ULL,
		0x0A791AFD29AD2526ULL,
		0x52BE7E160F8E33D9ULL,
		0x000000000000E3D9ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
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
		0xE04ED869431F028FULL,
		0x34129E9A554F26BAULL,
		0xE0A01760109E45B4ULL,
		0x481C44B89668BD3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x028F000000000000ULL,
		0x26BAE04ED869431FULL,
		0x45B434129E9A554FULL,
		0xBD3CE0A01760109EULL,
		0x0000481C44B89668ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
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
		0x277ECCFA4E78EB45ULL,
		0xD025FD7A623AE8B4ULL,
		0xCE4B5FCF008797ADULL,
		0x2E0DAA114E88A96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBF667D273C75A280ULL,
		0x12FEBD311D745A13ULL,
		0x25AFE78043CBD6E8ULL,
		0x06D508A74454B667ULL,
		0x0000000000000017ULL
	}};
	shift = 57;
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
		0xE8CCFAC0DF8D7CB8ULL,
		0x18B10FB2B498C271ULL,
		0x35E2C97CE8369B7FULL,
		0x54D6D13691E87A96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4667D606FC6BE5C0ULL,
		0xC5887D95A4C6138FULL,
		0xAF164BE741B4DBF8ULL,
		0xA6B689B48F43D4B1ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 253;
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
		0x31111C7DFD8497EEULL,
		0x4280E44C04B511B2ULL,
		0x39F6FA98E26DCC53ULL,
		0xDD74C43F043C9AB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBFB092FDC0000000ULL,
		0x8096A2364622238FULL,
		0x1C4DB98A68501C89ULL,
		0xE0879356673EDF53ULL,
		0x000000001BAE9887ULL
	}};
	shift = 35;
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
		0x92372923FB815666ULL,
		0x97DD7A1FF1D0573AULL,
		0xEB425DE628AB6719ULL,
		0x03F5B39142261036ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02ACCC0000000000ULL,
		0xA0AE75246E5247F7ULL,
		0x56CE332FBAF43FE3ULL,
		0x4C206DD684BBCC51ULL,
		0x00000007EB672284ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
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
		0xBCDD167B495F65C0ULL,
		0xCD9C05E52EEC8449ULL,
		0x1886615F74971907ULL,
		0xFDE007B1B8370CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x92BECB8000000000ULL,
		0x5DD9089379BA2CF6ULL,
		0xE92E320F9B380BCAULL,
		0x706E195C310CC2BEULL,
		0x00000001FBC00F63ULL
	}};
	shift = 31;
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
		0x6DC8DCE390CBD9F3ULL,
		0xBAB75A2DD409B127ULL,
		0xCC198D0114CF6ACBULL,
		0x0E6C8030B7F1B5CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF67CC00000000000ULL,
		0x6C49DB723738E432ULL,
		0xDAB2EEADD68B7502ULL,
		0x6D73B30663404533ULL,
		0x0000039B200C2DFCULL
	}};
	shift = 18;
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
		0x44BCED5177D875B8ULL,
		0xF116AB6D26E9907BULL,
		0xAD39C332A458EF7BULL,
		0xE3235F35FE8FFAD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A8BBEC3ADC0000ULL,
		0x55B69374C83DA25EULL,
		0xE199522C77BDF88BULL,
		0xAF9AFF47FD6A569CULL,
		0x0000000000007191ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 241;
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
		0xCCE3D5EBF35C7553ULL,
		0x8979EEC5165298ADULL,
		0xE9427C989FD9F0DCULL,
		0xEE8971025F4623DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF57AFCD71D54C000ULL,
		0x7BB14594A62B7338ULL,
		0x9F2627F67C37225EULL,
		0x5C4097D188F6FA50ULL,
		0x0000000000003BA2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 178;
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
		0x7718019550F1512AULL,
		0xF52D93C9C2EADEA1ULL,
		0x1197E154F0357ED7ULL,
		0x5D6D0D680A9A8B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x44A8000000000000ULL,
		0x7A85DC60065543C5ULL,
		0xFB5FD4B64F270BABULL,
		0x2C8C465F8553C0D5ULL,
		0x000175B435A02A6AULL
	}};
	shift = 14;
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
		0x6DBAF2FC80E7DE78ULL,
		0x9261450894206BABULL,
		0x3A292D59ECF02575ULL,
		0xB167586655C418D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE4073EF3C0000000ULL,
		0x44A1035D5B6DD797ULL,
		0xCF67812BAC930A28ULL,
		0x32AE20C6A9D1496AULL,
		0x00000000058B3AC3ULL
	}};
	shift = 37;
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
		0x6BEE108F92436CB3ULL,
		0xAF6BD2B344AE6A9EULL,
		0xD2803CF2D536DE34ULL,
		0x98407BC0CC26E853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x21B6598000000000ULL,
		0x57354F35F70847C9ULL,
		0x9B6F1A57B5E959A2ULL,
		0x137429E9401E796AULL,
		0x0000004C203DE066ULL
	}};
	shift = 25;
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
		0x289261EB2334B5F1ULL,
		0x3D3449E83877230FULL,
		0x3AC33AC0F7ADB08DULL,
		0x74C2458678D01552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9261EB2334B5F100ULL,
		0x3449E83877230F28ULL,
		0xC33AC0F7ADB08D3DULL,
		0xC2458678D015523AULL,
		0x0000000000000074ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 248;
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
		0xDD278AC15C5D69E4ULL,
		0xC54FFB05EB770C8DULL,
		0x8EFEBEF2E04D971BULL,
		0x8FDCE1DD3C9BA6FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x78AC15C5D69E4000ULL,
		0xFFB05EB770C8DDD2ULL,
		0xEBEF2E04D971BC54ULL,
		0xCE1DD3C9BA6FF8EFULL,
		0x00000000000008FDULL,
		0x0000000000000000ULL
	}};
	shift = 116;
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
		0x68E8674CDEB01360ULL,
		0xC0F91C4EA8819DD0ULL,
		0x802B05901222A198ULL,
		0xDBE40CBCF1BB91E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7433A66F5809B000ULL,
		0x7C8E275440CEE834ULL,
		0x1582C8091150CC60ULL,
		0xF2065E78DDC8F340ULL,
		0x000000000000006DULL
	}};
	shift = 57;
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
		0x39FA2069520A2F26ULL,
		0xB837C090F380868EULL,
		0x55E09E0CD1AFE6F4ULL,
		0x939F0C14530FF74AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x881A54828BC98000ULL,
		0xF0243CE021A38E7EULL,
		0x2783346BF9BD2E0DULL,
		0xC30514C3FDD29578ULL,
		0x00000000000024E7ULL
	}};
	shift = 50;
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
		0x8D602D2A57480BBEULL,
		0x653656007D752FA5ULL,
		0x8C14038C4D6BC3B8ULL,
		0x5BCB6A88F2768E4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2A57480BBE000000ULL,
		0x007D752FA58D602DULL,
		0x8C4D6BC3B8653656ULL,
		0x88F2768E4B8C1403ULL,
		0x00000000005BCB6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
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
		0x27102C67D2513F9EULL,
		0xC7B1FCC40093EC84ULL,
		0xE9B674B1312CB9D8ULL,
		0x6CC43C81BB2EFE48ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F9E000000000000ULL,
		0xEC8427102C67D251ULL,
		0xB9D8C7B1FCC40093ULL,
		0xFE48E9B674B1312CULL,
		0x00006CC43C81BB2EULL
	}};
	shift = 16;
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
		0x6926F0ABCC13133CULL,
		0x4A74DF9DFD4F958CULL,
		0x58EF04E35FD61121ULL,
		0x0216333BC5C110F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDE15798262678000ULL,
		0x9BF3BFA9F2B18D24ULL,
		0xE09C6BFAC224294EULL,
		0xC66778B8221F2B1DULL,
		0x0000000000000042ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
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
		0xAD1AD952E4E0F36AULL,
		0x0E9B9A0948AEEE90ULL,
		0x01024470AAD38952ULL,
		0xB254F07558885C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD400000000000000ULL,
		0x215A35B2A5C9C1E6ULL,
		0xA41D373412915DDDULL,
		0xDC020488E155A712ULL,
		0x0164A9E0EAB110B8ULL
	}};
	shift = 7;
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
		0xA0FAF8D8C9D1EB0FULL,
		0x1C3C559F2A7D2AC9ULL,
		0x6F2809B1A8E3D2EDULL,
		0x794B5804DD3DFA0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F00000000000000ULL,
		0xC9A0FAF8D8C9D1EBULL,
		0xED1C3C559F2A7D2AULL,
		0x0C6F2809B1A8E3D2ULL,
		0x00794B5804DD3DFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 136;
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
		0x91A8690FA16B3C38ULL,
		0xD0A88C83A38BE8AEULL,
		0x87BF2EA21E0BCF61ULL,
		0xBC24DF192D6551B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6B3C380000000000ULL,
		0x8BE8AE91A8690FA1ULL,
		0x0BCF61D0A88C83A3ULL,
		0x6551B387BF2EA21EULL,
		0x000000BC24DF192DULL,
		0x0000000000000000ULL
	}};
	shift = 88;
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
		0xE1C8044FA2FC65BEULL,
		0x84143CFBDB10370CULL,
		0x0203FFD7C905BFA2ULL,
		0x15F0212C88FD6BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x32DF000000000000ULL,
		0x1B8670E40227D17EULL,
		0xDFD1420A1E7DED88ULL,
		0xB5F18101FFEBE482ULL,
		0x00000AF81096447EULL,
		0x0000000000000000ULL
	}};
	shift = 81;
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
		0x25E5C5FB0530BAA0ULL,
		0x652D9DD33239FC3BULL,
		0x9E53808FB890B5AFULL,
		0x6D1F5B3F8657D891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6175400000000000ULL,
		0x73F8764BCB8BF60AULL,
		0x216B5ECA5B3BA664ULL,
		0xAFB1233CA7011F71ULL,
		0x000000DA3EB67F0CULL
	}};
	shift = 23;
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
		0xDA9EBB779941ACB8ULL,
		0x3F57D5DCB9CF8F3EULL,
		0x4128F49149DC4624ULL,
		0x01B29ABDF21A6BD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDB53D76EF3283597ULL,
		0x87EAFABB9739F1E7ULL,
		0x88251E92293B88C4ULL,
		0x00365357BE434D7AULL,
		0x0000000000000000ULL
	}};
	shift = 67;
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
		0xEF5F2D8B3EA405D1ULL,
		0xFDF1DACD93B80241ULL,
		0x47A13D89E352BBADULL,
		0xE35736D23ABD1527ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE5B167D480BA2000ULL,
		0x3B59B27700483DEBULL,
		0x27B13C6A5775BFBEULL,
		0xE6DA4757A2A4E8F4ULL,
		0x0000000000001C6AULL
	}};
	shift = 51;
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
		0x15CB0CA170D363DCULL,
		0x27700637466890DCULL,
		0x38198F5BF85E1581ULL,
		0x78A51E69FD513B36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50B869B1EE000000ULL,
		0x1BA334486E0AE586ULL,
		0xADFC2F0AC093B803ULL,
		0x34FEA89D9B1C0CC7ULL,
		0x00000000003C528FULL,
		0x0000000000000000ULL
	}};
	shift = 105;
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
		0xF946B5B4845E1A80ULL,
		0x773FEAE97D3C76D7ULL,
		0xCBF693F01C116738ULL,
		0x75C63F910ABC927FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x786A000000000000ULL,
		0xF1DB5FE51AD6D211ULL,
		0x459CE1DCFFABA5F4ULL,
		0xF249FF2FDA4FC070ULL,
		0x000001D718FE442AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 214;
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
		0x59FFAF894028B99EULL,
		0xA6DDBF5705A42715ULL,
		0x150881EE782E84B6ULL,
		0x132E879845F8210DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7C4A0145CCF00000ULL,
		0xFAB82D2138AACFFDULL,
		0x0F73C17425B536EDULL,
		0x3CC22FC10868A844ULL,
		0x0000000000009974ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
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
		0x6FE4CC41325623F6ULL,
		0x4D6435C9E366981FULL,
		0xF86C6C5F8E11539DULL,
		0xAA18885315DEB861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47EC000000000000ULL,
		0x303EDFC9988264ACULL,
		0xA73A9AC86B93C6CDULL,
		0x70C3F0D8D8BF1C22ULL,
		0x0001543110A62BBDULL
	}};
	shift = 15;
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
		0xF9553FF318954D90ULL,
		0xC911C97C9BC10C22ULL,
		0x4FE54E74FB6B86DAULL,
		0x160BD8619303CF65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2553640000000000ULL,
		0xF04308BE554FFCC6ULL,
		0xDAE1B6B244725F26ULL,
		0xC0F3D953F9539D3EULL,
		0x0000000582F61864ULL
	}};
	shift = 26;
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
		0x599CDDC9888C5211ULL,
		0x23EC4C6435D1DC2DULL,
		0xD14864A54867D67FULL,
		0x6FEA14D85C70E1FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3772622314844000ULL,
		0x13190D74770B5667ULL,
		0x19295219F59FC8FBULL,
		0x8536171C387FB452ULL,
		0x0000000000001BFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 242;
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
		0x36D96D5857E4C683ULL,
		0x796175ED149F5B25ULL,
		0xDC00D0DA0E90B76FULL,
		0x87974EAD79D53EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8300000000000000ULL,
		0x2536D96D5857E4C6ULL,
		0x6F796175ED149F5BULL,
		0xA2DC00D0DA0E90B7ULL,
		0x0087974EAD79D53EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
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
		0x9D61CAD89326DD98ULL,
		0x5B593DE3C913B563ULL,
		0x8D263586D9B6B655ULL,
		0x75262632A9AD1A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6600000000000000ULL,
		0x58E75872B624C9B7ULL,
		0x9556D64F78F244EDULL,
		0xA463498D61B66DADULL,
		0x001D49898CAA6B46ULL
	}};
	shift = 10;
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
		0x613E5C93D5A91675ULL,
		0xECD63DB915238194ULL,
		0x06CC26D068A4C51EULL,
		0x67EF835A47B7AC84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522CEA0000000000ULL,
		0x470328C27CB927ABULL,
		0x498A3DD9AC7B722AULL,
		0x6F59080D984DA0D1ULL,
		0x000000CFDF06B48FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
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
		0x0F82AB11263217C3ULL,
		0xEFA07C716CD6F32CULL,
		0x2FB831FE67CFACC9ULL,
		0xA81470562DEC2EE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF0556224C642F860ULL,
		0xF40F8E2D9ADE6581ULL,
		0xF7063FCCF9F5993DULL,
		0x028E0AC5BD85DCC5ULL,
		0x0000000000000015ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
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
		0x5DF5EBDF5DE2061BULL,
		0x55C2538D4850CC5FULL,
		0xF0F092051E49FE47ULL,
		0xBBD3B10FCCC887A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAF5EFAEF1030D800ULL,
		0x129C6A428662FAEFULL,
		0x849028F24FF23AAEULL,
		0x9D887E66443D2F87ULL,
		0x00000000000005DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
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
		0x3B400E3D63F6595BULL,
		0xA78DC433EFE29AC6ULL,
		0xD96E4A73B464CC94ULL,
		0x8572AEE5D15A1A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x038F58FD9656C000ULL,
		0x710CFBF8A6B18ED0ULL,
		0x929CED19332529E3ULL,
		0xABB97456869DB65BULL,
		0x000000000000215CULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0xD6879B575DCFADE6ULL,
		0x832370F4F8D1448EULL,
		0xE08A24EB44159419ULL,
		0x2FA03E845063E526ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BCC000000000000ULL,
		0x891DAD0F36AEBB9FULL,
		0x28330646E1E9F1A2ULL,
		0xCA4DC11449D6882BULL,
		0x00005F407D08A0C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
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
		0x58345F8B65442EFDULL,
		0x9CA0A14E8F83B7B0ULL,
		0x33C2831843E78F3CULL,
		0xDAA6858110ABE928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCA885DFA00000000ULL,
		0x1F076F60B068BF16ULL,
		0x87CF1E793941429DULL,
		0x2157D25067850630ULL,
		0x00000001B54D0B02ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
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
		0x68C5B1FE18C40D86ULL,
		0x3037D174A6DD79DEULL,
		0x550673EA850BCEDCULL,
		0x06FE227E97E83E33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD8FF0C6206C30000ULL,
		0xE8BA536EBCEF3462ULL,
		0x39F54285E76E181BULL,
		0x113F4BF41F19AA83ULL,
		0x000000000000037FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0xD72B7C3935D7BB98ULL,
		0x0CA389C1ECA78AF7ULL,
		0x285357CC5F8F75B4ULL,
		0x4E0B983E139E656CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE56F8726BAF7730ULL,
		0x19471383D94F15EFULL,
		0x50A6AF98BF1EEB68ULL,
		0x9C17307C273CCAD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
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
		0x4D4E4DA11CF6E315ULL,
		0x528CC3BAD378D075ULL,
		0xE3ADEBC9B9478A07ULL,
		0x459647DE3CEB0CD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x726D08E7B718A800ULL,
		0x661DD69BC683AA6AULL,
		0x6F5E4DCA3C503A94ULL,
		0xB23EF1E75866971DULL,
		0x000000000000022CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
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
		0x5EA61833179C40FFULL,
		0xB012AFFDE1B9EBCCULL,
		0x6BC1AF4D0BD9B9D8ULL,
		0xFD3923D38284C65AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C198BCE207F8000ULL,
		0x57FEF0DCF5E62F53ULL,
		0xD7A685ECDCEC5809ULL,
		0x91E9C142632D35E0ULL,
		0x0000000000007E9CULL,
		0x0000000000000000ULL
	}};
	shift = 113;
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
		0x5BB03C4CD430BBEFULL,
		0x82E93128736B2B12ULL,
		0x85F1807976BA6CC5ULL,
		0x7AAC171FD4DC465AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEF00000000000000ULL,
		0x125BB03C4CD430BBULL,
		0xC582E93128736B2BULL,
		0x5A85F1807976BA6CULL,
		0x007AAC171FD4DC46ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
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
		0x4252710B676EAA3AULL,
		0xEE5C87A8274785DAULL,
		0x7BA84F231E20163FULL,
		0xD926BA1695338E07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x42D9DBAA8E800000ULL,
		0xEA09D1E17690949CULL,
		0xC8C788058FFB9721ULL,
		0x85A54CE381DEEA13ULL,
		0x00000000003649AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
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
		0x2F12B3A8B54CFCB8ULL,
		0x96413E2ACA6591C0ULL,
		0x44EF6CDBC9636FAFULL,
		0x99ACF8837329A04BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x533F2E0000000000ULL,
		0x9964700BC4ACEA2DULL,
		0x58DBEBE5904F8AB2ULL,
		0xCA6812D13BDB36F2ULL,
		0x000000266B3E20DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
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
		0x8C4C7A814EF49BD4ULL,
		0xF1AA0282D7A7AB89ULL,
		0x159ED8D74B2EA199ULL,
		0x77CA6726D49978B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3131EA053BD26F50ULL,
		0xC6A80A0B5E9EAE26ULL,
		0x567B635D2CBA8667ULL,
		0xDF299C9B5265E2E0ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0x6FABF7B9DEC64172ULL,
		0xADD966B32AE9AB21ULL,
		0x07BF32B5B704DD6CULL,
		0xF05976DA25D17781ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC64172000000000ULL,
		0xAE9AB216FABF7B9DULL,
		0x704DD6CADD966B32ULL,
		0x5D1778107BF32B5BULL,
		0x0000000F05976DA2ULL
	}};
	shift = 28;
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
		0xA882A536727633E7ULL,
		0xB979610F9DFA6EFBULL,
		0xF6893F5BC813748FULL,
		0x00B16D62918F013DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE700000000000000ULL,
		0xFBA882A536727633ULL,
		0x8FB979610F9DFA6EULL,
		0x3DF6893F5BC81374ULL,
		0x0000B16D62918F01ULL
	}};
	shift = 8;
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
		0x29EDE3D249BF06C2ULL,
		0xCF1BED9903D75FBCULL,
		0x9C90D60E0C9164FCULL,
		0x5CBFA4040A7C5A99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x853DBC7A4937E0D8ULL,
		0x99E37DB3207AEBF7ULL,
		0x33921AC1C1922C9FULL,
		0x0B97F480814F8B53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
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
		0x82C0BE06CDEDD6C5ULL,
		0xEDE100B61A243827ULL,
		0x9026CAFC740215C3ULL,
		0x7A1863986F533C23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CDEDD6C50000000ULL,
		0x61A24382782C0BE0ULL,
		0xC740215C3EDE100BULL,
		0x86F533C239026CAFULL,
		0x0000000007A18639ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 228;
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
		0xF440B477027D4BEAULL,
		0x737D780188E489CAULL,
		0xACC7917EC95E17FCULL,
		0x8CAB75FD70F8A507ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBEA0000000000000ULL,
		0x9CAF440B477027D4ULL,
		0x7FC737D780188E48ULL,
		0x507ACC7917EC95E1ULL,
		0x0008CAB75FD70F8AULL
	}};
	shift = 12;
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
		0x25455A7504A9580BULL,
		0x5D0E5D3E031A8752ULL,
		0xB37D56C19866FF8DULL,
		0x6C6E060B294FB5B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C00000000000000ULL,
		0x48951569D412A560ULL,
		0x35743974F80C6A1DULL,
		0xCACDF55B06619BFEULL,
		0x01B1B8182CA53ED6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 198;
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
		0xED5130F58043F545ULL,
		0x9807D1E0259529BFULL,
		0x97CA693F958A5B80ULL,
		0x0E8EA0E7A983F2BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8987AC021FAA280ULL,
		0x03E8F012CA94DFF6ULL,
		0xE5349FCAC52DC04CULL,
		0x475073D4C1F95D4BULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
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
		0x9196461439D919C3ULL,
		0x8D77C104B6249F0BULL,
		0x91FB8D6C6F9126C4ULL,
		0x975BEC9BD1E9BFA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61439D919C300000ULL,
		0x104B6249F0B91964ULL,
		0xD6C6F9126C48D77CULL,
		0xC9BD1E9BFA891FB8ULL,
		0x00000000000975BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 236;
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
		0x6118D97929DEACABULL,
		0x449EAA409CADFDB8ULL,
		0x3BA5E857194C6653ULL,
		0xB0D324E39BEABE8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6558000000000000ULL,
		0xEDC308C6CBC94EF5ULL,
		0x329A24F55204E56FULL,
		0xF479DD2F42B8CA63ULL,
		0x00058699271CDF55ULL
	}};
	shift = 13;
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
		0x0F0D7284A1A68D0BULL,
		0x75AB9485E56A35B5ULL,
		0x03748AE421CB2B45ULL,
		0x34E9EC03D01335B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5CA12869A342C000ULL,
		0xE521795A8D6D43C3ULL,
		0x22B90872CAD15D6AULL,
		0x7B00F404CD6D40DDULL,
		0x0000000000000D3AULL,
		0x0000000000000000ULL
	}};
	shift = 114;
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
		0x6AF94EE1E9C7EF02ULL,
		0xFF8311A4BFB0A057ULL,
		0x8795F07985498DF0ULL,
		0x19D1A2C0938D80B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD38FDE0400000000ULL,
		0x7F6140AED5F29DC3ULL,
		0x0A931BE1FF062349ULL,
		0x271B01650F2BE0F3ULL,
		0x0000000033A34581ULL
	}};
	shift = 31;
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
		0xE61239B3A1328C8AULL,
		0x129C2304F0250DE7ULL,
		0xD5DA13552765CBE8ULL,
		0x8E40565E67F0712FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA322800000000000ULL,
		0x4379F9848E6CE84CULL,
		0x72FA04A708C13C09ULL,
		0x1C4BF57684D549D9ULL,
		0x00002390159799FCULL
	}};
	shift = 18;
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
		0xF9CAECDA6EEF82DDULL,
		0x15339AF96328BAB7ULL,
		0xCCB37BE540D5EB04ULL,
		0x58144BF486319EBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D9B4DDDF05BA000ULL,
		0x735F2C651756FF39ULL,
		0x6F7CA81ABD6082A6ULL,
		0x897E90C633D7D996ULL,
		0x0000000000000B02ULL
	}};
	shift = 51;
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
		0xBA31C435FFD619A8ULL,
		0xF8AE42265F899DE4ULL,
		0x112974F6BA9EA880ULL,
		0x1BDA81EA18045546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x19A8000000000000ULL,
		0x9DE4BA31C435FFD6ULL,
		0xA880F8AE42265F89ULL,
		0x5546112974F6BA9EULL,
		0x00001BDA81EA1804ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0xBD1BAFEB1078F46CULL,
		0xAA5CD15B4DE36C18ULL,
		0xE25B650E19071B44ULL,
		0x0C11F294FADDAB00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDD7F5883C7A36000ULL,
		0xE68ADA6F1B60C5E8ULL,
		0xDB2870C838DA2552ULL,
		0x8F94A7D6ED580712ULL,
		0x0000000000000060ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
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
		0x204B4D12CA3C167BULL,
		0xCC3B0382894EB242ULL,
		0x123B464FA0F75F13ULL,
		0xCA63BAC742695788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x689651E0B3D80000ULL,
		0x1C144A759211025AULL,
		0x327D07BAF89E61D8ULL,
		0xD63A134ABC4091DAULL,
		0x000000000006531DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
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
		0x3F50DBC89D54A185ULL,
		0x3C1D2C4D841BBFE1ULL,
		0x9C69D3A159194A62ULL,
		0xED9B84F61ACBCCA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5000000000000000ULL,
		0x13F50DBC89D54A18ULL,
		0x23C1D2C4D841BBFEULL,
		0x89C69D3A159194A6ULL,
		0x0ED9B84F61ACBCCAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
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
		0xA0857AF168788E88ULL,
		0x481A4228A18DDFA4ULL,
		0x0C48953928B7F2C4ULL,
		0xC2794F683B7EB733ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC5A1E23A2000000ULL,
		0x8A286377E928215EULL,
		0x4E4A2DFCB1120690ULL,
		0xDA0EDFADCCC31225ULL,
		0x0000000000309E53ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
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
		0x41EC9E1D025A7866ULL,
		0x6015DB9D809DCEF6ULL,
		0x525CC5ACA749E46BULL,
		0xB78A7ED46E78A2ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x907B278740969E19ULL,
		0xD80576E7602773BDULL,
		0xD497316B29D2791AULL,
		0x2DE29FB51B9E28AAULL
	}};
	shift = 2;
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
		0xDC4B842368A6FAF5ULL,
		0x9EDA0B704FB12800ULL,
		0xB99E7DA30B4DDD18ULL,
		0x12C8420F40765D6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA6FAF50000000000ULL,
		0xB12800DC4B842368ULL,
		0x4DDD189EDA0B704FULL,
		0x765D6BB99E7DA30BULL,
		0x00000012C8420F40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
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
		0x3AA65EFE8AC483B7ULL,
		0xEDC4A983279F8854ULL,
		0x588D0B9E061775EBULL,
		0x0D087D126350082BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBFA2B120EDC00000ULL,
		0x60C9E7E2150EA997ULL,
		0xE78185DD7AFB712AULL,
		0x4498D4020AD62342ULL,
		0x000000000003421FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
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
		0xC26DC59F7450F47FULL,
		0x1E111E5FEA71777BULL,
		0x579EF9EF823B0C84ULL,
		0xDA1E5C630A408B77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x26DC59F7450F47F0ULL,
		0xE111E5FEA71777BCULL,
		0x79EF9EF823B0C841ULL,
		0xA1E5C630A408B775ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
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
		0xBA56DFB1FAA6B3ADULL,
		0x9E4D3815BD401152ULL,
		0x8778694896E61EA7ULL,
		0xC9CAC2350BB8BB67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AD0000000000000ULL,
		0x152BA56DFB1FAA6BULL,
		0xEA79E4D3815BD401ULL,
		0xB678778694896E61ULL,
		0x000C9CAC2350BB8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 204;
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
		0x87C0663ABB550EB3ULL,
		0xBB50F518DA873698ULL,
		0x91481F020D6975B4ULL,
		0x5B9E4D390183D5C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3ABB550EB3000000ULL,
		0x18DA87369887C066ULL,
		0x020D6975B4BB50F5ULL,
		0x390183D5C291481FULL,
		0x00000000005B9E4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
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
		0x24FF9C193A55F285ULL,
		0x0B129C2967257851ULL,
		0x4B9AD6EC02FA01A9ULL,
		0xECAF7C58D9998657ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE7064E957CA1400ULL,
		0x4A70A59C95E14493ULL,
		0x6B5BB00BE806A42CULL,
		0xBDF1636666195D2EULL,
		0x00000000000003B2ULL,
		0x0000000000000000ULL
	}};
	shift = 118;
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
		0x03A5F83FC71107A1ULL,
		0x7DCD403C52E5895FULL,
		0xDB53CD2AF80AB3C0ULL,
		0x0E1B0BD47BCB7B34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF420000000000000ULL,
		0x2BE074BF07F8E220ULL,
		0x780FB9A8078A5CB1ULL,
		0x669B6A79A55F0156ULL,
		0x0001C3617A8F796FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
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
		0xA03D64B003C05420ULL,
		0x80CB51860787155DULL,
		0x130DB60541784BECULL,
		0x1017E192BC42DC75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2000000000000000ULL,
		0x5DA03D64B003C054ULL,
		0xEC80CB5186078715ULL,
		0x75130DB60541784BULL,
		0x001017E192BC42DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 200;
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
		0x4A183858631E2D94ULL,
		0x6DD525CADDED224CULL,
		0x63C3353BE706ECC1ULL,
		0xD8F7350FF0A36FBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2860E1618C78B650ULL,
		0xB754972B77B48931ULL,
		0x8F0CD4EF9C1BB305ULL,
		0x63DCD43FC28DBEF9ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 254;
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
		0x88040F61B90F840BULL,
		0x1DF8BB2C5B5272F5ULL,
		0xEFB633428D4599FEULL,
		0xCBDB396E9A351354ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD86E43E102C00000ULL,
		0xCB16D49CBD620103ULL,
		0xD0A351667F877E2EULL,
		0x5BA68D44D53BED8CULL,
		0x000000000032F6CEULL,
		0x0000000000000000ULL
	}};
	shift = 106;
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
		0x413D3C3165205BF3ULL,
		0xF32B68C2201AEA28ULL,
		0x56B6FAB1A7BA398DULL,
		0x878915B7BAD1453EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x165205BF30000000ULL,
		0x2201AEA28413D3C3ULL,
		0x1A7BA398DF32B68CULL,
		0x7BAD1453E56B6FABULL,
		0x000000000878915BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x27586F799E776A12ULL,
		0x0557B29CA712FC9DULL,
		0x4A5970E51A8E3234ULL,
		0x937F7514D355C688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC37BCCF3BB50900ULL,
		0xABD94E53897E4E93ULL,
		0x2CB8728D47191A02ULL,
		0xBFBA8A69AAE34425ULL,
		0x0000000000000049ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 249;
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
		0x0E310FC45E2A3CDCULL,
		0xA23EB29DC4134759ULL,
		0xCA048A54D95B939CULL,
		0xC0EA82289E64F4C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0x6438C43F1178A8F3ULL,
		0x7288FACA77104D1DULL,
		0x2328122953656E4EULL,
		0x0303AA08A27993D3ULL
	}};
	shift = 6;
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
		0x306F087289A78B1BULL,
		0x3DCD4782428A5584ULL,
		0x2B534DF9A4AEAAC9ULL,
		0x80F4AC1F07A1B06BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x1837843944D3C58DULL,
		0x9EE6A3C121452AC2ULL,
		0x95A9A6FCD2575564ULL,
		0x407A560F83D0D835ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
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
		0xAD1D5B5F96465C56ULL,
		0x383CA2383CD19207ULL,
		0x5A776B9D76268399ULL,
		0xF77053083AE474FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD1D5B5F96465C56ULL,
		0x383CA2383CD19207ULL,
		0x5A776B9D76268399ULL,
		0xF77053083AE474FEULL
	}};
	shift = 0;
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
		0xA4C3FDA66E2CAC2AULL,
		0xEDC8DAF2F85761B0ULL,
		0xF1227902C39C665CULL,
		0xE7F4D0E056976962ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC595854000000000ULL,
		0x0AEC3614987FB4CDULL,
		0x738CCB9DB91B5E5FULL,
		0xD2ED2C5E244F2058ULL,
		0x0000001CFE9A1C0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 219;
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
		0xAE9D1029DA27F5D4ULL,
		0x8F7317E314B5C559ULL,
		0x5F30D158B9D4D645ULL,
		0xEBE119D873BE3F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFAEA000000000000ULL,
		0xE2ACD74E8814ED13ULL,
		0x6B22C7B98BF18A5AULL,
		0x1FB0AF9868AC5CEAULL,
		0x000075F08CEC39DFULL,
		0x0000000000000000ULL
	}};
	shift = 81;
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
		0xC11FF37D7DFC170AULL,
		0x69B8A8AFDCC0CD62ULL,
		0xD1F1B78C8BD26F33ULL,
		0x7FD6DE8B874CB815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCDF5F7F05C280000ULL,
		0xA2BF7303358B047FULL,
		0xDE322F49BCCDA6E2ULL,
		0x7A2E1D32E05747C6ULL,
		0x000000000001FF5BULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x98725361AD1C95BAULL,
		0xE6FBED3A06E3328BULL,
		0x18E28C42C534A268ULL,
		0xC99AF72FB649E55BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9B0D68E4ADD00000ULL,
		0x69D03719945CC392ULL,
		0x621629A5134737DFULL,
		0xB97DB24F2AD8C714ULL,
		0x0000000000064CD7ULL
	}};
	shift = 45;
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
		0xE00275AC134D2CE6ULL,
		0x975EFB49A14E3139ULL,
		0xB5925A8C3211004DULL,
		0x2AAD222AE3180931ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x34B3980000000000ULL,
		0x38C4E78009D6B04DULL,
		0x4401365D7BED2685ULL,
		0x6024C6D6496A30C8ULL,
		0x000000AAB488AB8CULL
	}};
	shift = 22;
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
		0x81B01857F3F31890ULL,
		0xAFA10D70EDAB3F54ULL,
		0x6C62F37D73D350D2ULL,
		0xE8E5A542F59F77C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9F98C4800000000ULL,
		0x76D59FAA40D80C2BULL,
		0xB9E9A86957D086B8ULL,
		0x7ACFBBE1363179BEULL,
		0x000000007472D2A1ULL
	}};
	shift = 33;
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
		0x110C659B04664982ULL,
		0xF6A71A77F8A364E3ULL,
		0x082CF43A7274D087ULL,
		0x03868218DE24B1A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9820000000000000ULL,
		0x4E3110C659B04664ULL,
		0x087F6A71A77F8A36ULL,
		0x1A2082CF43A7274DULL,
		0x00003868218DE24BULL
	}};
	shift = 12;
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
		0xC2F06D5731C80369ULL,
		0x2109FE5607E6F775ULL,
		0xC9E758ADF72BD21CULL,
		0x0C307F65AFE0C837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7200DA4000000000ULL,
		0xF9BDDD70BC1B55CCULL,
		0xCAF48708427F9581ULL,
		0xF8320DF279D62B7DULL,
		0x000000030C1FD96BULL,
		0x0000000000000000ULL
	}};
	shift = 90;
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
		0x37A59EBD96B5D7CEULL,
		0xC5415D75A32F5761ULL,
		0xD757CFC2F33AB43DULL,
		0x524E4B57B8176B9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x4DE967AF65AD75F3ULL,
		0x7150575D68CBD5D8ULL,
		0xF5D5F3F0BCCEAD0FULL,
		0x149392D5EE05DAE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
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
		0x9C0D05FBBD0E609DULL,
		0x2E99CD3517332977ULL,
		0x20606A5CE57CCA36ULL,
		0xD497B14B79FD54E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CC13A0000000000ULL,
		0x6652EF381A0BF77AULL,
		0xF9946C5D339A6A2EULL,
		0xFAA9C840C0D4B9CAULL,
		0x000001A92F6296F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 215;
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
		0x5DAEE47A26698FF5ULL,
		0x781E4ABFAB9969C0ULL,
		0xFD085A192CE8F6AEULL,
		0x771B294DEB48F565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x2ED7723D1334C7FAULL,
		0x3C0F255FD5CCB4E0ULL,
		0xFE842D0C96747B57ULL,
		0x3B8D94A6F5A47AB2ULL,
		0x0000000000000000ULL
	}};
	shift = 65;
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
		0x0CF3273405E83A63ULL,
		0x6797814D1DE8C223ULL,
		0xBE019964AE61C6AAULL,
		0xA623CD578E86E3E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A0E98C000000000ULL,
		0x7A3088C33CC9CD01ULL,
		0x9871AA99E5E05347ULL,
		0xA1B8FA6F8066592BULL,
		0x0000002988F355E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 218;
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
		0x068335B11F987E8FULL,
		0x92750B9684330F69ULL,
		0x51ED8EC36B85F789ULL,
		0x969D4C97C441E3B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x41A0CD6C47E61FA3ULL,
		0x649D42E5A10CC3DAULL,
		0x147B63B0DAE17DE2ULL,
		0x25A75325F11078ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
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
		0xFCC85D38CF5E0A28ULL,
		0x3DB2440DFAAE15D5ULL,
		0x1A04050EF01E7FDBULL,
		0xA17845E29A57A04DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE33D7828A0000000ULL,
		0x37EAB85757F32174ULL,
		0x3BC079FF6CF6C910ULL,
		0x8A695E8134681014ULL,
		0x000000000285E117ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 230;
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
		0x07E2500D78C952FBULL,
		0x67C94954075CF730ULL,
		0x69B98BA3AB7F8030ULL,
		0x4A88A9FDFA240004ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x952FB00000000000ULL,
		0xCF73007E2500D78CULL,
		0xF803067C94954075ULL,
		0x4000469B98BA3AB7ULL,
		0x000004A88A9FDFA2ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
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
		0x547DD4C1D1E946A6ULL,
		0x85F6350F0721E091ULL,
		0x91ED22C6D3565DFAULL,
		0x3109C7C32D25F337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3EEA60E8F4A3530ULL,
		0x2FB1A878390F048AULL,
		0x8F6916369AB2EFD4ULL,
		0x884E3E19692F99BCULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
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
		0x2AE3732D8666920AULL,
		0xBE77DEA3A5D7B9F5ULL,
		0xE208A15B2221866EULL,
		0x919FB9965263E4DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCCB6199A48280000ULL,
		0x7A8E975EE7D4AB8DULL,
		0x856C888619BAF9DFULL,
		0xE659498F936F8822ULL,
		0x000000000002467EULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0xFEBAF0DD813F308DULL,
		0xB5439EF1BF3701E8ULL,
		0xC973260C4EE3A2F6ULL,
		0xD990066711DFBBBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBC37604FCC23400ULL,
		0x0E7BC6FCDC07A3FAULL,
		0xCC98313B8E8BDAD5ULL,
		0x40199C477EEEF725ULL,
		0x0000000000000366ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
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
		0x217665A9D331ECF9ULL,
		0xA0AC2A6AA265A7DCULL,
		0xDF27DB68EC7E9FF1ULL,
		0xA935DF643CEBA1C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB3E4000000000000ULL,
		0x9F7085D996A74CC7ULL,
		0x7FC682B0A9AA8996ULL,
		0x87077C9F6DA3B1FAULL,
		0x0002A4D77D90F3AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 142;
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
		0xD9C6C12C988E1981ULL,
		0x4E7EF6628C8AB2ABULL,
		0x2E2C3A1605253879ULL,
		0xE7B151808A196A9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8660400000000000ULL,
		0xACAAF671B04B2623ULL,
		0x4E1E539FBD98A322ULL,
		0x5AA7CB8B0E858149ULL,
		0x000039EC54602286ULL
	}};
	shift = 18;
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
		0x4F0E90E72D029EDFULL,
		0x067DFC09C3C8E7EEULL,
		0xC4D3D9951509083BULL,
		0x0A9C141B94B07F31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x2787487396814F6FULL,
		0x833EFE04E1E473F7ULL,
		0xE269ECCA8A84841DULL,
		0x054E0A0DCA583F98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
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
		0xA12B6B32359C189AULL,
		0x758F1AA695C82598ULL,
		0x601C3B78B235FBD4ULL,
		0x00D9B9826ABE04C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6646B38313400000ULL,
		0x54D2B904B314256DULL,
		0x6F1646BF7A8EB1E3ULL,
		0x304D57C0984C0387ULL,
		0x0000000000001B37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 235;
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
		0xE0242D123755E924ULL,
		0x52DB9DD9B597614BULL,
		0x82FD22DEA48B7952ULL,
		0x40A9ECF5D53C53E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBD24800000000000ULL,
		0xEC297C0485A246EAULL,
		0x6F2A4A5B73BB36B2ULL,
		0x8A7CD05FA45BD491ULL,
		0x000008153D9EBAA7ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
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
		0x7E9CA0122CF66DC7ULL,
		0xE8C3E9AA1C32ABC0ULL,
		0x3A09700463223765ULL,
		0x1C5BB427239563A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5009167B36E38000ULL,
		0xF4D50E1955E03F4EULL,
		0xB80231911BB2F461ULL,
		0xDA1391CAB1D11D04ULL,
		0x0000000000000E2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
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
		0x708AFBCB5950D42EULL,
		0x8606BF3DCDB85EF9ULL,
		0xDBB5417B879D843EULL,
		0xD2F416E74A642C05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6A17000000000000ULL,
		0x2F7CB8457DE5ACA8ULL,
		0xC21F43035F9EE6DCULL,
		0x1602EDDAA0BDC3CEULL,
		0x0000697A0B73A532ULL
	}};
	shift = 17;
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
		0x533389B13CEA68F2ULL,
		0x0E32021209A632F9ULL,
		0x9A3C2F87535C97EFULL,
		0xA7DB036C35AEA9FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF3A9A3C800000000ULL,
		0x2698CBE54CCE26C4ULL,
		0x4D725FBC38C80848ULL,
		0xD6BAA7F668F0BE1DULL,
		0x000000029F6C0DB0ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
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
		0x8983307F4B520568ULL,
		0xD31328632573F757ULL,
		0x4C53136970B621D0ULL,
		0x202CB1FDE57F0A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA000000000000000ULL,
		0x5E260CC1FD2D4815ULL,
		0x434C4CA18C95CFDDULL,
		0xF1314C4DA5C2D887ULL,
		0x0080B2C7F795FC28ULL
	}};
	shift = 6;
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
		0x4D3F28AD6A70CC14ULL,
		0x229CDAA35BAC8A5DULL,
		0xB1EBF7C0B0D929D5ULL,
		0x6DFA345BE517433BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC140000000000000ULL,
		0xA5D4D3F28AD6A70CULL,
		0x9D5229CDAA35BAC8ULL,
		0x33BB1EBF7C0B0D92ULL,
		0x0006DFA345BE5174ULL
	}};
	shift = 12;
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
		0xE97EB5FA085D2590ULL,
		0x3584E77DBD0CFE65ULL,
		0xEA96A8F79FF84A2FULL,
		0x4A4599457AEF9813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xCBD2FD6BF410BA4BULL,
		0x5E6B09CEFB7A19FCULL,
		0x27D52D51EF3FF094ULL,
		0x00948B328AF5DF30ULL
	}};
	shift = 7;
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
		0xF4ABE41C21299E78ULL,
		0x4A83A5D5D44F3BE0ULL,
		0x1015F7EAF7F34C75ULL,
		0x741FB0262354F655ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E00000000000000ULL,
		0xF83D2AF907084A67ULL,
		0x1D52A0E9757513CEULL,
		0x9544057DFABDFCD3ULL,
		0x001D07EC0988D53DULL,
		0x0000000000000000ULL
	}};
	shift = 74;
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
		0x3FD6AB1EE02DEA9AULL,
		0x92AEA2E680D69DA3ULL,
		0x48DD67DF071D7B0FULL,
		0x9FAF739076DD72E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD53400000000000ULL,
		0xD3B467FAD563DC05ULL,
		0xAF61F255D45CD01AULL,
		0xAE5D091BACFBE0E3ULL,
		0x000013F5EE720EDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
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
		0x454C1AB6086CDF85ULL,
		0xACE96409BEBB692DULL,
		0x5ABB86F02F248EE2ULL,
		0xD96039238A365D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37E1400000000000ULL,
		0xDA4B515306AD821BULL,
		0x23B8AB3A59026FAEULL,
		0x975196AEE1BC0BC9ULL,
		0x000036580E48E28DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 210;
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
		0x00EBF19BE513936FULL,
		0x9F48A5AF494E75CEULL,
		0xAC84B500C2EE9B75ULL,
		0xF2088C3A17685827ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37CA2726DE000000ULL,
		0x5E929CEB9C01D7E3ULL,
		0x0185DD36EB3E914BULL,
		0x742ED0B04F59096AULL,
		0x0000000001E41118ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 231;
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
		0x4E0DF848B6EDAF75ULL,
		0xC4CCFA2E8533C7AAULL,
		0xE2BD01978C90F350ULL,
		0x00B63424BBA46C70ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BA8000000000000ULL,
		0x3D52706FC245B76DULL,
		0x9A862667D174299EULL,
		0x638715E80CBC6487ULL,
		0x000005B1A125DD23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 205;
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
		0xFFD83B6E926642ABULL,
		0x6F997A39EB0FEBC7ULL,
		0x15D26B63CF70ADEFULL,
		0x29BDF4B67F968125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AB0000000000000ULL,
		0xBC7FFD83B6E92664ULL,
		0xDEF6F997A39EB0FEULL,
		0x12515D26B63CF70AULL,
		0x00029BDF4B67F968ULL
	}};
	shift = 12;
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
		0xA327C03D905E9765ULL,
		0x0067573183015242ULL,
		0xFF06F5417A60BD9CULL,
		0x5076BB06DDEED041ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6417A5D94000000ULL,
		0xC60C05490A8C9F00ULL,
		0x05E982F670019D5CULL,
		0x1B77BB4107FC1BD5ULL,
		0x000000000141DAECULL
	}};
	shift = 38;
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
		0x45159D275C2E75A3ULL,
		0xB994439341E2D83FULL,
		0x84B02DCDF754571FULL,
		0x10F5F731632E66A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A30000000000000ULL,
		0x83F45159D275C2E7ULL,
		0x71FB994439341E2DULL,
		0x6A484B02DCDF7545ULL,
		0x00010F5F731632E6ULL
	}};
	shift = 12;
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
		0xE701CCFEC7FDA566ULL,
		0x144ACBDD96DAE519ULL,
		0x7E56A63E7228CDE8ULL,
		0x43F2B8CB29B5D6DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x3CE0399FD8FFB4ACULL,
		0x0289597BB2DB5CA3ULL,
		0x4FCAD4C7CE4519BDULL,
		0x087E57196536BADBULL
	}};
	shift = 3;
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
		0xB1BEF1F62D031288ULL,
		0x6A7F96F9C1420051ULL,
		0x43F04CB1FAED3390ULL,
		0x8A3713D16287428BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x637DE3EC5A062510ULL,
		0xD4FF2DF3828400A3ULL,
		0x87E09963F5DA6720ULL,
		0x146E27A2C50E8516ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
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
		0x481160B906F6B8FDULL,
		0x8AC61E6ACC1B16CAULL,
		0x16CBA61AA4C7281CULL,
		0xBF53E9A8F8F6BE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x06F6B8FD00000000ULL,
		0xCC1B16CA481160B9ULL,
		0xA4C7281C8AC61E6AULL,
		0xF8F6BE1D16CBA61AULL,
		0x00000000BF53E9A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
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
		0x8A5627283A6F9283ULL,
		0xFC86BD4E6C13F022ULL,
		0xFE4FD3FDC986D96BULL,
		0x9CAA72583CCF5DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4180000000000000ULL,
		0x11452B13941D37C9ULL,
		0xB5FE435EA73609F8ULL,
		0xF27F27E9FEE4C36CULL,
		0x004E55392C1E67AEULL
	}};
	shift = 9;
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
		0x428E9B77CEAF4EA1ULL,
		0x8E9B5685AB74F9CDULL,
		0x2BF1108A5677578DULL,
		0x204815CB4FC150E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE757A75080000000ULL,
		0xD5BA7CE6A1474DBBULL,
		0x2B3BABC6C74DAB42ULL,
		0xA7E0A87295F88845ULL,
		0x0000000010240AE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 225;
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
		0x6AB40FC82308CB51ULL,
		0x2BCD5DACF8141E52ULL,
		0x3608515C4590C692ULL,
		0x8DD1739720DE1082ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF90461196A200000ULL,
		0xB59F0283CA4D5681ULL,
		0x2B88B218D24579ABULL,
		0x72E41BC21046C10AULL,
		0x000000000011BA2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 171;
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
		0x5A0DD2ECB0A2604EULL,
		0x4A0A9130C3B03FFDULL,
		0x7983CBDFA084D15FULL,
		0x71B8169753205367ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x41BA5D96144C09C0ULL,
		0x415226187607FFABULL,
		0x30797BF4109A2BE9ULL,
		0x3702D2EA640A6CEFULL,
		0x000000000000000EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 187;
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
		0xBA8903C88753D35FULL,
		0xF9A54C4CEC3E2FB9ULL,
		0x73AD1FD6C5E2E4C3ULL,
		0x1BDB21AD34F858EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9E9AF8000000000ULL,
		0x1F17DCDD4481E443ULL,
		0xF17261FCD2A62676ULL,
		0x7C2C77B9D68FEB62ULL,
		0x0000000DED90D69AULL,
		0x0000000000000000ULL
	}};
	shift = 89;
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
		0x2989240B9AA93716ULL,
		0x64AB5FB2548A04E3ULL,
		0xBFBA4A589F6D9C25ULL,
		0x4501546EA8C5AF11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x902E6AA4DC580000ULL,
		0x7EC95228138CA624ULL,
		0x29627DB6709592ADULL,
		0x51BAA316BC46FEE9ULL,
		0x0000000000011405ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
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
		0x6B0100D81161135CULL,
		0xDDF801D951435436ULL,
		0x6B8F8845120AC5E6ULL,
		0xCC0C92AC77DF4EC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD81161135C000000ULL,
		0xD9514354366B0100ULL,
		0x45120AC5E6DDF801ULL,
		0xAC77DF4EC66B8F88ULL,
		0x0000000000CC0C92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 232;
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
		0x81C38117A3745278ULL,
		0x35A9AFCD745302ECULL,
		0xAC333F3736F16D93ULL,
		0x5D50DA00E07A279BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7A37452780000000ULL,
		0xD745302EC81C3811ULL,
		0x736F16D9335A9AFCULL,
		0x0E07A279BAC333F3ULL,
		0x0000000005D50DA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0xF438F362E7372883ULL,
		0x77A6B570D941DED5ULL,
		0xED97BE55027A9F2AULL,
		0x63EB29D3B3D5CB05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5106000000000000ULL,
		0xBDABE871E6C5CE6EULL,
		0x3E54EF4D6AE1B283ULL,
		0x960BDB2F7CAA04F5ULL,
		0x0000C7D653A767ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 207;
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
		0x5A2D67DF63EBEFD3ULL,
		0x8D51D6FFC684D3E7ULL,
		0x5AD08D33D5B804A8ULL,
		0x017D28B6C334CE78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD67DF63EBEFD3000ULL,
		0x1D6FFC684D3E75A2ULL,
		0x08D33D5B804A88D5ULL,
		0xD28B6C334CE785ADULL,
		0x0000000000000017ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
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
		0xC0493B2A8F580CE4ULL,
		0x3BA02A6182494BBAULL,
		0x18BA6AC7ACEE5C21ULL,
		0x263633390C86CF23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7200000000000000ULL,
		0xDD60249D9547AC06ULL,
		0x109DD01530C124A5ULL,
		0x918C5D3563D6772EULL,
		0x00131B199C864367ULL
	}};
	shift = 9;
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
		0xD2EB0C6D0F47E1D9ULL,
		0x2F7C860C91FDAD75ULL,
		0xF8F9EDE52F25B66BULL,
		0x22685765EB9D529EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC3B200000000000ULL,
		0xB5AEBA5D618DA1E8ULL,
		0xB6CD65EF90C1923FULL,
		0xAA53DF1F3DBCA5E4ULL,
		0x0000044D0AECBD73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 211;
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
		0x08EAE599DE7548FEULL,
		0x1DDCAA92E069970FULL,
		0x435CC5BCA35FFCE3ULL,
		0xDF8FACDA74CC1BA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0x7847572CCEF3AA47ULL,
		0x18EEE55497034CB8ULL,
		0x121AE62DE51AFFE7ULL,
		0x06FC7D66D3A660DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 133;
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
		0xDBA44054312AE69AULL,
		0x2DD4327019C18990ULL,
		0x8E2EED30FC8E6ADDULL,
		0xF37155BCB9C496A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4D00000000000000ULL,
		0xC86DD2202A189573ULL,
		0x6E96EA19380CE0C4ULL,
		0x52471776987E4735ULL,
		0x0079B8AADE5CE24BULL,
		0x0000000000000000ULL
	}};
	shift = 73;
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
		0xF12630ED5FE552FAULL,
		0x8BAB94CA03BDE78AULL,
		0xC0317385A6DE44F6ULL,
		0x251AADD1E2C4A4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FA0000000000000ULL,
		0x78AF12630ED5FE55ULL,
		0x4F68BAB94CA03BDEULL,
		0x4FBC0317385A6DE4ULL,
		0x000251AADD1E2C4AULL
	}};
	shift = 12;
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
		0x5A5FE4522F14CC58ULL,
		0xFE961C8EB148AC1BULL,
		0x0F721C391DE1C5D7ULL,
		0xE845EC705DA001B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x6D697F9148BC5331ULL,
		0x5FFA58723AC522B0ULL,
		0xD83DC870E4778717ULL,
		0x03A117B1C1768006ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
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
		0xCA71B0847E28EC61ULL,
		0x5B15C5978ED741C3ULL,
		0x3E188E5291B60A04ULL,
		0x3F696BE577EC2729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C20000000000000ULL,
		0x38794E36108FC51DULL,
		0x408B62B8B2F1DAE8ULL,
		0xE527C311CA5236C1ULL,
		0x0007ED2D7CAEFD84ULL
	}};
	shift = 11;
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
		0x9E62336D929E792DULL,
		0x88B059A3F7907719ULL,
		0x9E3B9D0E56EAC120ULL,
		0x548B255765315F52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE62336D929E792D0ULL,
		0x8B059A3F79077199ULL,
		0xE3B9D0E56EAC1208ULL,
		0x48B255765315F529ULL,
		0x0000000000000005ULL
	}};
	shift = 60;
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
		0xD66D3C9B4D933CDBULL,
		0x739D1C1A1894291DULL,
		0x681F81360BE3ADEFULL,
		0xFC2B78FF4E46040FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79B6000000000000ULL,
		0x523BACDA79369B26ULL,
		0x5BDEE73A38343128ULL,
		0x081ED03F026C17C7ULL,
		0x0001F856F1FE9C8CULL
	}};
	shift = 15;
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
		0x831EA5D3C75CBB26ULL,
		0x39922CE6900AE346ULL,
		0xE57454E5065FED10ULL,
		0x2CD1D366AA72726BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE5D930000000000ULL,
		0x0571A3418F52E9E3ULL,
		0x2FF6881CC9167348ULL,
		0x393935F2BA2A7283ULL,
		0x0000001668E9B355ULL
	}};
	shift = 25;
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
		0x83A5B2E6600F43AEULL,
		0x84DB61413345EE5DULL,
		0xCA09BA53488F1871ULL,
		0xF1B869378B1526E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0EB8000000000000ULL,
		0xB9760E96CB99803DULL,
		0x61C6136D8504CD17ULL,
		0x9B972826E94D223CULL,
		0x0003C6E1A4DE2C54ULL
	}};
	shift = 14;
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
		0xCAE7BBDD77132CFDULL,
		0xD0939B4DE04D6D89ULL,
		0x94E6D2E8E2192FB0ULL,
		0x71CB549D666BD73EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7E80000000000000ULL,
		0xC4E573DDEEBB8996ULL,
		0xD86849CDA6F026B6ULL,
		0x9F4A736974710C97ULL,
		0x0038E5AA4EB335EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
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
		0x78F226C0F9DC2016ULL,
		0x063E183A28B0062EULL,
		0xC24826BF1B42B136ULL,
		0x301668F8EABF1E42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E44D81F3B8402C0ULL,
		0xC7C307451600C5CFULL,
		0x4904D7E3685626C0ULL,
		0x02CD1F1D57E3C858ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 251;
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
		0x0D0FA3254B8D3D7BULL,
		0x16CF76AAEAA4427EULL,
		0xE386044CC49429D2ULL,
		0x7C1B312C68B36DBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x0687D192A5C69EBDULL,
		0x0B67BB557552213FULL,
		0xF1C30226624A14E9ULL,
		0x3E0D98963459B6DFULL
	}};
	shift = 1;
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
		0x7678FB857CF39649ULL,
		0x7BAA4FFE15271449ULL,
		0xE33F40B85B8CFAEBULL,
		0xCB3BC33447AA4402ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x79CB248000000000ULL,
		0x938A24BB3C7DC2BEULL,
		0xC67D75BDD527FF0AULL,
		0xD52201719FA05C2DULL,
		0x000000659DE19A23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 153;
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
		0xBBDED3B867E46792ULL,
		0xB507CDE4D59DFD46ULL,
		0x36BF8096192CB0FDULL,
		0x226D1F86DDC8B8B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6792000000000000ULL,
		0xFD46BBDED3B867E4ULL,
		0xB0FDB507CDE4D59DULL,
		0xB8B036BF8096192CULL,
		0x0000226D1F86DDC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 208;
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
		0x233139389756A2F1ULL,
		0x8B3C555953274265ULL,
		0x4CCC73EF45762F8EULL,
		0xA71A6CE9BA0E053FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL,
		0xA466272712EAD45EULL,
		0xD1678AAB2A64E84CULL,
		0xE9998E7DE8AEC5F1ULL,
		0x14E34D9D3741C0A7ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
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
		0x69C0987B45347F4AULL,
		0xB409B9F0F84C090DULL,
		0xE41F32A9467CF781ULL,
		0x41DEF760515503D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1ED14D1FD2800000ULL,
		0x7C3E1302435A7026ULL,
		0xAA519F3DE06D026EULL,
		0xD8145540F4F907CCULL,
		0x00000000001077BDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
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
		0x6E7F5EA4D89ED3E1ULL,
		0x093D2F8D3EF81B3BULL,
		0x6F256E4084364C13ULL,
		0xC2BECE5508A49A20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF840000000000000ULL,
		0xCEDB9FD7A93627B4ULL,
		0x04C24F4BE34FBE06ULL,
		0x881BC95B90210D93ULL,
		0x0030AFB395422926ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 138;
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
		0x6EDD3EB33DAA2BC8ULL,
		0x3E80E6FC917EDFB6ULL,
		0x0908F606F92EC685ULL,
		0xA7BB8D3DAC6DC18DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6A8AF20000000000ULL,
		0x5FB7ED9BB74FACCFULL,
		0x4BB1A14FA039BF24ULL,
		0x1B706342423D81BEULL,
		0x00000029EEE34F6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 154;
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
		0xB8F9463925FE508CULL,
		0xB96E3CDFFE73741CULL,
		0x47508DD772488528ULL,
		0x1E46E0DC3FEC9F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x497F942300000000ULL,
		0xFF9CDD072E3E518EULL,
		0xDC92214A2E5B8F37ULL,
		0x0FFB27D2D1D42375ULL,
		0x000000000791B837ULL
	}};
	shift = 34;
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
		0x996334C3FD09BB86ULL,
		0xC734D15F0A6B923EULL,
		0x9339CC2417352FDBULL,
		0xA6BD148548C10A81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFE84DDC300000000ULL,
		0x8535C91F4CB19A61ULL,
		0x0B9A97EDE39A68AFULL,
		0xA4608540C99CE612ULL,
		0x00000000535E8A42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
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
		0xB8EFBF4C342AB6C7ULL,
		0x8B3F74666935AFFAULL,
		0xB9D5A679451DFDBEULL,
		0xBB6254DD0D883335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x55B6380000000000ULL,
		0xAD7FD5C77DFA61A1ULL,
		0xEFEDF459FBA33349ULL,
		0x4199ADCEAD33CA28ULL,
		0x000005DB12A6E86CULL,
		0x0000000000000000ULL
	}};
	shift = 85;
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
		0x315CB8BB187086B1ULL,
		0x8227FFF110B49601ULL,
		0x8D7DDCEA8953F770ULL,
		0x5E9B669A0CC442D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB187086B10000000ULL,
		0x110B49601315CB8BULL,
		0xA8953F7708227FFFULL,
		0xA0CC442D98D7DDCEULL,
		0x0000000005E9B669ULL
	}};
	shift = 36;
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
		0x55252BEE532A2034ULL,
		0x26120D1AA7663926ULL,
		0xD6495BD79F95F453ULL,
		0x24F0E8E4521394B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEE532A2034000000ULL,
		0x1AA766392655252BULL,
		0xD79F95F45326120DULL,
		0xE4521394B0D6495BULL,
		0x000000000024F0E8ULL
	}};
	shift = 40;
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
		0xE7A581E0814F4ED6ULL,
		0xE6C70F0B9B1F4DB0ULL,
		0xF9D889E4DE7E4F13ULL,
		0x6C706383EC0B9622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x39E960782053D3B5ULL,
		0xF9B1C3C2E6C7D36CULL,
		0xBE762279379F93C4ULL,
		0x1B1C18E0FB02E588ULL
	}};
	shift = 2;
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
		0x38F39B3ECB99BB52ULL,
		0xC898AC691B132AEEULL,
		0x7BE8D11DCCCDC745ULL,
		0x2B31FFFE74B71408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7D973376A4000000ULL,
		0xD2362655DC71E736ULL,
		0x3B999B8E8B913158ULL,
		0xFCE96E2810F7D1A2ULL,
		0x00000000005663FFULL
	}};
	shift = 39;
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
		0xCE328733EE139216ULL,
		0xC342D16B3B975D07ULL,
		0xF16ED30F9B1AF163ULL,
		0xB0EAAA787D36216CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27242C0000000000ULL,
		0x2EBA0F9C650E67DCULL,
		0x35E2C78685A2D677ULL,
		0x6C42D9E2DDA61F36ULL,
		0x00000161D554F0FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 151;
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
		0x04092485E5A07391ULL,
		0xB9F2753BABB81854ULL,
		0xB0B4821CEB3FB259ULL,
		0x815A70E65C991EB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5A07391000000000ULL,
		0xBB8185404092485EULL,
		0xB3FB259B9F2753BAULL,
		0xC991EB1B0B4821CEULL,
		0x0000000815A70E65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
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
		0x463C4687C1489EE4ULL,
		0xAF726950A00BEBF0ULL,
		0xE3D3FE670AF25B26ULL,
		0x0FFA1827C49EA844ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE2343E0A44F72000ULL,
		0x934A85005F5F8231ULL,
		0x9FF3385792D9357BULL,
		0xD0C13E24F542271EULL,
		0x000000000000007FULL
	}};
	shift = 53;
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
		0x2223E6EAF580C59BULL,
		0x587DDAA32D16950BULL,
		0xF8A842438DCE5C6BULL,
		0x5B74C4F9A7BD4543ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C59B00000000000ULL,
		0x6950B2223E6EAF58ULL,
		0xE5C6B587DDAA32D1ULL,
		0xD4543F8A842438DCULL,
		0x000005B74C4F9A7BULL
	}};
	shift = 20;
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
		0x05E284A438795338ULL,
		0xFB5B1D049DDF2B83ULL,
		0x9009C98160074163ULL,
		0x34C9FCA742F55858ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F2A67000000000ULL,
		0x3BBE57060BC50948ULL,
		0xC00E82C7F6B63A09ULL,
		0x85EAB0B120139302ULL,
		0x000000006993F94EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 223;
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
		0x3F3F8D560843AB59ULL,
		0xAF6D4754F79AC99EULL,
		0x9C1AEB8365B4A8EAULL,
		0x25238E70897B93CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x210EAD6400000000ULL,
		0xDE6B2678FCFE3558ULL,
		0x96D2A3AABDB51D53ULL,
		0x25EE4F3E706BAE0DULL,
		0x00000000948E39C2ULL
	}};
	shift = 30;
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
		0xAA22EB2FCED59DB5ULL,
		0x37C4BAA63187A656ULL,
		0x9997EB5C727DA739ULL,
		0x92D552EA3725AF64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x117597E76ACEDA80ULL,
		0xE25D5318C3D32B55ULL,
		0xCBF5AE393ED39C9BULL,
		0x6AA9751B92D7B24CULL,
		0x0000000000000049ULL
	}};
	shift = 57;
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
		0xC7FDC5C8C690D224ULL,
		0xE30C7F57A22B24AAULL,
		0xFCA214918E28815FULL,
		0x3346BBAB3AC3E8A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C690D2240000000ULL,
		0x7A22B24AAC7FDC5CULL,
		0x18E28815FE30C7F5ULL,
		0xB3AC3E8A4FCA2149ULL,
		0x0000000003346BBAULL,
		0x0000000000000000ULL
	}};
	shift = 100;
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
		0xF3F0E39B5CDB8BBDULL,
		0x27CB6D4C61C61DEFULL,
		0x0B390D175037445BULL,
		0x03B5FEEA0C58EE0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3F0E39B5CDB8BBD0ULL,
		0x7CB6D4C61C61DEFFULL,
		0xB390D175037445B2ULL,
		0x3B5FEEA0C58EE0F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
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
		0x8AEA192938630590ULL,
		0xA8C332CB0084E637ULL,
		0x2DCC14E48E573803ULL,
		0x86437E5D3367E37FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3863059000000000ULL,
		0x0084E6378AEA1929ULL,
		0x8E573803A8C332CBULL,
		0x3367E37F2DCC14E4ULL,
		0x0000000086437E5DULL,
		0x0000000000000000ULL
	}};
	shift = 96;
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
		0x5F38C7A60A6713A2ULL,
		0x7B0C9B8D8D3CD7F0ULL,
		0x5D2A81F5A4986CE1ULL,
		0xA656F910E8E20062ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8C7A60A6713A2000ULL,
		0xC9B8D8D3CD7F05F3ULL,
		0xA81F5A4986CE17B0ULL,
		0x6F910E8E200625D2ULL,
		0x0000000000000A65ULL
	}};
	shift = 52;
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
		0x30A8E077314D19F7ULL,
		0xD4965FB388E09DBFULL,
		0xFCB532F1B5C1A50CULL,
		0xF2D704D369BFF066ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x629A33EE00000000ULL,
		0x11C13B7E6151C0EEULL,
		0x6B834A19A92CBF67ULL,
		0xD37FE0CDF96A65E3ULL,
		0x00000001E5AE09A6ULL
	}};
	shift = 31;
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
		0x0AA958D5D406D55CULL,
		0xD9EE256E0D649C65ULL,
		0x6D976660AEAB2198ULL,
		0x9FDD076F617916CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2AA56357501B5570ULL,
		0x67B895B835927194ULL,
		0xB65D9982BAAC8663ULL,
		0x7F741DBD85E45B31ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
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
		0x710B050ED9C5DC2AULL,
		0xB5CFC6C90BE4ECC9ULL,
		0x2CECC0977C68CC2DULL,
		0x6B1F80B5F42473BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x50ED9C5DC2A00000ULL,
		0x6C90BE4ECC9710B0ULL,
		0x0977C68CC2DB5CFCULL,
		0x0B5F42473BB2CECCULL,
		0x000000000006B1F8ULL,
		0x0000000000000000ULL
	}};
	shift = 108;
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
		0x0D820734C99F123DULL,
		0x5B230C8EDA925196ULL,
		0x611731F2151448FCULL,
		0xA8203DAD549B30C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20734C99F123D000ULL,
		0x30C8EDA9251960D8ULL,
		0x731F2151448FC5B2ULL,
		0x03DAD549B30C2611ULL,
		0x0000000000000A82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 244;
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
		0xEB7B3F9F80AB2D17ULL,
		0xF5DE68E7215CC3D1ULL,
		0xD4F07129361BE01EULL,
		0x119D3AE35F2631A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD9FCFC055968B800ULL,
		0xF347390AE61E8F5BULL,
		0x838949B0DF00F7AEULL,
		0xE9D71AF9318D36A7ULL,
		0x000000000000008CULL
	}};
	shift = 53;
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
		0x85456C17BB0F3F7FULL,
		0x1646BC3524BA927AULL,
		0xA50200724D8F6696ULL,
		0x6A1F350BE6270177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x61E7EFE000000000ULL,
		0x97524F50A8AD82F7ULL,
		0xB1ECD2C2C8D786A4ULL,
		0xC4E02EF4A0400E49ULL,
		0x0000000D43E6A17CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
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
		0x4BF2A29E649AFD6BULL,
		0xF1493FA610D17791ULL,
		0x09A967DE1E1B6C71ULL,
		0x5462BBD99AC6BF0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEB58000000000000ULL,
		0xBC8A5F9514F324D7ULL,
		0x638F8A49FD30868BULL,
		0xF8784D4B3EF0F0DBULL,
		0x0002A315DECCD635ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
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
		0x6A64AEF94F2C4DF7ULL,
		0x9FE217F34219667CULL,
		0x377D8BB5032449ECULL,
		0x7B0C0C2BFFCA31AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6A64AEF94F2C4DF7ULL,
		0x9FE217F34219667CULL,
		0x377D8BB5032449ECULL,
		0x7B0C0C2BFFCA31AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0x327AD51B1279EA49ULL,
		0x01A9E50157655DCFULL,
		0x6D12DE3069CFB1FDULL,
		0x08A9501BDA6C3D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEA49000000000000ULL,
		0x5DCF327AD51B1279ULL,
		0xB1FD01A9E5015765ULL,
		0x3D176D12DE3069CFULL,
		0x000008A9501BDA6CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
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
		0x342835A9933041B1ULL,
		0xF290DAB2E3BA18E2ULL,
		0x9B8C9786FD938C91ULL,
		0x44CDFC85F4D7FDDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x8D0A0D6A64CC106CULL,
		0x7CA436ACB8EE8638ULL,
		0xA6E325E1BF64E324ULL,
		0x11337F217D35FF76ULL,
		0x0000000000000000ULL
	}};
	shift = 66;
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
		0x657243C351E47DFCULL,
		0xFB9F9BD41B6FF9C8ULL,
		0x2482A1BD0DFA3B41ULL,
		0x934298A7CE5C6B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE48786A3C8FBF800ULL,
		0x3F37A836DFF390CAULL,
		0x05437A1BF47683F7ULL,
		0x85314F9CB8D6E649ULL,
		0x0000000000000126ULL
	}};
	shift = 55;
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
	return 0;
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0010000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x0000000000000020ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000002000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
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
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000004ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 192;
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
		0x0000000000008000ULL,
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
		0x0000000000800000ULL,
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
	shift = 184;
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
		0x0000000000000008ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000080000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
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
		0x0000000008000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0008000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x0000000000010000ULL,
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
	shift = 84;
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
		0x0000000000000400ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000040000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
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
	return 0;
}