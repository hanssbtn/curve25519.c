#include "../tests.h"

int32_t curve25519_key_lshift_inplace_test(void) {
	printf("Inplace Key Left Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6E533444E98B9C6FULL,
		0x5CB597CA577086AEULL,
		0x003A9A02242B23CCULL,
		0x11C93BDA5CCA754DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x2E71BC0000000000ULL,
		0xC21AB9B94CD113A6ULL,
		0xAC8F3172D65F295DULL,
		0x29D53400EA680890ULL,
		0x0000004724EF6973ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int shift = 106;
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6E326F3884952CCEULL,
		0xAB581D3CB63991C5ULL,
		0x0A7E1F645FA8A6D4ULL,
		0x470BEC5457783A19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF3884952CCE00000ULL,
		0xD3CB63991C56E326ULL,
		0xF645FA8A6D4AB581ULL,
		0xC5457783A190A7E1ULL,
		0x00000000000470BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF666B05AA85891DFULL,
		0xFD54B4FCDE60A882ULL,
		0x227C8DF9CD47151CULL,
		0x50A76B6201EE5ED5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x7B33582D542C48EFULL,
		0x7EAA5A7E6F305441ULL,
		0x913E46FCE6A38A8EULL,
		0x2853B5B100F72F6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 127;
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7CC049C23C23D5E2ULL,
		0xCE221D11796AFE76ULL,
		0xF587F96C1867C450ULL,
		0x071360B74FFCDF82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23C23D5E20000000ULL,
		0x1796AFE767CC049CULL,
		0xC1867C450CE221D1ULL,
		0x74FFCDF82F587F96ULL,
		0x000000000071360BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B5361A11884AD5AULL,
		0x8CA0F255DA85CFA8ULL,
		0xC61DD4CC3C5A51EEULL,
		0x5DD6DCBE02462DB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD08C4256AD000000ULL,
		0x2AED42E7D445A9B0ULL,
		0x661E2D28F7465079ULL,
		0x5F012316D9630EEAULL,
		0x00000000002EEB6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBB818F597B8E8B26ULL,
		0x17DAA2E4A81B9D38ULL,
		0x541B888C7211B0A7ULL,
		0x6EE2C57D3C530C95ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x18F597B8E8B26000ULL,
		0xAA2E4A81B9D38BB8ULL,
		0xB888C7211B0A717DULL,
		0x2C57D3C530C95541ULL,
		0x00000000000006EEULL,
		0x0000000000000000ULL
	}};
	shift = 140;
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC22544EFC8A87DEDULL,
		0xDF06C4217D200115ULL,
		0xB619D274DC9A5797ULL,
		0x701DA906E3467A15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9150FBDA00000000ULL,
		0xFA40022B844A89DFULL,
		0xB934AF2FBE0D8842ULL,
		0xC68CF42B6C33A4E9ULL,
		0x00000000E03B520DULL
	}};
	shift = 225;
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE9D13D349A831060ULL,
		0xD7FD422522AC5ADBULL,
		0x6C55C74CD9944545ULL,
		0x5C29E48BD9A0E641ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C00000000000000ULL,
		0x5B7D3A27A6935062ULL,
		0xA8BAFFA844A4558BULL,
		0xC82D8AB8E99B3288ULL,
		0x000B853C917B341CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x754C1B097B16E46FULL,
		0x33674294115F1840ULL,
		0x63BD87A6D58F784FULL,
		0x6DFC70E4AEF26245ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEC5B91BC00000000ULL,
		0x457C6101D5306C25ULL,
		0x563DE13CCD9D0A50ULL,
		0xBBC989158EF61E9BULL,
		0x00000001B7F1C392ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC92BDBF715235A70ULL,
		0x1C3209CB7ED4BCA4ULL,
		0x6E425AC20F451448ULL,
		0x5D0C4D9521FAE451ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x92BDBF715235A700ULL,
		0xC3209CB7ED4BCA4CULL,
		0xE425AC20F4514481ULL,
		0xD0C4D9521FAE4516ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7FE4A6409CC078A5ULL,
		0x988572B31789B810ULL,
		0xAD4E9BC2D43FD840ULL,
		0x53F990946D7AC866ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA6409CC078A50000ULL,
		0x72B31789B8107FE4ULL,
		0x9BC2D43FD8409885ULL,
		0x90946D7AC866AD4EULL,
		0x00000000000053F9ULL
	}};
	shift = 208;
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE0701A6056C392B5ULL,
		0xC49EAACC936A3F13ULL,
		0x0F4E8A1DCF47924FULL,
		0x0DD21FB5B816E12DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7256A00000000000ULL,
		0x47E27C0E034C0AD8ULL,
		0xF249F893D559926DULL,
		0xDC25A1E9D143B9E8ULL,
		0x000001BA43F6B702ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 109;
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE71445ED88A27A52ULL,
		0xF9D3D0BD07407EAAULL,
		0xCFC78B77DBDE6C09ULL,
		0x4D50C040BA3DB70AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3D29000000000000ULL,
		0x3F55738A22F6C451ULL,
		0x3604FCE9E85E83A0ULL,
		0xDB8567E3C5BBEDEFULL,
		0x000026A860205D1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 111;
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x50CCA549BCDF56E7ULL,
		0xAC8301AAC228EFBDULL,
		0xBE679E2906018543ULL,
		0x39FEB99C7783DB78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6E70000000000000ULL,
		0xFBD50CCA549BCDF5ULL,
		0x543AC8301AAC228EULL,
		0xB78BE679E2906018ULL,
		0x00039FEB99C7783DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x595273FA43A4BDCFULL,
		0xCA72913649B90C06ULL,
		0x531A3652A029E23BULL,
		0x4E9485B3BE51811EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x273FA43A4BDCF000ULL,
		0x2913649B90C06595ULL,
		0xA3652A029E23BCA7ULL,
		0x485B3BE51811E531ULL,
		0x00000000000004E9ULL
	}};
	shift = 204;
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3A67CF8BDDD36F3DULL,
		0x073BEB32669A7409ULL,
		0xCA930A8ECD684966ULL,
		0x3985374EE1870307ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF17BBA6DE7A00000ULL,
		0x664CD34E81274CF9ULL,
		0x51D9AD092CC0E77DULL,
		0xE9DC30E060F95261ULL,
		0x00000000000730A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6A8A1450C59BDF4BULL,
		0xE18B0DAF16F3124BULL,
		0x3E407797D65A1881ULL,
		0x0ABE1957F6BC2388ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CDEFA5800000000ULL,
		0xB798925B5450A286ULL,
		0xB2D0C40F0C586D78ULL,
		0xB5E11C41F203BCBEULL,
		0x0000000055F0CABFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0A4FCB1CACF01A29ULL,
		0xC59527A56C191027ULL,
		0x63CA9B693C6EDC3BULL,
		0x4A5BF8CA519C10DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0345200000000000ULL,
		0x2204E149F963959EULL,
		0xDB8778B2A4F4AD83ULL,
		0x821B8C79536D278DULL,
		0x0000094B7F194A33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF3AEF25E171A3DE7ULL,
		0x0E889C55EEDB7312ULL,
		0x180479986045652BULL,
		0x635F425E2D5D464BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC68F79C000000000ULL,
		0xB6DCC4BCEBBC9785ULL,
		0x11594AC3A227157BULL,
		0x575192C6011E6618ULL,
		0x00000018D7D0978BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1778282839D962E1ULL,
		0x702E785BA3940C9BULL,
		0x6CFAD2803B2B3DEEULL,
		0x232CE52136E20626ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5C2000000000000ULL,
		0x19362EF0505073B2ULL,
		0x7BDCE05CF0B74728ULL,
		0x0C4CD9F5A5007656ULL,
		0x00004659CA426DC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5B2C5C36DE50361FULL,
		0xD2DDD52AA6DDE00EULL,
		0x1117C7797CAD15B8ULL,
		0x655B3614FC61B616ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1F00000000000000ULL,
		0x0E5B2C5C36DE5036ULL,
		0xB8D2DDD52AA6DDE0ULL,
		0x161117C7797CAD15ULL,
		0x00655B3614FC61B6ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1A5C4D142D76CEBEULL,
		0xF212D30535F5112FULL,
		0x70D13C90CFEA4D7EULL,
		0x7F118C220234CD6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF800000000000000ULL,
		0xBC69713450B5DB3AULL,
		0xFBC84B4C14D7D444ULL,
		0xBDC344F2433FA935ULL,
		0x01FC46308808D335ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x73DB77B3E553C0D7ULL,
		0x828541EECBD383DEULL,
		0x50CD42B396F2DDB8ULL,
		0x049BC8F546DDDD25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDBBD9F2A9E06B80ULL,
		0x42A0F765E9C1EF39ULL,
		0x66A159CB796EDC41ULL,
		0x4DE47AA36EEE92A8ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA1D47651F49BC77AULL,
		0x4C83E3B8AF3C182DULL,
		0xCC6044C3D3BF7DB7ULL,
		0x1CB1C51246FB644EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6F1DE80000000000ULL,
		0xF060B68751D947D2ULL,
		0xFDF6DD320F8EE2BCULL,
		0xED913B3181130F4EULL,
		0x00000072C714491BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x470B2FA04510609DULL,
		0x25ACE1BA9EAF8973ULL,
		0x87A344A42CC09C85ULL,
		0x310E8EFF45905A0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x20C13A0000000000ULL,
		0x5F12E68E165F408AULL,
		0x81390A4B59C3753DULL,
		0x20B4150F46894859ULL,
		0x000000621D1DFE8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x786F6B9713A5E453ULL,
		0x9A0191E8874941FDULL,
		0x220D1DD17492387FULL,
		0x1882026324322279ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5C4E97914C00000ULL,
		0x7A21D2507F5E1BDAULL,
		0x745D248E1FE68064ULL,
		0x98C90C889E488347ULL,
		0x0000000000062080ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x875F02B1C01F4EE3ULL,
		0xD8B75F9438EB616EULL,
		0xB30252AF5E4CD2B9ULL,
		0x2F4B7580E3631099ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC0AC7007D3B8C000ULL,
		0xD7E50E3AD85BA1D7ULL,
		0x94ABD79334AE762DULL,
		0xDD6038D8C4266CC0ULL,
		0x0000000000000BD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE03F225D203640E8ULL,
		0x8DDF0298067BE48DULL,
		0xE8CAEBF38C283368ULL,
		0x01EA119D8F551B67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE44BA406C81D0000ULL,
		0xE05300CF7C91BC07ULL,
		0x5D7E7185066D11BBULL,
		0x4233B1EAA36CFD19ULL,
		0x000000000000003DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9914331C30EE7836ULL,
		0x29A03B8182C564E3ULL,
		0xBC421849F0C1F357ULL,
		0x4FF2B096F11C7468ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4331C30EE7836000ULL,
		0x03B8182C564E3991ULL,
		0x21849F0C1F35729AULL,
		0x2B096F11C7468BC4ULL,
		0x00000000000004FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAA06CDA0FA5AD6CAULL,
		0x3BC7322B5B248380ULL,
		0x6D3FFF63A40F6F61ULL,
		0x65222C8D0FE62EE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB5AD940000000000ULL,
		0x490701540D9B41F4ULL,
		0x1EDEC2778E6456B6ULL,
		0xCC5DC0DA7FFEC748ULL,
		0x000000CA44591A1FULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x82CCAF5A74371A96ULL,
		0x1FBEBC0E63BEFF06ULL,
		0x1DE500E0F7CC2AD6ULL,
		0x25BA45638466B925ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA960000000000000ULL,
		0xF0682CCAF5A74371ULL,
		0xAD61FBEBC0E63BEFULL,
		0x9251DE500E0F7CC2ULL,
		0x00025BA45638466BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0DAC17B5BA3F0AF1ULL,
		0xD1FE16DDA8674C51ULL,
		0x36E4EEEFDB1248EBULL,
		0x19836AE995FF6931ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL,
		0x10DAC17B5BA3F0AFULL,
		0xBD1FE16DDA8674C5ULL,
		0x136E4EEEFDB1248EULL,
		0x019836AE995FF693ULL,
		0x0000000000000000ULL
	}};
	shift = 188;
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFAD623ADED04CB57ULL,
		0x6F2FA353DA0E349AULL,
		0x22B8CDA6EB1A0364ULL,
		0x797E47A428137580ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0xBEB588EB7B4132D5ULL,
		0x1BCBE8D4F6838D26ULL,
		0x08AE3369BAC680D9ULL,
		0x1E5F91E90A04DD60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA817772EDAF5095EULL,
		0xC02B18394BDD83D6ULL,
		0xCDAF85F6979AF41AULL,
		0x437E6943CEA96BC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA12BC00000000000ULL,
		0xB07AD502EEE5DB5EULL,
		0x5E8358056307297BULL,
		0x2D78B9B5F0BED2F3ULL,
		0x0000086FCD2879D5ULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x148648BBBED90CACULL,
		0xF51A3D1E477C544EULL,
		0xC8C750572C641756ULL,
		0x574BFED9A502DC5DULL,
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
		0x8521922EEFB6432BULL,
		0xBD468F4791DF1513ULL,
		0x7231D415CB1905D5ULL,
		0x15D2FFB66940B717ULL
	}};
	shift = 254;
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDBB8F02AC686D059ULL,
		0x4AB1D9DD1C395D85ULL,
		0x17E32A64F20506AEULL,
		0x73324D55205E2FA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC800000000000000ULL,
		0x2EDDC78156343682ULL,
		0x72558ECEE8E1CAECULL,
		0x08BF195327902835ULL,
		0x0399926AA902F17DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8B482FDA9EF0088BULL,
		0x05F1C0DC1497C24FULL,
		0x31BCBFDC312AE315ULL,
		0x6762E9318C070255ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7804458000000000ULL,
		0x4BE127C5A417ED4FULL,
		0x95718A82F8E06E0AULL,
		0x03812A98DE5FEE18ULL,
		0x00000033B17498C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0B67592D2F775292ULL,
		0x18BB48F60FA455A2ULL,
		0x1C7313037ED2FE2CULL,
		0x4190FF25DEDEE798ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7592D2F775292000ULL,
		0xB48F60FA455A20B6ULL,
		0x313037ED2FE2C18BULL,
		0x0FF25DEDEE7981C7ULL,
		0x0000000000000419ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x608CDA7F06FE2C03ULL,
		0x009C34230707F5D1ULL,
		0xF6DEF76896F5AA69ULL,
		0x4A99AC9DC86572BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4FE0DFC58060000ULL,
		0x68460E0FEBA2C119ULL,
		0xEED12DEB54D20138ULL,
		0x593B90CAE579EDBDULL,
		0x0000000000009533ULL
	}};
	shift = 209;
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCBBB68613E16C753ULL,
		0x72769D3124B1FE38ULL,
		0x6B6E4B437778675DULL,
		0x56E7433681FEF750ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C00000000000000ULL,
		0xE32EEDA184F85B1DULL,
		0x75C9DA74C492C7F8ULL,
		0x41ADB92D0DDDE19DULL,
		0x015B9D0CDA07FBDDULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75154807A46F9847ULL,
		0x74C3E5AB6B220370ULL,
		0x11E96C2B30649AE8ULL,
		0x79AE968677F8673BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0F48DF308E000000ULL,
		0x56D64406E0EA2A90ULL,
		0x5660C935D0E987CBULL,
		0x0CEFF0CE7623D2D8ULL,
		0x0000000000F35D2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9988106CC7CD7EBAULL,
		0xEB766014DD3327ACULL,
		0x366FD0C47DE0275EULL,
		0x5E615E1816DDE4C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD74000000000000ULL,
		0x4F59331020D98F9AULL,
		0x4EBDD6ECC029BA66ULL,
		0xC9926CDFA188FBC0ULL,
		0x0000BCC2BC302DBBULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x380AE0FBF454D662ULL,
		0x8192E3771B21535CULL,
		0x7748A59DF120EF67ULL,
		0x28F1D760F89537A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05707DFA2A6B3100ULL,
		0xC971BB8D90A9AE1CULL,
		0xA452CEF89077B3C0ULL,
		0x78EBB07C4A9BD0BBULL,
		0x0000000000000014ULL
	}};
	shift = 199;
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEBFB8567B35B0529ULL,
		0x02B952D59411D6B8ULL,
		0x667C9DF242CAA7DEULL,
		0x309B0EC66C6179AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFEE159ECD6C14A4ULL,
		0x0AE54B5650475AE3ULL,
		0x99F277C90B2A9F78ULL,
		0xC26C3B19B185E6BDULL,
		0x0000000000000000ULL
	}};
	shift = 194;
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x98C1238473C6C21FULL,
		0x5F550BE32362C0FEULL,
		0x43AA2C4CCF08F85CULL,
		0x5E19C8D0BC103A6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x708E78D843E00000ULL,
		0x7C646C581FD31824ULL,
		0x8999E11F0B8BEAA1ULL,
		0x1A1782074D487545ULL,
		0x00000000000BC339ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB8759B4CDF11D501ULL,
		0xB8B3B97A40D064AAULL,
		0x9C4C461CEF921C84ULL,
		0x1936EC5CB06C96B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1D50100000000000ULL,
		0x064AAB8759B4CDF1ULL,
		0x21C84B8B3B97A40DULL,
		0xC96B09C4C461CEF9ULL,
		0x000001936EC5CB06ULL,
		0x0000000000000000ULL
	}};
	shift = 172;
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7CC354664979B4E3ULL,
		0x8EA0A031F630FEBBULL,
		0xF2A7A58810581D06ULL,
		0x27298C556DF816B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD38C000000000000ULL,
		0xFAEDF30D519925E6ULL,
		0x741A3A8280C7D8C3ULL,
		0x5AC7CA9E96204160ULL,
		0x00009CA63155B7E0ULL
	}};
	shift = 242;
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x574075D076E2BBA7ULL,
		0x5EC998D4D3F3040BULL,
		0x9C864635016CABB5ULL,
		0x58CF6832C8AF4B60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3800000000000000ULL,
		0x5ABA03AE83B715DDULL,
		0xAAF64CC6A69F9820ULL,
		0x04E43231A80B655DULL,
		0x02C67B4196457A5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x25178A8F76390C47ULL,
		0x06F7599A9FEC7C7FULL,
		0xA3ADFAAD9438B455ULL,
		0x61C1DF22ACB3441FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4311C00000000000ULL,
		0x1F1FC945E2A3DD8EULL,
		0x2D1541BDD666A7FBULL,
		0xD107E8EB7EAB650EULL,
		0x0000187077C8AB2CULL
	}};
	shift = 238;
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDAEC9627A07D5BE1ULL,
		0xE27FC3F71E49BCC3ULL,
		0xA322589A8B7B7B87ULL,
		0x6C5E3AE4AD718971ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x627A07D5BE100000ULL,
		0x3F71E49BCC3DAEC9ULL,
		0x89A8B7B7B87E27FCULL,
		0xAE4AD718971A3225ULL,
		0x000000000006C5E3ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC15316624E481375ULL,
		0x9A2C2CB4ACA7629DULL,
		0xBDD31D064901C101ULL,
		0x116D0FFD45BA8F93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x24E4813750000000ULL,
		0x4ACA7629DC153166ULL,
		0x64901C1019A2C2CBULL,
		0xD45BA8F93BDD31D0ULL,
		0x000000000116D0FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0A986428C6E14E73ULL,
		0xD0F70405B7700EF5ULL,
		0x6666114E01B02BDBULL,
		0x7525215872CE934EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8539CC000000000ULL,
		0xDC03BD42A6190A31ULL,
		0x6C0AF6F43DC1016DULL,
		0xB3A4D39999845380ULL,
		0x0000001D4948561CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCC16EFC8A60D60B8ULL,
		0xC60836DC0EA69DC8ULL,
		0x84239FBCA5B0A5F0ULL,
		0x043EAFD2B95F2D44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1700000000000000ULL,
		0xB91982DDF914C1ACULL,
		0xBE18C106DB81D4D3ULL,
		0xA8908473F794B614ULL,
		0x000087D5FA572BE5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1CD476545DC49411ULL,
		0x273F578261C03571ULL,
		0x4DD8A19748884D0AULL,
		0x24787AF9797D484DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD951771250440000ULL,
		0x5E098700D5C47351ULL,
		0x865D222134289CFDULL,
		0xEBE5E5F521353762ULL,
		0x00000000000091E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 82;
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA8FA9B954D7C11BFULL,
		0x49C89FB239E2C407ULL,
		0xD3233FD5F073052AULL,
		0x4D41C6470B7337DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1BF0000000000000ULL,
		0x407A8FA9B954D7C1ULL,
		0x52A49C89FB239E2CULL,
		0x7DFD3233FD5F0730ULL,
		0x0004D41C6470B733ULL
	}};
	shift = 244;
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3F0B54E46808E82EULL,
		0xDFB9202E2B1CEF39ULL,
		0x85F9B0C4B0D39133ULL,
		0x1C1DEF26EA04A906ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x46808E82E0000000ULL,
		0xE2B1CEF393F0B54EULL,
		0x4B0D39133DFB9202ULL,
		0x6EA04A90685F9B0CULL,
		0x0000000001C1DEF2ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD76E5EBC8A5A2B2DULL,
		0xBF0DA94581D2B0F6ULL,
		0xA700A49871069C39ULL,
		0x558EE54A7A6CA385ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x452D159680000000ULL,
		0xC0E9587B6BB72F5EULL,
		0x38834E1CDF86D4A2ULL,
		0x3D3651C2D380524CULL,
		0x000000002AC772A5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCE82C50A3A84A19BULL,
		0x97E6F1E19C459445ULL,
		0x03866715A34C856CULL,
		0x06DF0EB79256D1ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC50A3A84A19B0000ULL,
		0xF1E19C459445CE82ULL,
		0x6715A34C856C97E6ULL,
		0x0EB79256D1AB0386ULL,
		0x00000000000006DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC12337995EE28ADAULL,
		0x3686001077A08307ULL,
		0x4134FF6A64E2EB3CULL,
		0x3AAB3CB106F6B6B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x56D0000000000000ULL,
		0x183E0919BCCAF714ULL,
		0x59E1B4300083BD04ULL,
		0xB5C209A7FB532717ULL,
		0x0001D559E58837B5ULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8E4D2C433D76EDECULL,
		0x21F3644944850AA7ULL,
		0x58F36A18E56F3491ULL,
		0x44D702DB551360ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC433D76EDEC00000ULL,
		0x44944850AA78E4D2ULL,
		0xA18E56F349121F36ULL,
		0x2DB551360AD58F36ULL,
		0x0000000000044D70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x467701CD801DA03CULL,
		0xD22325B2DDB5E59AULL,
		0x9EB61DB5676E082EULL,
		0x5C7433578D2CB0D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC00ED01E00000000ULL,
		0x6EDAF2CD233B80E6ULL,
		0xB3B70417691192D9ULL,
		0xC696586C4F5B0EDAULL,
		0x000000002E3A19ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF279F128727E1559ULL,
		0x0386F8C1378EC7B4ULL,
		0x634DEB117E0E5922ULL,
		0x118BA6F7ECB22D81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x727E155900000000ULL,
		0x378EC7B4F279F128ULL,
		0x7E0E59220386F8C1ULL,
		0xECB22D81634DEB11ULL,
		0x00000000118BA6F7ULL
	}};
	shift = 224;
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1309ED29AF85CF8DULL,
		0xB8B09537B8D74B8BULL,
		0x8A3B2E119162F641ULL,
		0x3034DAEE031BF833ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9F1A000000000000ULL,
		0x97162613DA535F0BULL,
		0xEC8371612A6F71AEULL,
		0xF06714765C2322C5ULL,
		0x00006069B5DC0637ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x450111C8AEE6F744ULL,
		0xF27BD54F126D7756ULL,
		0x00184D7E6C0F5932ULL,
		0x017E8536B6BE1B7BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x23915DCDEE880000ULL,
		0xAA9E24DAEEAC8A02ULL,
		0x9AFCD81EB265E4F7ULL,
		0x0A6D6D7C36F60030ULL,
		0x00000000000002FDULL
	}};
	shift = 209;
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1157C7D39CDD9334ULL,
		0xD628A33D144831CBULL,
		0xFB75A6A05D90BC0AULL,
		0x01F65F271E28161EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x622AF8FA739BB266ULL,
		0x5AC51467A2890639ULL,
		0xDF6EB4D40BB21781ULL,
		0x003ECBE4E3C502C3ULL
	}};
	shift = 253;
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x49459761B7F02A55ULL,
		0xBC1B8D03B5079FB1ULL,
		0xC2129C1D88BB260EULL,
		0x3F167278B14AFDABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25165D86DFC0A954ULL,
		0xF06E340ED41E7EC5ULL,
		0x084A707622EC983AULL,
		0xFC59C9E2C52BF6AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB99A0E44BD3B5EADULL,
		0x118ABD37724EC16AULL,
		0x9E07BD397A5010F7ULL,
		0x40B7AE08B7EDFDCFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x225E9DAF56800000ULL,
		0x9BB92760B55CCD07ULL,
		0x9CBD28087B88C55EULL,
		0x045BF6FEE7CF03DEULL,
		0x0000000000205BD7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCF6077CDDD4E72FAULL,
		0x9107B39016F68CF8ULL,
		0xDCBC9CEA790FC2FDULL,
		0x2234B13F98F3044EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3D81DF377539CBE8ULL,
		0x441ECE405BDA33E3ULL,
		0x72F273A9E43F0BF6ULL,
		0x88D2C4FE63CC113BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE01424A8D74C37AFULL,
		0x204D8DA4762BD20BULL,
		0xAE721C09058A0B65ULL,
		0x2BD70E8960799A28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6F5E000000000000ULL,
		0xA417C0284951AE98ULL,
		0x16CA409B1B48EC57ULL,
		0x34515CE438120B14ULL,
		0x000057AE1D12C0F3ULL
	}};
	shift = 241;
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC8A4BAE1739841D4ULL,
		0x46EC2B29E5E08302ULL,
		0xFEC7E0371B7F317EULL,
		0x74416E3A027DFC7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC2E73083A8000000ULL,
		0x53CBC10605914975ULL,
		0x6E36FE62FC8DD856ULL,
		0x7404FBF8FFFD8FC0ULL,
		0x0000000000E882DCULL
	}};
	shift = 217;
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x811C8E3E8926BC9FULL,
		0xF005CF27DD753F86ULL,
		0xFC7F489EBEA30750ULL,
		0x77D69ADDD7DB4607ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE000000000000000ULL,
		0xD02391C7D124D793ULL,
		0x1E00B9E4FBAEA7F0ULL,
		0xFF8FE913D7D460EAULL,
		0x0EFAD35BBAFB68C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x09029329B0D7C3ECULL,
		0xDB6F079BCD7066B0ULL,
		0xD763B57418D7C75EULL,
		0x4E6CD559906C4D12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1AF87D8000000000ULL,
		0xAE0CD60120526536ULL,
		0x1AF8EBDB6DE0F379ULL,
		0x0D89A25AEC76AE83ULL,
		0x00000009CD9AAB32ULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8A4F912B4F2D7F5AULL,
		0x7BDEFC707460A5F0ULL,
		0x52801D1EF86F616CULL,
		0x7D06391F6FFC7147ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5A00000000000000ULL,
		0xF08A4F912B4F2D7FULL,
		0x6C7BDEFC707460A5ULL,
		0x4752801D1EF86F61ULL,
		0x007D06391F6FFC71ULL
	}};
	shift = 248;
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7AB0966DA0BE8069ULL,
		0x220E1F3F6427AC1CULL,
		0x48F647E10F44E448ULL,
		0x28A4680F03C83F8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x12CDB417D00D2000ULL,
		0xC3E7EC84F5838F56ULL,
		0xC8FC21E89C890441ULL,
		0x8D01E07907F1E91EULL,
		0x0000000000000514ULL
	}};
	shift = 205;
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x602D77D8EB18875EULL,
		0x53244CDF7F649D26ULL,
		0xC21D9C485BC23F66ULL,
		0x15AC7BC51C113894ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFB1D6310EBC00000ULL,
		0x9BEFEC93A4CC05AEULL,
		0x890B7847ECCA6489ULL,
		0x78A38227129843B3ULL,
		0x000000000002B58FULL
	}};
	shift = 213;
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8799A6E9F4824E86ULL,
		0xABB04737882BC271ULL,
		0x81AAAF53779E2D47ULL,
		0x63B59B7FD8F36B4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9A6E9F4824E86000ULL,
		0x04737882BC271879ULL,
		0xAAF53779E2D47ABBULL,
		0x59B7FD8F36B4F81AULL,
		0x000000000000063BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x978B71BD785F4D01ULL,
		0xFFA471F91C28444EULL,
		0x2898B6295885DDB7ULL,
		0x339DBDD77CEE58A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xBC5B8DEBC2FA6808ULL,
		0xFD238FC8E1422274ULL,
		0x44C5B14AC42EEDBFULL,
		0x9CEDEEBBE772C509ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFAA53E839DB1441AULL,
		0x803D2D361AF23613ULL,
		0x2A979429DD1C7A95ULL,
		0x55A65F3661FF0A74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x7F54A7D073B62883ULL,
		0xB007A5A6C35E46C2ULL,
		0x8552F2853BA38F52ULL,
		0x0AB4CBE6CC3FE14EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6B5ABB7271C9690BULL,
		0xD6ACF4937918CC1DULL,
		0xB344684F3EF6F2E5ULL,
		0x6285301F8EFF9801ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7271C9690B000000ULL,
		0x937918CC1D6B5ABBULL,
		0x4F3EF6F2E5D6ACF4ULL,
		0x1F8EFF9801B34468ULL,
		0x0000000000628530ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7DDD4FE93034DBE0ULL,
		0x7A6953BA1AD99546ULL,
		0x0DFC46ADDD631122ULL,
		0x5F082E938761BA15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7F4981A6DF000000ULL,
		0x9DD0D6CCAA33EEEAULL,
		0x356EEB188913D34AULL,
		0x749C3B0DD0A86FE2ULL,
		0x000000000002F841ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x601EFE2CFD2C5622ULL,
		0x4808248D6D896D4AULL,
		0xC033ACBA3195DF47ULL,
		0x19489AA24959E945ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5888000000000000ULL,
		0xB529807BF8B3F4B1ULL,
		0x7D1D20209235B625ULL,
		0xA51700CEB2E8C657ULL,
		0x000065226A892567ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAE22BDA3426260EFULL,
		0x0ACF038C4229B0DCULL,
		0xBC0FB0A0BC71CBCCULL,
		0x7999C79A2460D6A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDE00000000000000ULL,
		0xB95C457B4684C4C1ULL,
		0x98159E0718845361ULL,
		0x4D781F614178E397ULL,
		0x00F3338F3448C1ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB069CBE03AB2F9E3ULL,
		0x5E4CBF69C30405FCULL,
		0xA6F4ADCB92EF9A7CULL,
		0x1F634E9AFB58C254ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x397C07565F3C6000ULL,
		0x97ED386080BF960DULL,
		0x95B9725DF34F8BC9ULL,
		0x69D35F6B184A94DEULL,
		0x00000000000003ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x57F297876C470744ULL,
		0x9189E796FC2DB3CAULL,
		0x90723344538A4B10ULL,
		0x72FCA80AC55A12F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4BC3B62383A20000ULL,
		0xF3CB7E16D9E52BF9ULL,
		0x19A229C5258848C4ULL,
		0x540562AD097B4839ULL,
		0x000000000000397EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 79;
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1BB2D52F5F449312ULL,
		0x35ACD4D44D38D858ULL,
		0x73FC8BBA98498CA2ULL,
		0x61ECDA8001AF18DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB2D52F5F4493120ULL,
		0x5ACD4D44D38D8581ULL,
		0x3FC8BBA98498CA23ULL,
		0x1ECDA8001AF18DA7ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC3CFCE14F7692194ULL,
		0x092B22F19F79B567ULL,
		0x3CFE6B1C241EDDB1ULL,
		0x71F603955A61EFD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F76921940000000ULL,
		0x19F79B567C3CFCE1ULL,
		0xC241EDDB1092B22FULL,
		0x55A61EFD83CFE6B1ULL,
		0x00000000071F6039ULL
	}};
	shift = 220;
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x88F8E67157FC4D8AULL,
		0x132229D4835968D4ULL,
		0x75AC407894D2E773ULL,
		0x4F9B7BCFE084195DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCE2AFF89B1400000ULL,
		0x3A906B2D1A911F1CULL,
		0x0F129A5CEE626445ULL,
		0x79FC10832BAEB588ULL,
		0x000000000009F36FULL
	}};
	shift = 213;
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7C8D66E0CA0689E5ULL,
		0xAE3204A1825EBD60ULL,
		0x446E34491648674FULL,
		0x38E1242876EFFED8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1A27940000000000ULL,
		0x7AF581F2359B8328ULL,
		0x219D3EB8C8128609ULL,
		0xBFFB6111B8D12459ULL,
		0x000000E38490A1DBULL
	}};
	shift = 234;
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5D73B37390E27FB3ULL,
		0xA57D9E3287BACD27ULL,
		0x882D58B606242EE1ULL,
		0x5C14DD5426E90A22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE766E721C4FF6600ULL,
		0xFB3C650F759A4EBAULL,
		0x5AB16C0C485DC34AULL,
		0x29BAA84DD2144510ULL,
		0x00000000000000B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD953B1348E6FB6A0ULL,
		0xEFF7F5A84F65228EULL,
		0x2097054807E7B6E5ULL,
		0x024805745F550040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDF6D400000000000ULL,
		0xCA451DB2A762691CULL,
		0xCF6DCBDFEFEB509EULL,
		0xAA0080412E0A900FULL,
		0x00000004900AE8BEULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCDD1FDF953DB9BC3ULL,
		0x43BF2AAD2E3F6E64ULL,
		0x5458FC30F4AE2977ULL,
		0x1EA1507C15CF5DF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F6E6F0C00000000ULL,
		0xB8FDB9933747F7E5ULL,
		0xD2B8A5DD0EFCAAB4ULL,
		0x573D77C95163F0C3ULL,
		0x000000007A8541F0ULL
	}};
	shift = 226;
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFFD9EAC9F1DC4894ULL,
		0xF518597179F55678ULL,
		0xAA786B4EE85B3DE0ULL,
		0x37C0A99EF3A2A471ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3D593E3B8912800ULL,
		0x30B2E2F3EAACF1FFULL,
		0xF0D69DD0B67BC1EAULL,
		0x81533DE74548E354ULL,
		0x000000000000006FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x06DE7F371869B378ULL,
		0xE64CD870158A6F6BULL,
		0x08A33D24EB37532BULL,
		0x5A3FD6784C88AB5CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F00000000000000ULL,
		0xED60DBCFE6E30D36ULL,
		0x657CC99B0E02B14DULL,
		0x6B811467A49D66EAULL,
		0x000B47FACF099115ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF83A7D35AC0583B9ULL,
		0xDDF341B059FFD65DULL,
		0x20A9767B44896CCEULL,
		0x4D07FDD87326ECC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9000000000000000ULL,
		0xDF83A7D35AC0583BULL,
		0xEDDF341B059FFD65ULL,
		0x620A9767B44896CCULL,
		0x04D07FDD87326ECCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x07CD80461DBAC76DULL,
		0x1D575CAAB42CF5C7ULL,
		0x5D928819F31CB74AULL,
		0x48B98A223668050CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8EDA000000000000ULL,
		0xEB8E0F9B008C3B75ULL,
		0x6E943AAEB9556859ULL,
		0x0A18BB251033E639ULL,
		0x0000917314446CD0ULL
	}};
	shift = 241;
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x725B6EF8DE54FE27ULL,
		0xCA69B891A3AC68EBULL,
		0xF465C70358D1FF71ULL,
		0x655FB552DC4D18C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE27000000000000ULL,
		0x68EB725B6EF8DE54ULL,
		0xFF71CA69B891A3ACULL,
		0x18C2F465C70358D1ULL,
		0x0000655FB552DC4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA249D797D3DBB18BULL,
		0xE7F30BE842978234ULL,
		0xA141CE758D57E895ULL,
		0x0F454F8A721266F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF6EC62C000000000ULL,
		0xA5E08D289275E5F4ULL,
		0x55FA2579FCC2FA10ULL,
		0x8499BCE850739D63ULL,
		0x00000003D153E29CULL
	}};
	shift = 230;
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF104401EA3D50A1CULL,
		0x4DDFA9210B500F29ULL,
		0xA700EB096B882FD2ULL,
		0x788C842504307728ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8F5428700000000ULL,
		0x42D403CA7C411007ULL,
		0x5AE20BF49377EA48ULL,
		0x410C1DCA29C03AC2ULL,
		0x000000001E232109ULL
	}};
	shift = 222;
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1DD191C803A79143ULL,
		0xE568F2F9BD220A77ULL,
		0x7B01878205180398ULL,
		0x3EB2AEB82A77BEBCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4647200E9E450C00ULL,
		0xA3CBE6F48829DC77ULL,
		0x061E0814600E6395ULL,
		0xCABAE0A9DEFAF1ECULL,
		0x00000000000000FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x132B4537025DCC2EULL,
		0x7D29A36EE2AF32CCULL,
		0x82E4CA1B4B43F195ULL,
		0x7105DB9FBFC8C3F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAD14DC097730B800ULL,
		0xA68DBB8ABCCB304CULL,
		0x93286D2D0FC655F4ULL,
		0x176E7EFF230FC60BULL,
		0x00000000000001C4ULL
	}};
	shift = 202;
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x62C6C54ED371310AULL,
		0x62AC5A8CE44E68B3ULL,
		0x900DAAAB10849E4FULL,
		0x6F598F8F5F3BFD9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C6C54ED371310A0ULL,
		0x2AC5A8CE44E68B36ULL,
		0x00DAAAB10849E4F6ULL,
		0xF598F8F5F3BFD9B9ULL,
		0x0000000000000006ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDF1B5AD9EB96C4DEULL,
		0xD87F79681DCAD84EULL,
		0x06D52A9BC8E4F245ULL,
		0x100E91212EAC717CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE5B1378000000000ULL,
		0x72B613B7C6D6B67AULL,
		0x393C91761FDE5A07ULL,
		0xAB1C5F01B54AA6F2ULL,
		0x0000000403A4484BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2AC7F801A285C887ULL,
		0x684D924FB43DB404ULL,
		0x24AF7DB4FE39336DULL,
		0x4932E00F839F3E3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF801A285C8870000ULL,
		0x924FB43DB4042AC7ULL,
		0x7DB4FE39336D684DULL,
		0xE00F839F3E3E24AFULL,
		0x0000000000004932ULL
	}};
	shift = 208;
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1F9CE9E144B6429BULL,
		0xC31685F0638891C7ULL,
		0x09E466EEE51D78D0ULL,
		0x785DB83811391B71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD800000000000000ULL,
		0x38FCE74F0A25B214ULL,
		0x8618B42F831C448EULL,
		0x884F23377728EBC6ULL,
		0x03C2EDC1C089C8DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCF697967B4C319E0ULL,
		0x3B4258EAF1285B5AULL,
		0x23990B5D958C72EDULL,
		0x07959687CD2DA6B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x5ACF697967B4C319ULL,
		0xED3B4258EAF1285BULL,
		0xB323990B5D958C72ULL,
		0x0007959687CD2DA6ULL,
		0x0000000000000000ULL
	}};
	shift = 184;
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB060D26B01D6E918ULL,
		0x145782E14AA74120ULL,
		0x6BF3BB086A1CE1D1ULL,
		0x46A2914AA30CCD8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x693580EB748C0000ULL,
		0xC170A553A0905830ULL,
		0xDD84350E70E88A2BULL,
		0x48A5518666C7B5F9ULL,
		0x0000000000002351ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD3B923F9EA67E6F0ULL,
		0x92B81EF2FF7C2BACULL,
		0x87423ED24034123FULL,
		0x386ABC6A1D96E790ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA67E6F000000000ULL,
		0xFF7C2BACD3B923F9ULL,
		0x4034123F92B81EF2ULL,
		0x1D96E79087423ED2ULL,
		0x00000000386ABC6AULL
	}};
	shift = 224;
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4D00F240811067D0ULL,
		0x16D34890D793F3E6ULL,
		0xFD3DFD9D99876147ULL,
		0x568CE6F50EF309D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08833E8000000000ULL,
		0xBC9F9F3268079204ULL,
		0xCC3B0A38B69A4486ULL,
		0x77984E9FE9EFECECULL,
		0x00000002B46737A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x5C9DC7B74E578A7BULL,
		0xCCA25287D1FC39DBULL,
		0xBA05B580614BA99AULL,
		0x561E11A2F4B4453DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B00000000000000ULL,
		0xDB5C9DC7B74E578AULL,
		0x9ACCA25287D1FC39ULL,
		0x3DBA05B580614BA9ULL,
		0x00561E11A2F4B445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x95D7047373783264ULL,
		0x81259366D2DA2C46ULL,
		0x007228858FA81893ULL,
		0x6F89DCAB7519F05FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9BC1932000000000ULL,
		0x96D16234AEB8239BULL,
		0x7D40C49C092C9B36ULL,
		0xA8CF82F80391442CULL,
		0x000000037C4EE55BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6BF1E4F71EEF9DC5ULL,
		0x8592A92600BD0D1EULL,
		0xB58903A791385741ULL,
		0x689FBE995FFECF71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xDF3B8A0000000000ULL,
		0x7A1A3CD7E3C9EE3DULL,
		0x70AE830B25524C01ULL,
		0xFD9EE36B12074F22ULL,
		0x000000D13F7D32BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 105;
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x01AC828003610319ULL,
		0x9151570AE7C6425AULL,
		0x7E4D312B6935B9EBULL,
		0x2B22870B9FFB6565ULL,
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
		0x01AC828003610319ULL,
		0x9151570AE7C6425AULL,
		0x7E4D312B6935B9EBULL,
		0x2B22870B9FFB6565ULL
	}};
	shift = 256;
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x39D76FD23964C590ULL,
		0xD5940D96EB3273EEULL,
		0x4E5FEB27836DE889ULL,
		0x1AAFE357302AC048ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x62C8000000000000ULL,
		0x39F71CEBB7E91CB2ULL,
		0xF444EACA06CB7599ULL,
		0x6024272FF593C1B6ULL,
		0x00000D57F1AB9815ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDF39E3FDAE07B51FULL,
		0xAE33E36C50C84548ULL,
		0xB0180D7DE66515D3ULL,
		0x7955F23942C8E25CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF39E3FDAE07B51F0ULL,
		0xE33E36C50C84548DULL,
		0x0180D7DE66515D3AULL,
		0x955F23942C8E25CBULL,
		0x0000000000000007ULL
	}};
	shift = 196;
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4450973ED48E986FULL,
		0x452D9C62E69C9BB4ULL,
		0x1CE4EC6CD8C0EE59ULL,
		0x49558FD2C686791CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC00000000000000ULL,
		0xD111425CFB523A61ULL,
		0x6514B6718B9A726EULL,
		0x707393B1B36303B9ULL,
		0x0125563F4B1A19E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0AE10A5557E7691EULL,
		0x84B171BAE900EA14ULL,
		0xA2091D4A4D81E930ULL,
		0x7FA04F57C1165202ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA47800000000000ULL,
		0x3A8502B8429555F9ULL,
		0x7A4C212C5C6EBA40ULL,
		0x9480A88247529360ULL,
		0x00001FE813D5F045ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6245152E85076BA4ULL,
		0x7AB2D6FE3F3B0D9AULL,
		0x9C13A71D68BFAB03ULL,
		0x48BEB17E88C6CE58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA141DAE900000000ULL,
		0x8FCEC3669891454BULL,
		0x5A2FEAC0DEACB5BFULL,
		0xA231B3962704E9C7ULL,
		0x00000000122FAC5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7E1A7BD82312AE77ULL,
		0x34C92D5F418E99D5ULL,
		0xC27254973EDD6173ULL,
		0x12B11456ACE1D493ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2312AE7700000000ULL,
		0x418E99D57E1A7BD8ULL,
		0x3EDD617334C92D5FULL,
		0xACE1D493C2725497ULL,
		0x0000000012B11456ULL
	}};
	shift = 224;
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xABB77A655B3B2B71ULL,
		0xD1EC43F1B06236B7ULL,
		0x9FE009583A46D8A6ULL,
		0x531C0BFF7634FC98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC400000000000000ULL,
		0xDEAEDDE9956CECADULL,
		0x9B47B10FC6C188DAULL,
		0x627F802560E91B62ULL,
		0x014C702FFDD8D3F2ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0707CAB3B657540CULL,
		0x73BECC30962BACDBULL,
		0xAF5BB3F73FB0727AULL,
		0x4C87539158C7A1C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5D50300000000000ULL,
		0xAEB36C1C1F2ACED9ULL,
		0xC1C9E9CEFB30C258ULL,
		0x1E871EBD6ECFDCFEULL,
		0x000001321D4E4563ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 106;
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x12548A96EB31913BULL,
		0xEDD7A30E5CAD32ACULL,
		0x7CF253DAF9F1E2E6ULL,
		0x34D98C87F8F8E0E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6632276000000000ULL,
		0x95A655824A9152DDULL,
		0x3E3C5CDDBAF461CBULL,
		0x1F1C1C0F9E4A7B5FULL,
		0x000000069B3190FFULL,
		0x0000000000000000ULL
	}};
	shift = 165;
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8DE05987D2208383ULL,
		0x42BAF821DACB5D9EULL,
		0x743066FAE0F28DF0ULL,
		0x72F3E577DE0DC50CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0706000000000000ULL,
		0xBB3D1BC0B30FA441ULL,
		0x1BE08575F043B596ULL,
		0x8A18E860CDF5C1E5ULL,
		0x0000E5E7CAEFBC1BULL
	}};
	shift = 241;
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE0F0D41D43B18381ULL,
		0x33AECDE50C880B86ULL,
		0x08FBB3135AEDD099ULL,
		0x0B92F0AC8208E2CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8763070200000000ULL,
		0x1910170DC1E1A83AULL,
		0xB5DBA132675D9BCAULL,
		0x0411C59A11F76626ULL,
		0x000000001725E159ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x20A8D0EBD871C0F3ULL,
		0x0D508626855C6166ULL,
		0x33638754E319CBD4ULL,
		0x18B4DFF85B40D555ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AF61C703CC00000ULL,
		0x89A1571859882A34ULL,
		0xD538C672F5035421ULL,
		0xFE16D035554CD8E1ULL,
		0x0000000000062D37ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x94DFB747EB3D6E9DULL,
		0xF261C89773120575ULL,
		0x2C2857A555AAB967ULL,
		0x3DCBDEF530CF9295ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA3F59EB74E800000ULL,
		0x4BB98902BACA6FDBULL,
		0xD2AAD55CB3F930E4ULL,
		0x7A9867C94A96142BULL,
		0x00000000001EE5EFULL
	}};
	shift = 215;
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBC9E1684A957E50AULL,
		0xFABC9DB93759DD9BULL,
		0xB4005779D2DABB0AULL,
		0x052680F5859CEE3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x93C2D0952AFCA140ULL,
		0x5793B726EB3BB377ULL,
		0x800AEF3A5B57615FULL,
		0xA4D01EB0B39DC7B6ULL,
		0x0000000000000000ULL
	}};
	shift = 197;
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x784FEDBD501F4647ULL,
		0xD1F674DDD329AC23ULL,
		0x3D421115D687921DULL,
		0x3F59C2FE9241FE41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91C0000000000000ULL,
		0x08DE13FB6F5407D1ULL,
		0x87747D9D3774CA6BULL,
		0x904F50844575A1E4ULL,
		0x000FD670BFA4907FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9494F5EE3B9FD2CDULL,
		0x075595507C37FD43ULL,
		0xE01A76862F99A4AFULL,
		0x3A68E8FD95DBD48AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA4A7AF71DCFE9668ULL,
		0x3AACAA83E1BFEA1CULL,
		0x00D3B4317CCD2578ULL,
		0xD34747ECAEDEA457ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x768107AA88BA4F62ULL,
		0xE2617371CBA7A34EULL,
		0xD90F3DA914C864A6ULL,
		0x17D4FF6FAB795898ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2E93D88000000000ULL,
		0xE9E8D39DA041EAA2ULL,
		0x321929B8985CDC72ULL,
		0xDE56263643CF6A45ULL,
		0x00000005F53FDBEAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 102;
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9BEFFC0C1AC9158BULL,
		0x3A0AD25F353B90D4ULL,
		0x12FF38AE7B5C2FC9ULL,
		0x00A37E4C8C0E6BD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x060D648AC5800000ULL,
		0x2F9A9DC86A4DF7FEULL,
		0x573DAE17E49D0569ULL,
		0x26460735E9897F9CULL,
		0x00000000000051BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCD6DAC201CA7085CULL,
		0x30C194B0BB9F1B08ULL,
		0x6C1A76680FE52D55ULL,
		0x1F1F570E0D609697ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3842E00000000000ULL,
		0xF8D8466B6D6100E5ULL,
		0x296AA9860CA585DCULL,
		0x04B4BB60D3B3407FULL,
		0x000000F8FAB8706BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 43;
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB1E239B363F1A208ULL,
		0xAD9A5CE705D5F100ULL,
		0x1B035581AC3C55C6ULL,
		0x50E7D5FD333CBF86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6882000000000000ULL,
		0x7C402C788E6CD8FCULL,
		0x1571AB669739C175ULL,
		0x2FE186C0D5606B0FULL,
		0x00001439F57F4CCFULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x46FF9BA0F5F9204FULL,
		0x17E4446B782A7D6BULL,
		0x50C56985C7C27215ULL,
		0x6B83C5955E602919ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAFC9027800000000ULL,
		0xC153EB5A37FCDD07ULL,
		0x3E1390A8BF22235BULL,
		0xF30148CA862B4C2EULL,
		0x000000035C1E2CAAULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x860772A13F0CE07AULL,
		0x5A38732B5769505FULL,
		0x7460B0E549496D91ULL,
		0x338C84F8E61D295FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x81E8000000000000ULL,
		0x417E181DCA84FC33ULL,
		0xB64568E1CCAD5DA5ULL,
		0xA57DD182C3952525ULL,
		0x0000CE3213E39874ULL
	}};
	shift = 242;
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8C1689002822A540ULL,
		0xE1E6E5F0631882EDULL,
		0xC11103926ADAACABULL,
		0x5D9F2D51BF67F1B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x22A5400000000000ULL,
		0x1882ED8C16890028ULL,
		0xDAACABE1E6E5F063ULL,
		0x67F1B8C11103926AULL,
		0x0000005D9F2D51BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x25DA40B36C02F9ADULL,
		0x680D370D8EFADCACULL,
		0x18E60D1D27A14348ULL,
		0x295AE74D7017E6B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x12ED2059B6017CD6ULL,
		0x34069B86C77D6E56ULL,
		0x0C73068E93D0A1A4ULL,
		0x14AD73A6B80BF358ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA9204065013B4F49ULL,
		0x1D61695303CDA3A5ULL,
		0xA1958C37FE813DD3ULL,
		0x4CD07F72F1C6DE22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9404ED3D24000000ULL,
		0x4C0F368E96A48101ULL,
		0xDFFA04F74C7585A5ULL,
		0xCBC71B788A865630ULL,
		0x00000000013341FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFCCA0CA79AE4AEF1ULL,
		0x4538E239F1F6355BULL,
		0x6BC93403572D93F6ULL,
		0x732ACC3ECDF45287ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0CA79AE4AEF10000ULL,
		0xE239F1F6355BFCCAULL,
		0x3403572D93F64538ULL,
		0xCC3ECDF452876BC9ULL,
		0x000000000000732AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC6043FCD55F97A73ULL,
		0x2B8B36DCE0E55B58ULL,
		0x5F4A16E9730A015BULL,
		0x503F352AB2826905ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9CC000000000000ULL,
		0x6D631810FF3557E5ULL,
		0x056CAE2CDB738395ULL,
		0xA4157D285BA5CC28ULL,
		0x000140FCD4AACA09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xC3844AFA53EAB22DULL,
		0x8B8D07E9FE3E7580ULL,
		0xFBC23B3A66C2E4F7ULL,
		0x1FC1549F42F584A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0E112BE94FAAC8B4ULL,
		0x2E341FA7F8F9D603ULL,
		0xEF08ECE99B0B93DEULL,
		0x7F05527D0BD6129BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEE57D8D09DBA05E0ULL,
		0x68E95F96DACB58EDULL,
		0xEA2E64990486205CULL,
		0x719332A2BAF24EF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC684EDD02F000000ULL,
		0xFCB6D65AC76F72BEULL,
		0x24C8243102E3474AULL,
		0x9515D792779F5173ULL,
		0x0000000000038C99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x80FD817DF8D6A488ULL,
		0x6F3014C5EAF3B1D3ULL,
		0x1512AA134334CD8AULL,
		0x7FD659948DC2BA6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x80FD817DF8D6A488ULL,
		0x6F3014C5EAF3B1D3ULL,
		0x1512AA134334CD8AULL,
		0x7FD659948DC2BA6AULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8FC7D9185F876A52ULL,
		0xC6D6832D872866D7ULL,
		0x0B4CFF3E51DCA249ULL,
		0x42B3BEB0F6B4E521ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7E3EC8C2FC3B5290ULL,
		0x36B4196C394336BCULL,
		0x5A67F9F28EE5124EULL,
		0x159DF587B5A72908ULL,
		0x0000000000000002ULL
	}};
	shift = 195;
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7D2B09F7342C3C69ULL,
		0xE06BA3FDB51329A6ULL,
		0x58F75E115CFC82F6ULL,
		0x072C1BF4A709EBC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61E3480000000000ULL,
		0x994D33E9584FB9A1ULL,
		0xE417B7035D1FEDA8ULL,
		0x4F5E0AC7BAF08AE7ULL,
		0x0000003960DFA538ULL
	}};
	shift = 235;
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x90864C63DB0E7FDEULL,
		0xA51B69034CC2D5F8ULL,
		0x1BB22E4B5A1C67E4ULL,
		0x7B1052D9002BBC30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x210C98C7B61CFFBCULL,
		0x4A36D2069985ABF1ULL,
		0x37645C96B438CFC9ULL,
		0xF620A5B200577860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4E2A3E2B024C02C5ULL,
		0x49D325BA4A9F6E4CULL,
		0xAD4409D351563A8CULL,
		0x74EFB87838088C54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x38A8F8AC09300B14ULL,
		0x274C96E92A7DB931ULL,
		0xB510274D4558EA31ULL,
		0xD3BEE1E0E0223152ULL,
		0x0000000000000001ULL
	}};
	shift = 194;
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCAB1AAB1C8107D44ULL,
		0xBFB501876661C037ULL,
		0x8C81E2DD126C8BA4ULL,
		0x660AFCB3D1BA176DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x7CAB1AAB1C8107D4ULL,
		0x4BFB501876661C03ULL,
		0xD8C81E2DD126C8BAULL,
		0x0660AFCB3D1BA176ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3C49F5B6AB1626A1ULL,
		0x0E0ED6B1181540EDULL,
		0x5410BD9652986CE5ULL,
		0x43ABCFD419F44A9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D562C4D42000000ULL,
		0x62302A81DA7893EBULL,
		0x2CA530D9CA1C1DADULL,
		0xA833E8953AA8217BULL,
		0x000000000087579FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x76264E4B5F85929FULL,
		0x20E6C2A591CB8F43ULL,
		0x8102E45474B6129BULL,
		0x5891867E0FCE83D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x53E0000000000000ULL,
		0xE86EC4C9C96BF0B2ULL,
		0x53641CD854B23971ULL,
		0x7A30205C8A8E96C2ULL,
		0x000B1230CFC1F9D0ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x588EEF2E92A8CFE7ULL,
		0x7752BD9DCD79A52DULL,
		0x4C7FD57815DF391FULL,
		0x58ED3C3D9007D35EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x88EEF2E92A8CFE70ULL,
		0x752BD9DCD79A52D5ULL,
		0xC7FD57815DF391F7ULL,
		0x8ED3C3D9007D35E4ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x4CA157DB92533764ULL,
		0xC3DE9B801EEF461CULL,
		0x5677DA8CBFA85499ULL,
		0x4C5C9A83E91E945AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x494CDD9000000000ULL,
		0x7BBD187132855F6EULL,
		0xFEA152670F7A6E00ULL,
		0xA47A516959DF6A32ULL,
		0x0000000131726A0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2555AA5866F4A064ULL,
		0x9495A491CA5A935CULL,
		0x5206AC7DF362E2F9ULL,
		0x48EB856551281F10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD28190000000000ULL,
		0x96A4D709556A9619ULL,
		0xD8B8BE6525692472ULL,
		0x4A07C41481AB1F7CULL,
		0x000000123AE15954ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6D920FF0E8CCDE87ULL,
		0xD5ACDA7C73ABC0C4ULL,
		0xD9A5E50A282C76A1ULL,
		0x5E4F8C8D2CE53A8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x666F438000000000ULL,
		0xD5E06236C907F874ULL,
		0x163B50EAD66D3E39ULL,
		0x729D47ECD2F28514ULL,
		0x0000002F27C64696ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x56CAA9677556FA5FULL,
		0x7D0390995DB8AA4DULL,
		0x5B525CA8D43C6492ULL,
		0x5C05754D063A7F08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB7D2F8000000000ULL,
		0xDC5526AB6554B3BAULL,
		0x1E32493E81C84CAEULL,
		0x1D3F842DA92E546AULL,
		0x0000002E02BAA683ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x10DC03BAEDB623D5ULL,
		0xAA5A04547713ED1AULL,
		0xA9E4674B8155B986ULL,
		0x20A7CC524CD7C455ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x775DB6C47AA00000ULL,
		0x8A8EE27DA3421B80ULL,
		0xE9702AB730D54B40ULL,
		0x8A499AF88AB53C8CULL,
		0x00000000000414F9ULL
	}};
	shift = 213;
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3404973798604484ULL,
		0x172713236FB31F50ULL,
		0xC48259D0E698B04AULL,
		0x223BB1426689DA5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24B9BCC302242000ULL,
		0x38991B7D98FA81A0ULL,
		0x12CE8734C58250B9ULL,
		0xDD8A13344ED2DE24ULL,
		0x0000000000000111ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB4E1C76F67B862A1ULL,
		0x0C4D12258420B0B6ULL,
		0x052634A0465D9608ULL,
		0x6F20D6E0B1850161ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8400000000000000ULL,
		0xDAD3871DBD9EE18AULL,
		0x20313448961082C2ULL,
		0x841498D281197658ULL,
		0x01BC835B82C61405ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 122;
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xD5F313F7EB781EFEULL,
		0xFCE109FBDAF92ECCULL,
		0xE51B35C57FC1245EULL,
		0x12A112F7DDCD7C9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BF8000000000000ULL,
		0xBB3357CC4FDFADE0ULL,
		0x917BF38427EF6BE4ULL,
		0xF26B946CD715FF04ULL,
		0x00004A844BDF7735ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E84CE4D95C8BD78ULL,
		0x4C0B10E788D1FBB8ULL,
		0x11E423DC98F67F48ULL,
		0x4EBAC87016DEAA7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B2B917AF0000000ULL,
		0xCF11A3F7701D099CULL,
		0xB931ECFE90981621ULL,
		0xE02DBD54FE23C847ULL,
		0x00000000009D7590ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x748947F9DEFC0D39ULL,
		0x349B769993698979ULL,
		0xA3967548148A18AAULL,
		0x2CD777A0DB30A5CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA44A3FCEF7E069C8ULL,
		0xA4DBB4CC9B4C4BCBULL,
		0x1CB3AA40A450C551ULL,
		0x66BBBD06D9852E5DULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x718BDE678CB63E9BULL,
		0x9C0D1B5D8F693DF3ULL,
		0x7F5281FB9160DC3FULL,
		0x686B2009974D1F66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD360000000000000ULL,
		0xBE6E317BCCF196C7ULL,
		0x87F381A36BB1ED27ULL,
		0xECCFEA503F722C1BULL,
		0x000D0D640132E9A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xAFF9188D76845AD0ULL,
		0xF737919336BDB5F0ULL,
		0x36AA312F69C57559ULL,
		0x14DD23563F2FE654ULL,
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
		0x2BFE46235DA116B4ULL,
		0x7DCDE464CDAF6D7CULL,
		0x0DAA8C4BDA715D56ULL,
		0x053748D58FCBF995ULL
	}};
	shift = 254;
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x52923471B8B05455ULL,
		0xFF6CD91C6B5F7970ULL,
		0x471C9A6482F0E698ULL,
		0x3C9FC4B566A3D2ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5154000000000000ULL,
		0xE5C14A48D1C6E2C1ULL,
		0x9A63FDB36471AD7DULL,
		0x4AB51C7269920BC3ULL,
		0x0000F27F12D59A8FULL,
		0x0000000000000000ULL
	}};
	shift = 178;
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xBBAEEB7D7723CCA3ULL,
		0x46E44B6ED0A9B8BAULL,
		0xB4ACF6AF4CDDFFA5ULL,
		0x083F050BC5156D91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCA3000000000000ULL,
		0xB8BABBAEEB7D7723ULL,
		0xFFA546E44B6ED0A9ULL,
		0x6D91B4ACF6AF4CDDULL,
		0x0000083F050BC515ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x59DA48FDF031BC5DULL,
		0xC8ED79309835A548ULL,
		0x34285CA25B3375AAULL,
		0x0CC708D11BB50F4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE06378BA00000000ULL,
		0x306B4A90B3B491FBULL,
		0xB666EB5591DAF261ULL,
		0x376A1E9E6850B944ULL,
		0x00000000198E11A2ULL,
		0x0000000000000000ULL
	}};
	shift = 161;
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x30FDE203ED50FE2AULL,
		0x77DE2BF45B421C25ULL,
		0x57A8357A080867FCULL,
		0x100F50EADDA3E61DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8A8000000000000ULL,
		0x7094C3F7880FB543ULL,
		0x9FF1DF78AFD16D08ULL,
		0x98755EA0D5E82021ULL,
		0x0000403D43AB768FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCB6FCE1C3B94D417ULL,
		0xF64148423F8E6EFAULL,
		0x2A318A3504C9DE39ULL,
		0x69612F2FC0A3FB9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE1C3B94D41700000ULL,
		0x8423F8E6EFACB6FCULL,
		0xA3504C9DE39F6414ULL,
		0xF2FC0A3FB9A2A318ULL,
		0x0000000000069612ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6B66F60FA036078DULL,
		0x88859613C881C446ULL,
		0x4A69E6E67BE3752AULL,
		0x282EF8913BF15DFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x01B03C6800000000ULL,
		0x440E22335B37B07DULL,
		0xDF1BA954442CB09EULL,
		0xDF8AEFF2534F3733ULL,
		0x000000014177C489ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 99;
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEB6420D43434908BULL,
		0x2067D28B4630B22BULL,
		0x748EA4E5CAAB27C2ULL,
		0x5A7201D17D4D03C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x908B000000000000ULL,
		0xB22BEB6420D43434ULL,
		0x27C22067D28B4630ULL,
		0x03C9748EA4E5CAABULL,
		0x00005A7201D17D4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFAD34DA9311967FDULL,
		0xA81B92C25A5DBA66ULL,
		0x48285AC9963C633EULL,
		0x1A875718EF2970D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x67FD000000000000ULL,
		0xBA66FAD34DA93119ULL,
		0x633EA81B92C25A5DULL,
		0x70D948285AC9963CULL,
		0x00001A875718EF29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 112;
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x84650CF92B9D34C9ULL,
		0xC7CF17018CA5D83EULL,
		0xA5FB63BD2BEAEFBAULL,
		0x34A754EC2391194EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9000000000000000ULL,
		0xE84650CF92B9D34CULL,
		0xAC7CF17018CA5D83ULL,
		0xEA5FB63BD2BEAEFBULL,
		0x034A754EC2391194ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEC6F2F4A931D49A4ULL,
		0xDE1EDC5F700363EBULL,
		0x402468EEBB9C40BFULL,
		0x45CDFDDFFEEF9BB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9A40000000000000ULL,
		0x3EBEC6F2F4A931D4ULL,
		0x0BFDE1EDC5F70036ULL,
		0xBB8402468EEBB9C4ULL,
		0x00045CDFDDFFEEF9ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7B4D5AD373CD8A50ULL,
		0x6A04EAB8C4AC3488ULL,
		0xF8C3146300A46A11ULL,
		0x6CB43C22240D9DD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9400000000000000ULL,
		0x221ED356B4DCF362ULL,
		0x845A813AAE312B0DULL,
		0x743E30C518C0291AULL,
		0x001B2D0F08890367ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0E21C01E37D060ADULL,
		0x974EE9336B3C17A6ULL,
		0x2E1F258453482CE3ULL,
		0x4A1F1E1A792AECEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE21C01E37D060AD0ULL,
		0x74EE9336B3C17A60ULL,
		0xE1F258453482CE39ULL,
		0xA1F1E1A792AECEB2ULL,
		0x0000000000000004ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xE891CB69C9494559ULL,
		0x9990AFCA0031F011ULL,
		0xD73D9925E31D4246ULL,
		0x6E523638226ADE87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x91CB69C949455900ULL,
		0x90AFCA0031F011E8ULL,
		0x3D9925E31D424699ULL,
		0x523638226ADE87D7ULL,
		0x000000000000006EULL,
		0x0000000000000000ULL
	}};
	shift = 136;
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFE1E78081505A767ULL,
		0xAFB234D1B468CF01ULL,
		0x969A7F39FC893BBDULL,
		0x0CC75368590C4E58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C040A82D3B38000ULL,
		0x1A68DA346780FF0FULL,
		0x3F9CFE449DDED7D9ULL,
		0xA9B42C86272C4B4DULL,
		0x0000000000000663ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9FCA2BB6AF0BC234ULL,
		0xFDF8E9163CA62A9CULL,
		0x71878B7D9A86AEA4ULL,
		0x18D08B22B9FCEB64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3400000000000000ULL,
		0x9C9FCA2BB6AF0BC2ULL,
		0xA4FDF8E9163CA62AULL,
		0x6471878B7D9A86AEULL,
		0x0018D08B22B9FCEBULL
	}};
	shift = 248;
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6B0D89BBC40BAFC9ULL,
		0xF9E327C3E8A3AF35ULL,
		0x8FD1D6329990083BULL,
		0x1C6E9296CE348D5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x5AC3626EF102EBF2ULL,
		0xFE78C9F0FA28EBCDULL,
		0xA3F4758CA664020EULL,
		0x071BA4A5B38D2357ULL
	}};
	shift = 254;
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x01E5F172307A45D6ULL,
		0xB78171724B40753AULL,
		0x0D510D2F65C0FF6FULL,
		0x78C744EAA547D11EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF2F8B9183D22EB00ULL,
		0xC0B8B925A03A9D00ULL,
		0xA88697B2E07FB7DBULL,
		0x63A27552A3E88F06ULL,
		0x000000000000003CULL
	}};
	shift = 199;
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x72CD35BA213FB55DULL,
		0xB7154183285E590DULL,
		0x686A24F3375A0832ULL,
		0x3C98CA412E8C4A1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72CD35BA213FB55DULL,
		0xB7154183285E590DULL,
		0x686A24F3375A0832ULL,
		0x3C98CA412E8C4A1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x371352E7260367A8ULL,
		0x0A0CA9DCB80854AAULL,
		0x56242CD909E3EE81ULL,
		0x6514D46960A1C8B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4C06CF5000000000ULL,
		0x7010A9546E26A5CEULL,
		0x13C7DD02141953B9ULL,
		0xC143916EAC4859B2ULL,
		0x00000000CA29A8D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x55B3D05CDF236ED6ULL,
		0x9C44B24BBDAD44E0ULL,
		0x0B760C4EADA45A8AULL,
		0x0ABB63E41DC08F4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5B3D05CDF236ED60ULL,
		0xC44B24BBDAD44E05ULL,
		0xB760C4EADA45A8A9ULL,
		0xABB63E41DC08F4F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB8B23DC72F0AE16AULL,
		0xE627D38F71D8EB02ULL,
		0x6601FE319D81E9D5ULL,
		0x43846B93994827FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3978570B50000000ULL,
		0x7B8EC75815C591EEULL,
		0x8CEC0F4EAF313E9CULL,
		0x9CCA413FFB300FF1ULL,
		0x00000000021C235CULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2EEC764A1FC4B5E6ULL,
		0x2FF888BA68218023ULL,
		0x0BFA2FD728531EDFULL,
		0x3B433754E16C54CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE25AF3000000000ULL,
		0x410C01197763B250ULL,
		0x4298F6F97FC445D3ULL,
		0x0B62A6605FD17EB9ULL,
		0x00000001DA19BAA7ULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2E1CDA43BC091F17ULL,
		0x7AE27C3E84D4780FULL,
		0x94517C87FACD5F23ULL,
		0x16AF4D2A6A295E2BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73690EF0247C5C00ULL,
		0x89F0FA1351E03CB8ULL,
		0x45F21FEB357C8DEBULL,
		0xBD34A9A8A578AE51ULL,
		0x000000000000005AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDEA23D5C59375E3DULL,
		0xBFB16B4F02C26E17ULL,
		0xBEAFC7002E6C52D6ULL,
		0x7DFE980C7289C191ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xF7A88F57164DD78FULL,
		0xAFEC5AD3C0B09B85ULL,
		0x6FABF1C00B9B14B5ULL,
		0x1F7FA6031CA27064ULL,
		0x0000000000000000ULL
	}};
	shift = 190;
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xEFFB22A745593A0EULL,
		0xA29C3DC183404A01ULL,
		0x961CA83F7ABCAE0EULL,
		0x0D92FCDD451D12BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x3DFF6454E8AB2741ULL,
		0xD45387B830680940ULL,
		0xD2C39507EF5795C1ULL,
		0x01B25F9BA8A3A257ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xB798CBAD3DF1626DULL,
		0x5AE832FAE0578402ULL,
		0x4D30C3886A1ACA76ULL,
		0x043F78724DBD10A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xDA00000000000000ULL,
		0x056F31975A7BE2C4ULL,
		0xECB5D065F5C0AF08ULL,
		0x489A618710D43594ULL,
		0x00087EF0E49B7A21ULL,
		0x0000000000000000ULL
	}};
	shift = 185;
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x7140FA99AC770807ULL,
		0xFABDDB8773E53F77ULL,
		0x514EA494B997F2BBULL,
		0x6FA2CB29D0AAE422ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40FA99AC77080700ULL,
		0xBDDB8773E53F7771ULL,
		0x4EA494B997F2BBFAULL,
		0xA2CB29D0AAE42251ULL,
		0x000000000000006FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xF7E650811F51023BULL,
		0x3A31530ECBB7A886ULL,
		0x627583AB30F9C588ULL,
		0x4842EF01E26061AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F51023B00000000ULL,
		0xCBB7A886F7E65081ULL,
		0x30F9C5883A31530EULL,
		0xE26061AA627583ABULL,
		0x000000004842EF01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x18C9EDA495C0AD14ULL,
		0xAEB66838F7E14E60ULL,
		0x4238561DD7D80E9CULL,
		0x4223A29B786C15D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD140000000000000ULL,
		0xE6018C9EDA495C0AULL,
		0xE9CAEB66838F7E14ULL,
		0x5D54238561DD7D80ULL,
		0x0004223A29B786C1ULL
	}};
	shift = 244;
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x75098543AD42F51DULL,
		0x8CFE7F254761E055ULL,
		0xD8A7B2FEAC6DC73AULL,
		0x6436E8F395730E58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A1D6A17A8E80000ULL,
		0xF92A3B0F02ABA84CULL,
		0x97F5636E39D467F3ULL,
		0x479CAB9872C6C53DULL,
		0x00000000000321B7ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x576382811059C150ULL,
		0xF6337B73CE7834B9ULL,
		0x14A9EDB6F0E47D50ULL,
		0x45E3D2FAF7B639ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x576382811059C150ULL,
		0xF6337B73CE7834B9ULL,
		0x14A9EDB6F0E47D50ULL,
		0x45E3D2FAF7B639ADULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xFAAEA9A5444F0347ULL,
		0x37328E8A65F90186ULL,
		0x253FA10E28614004ULL,
		0x47C9583B6504DA21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA5444F0347000000ULL,
		0x8A65F90186FAAEA9ULL,
		0x0E2861400437328EULL,
		0x3B6504DA21253FA1ULL,
		0x000000000047C958ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 88;
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x588AFFD9CF53E13EULL,
		0x4A16FDBC287E092FULL,
		0x48D681FFBEFDA272ULL,
		0x57FDC238EA024086ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE13E000000000000ULL,
		0x092F588AFFD9CF53ULL,
		0xA2724A16FDBC287EULL,
		0x408648D681FFBEFDULL,
		0x000057FDC238EA02ULL
	}};
	shift = 240;
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x9BFF0A48F6F52B76ULL,
		0xC4EB94FF35030B97ULL,
		0x5EA940C5DE0E7F20ULL,
		0x4D4725EDB3060C8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A95BB0000000000ULL,
		0x8185CBCDFF85247BULL,
		0x073F906275CA7F9AULL,
		0x830646AF54A062EFULL,
		0x00000026A392F6D9ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x2CF77AC0B78283B5ULL,
		0x8517D231A72B67E3ULL,
		0xF19019BF4F3FC0E4ULL,
		0x5F31FB68DE8D3534ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0ED4000000000000ULL,
		0x9F8CB3DDEB02DE0AULL,
		0x0392145F48C69CADULL,
		0xD4D3C64066FD3CFFULL,
		0x00017CC7EDA37A34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 114;
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xCB90639A68F771AAULL,
		0x90B7B3D988408826ULL,
		0x0736259538C53A29ULL,
		0x394AA4AC61211B23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEE3540000000000ULL,
		0x81104D9720C734D1ULL,
		0x8A7453216F67B310ULL,
		0x4236460E6C4B2A71ULL,
		0x00000072954958C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x3C5227EB8A284490ULL,
		0xDD6899748D7E0BF4ULL,
		0x92F188CA0F925B84ULL,
		0x7B743246F3C0A78BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x44FD714508920000ULL,
		0x132E91AFC17E878AULL,
		0x311941F24B709BADULL,
		0x8648DE7814F1725EULL,
		0x0000000000000F6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 77;
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x673F4F9ECF3E7DECULL,
		0x95AE3AB5F29C9D77ULL,
		0xE0405BE3DF2C00FEULL,
		0x165FCD8861FA123AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF9F7B00000000000ULL,
		0x7275DD9CFD3E7B3CULL,
		0xB003FA56B8EAD7CAULL,
		0xE848EB81016F8F7CULL,
		0x000000597F362187ULL,
		0x0000000000000000ULL
	}};
	shift = 170;
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB7A9227AB78ACBFULL,
		0x55CF5556706F58CBULL,
		0x9A6FB57914BAE8D6ULL,
		0x3D274BDA91FCA711ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADEA489EADE2B2FCULL,
		0x573D5559C1BD632EULL,
		0x69BED5E452EBA359ULL,
		0xF49D2F6A47F29C46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x51188CB1C1188905ULL,
		0x670C2C974AFC0F7EULL,
		0x66F2512575E45D51ULL,
		0x17C9EE16F9763BF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x88CB1C1188905000ULL,
		0xC2C974AFC0F7E511ULL,
		0x2512575E45D51670ULL,
		0x9EE16F9763BF866FULL,
		0x000000000000017CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x8DDB3761DB4A0C35ULL,
		0x649121C3171602D3ULL,
		0xA37AA1EA23F16D37ULL,
		0x6497C479BBECCA0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x186A000000000000ULL,
		0x05A71BB66EC3B694ULL,
		0xDA6EC92243862E2CULL,
		0x941F46F543D447E2ULL,
		0x0000C92F88F377D9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xDFA7710FF0DC1865ULL,
		0xA41DF11B4B185EFBULL,
		0x976D1FF0E881E9DFULL,
		0x7D273D0C6496D12BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB830CA0000000000ULL,
		0x30BDF7BF4EE21FE1ULL,
		0x03D3BF483BE23696ULL,
		0x2DA2572EDA3FE1D1ULL,
		0x000000FA4E7A18C9ULL
	}};
	shift = 233;
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x1E385DEC8453FD12ULL,
		0xF57F211C9D5CD9D9ULL,
		0x251063464E8B40D2ULL,
		0x15E5466D1B08B1E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E385DEC8453FD12ULL,
		0xF57F211C9D5CD9D9ULL,
		0x251063464E8B40D2ULL,
		0x15E5466D1B08B1E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x48F81D2D9C7F1EC5ULL,
		0xDE37249247555A4BULL,
		0xF685BFF24C13ABF9ULL,
		0x18E163B8907296F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE074B671FC7B1400ULL,
		0xDC92491D55692D23ULL,
		0x16FFC9304EAFE778ULL,
		0x858EE241CA5BDBDAULL,
		0x0000000000000063ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x0CCA0B2B2AA43F92ULL,
		0xE7A13D0C731F421FULL,
		0x9BCAF6C27C80E356ULL,
		0x5FE2E6253ABAE437ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x665059595521FC90ULL,
		0x3D09E86398FA10F8ULL,
		0xDE57B613E4071AB7ULL,
		0xFF173129D5D721BCULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x6EBABDF519B61832ULL,
		0x4A136BBF51F24169ULL,
		0x3F456801791A3858ULL,
		0x6A2596A8E4CED810ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB618320000000000ULL,
		0xF241696EBABDF519ULL,
		0x1A38584A136BBF51ULL,
		0xCED8103F45680179ULL,
		0x0000006A2596A8E4ULL,
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
	curve25519_key_lshift_inplace(&k1, shift);
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
		0xA74AD4A386B29DECULL,
		0xF5AEF52F2D5AC396ULL,
		0x78AF8E4299B11E7AULL,
		0x567BEBF00CE2DBA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA56A51C3594EF600ULL,
		0xD77A9796AD61CB53ULL,
		0x57C7214CD88F3D7AULL,
		0x3DF5F806716DD03CULL,
		0x000000000000002BULL
	}};
	shift = 199;
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
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
		0x67DEA596F0849449ULL,
		0x83114954F05379D7ULL,
		0xB04CCFB0DE42A260ULL,
		0x2175970912C44FB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2DE10928920000ULL,
		0x92A9E0A6F3AECFBDULL,
		0x9F61BC8544C10622ULL,
		0x2E1225889F716099ULL,
		0x00000000000042EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x435F3BF0AB59D238ULL,
		0x89C7744D7B5FCE74ULL,
		0xF20A712170936755ULL,
		0x741E6C6F27DAC660ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF9DF855ACE91C000ULL,
		0x3BA26BDAFE73A21AULL,
		0x53890B849B3AAC4EULL,
		0xF363793ED6330790ULL,
		0x00000000000003A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x197E32DB7E207E50ULL,
		0x956A2AE988EFF874ULL,
		0x1FDD1C866DB59300ULL,
		0x42E3DB049D3AADA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xD065F8CB6DF881F9ULL,
		0x0255A8ABA623BFE1ULL,
		0x8C7F747219B6D64CULL,
		0x010B8F6C1274EAB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD218777FA84349E0ULL,
		0xC6F05B0C44B4C5A7ULL,
		0x85153CAD7A02FEC3ULL,
		0x51E6C15FF815A065ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBBFD421A4F000000ULL,
		0xD86225A62D3E90C3ULL,
		0xE56BD017F61E3782ULL,
		0x0AFFC0AD032C28A9ULL,
		0x0000000000028F36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E4769C092D8E7E5ULL,
		0x7782DD0F3711F730ULL,
		0xE020B8E26C7CC540ULL,
		0x2530B4AD434097EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6C73F28000000000ULL,
		0x88FB984F23B4E049ULL,
		0x3E62A03BC16E879BULL,
		0xA04BF770105C7136ULL,
		0x00000012985A56A1ULL,
		0x0000000000000000ULL
	}};
	shift = 167;
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D63F77999E0E33AULL,
		0x98728ED4B77DDAD3ULL,
		0xC08629C5F65D92F0ULL,
		0x45E766C8AFAA0B19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x667838CE80000000ULL,
		0x2DDF76B4C758FDDEULL,
		0x7D9764BC261CA3B5ULL,
		0x2BEA82C670218A71ULL,
		0x000000001179D9B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0FBA0FD0E08C9C2ULL,
		0x05A51DD2E833C16CULL,
		0x409C1AD5F09CC9C0ULL,
		0x268AC9CA96E6401FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9384000000000000ULL,
		0x82D9E1F741FA1C11ULL,
		0x93800B4A3BA5D067ULL,
		0x803E813835ABE139ULL,
		0x00004D1593952DCCULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB0FA69E9E5764050ULL,
		0x57D5C1F8E6A78DFFULL,
		0x964677148F9128ACULL,
		0x1FC578CB9EE582B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBB20280000000000ULL,
		0x53C6FFD87D34F4F2ULL,
		0xC894562BEAE0FC73ULL,
		0x72C158CB233B8A47ULL,
		0x0000000FE2BC65CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA20B5773FB013859ULL,
		0xCEBC95A3473055AFULL,
		0xF3ED8C83968F4121ULL,
		0x018015BA6425F61CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x70B2000000000000ULL,
		0xAB5F4416AEE7F602ULL,
		0x82439D792B468E60ULL,
		0xEC39E7DB19072D1EULL,
		0x000003002B74C84BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD579FDEAD6C33B70ULL,
		0x57DA3AA8F6D29660ULL,
		0x62A0EA4AE0EDADF6ULL,
		0x3B2DD759718A1DFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619DB80000000000ULL,
		0x694B306ABCFEF56BULL,
		0x76D6FB2BED1D547BULL,
		0xC50EFDB150752570ULL,
		0x0000001D96EBACB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82DD45EE110C21AEULL,
		0x7FB544B05C6A95DCULL,
		0xB8381717BCBBC5CFULL,
		0x6C5111EACA09B480ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE00000000000000ULL,
		0xDC82DD45EE110C21ULL,
		0xCF7FB544B05C6A95ULL,
		0x80B8381717BCBBC5ULL,
		0x006C5111EACA09B4ULL
	}};
	shift = 248;
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA66224F4B0D26346ULL,
		0x9355DE5DF84D33B2ULL,
		0x7F36ECFC5F965614ULL,
		0x4849BC1F1618B6A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC449E961A4C68C00ULL,
		0xABBCBBF09A67654CULL,
		0x6DD9F8BF2CAC2926ULL,
		0x93783E2C316D52FEULL,
		0x0000000000000090ULL
	}};
	shift = 201;
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6B884E8CDBAEF1BBULL,
		0x8AC35AE934B37BD4ULL,
		0xE03DFF8E9B69E802ULL,
		0x6F4B56B3195D6067ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x884E8CDBAEF1BB00ULL,
		0xC35AE934B37BD46BULL,
		0x3DFF8E9B69E8028AULL,
		0x4B56B3195D6067E0ULL,
		0x000000000000006FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF4DB187B6788045BULL,
		0x13AB36A2CDC22A22ULL,
		0x0DEEAAB1D7C79458ULL,
		0x00CBB6099651DE8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC3DB3C4022D80000ULL,
		0xB5166E115117A6D8ULL,
		0x558EBE3CA2C09D59ULL,
		0xB04CB28EF4506F75ULL,
		0x000000000000065DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1E3DFE5A7291F1C5ULL,
		0x5B4E8F58D89BC366ULL,
		0x55C50D7FF11824ADULL,
		0x0D9278856394EF27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2D3948F8E2800000ULL,
		0xAC6C4DE1B30F1EFFULL,
		0xBFF88C1256ADA747ULL,
		0x42B1CA7793AAE286ULL,
		0x000000000006C93CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00AA44EF6085D571ULL,
		0x1115ADCA61642CFDULL,
		0xE04F3A5FDF1F4AEBULL,
		0x76A19842896431CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4EF6085D57100000ULL,
		0xDCA61642CFD00AA4ULL,
		0xA5FDF1F4AEB1115AULL,
		0x842896431CEE04F3ULL,
		0x0000000000076A19ULL,
		0x0000000000000000ULL
	}};
	shift = 148;
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4DCB2A7384C6CDCULL,
		0xF6A0B84A651E3EA7ULL,
		0x7D3083654BDA09A2ULL,
		0x33A6CAD3EB0D7EA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9CE131B370000000ULL,
		0x299478FA9ED372CAULL,
		0x952F68268BDA82E1ULL,
		0x4FAC35FAA5F4C20DULL,
		0x0000000000CE9B2BULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCB3EA8C44E7BFECULL,
		0x2769748C5FB523A0ULL,
		0x59A3556C2573CC81ULL,
		0x55D77F685F04B93CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCB3EA8C44E7BFEC0ULL,
		0x769748C5FB523A0CULL,
		0x9A3556C2573CC812ULL,
		0x5D77F685F04B93C5ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90233B8783C6E0A5ULL,
		0xAE5A588F1B9C5A17ULL,
		0x8884C4F2AAC8EFF0ULL,
		0x5EF8A7C55AAE7F21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC6E0A50000000000ULL,
		0x9C5A1790233B8783ULL,
		0xC8EFF0AE5A588F1BULL,
		0xAE7F218884C4F2AAULL,
		0x0000005EF8A7C55AULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FA88DAC8341A752ULL,
		0x7784AA380D0E6200ULL,
		0x8ADD9EF5B1F95CB8ULL,
		0x3A77D81DC88A060BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x341A752000000000ULL,
		0xD0E62005FA88DAC8ULL,
		0x1F95CB87784AA380ULL,
		0x88A060B8ADD9EF5BULL,
		0x00000003A77D81DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1A2D68BC76287F1AULL,
		0xB78BD291DD18FC55ULL,
		0xA294D30CA6843A37ULL,
		0x49B1F4193BC3D9C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1A2D68BC76287F1AULL,
		0xB78BD291DD18FC55ULL,
		0xA294D30CA6843A37ULL,
		0x49B1F4193BC3D9C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 64;
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x258896DD52B53E3CULL,
		0xF720764C5CDD0B58ULL,
		0xFF6BEDA0702A21E7ULL,
		0x0C268D3AFA6BF714ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4F8F000000000000ULL,
		0x42D6096225B754ADULL,
		0x8879FDC81D931737ULL,
		0xFDC53FDAFB681C0AULL,
		0x00000309A34EBE9AULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9439E0F76198245EULL,
		0xBDA354A01D46A9EBULL,
		0xF2DF7C646230B35CULL,
		0x371167A44CE4401CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF000000000000000ULL,
		0x5CA1CF07BB0CC122ULL,
		0xE5ED1AA500EA354FULL,
		0xE796FBE32311859AULL,
		0x01B88B3D22672200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 123;
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96A3AC2739F98703ULL,
		0x26FCDDA59138CAF7ULL,
		0x3F67FAB8C9801FB2ULL,
		0x230D9B81A08724F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C0C000000000000ULL,
		0x2BDE5A8EB09CE7E6ULL,
		0x7EC89BF3769644E3ULL,
		0x93D0FD9FEAE32600ULL,
		0x00008C366E06821CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDFD0159659A1CDB5ULL,
		0xC0B533E9B2A4E279ULL,
		0xE3F38023323B57F5ULL,
		0x62E114727B02B600ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x659668736D400000ULL,
		0xFA6CA9389E77F405ULL,
		0x08CC8ED5FD702D4CULL,
		0x1C9EC0AD8038FCE0ULL,
		0x000000000018B845ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE004C0C1D434DF20ULL,
		0xAECC347BDC0493E5ULL,
		0xC5B6C574C41F7B74ULL,
		0x624C1B86AC75375CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF200000000000000ULL,
		0x3E5E004C0C1D434DULL,
		0xB74AECC347BDC049ULL,
		0x75CC5B6C574C41F7ULL,
		0x000624C1B86AC753ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21FB5F92C75EE77AULL,
		0x1160FA4BEC9E50F6ULL,
		0xC5EBF3B50CF1C591ULL,
		0x3E5959B6C0679252ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF258EBDCEF400000ULL,
		0x497D93CA1EC43F6BULL,
		0x76A19E38B2222C1FULL,
		0x36D80CF24A58BD7EULL,
		0x000000000007CB2BULL
	}};
	shift = 213;
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCD7332AE81417A3ULL,
		0x28DD287B9ACA70A3ULL,
		0x8529CA1BA2605478ULL,
		0x2BCF861186AB7E07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x99AE6655D0282F46ULL,
		0x51BA50F73594E147ULL,
		0x0A53943744C0A8F0ULL,
		0x579F0C230D56FC0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32427B3EACA68CB5ULL,
		0xA3BA88EB84582BDCULL,
		0x0B73E833215EFBA9ULL,
		0x1DC2347C4E49D8D7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0x0C909ECFAB29A32DULL,
		0x68EEA23AE1160AF7ULL,
		0xC2DCFA0CC857BEEAULL,
		0x07708D1F13927635ULL
	}};
	shift = 254;
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBBA81454ADF6BEA7ULL,
		0x9DC3B54525C39752ULL,
		0x62D8431B080EF1A9ULL,
		0x4A8B094DE4598BE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEA70000000000000ULL,
		0x752BBA81454ADF6BULL,
		0x1A99DC3B54525C39ULL,
		0xBE662D8431B080EFULL,
		0x0004A8B094DE4598ULL
	}};
	shift = 244;
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCDFBA0764222D30ULL,
		0xDF8108B038DCE286ULL,
		0x5942E0B23CB07B67ULL,
		0x2FC2EDC27A309EA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EE81D9088B4C000ULL,
		0x0422C0E3738A1B73ULL,
		0x0B82C8F2C1ED9F7EULL,
		0x0BB709E8C27A9D65ULL,
		0x00000000000000BFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x056F788205EFE188ULL,
		0x2FBFC931BC5502CEULL,
		0xB0C318B4D593ABB8ULL,
		0x5B98EE87199EC8CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8800000000000000ULL,
		0xCE056F788205EFE1ULL,
		0xB82FBFC931BC5502ULL,
		0xCDB0C318B4D593ABULL,
		0x005B98EE87199EC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF11DFDB45BA01BEFULL,
		0x75E3A285C60FA61EULL,
		0x34B7A888B9185F28ULL,
		0x7336C56EE38544CBULL,
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
		0xF11DFDB45BA01BEFULL,
		0x75E3A285C60FA61EULL,
		0x34B7A888B9185F28ULL,
		0x7336C56EE38544CBULL
	}};
	shift = 256;
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFAA1AA8BE6A87A68ULL,
		0x1A6A5A7C2FD20D63ULL,
		0xB9B03CF0415FC92FULL,
		0x5352364F03223071ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA8BE6A87A680000ULL,
		0x5A7C2FD20D63FAA1ULL,
		0x3CF0415FC92F1A6AULL,
		0x364F03223071B9B0ULL,
		0x0000000000005352ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4DBE14014E36D531ULL,
		0xE07E6DB0AD951E19ULL,
		0xD50601D94147AC80ULL,
		0x5999EC90ACD81F8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4C40000000000000ULL,
		0x86536F8500538DB5ULL,
		0x20381F9B6C2B6547ULL,
		0xE3B54180765051EBULL,
		0x0016667B242B3607ULL
	}};
	shift = 246;
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB82FDEB9B35D6AC9ULL,
		0x091FEC3C3F07197EULL,
		0xC6E6E250712A1164ULL,
		0x4F6426478ED1C52EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD9AEB56480000000ULL,
		0x1F838CBF5C17EF5CULL,
		0x389508B2048FF61EULL,
		0xC768E29763737128ULL,
		0x0000000027B21323ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 95;
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA47B70FDD9D9D2F0ULL,
		0x0BCA18098B705BB4ULL,
		0x74529EF4B9D6D60FULL,
		0x08C6B761B0CAF460ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x291EDC3F767674BCULL,
		0xC2F2860262DC16EDULL,
		0x1D14A7BD2E75B583ULL,
		0x0231ADD86C32BD18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 126;
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBEBB92089214FCA8ULL,
		0x810F809EB8D7BD28ULL,
		0x9709D8604CA13A10ULL,
		0x51E29ADC9E7F0A82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x89214FCA80000000ULL,
		0xEB8D7BD28BEBB920ULL,
		0x04CA13A10810F809ULL,
		0xC9E7F0A829709D86ULL,
		0x00000000051E29ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6AC2BA8124F3439ULL,
		0x55BE8FDC16637139ULL,
		0xF7F3506422CBED35ULL,
		0x7013BEFB32707662ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA0493CD0E4000000ULL,
		0x70598DC4E75AB0AEULL,
		0x908B2FB4D556FA3FULL,
		0xECC9C1D98BDFCD41ULL,
		0x0000000001C04EFBULL
	}};
	shift = 218;
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3045C285E0FD5B6ULL,
		0x7E902196B6E5EE59ULL,
		0xB033DCB27BD53409ULL,
		0x46664B3F9A1A1459ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xADB0000000000000ULL,
		0x72CD1822E142F07EULL,
		0xA04BF4810CB5B72FULL,
		0xA2CD819EE593DEA9ULL,
		0x0002333259FCD0D0ULL
	}};
	shift = 243;
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB576904CD5C35CCULL,
		0xA4646AF2B7BEDC08ULL,
		0x1F3C1D1395763F85ULL,
		0x07D2ADBC850C58FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x48266AE1AE600000ULL,
		0x5795BDF6E0455ABBULL,
		0xE89CABB1FC2D2323ULL,
		0x6DE42862C7F8F9E0ULL,
		0x0000000000003E95ULL,
		0x0000000000000000ULL
	}};
	shift = 147;
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF188BC427FDFB384ULL,
		0x096CACE2081C97B7ULL,
		0xC171A6BAFC815D76ULL,
		0x29610785630A4591ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E213FEFD9C20000ULL,
		0x5671040E4BDBF8C4ULL,
		0xD35D7E40AEBB04B6ULL,
		0x83C2B18522C8E0B8ULL,
		0x00000000000014B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CA8D872E6710D68ULL,
		0xB9B40412ECC3A139ULL,
		0x639C12AD04F066C8ULL,
		0x3509C0EDFF1A3D80ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD000000000000000ULL,
		0x72D951B0E5CCE21AULL,
		0x9173680825D98742ULL,
		0x00C738255A09E0CDULL,
		0x006A1381DBFE347BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63AC7AE3DB683780ULL,
		0x2382FC04E74927E2ULL,
		0x3F53E7D71D496E49ULL,
		0x2D7C7BF55D347224ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63D71EDB41BC000ULL,
		0xC17E0273A493F131ULL,
		0xA9F3EB8EA4B72491ULL,
		0xBE3DFAAE9A39121FULL,
		0x0000000000000016ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5BF2D542733C0128ULL,
		0x548EFA8FD7C7C015ULL,
		0xAAB89684DB8E3CB6ULL,
		0x023E9D37C4094184ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xCCF004A000000000ULL,
		0x5F1F00556FCB5509ULL,
		0x6E38F2D9523BEA3FULL,
		0x10250612AAE25A13ULL,
		0x0000000008FA74DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x763E3C07618FB9D6ULL,
		0x2FEFC316D21E7C93ULL,
		0x64687AB0DB9C0494ULL,
		0x68F2BDE75A139EF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xEC31F73AC0000000ULL,
		0xDA43CF926EC7C780ULL,
		0x1B73809285FDF862ULL,
		0xEB4273DE4C8D0F56ULL,
		0x000000000D1E57BCULL
	}};
	shift = 221;
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08F3A1AF9BFD4F3AULL,
		0x2AC61B2ACF432286ULL,
		0xA4AD310C54DC0058ULL,
		0x6C38F87ECAB7B0C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CDFEA79D0000000ULL,
		0x567A191430479D0DULL,
		0x62A6E002C15630D9ULL,
		0xF655BD8635256988ULL,
		0x000000000361C7C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7A0BFD4BDBEE557ULL,
		0xE5C1A40957991702ULL,
		0xBF3ABF9AD43612D8ULL,
		0x4A1A51C313FF1809ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDBEE55700000000ULL,
		0x57991702C7A0BFD4ULL,
		0xD43612D8E5C1A409ULL,
		0x13FF1809BF3ABF9AULL,
		0x000000004A1A51C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE8A2421E165ADFF4ULL,
		0x4C5A99986187F445ULL,
		0x62262898D7FF7054ULL,
		0x191EA9D75D671510ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x51210F0B2D6FFA00ULL,
		0x2D4CCC30C3FA22F4ULL,
		0x13144C6BFFB82A26ULL,
		0x8F54EBAEB38A8831ULL,
		0x000000000000000CULL
	}};
	shift = 199;
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6141497411070057ULL,
		0x45D273C6C70FE02BULL,
		0x11FAFB8DD6167F2FULL,
		0x43A6190AAA2D592AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0883802B80000000ULL,
		0x6387F015B0A0A4BAULL,
		0xEB0B3F97A2E939E3ULL,
		0x5516AC9508FD7DC6ULL,
		0x0000000021D30C85ULL
	}};
	shift = 223;
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14E28BF8F716D7A8ULL,
		0x429CA332999FB765ULL,
		0x2251DAD3E6A606B3ULL,
		0x2E335269BCF526E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE3DC5B5EA0000000ULL,
		0xCA667EDD94538A2FULL,
		0x4F9A981ACD0A728CULL,
		0xA6F3D49B8889476BULL,
		0x0000000000B8CD49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 90;
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09F989DE85A94227ULL,
		0x396E7911A135A85DULL,
		0x3D16CB36331D3C57ULL,
		0x608A73CA11B5E73DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7A16A5089C000000ULL,
		0x4684D6A17427E627ULL,
		0xD8CC74F15CE5B9E4ULL,
		0x2846D79CF4F45B2CULL,
		0x00000000018229CFULL,
		0x0000000000000000ULL
	}};
	shift = 154;
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75E9431B9BCBB04CULL,
		0x816F2A6B82A9FE20ULL,
		0xBB53D2AF446475E9ULL,
		0x4B4A337A74540C99ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9431B9BCBB04C00ULL,
		0x6F2A6B82A9FE2075ULL,
		0x53D2AF446475E981ULL,
		0x4A337A74540C99BBULL,
		0x000000000000004BULL
	}};
	shift = 200;
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x276F99DDEAFF3F63ULL,
		0x3290FD03511205F9ULL,
		0xE54603FED62B7FE7ULL,
		0x0907F3790EB48D91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF57F9FB18000000ULL,
		0x1A88902FC93B7CCEULL,
		0xF6B15BFF399487E8ULL,
		0xC875A46C8F2A301FULL,
		0x0000000000483F9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5201A395B3D82345ULL,
		0x20747E865471D42CULL,
		0x948E02046A09EA09ULL,
		0x4FCDBA22095071FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3450000000000000ULL,
		0x42C5201A395B3D82ULL,
		0xA0920747E865471DULL,
		0x1FB948E02046A09EULL,
		0x0004FCDBA2209507ULL,
		0x0000000000000000ULL
	}};
	shift = 180;
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9BAA0AAB6C7F113ULL,
		0xCB2B7067116EF22DULL,
		0xA7C09E6137603176ULL,
		0x22A0EDCD5466343FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFE22600000000000ULL,
		0xDE45B737541556D8ULL,
		0x062ED9656E0CE22DULL,
		0xC687F4F813CC26ECULL,
		0x000004541DB9AA8CULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFB31A8928A61A3DULL,
		0x13A406787FC0F5FDULL,
		0x8E52D0B9C59C3343ULL,
		0x500235332D199435ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF663512514C347AULL,
		0x27480CF0FF81EBFBULL,
		0x1CA5A1738B386686ULL,
		0xA0046A665A33286BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF73F0A2F86FE063FULL,
		0x2369766BD8E89680ULL,
		0xE96C27A59797C934ULL,
		0x3B3AB34F86BBC6D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE7E145F0DFC0C7EULL,
		0x46D2ECD7B1D12D01ULL,
		0xD2D84F4B2F2F9268ULL,
		0x7675669F0D778DADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EDDCAD5C7AD89BAULL,
		0x6E72ED4C51637AECULL,
		0x07747C79E96F3D25ULL,
		0x7A7C6FC9EA1BEF70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x6EE56AE3D6C4DD00ULL,
		0x3976A628B1BD7627ULL,
		0xBA3E3CF4B79E92B7ULL,
		0x3E37E4F50DF7B803ULL,
		0x000000000000003DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x707E20C702320019ULL,
		0x86976B5368941E6BULL,
		0xD02377C30F2D11F7ULL,
		0x2FF7910DEA80FFFEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0320000000000000ULL,
		0xCD6E0FC418E04640ULL,
		0x3EF0D2ED6A6D1283ULL,
		0xFFDA046EF861E5A2ULL,
		0x0005FEF221BD501FULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4423B7B024DC5A90ULL,
		0x5FF5AE2571CB3D11ULL,
		0x217E62F6B96F4374ULL,
		0x3D0F4F9A71783CDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA211DBD8126E2D48ULL,
		0x2FFAD712B8E59E88ULL,
		0x90BF317B5CB7A1BAULL,
		0x1E87A7CD38BC1E6DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x98438EE7CFA9DBA6ULL,
		0x050CA9B201395EDFULL,
		0xFAE2004EA1A5ED99ULL,
		0x4A14E0A5C1654883ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x30871DCF9F53B74CULL,
		0x0A1953640272BDBFULL,
		0xF5C4009D434BDB32ULL,
		0x9429C14B82CA9107ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB4FEE6972897A02ULL,
		0x6D62C0E9CB8281E1ULL,
		0xC41EB08D897F80CCULL,
		0x723F4854CCDD27F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x972897A020000000ULL,
		0x9CB8281E1EB4FEE6ULL,
		0xD897F80CC6D62C0EULL,
		0x4CCDD27F6C41EB08ULL,
		0x000000000723F485ULL,
		0x0000000000000000ULL
	}};
	shift = 156;
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x90572B0613AFA21BULL,
		0xC80CECEDBBCEFA29ULL,
		0x6F5B8DD7E81D3EF8ULL,
		0x0837F7D940FBF0FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAFA21B0000000000ULL,
		0xCEFA2990572B0613ULL,
		0x1D3EF8C80CECEDBBULL,
		0xFBF0FF6F5B8DD7E8ULL,
		0x0000000837F7D940ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B9328D0D3F54D15ULL,
		0xA4BCF47D535EE195ULL,
		0x75292FEBDE7A7A73ULL,
		0x4F4C3002D3328271ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4CA3434FD5345400ULL,
		0xF3D1F54D7B86556EULL,
		0xA4BFAF79E9E9CE92ULL,
		0x30C00B4CCA09C5D4ULL,
		0x000000000000013DULL
	}};
	shift = 202;
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70A82F6931F20EA0ULL,
		0x4CB019D703BC7109ULL,
		0xEFFE280C57EBF528ULL,
		0x4F26DC76B23366CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x498F907500000000ULL,
		0xB81DE3884B85417BULL,
		0x62BF5FA9426580CEULL,
		0xB5919B367F7FF140ULL,
		0x00000000027936E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 91;
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x00B160601B330963ULL,
		0x95312D60EB362395ULL,
		0x39FB0EFAA8755211ULL,
		0x6A2AC02C24C7D689ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2C60000000000000ULL,
		0x72A0162C0C036661ULL,
		0x4232A625AC1D66C4ULL,
		0xD1273F61DF550EAAULL,
		0x000D4558058498FAULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x620629222AB9EB5CULL,
		0x0E439C5FA8296D41ULL,
		0xC85157434E3AAB72ULL,
		0x6673212572A36249ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x2C40C52445573D6BULL,
		0x41C8738BF5052DA8ULL,
		0x390A2AE869C7556EULL,
		0x0CCE6424AE546C49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 125;
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x323E68E6FE8155CCULL,
		0xBF3FEDD015E51CAFULL,
		0xFAD0583C73A5E2F9ULL,
		0x634145B03C666EB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD1CDFD02AB980000ULL,
		0xDBA02BCA395E647CULL,
		0xB078E74BC5F37E7FULL,
		0x8B6078CCDD67F5A0ULL,
		0x000000000000C682ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA0AC54ADDFF1937CULL,
		0x83DF3D6E86BC65D3ULL,
		0xC30051DB301AD0F7ULL,
		0x1E0FDB6138F6A315ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77FC64DF00000000ULL,
		0xA1AF1974E82B152BULL,
		0xCC06B43DE0F7CF5BULL,
		0x4E3DA8C570C01476ULL,
		0x000000000783F6D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AEC5B9E3B9040A2ULL,
		0x37733D203A3C8062ULL,
		0xBBF036103B62F1DAULL,
		0x559E2F88155E9E39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x9EBB16E78EE41028ULL,
		0x8DDCCF480E8F2018ULL,
		0x6EFC0D840ED8BC76ULL,
		0x15678BE20557A78EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0FE5D5D1CF873FC7ULL,
		0x82958DAFCD23D451ULL,
		0x6FC2A38B3B611674ULL,
		0x47B8D168F9605C8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x5D5D1CF873FC7000ULL,
		0x58DAFCD23D4510FEULL,
		0x2A38B3B611674829ULL,
		0x8D168F9605C8C6FCULL,
		0x000000000000047BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 76;
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA2DA1C2CFAF98F7ULL,
		0x6CA3F16CE8913E78ULL,
		0x0FC0CF1F91773B93ULL,
		0x24899AB43B77D130ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE167D7CC7B800000ULL,
		0xB674489F3C7D16D0ULL,
		0x8FC8BB9DC9B651F8ULL,
		0x5A1DBBE89807E067ULL,
		0x00000000001244CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x300A6B32E7C55B64ULL,
		0xAE90D15660C9E04EULL,
		0x877C9A7C0D8A2100ULL,
		0x499FEE092CA9B8F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4000000000000000ULL,
		0xE300A6B32E7C55B6ULL,
		0x0AE90D15660C9E04ULL,
		0x3877C9A7C0D8A210ULL,
		0x0499FEE092CA9B8FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 60;
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD6159550E0E95F14ULL,
		0x1F0CF2833652FE9DULL,
		0xF679F4967CE45C8FULL,
		0x574F7E90E9E5AA88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xACAA87074AF8A000ULL,
		0x679419B297F4EEB0ULL,
		0xCFA4B3E722E478F8ULL,
		0x7BF4874F2D5447B3ULL,
		0x00000000000002BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB806D3C28D39175ULL,
		0x406A2671F055460DULL,
		0xAA6A66028005E232ULL,
		0x0096F4D3DDBDC0EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5D40000000000000ULL,
		0x837AE01B4F0A34E4ULL,
		0x8C901A899C7C1551ULL,
		0x3B6A9A9980A00178ULL,
		0x000025BD34F76F70ULL
	}};
	shift = 246;
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0ADFBF3B68504C3ULL,
		0xC92EDD773E24E3DCULL,
		0x9B881DA458245E1DULL,
		0x7BECD16F31B30DCBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x56FDF9DB42826180ULL,
		0x976EBB9F1271EE78ULL,
		0xC40ED22C122F0EE4ULL,
		0xF668B798D986E5CDULL,
		0x000000000000003DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9E270167B5E80A7ULL,
		0xEE3A4D8C8DA97EF0ULL,
		0xC91705CFF1D7BEB4ULL,
		0x4FBEE2AC3682C28AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4053800000000000ULL,
		0xBF7864F1380B3DAFULL,
		0xDF5A771D26C646D4ULL,
		0x6145648B82E7F8EBULL,
		0x000027DF71561B41ULL
	}};
	shift = 239;
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54B916A1EBFC7D2EULL,
		0x665726D7F66F28BEULL,
		0xC23826B9E64A1AA4ULL,
		0x7E938F83749EB764ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE3E97000000000ULL,
		0xB37945F2A5C8B50FULL,
		0x3250D52332B936BFULL,
		0xA4F5BB2611C135CFULL,
		0x00000003F49C7C1BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E989976911A4E29ULL,
		0xEDFDC944BD177DA5ULL,
		0x7B5687EC4651A3B9ULL,
		0x01457C594CA8CBF2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3132ED22349C5200ULL,
		0xFB92897A2EFB4B1DULL,
		0xAD0FD88CA34773DBULL,
		0x8AF8B2995197E4F6ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96899C8ACA528F0AULL,
		0x94F9E340C76B4BB9ULL,
		0x02D00CE7FE360DC4ULL,
		0x76BAD1AA363A1BDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1E14000000000000ULL,
		0x97732D13391594A5ULL,
		0x1B8929F3C6818ED6ULL,
		0x37B805A019CFFC6CULL,
		0x0000ED75A3546C74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 113;
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEC082EC540492BBDULL,
		0x23C67EABD8F6A54FULL,
		0x0CDF622343DA021BULL,
		0x22C09E1FE917D963ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A02495DE8000000ULL,
		0x5EC7B52A7F604176ULL,
		0x1A1ED010D91E33F5ULL,
		0xFF48BECB1866FB11ULL,
		0x00000000011604F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BCD78B45EBED99FULL,
		0x3B6860CF5296EE0AULL,
		0x4BF3216CF8F4E470ULL,
		0x4BB00AF17A05304EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0x4579AF168BD7DB33ULL,
		0x076D0C19EA52DDC1ULL,
		0xC97E642D9F1E9C8EULL,
		0x0976015E2F40A609ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04332E01300A9EACULL,
		0xD1E45C8F97C0C90BULL,
		0x5AE6BF019260E0D2ULL,
		0x33214F320F8E456AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x332E01300A9EAC00ULL,
		0xE45C8F97C0C90B04ULL,
		0xE6BF019260E0D2D1ULL,
		0x214F320F8E456A5AULL,
		0x0000000000000033ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D277DDBE13713C3ULL,
		0x20EDBE3FAE959A53ULL,
		0x1D4B4E1CD131C38FULL,
		0x58BBFEEC01A1820FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6D277DDBE13713C3ULL,
		0x20EDBE3FAE959A53ULL,
		0x1D4B4E1CD131C38FULL,
		0x58BBFEEC01A1820FULL,
		0x0000000000000000ULL
	}};
	shift = 192;
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC20D952BC1E28A53ULL,
		0xEA4D32F7EF04FE08ULL,
		0x79C8EB402C2CC9FCULL,
		0x17B327FA1600BA8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2BC1E28A53000000ULL,
		0xF7EF04FE08C20D95ULL,
		0x402C2CC9FCEA4D32ULL,
		0xFA1600BA8E79C8EBULL,
		0x000000000017B327ULL,
		0x0000000000000000ULL
	}};
	shift = 152;
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA964F8B7B2F8E3FEULL,
		0x444B0A939FA02AF4ULL,
		0x2325BBE8A58095A4ULL,
		0x1DC448E1239FB2BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DECBE38FF800000ULL,
		0xA4E7E80ABD2A593EULL,
		0xFA296025691112C2ULL,
		0x3848E7ECAF88C96EULL,
		0x0000000000077112ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC9C426BA900D4E46ULL,
		0xAB78DAF2809B072DULL,
		0x59E170C4D43F01DDULL,
		0x18E58C0B73EE6632ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x00D4E46000000000ULL,
		0x09B072DC9C426BA9ULL,
		0x43F01DDAB78DAF28ULL,
		0x3EE663259E170C4DULL,
		0x000000018E58C0B7ULL
	}};
	shift = 228;
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9DF678EEA2DA9432ULL,
		0x5E8E227031B7F815ULL,
		0x4FE3E56656EFB6C3ULL,
		0x7EFF4A7EA92E6A8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EEA2DA943200000ULL,
		0x27031B7F8159DF67ULL,
		0x56656EFB6C35E8E2ULL,
		0xA7EA92E6A8C4FE3EULL,
		0x000000000007EFF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4A1BBC4B98E23BE4ULL,
		0x3355B79B82ED7026ULL,
		0x40C036373BF0E030ULL,
		0x2C5F47E3568A3860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x388EF90000000000ULL,
		0xBB5C099286EF12E6ULL,
		0xFC380C0CD56DE6E0ULL,
		0xA28E1810300D8DCEULL,
		0x0000000B17D1F8D5ULL
	}};
	shift = 230;
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2E0349DBDE24FD97ULL,
		0x1AF66271A150C6EEULL,
		0x39F1105B12A490DBULL,
		0x2F92C7BED143BF73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0349DBDE24FD9700ULL,
		0xF66271A150C6EE2EULL,
		0xF1105B12A490DB1AULL,
		0x92C7BED143BF7339ULL,
		0x000000000000002FULL
	}};
	shift = 200;
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAE358AB5B3CA07AULL,
		0xE77561A0E554B18BULL,
		0x2BD71EC6FCE9CA29ULL,
		0x3CE2A78284FF79DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF400000000000000ULL,
		0x17B5C6B156B67940ULL,
		0x53CEEAC341CAA963ULL,
		0xB457AE3D8DF9D394ULL,
		0x0079C54F0509FEF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD294AD5BD8AEF63DULL,
		0xB953D12A7CDA1565ULL,
		0xE0C4CB6C24100907ULL,
		0x126B1D34456BAA6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB56F62BBD8F40000ULL,
		0x44A9F36855974A52ULL,
		0x2DB09040241EE54FULL,
		0x74D115AEA9BB8313ULL,
		0x00000000000049ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37848081065DCC8BULL,
		0x3667C1BACE8B13D2ULL,
		0x1A359BFF7EE2BD26ULL,
		0x75011B80A667A46CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x1BC24040832EE645ULL,
		0x1B33E0DD674589E9ULL,
		0x0D1ACDFFBF715E93ULL,
		0x3A808DC05333D236ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2A1D8A58F90C13BULL,
		0xE4A63A16867E917FULL,
		0xAC7D86A403F2E6B3ULL,
		0x5D04A84CF9ECA305ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA1D8A58F90C13B00ULL,
		0xA63A16867E917FA2ULL,
		0x7D86A403F2E6B3E4ULL,
		0x04A84CF9ECA305ACULL,
		0x000000000000005DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 72;
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A9E69275FFF1324ULL,
		0xA9D80E8194639236ULL,
		0xBCC0C745686352DFULL,
		0x63C74467A288DC4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEBFFE26480000000ULL,
		0x328C7246C753CD24ULL,
		0xAD0C6A5BF53B01D0ULL,
		0xF4511B89B79818E8ULL,
		0x000000000C78E88CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EF4F3DD07789FE9ULL,
		0x4AEAB825089797CCULL,
		0xE2BFD1411A752629ULL,
		0x312D8D01E3F8079CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD20000000000000ULL,
		0xF98FDE9E7BA0EF13ULL,
		0xC5295D5704A112F2ULL,
		0xF39C57FA28234EA4ULL,
		0x000625B1A03C7F00ULL,
		0x0000000000000000ULL
	}};
	shift = 181;
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x230C5E35ED02FE15ULL,
		0x06095E2DC60CB5BEULL,
		0x8DFA863F6AF45011ULL,
		0x5BD5078AEC5C4C0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA05FC2A000000000ULL,
		0xC196B7C4618BC6BDULL,
		0x5E8A0220C12BC5B8ULL,
		0x8B8981F1BF50C7EDULL,
		0x0000000B7AA0F15DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4AF4A19C4E1A1299ULL,
		0xDF968C19EC7196C9ULL,
		0x98C7B96A57F3BE36ULL,
		0x7243DA3C347A0EADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4A19C4E1A1299000ULL,
		0x68C19EC7196C94AFULL,
		0x7B96A57F3BE36DF9ULL,
		0x3DA3C347A0EAD98CULL,
		0x0000000000000724ULL
	}};
	shift = 204;
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8047A41D633EA7BEULL,
		0x93E6E9851BF6A166ULL,
		0x5135A2B987A15FF8ULL,
		0x19ECE2429F0F1425ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x023D20EB19F53DF0ULL,
		0x9F374C28DFB50B34ULL,
		0x89AD15CC3D0AFFC4ULL,
		0xCF671214F878A12AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x759517E07E55423AULL,
		0x1D86E78A8EC8A4EDULL,
		0x330BF1ABB663A847ULL,
		0x17B887EB3ED72E2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF03F2AA11D0000ULL,
		0x73C547645276BACAULL,
		0xF8D5DB31D4238EC3ULL,
		0x43F59F6B97171985ULL,
		0x0000000000000BDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6E146A7FBAB1EED1ULL,
		0x72ABAFFAC889B762ULL,
		0xF1D7E2CEE89D385DULL,
		0x26696A691F8BAB5DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1EED10000000000ULL,
		0x89B7626E146A7FBAULL,
		0x9D385D72ABAFFAC8ULL,
		0x8BAB5DF1D7E2CEE8ULL,
		0x00000026696A691FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8E894F60731DE253ULL,
		0x54F51F212C2C2F55ULL,
		0x65C520A7D202EC71ULL,
		0x1CBB925E6C94E13DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x894C000000000000ULL,
		0xBD563A253D81CC77ULL,
		0xB1C553D47C84B0B0ULL,
		0x84F59714829F480BULL,
		0x000072EE4979B253ULL
	}};
	shift = 242;
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0B5CD453BA1029A6ULL,
		0x7A3C5ACCEDB83697ULL,
		0x66CDDAA679B7FBAEULL,
		0x145461BBD4CD7FA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB5CD453BA1029A60ULL,
		0xA3C5ACCEDB836970ULL,
		0x6CDDAA679B7FBAE7ULL,
		0x45461BBD4CD7FA86ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 68;
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9A698ED771E7B3ULL,
		0x43BF4457B2D79922ULL,
		0xDC0432A1B75BF6FDULL,
		0x0D52843A3BCD0670ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8F3D980000000000ULL,
		0xBCC914E4D34C76BBULL,
		0xDFB7EA1DFA22BD96ULL,
		0x683386E021950DBAULL,
		0x0000006A9421D1DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x930A93A81A833434ULL,
		0xD1CB2BB9659CAB93ULL,
		0x03BC355AF1C28F53ULL,
		0x31FF2D3D284182A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6868000000000000ULL,
		0x5727261527503506ULL,
		0x1EA7A3965772CB39ULL,
		0x054007786AB5E385ULL,
		0x000063FE5A7A5083ULL
	}};
	shift = 241;
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A2B021083DC42BAULL,
		0x49D876DFAAA24429ULL,
		0x9D2A9024C80275B8ULL,
		0x61F19A68EADE4C54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE8000000000000ULL,
		0x10A568AC08420F71ULL,
		0xD6E12761DB7EAA89ULL,
		0x315274AA40932009ULL,
		0x000187C669A3AB79ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 50;
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x961FE698EA758C89ULL,
		0xAE816092A99A6FD3ULL,
		0x5217049E833C27BCULL,
		0x56F908715FD89963ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA758C8900000000ULL,
		0xA99A6FD3961FE698ULL,
		0x833C27BCAE816092ULL,
		0x5FD899635217049EULL,
		0x0000000056F90871ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFB2EBB42BDC86F78ULL,
		0xA73C727C8BBE22E9ULL,
		0x82053A5C2DF78D38ULL,
		0x6F32FAE0FE525705ULL,
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
		0xFD975DA15EE437BCULL,
		0x539E393E45DF1174ULL,
		0xC1029D2E16FBC69CULL,
		0x37997D707F292B82ULL
	}};
	shift = 255;
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x200EB7D6EB986AF1ULL,
		0x99F57B56A9E940D3ULL,
		0x98BAF3BD30B8EDC0ULL,
		0x00A853C447421D05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5E2000000000000ULL,
		0x81A6401D6FADD730ULL,
		0xDB8133EAF6AD53D2ULL,
		0x3A0B3175E77A6171ULL,
		0x00000150A7888E84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75195CE4D47C384FULL,
		0x9BF1A941B1AF27E5ULL,
		0x5ED7C400C1C5FBDCULL,
		0x7B0C463C8C72CC15ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA8F8709E00000000ULL,
		0x635E4FCAEA32B9C9ULL,
		0x838BF7B937E35283ULL,
		0x18E5982ABDAF8801ULL,
		0x00000000F6188C79ULL
	}};
	shift = 225;
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5EED63CA177CE98ULL,
		0x80DDA88CC5C77C63ULL,
		0xF63D5830B067E609ULL,
		0x24EEE4CF071A1AEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF285DF3A60000000ULL,
		0x33171DF18FD7BB58ULL,
		0xC2C19F98260376A2ULL,
		0x3C1C686BBBD8F560ULL,
		0x000000000093BB93ULL
	}};
	shift = 218;
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3885509A936B1464ULL,
		0xC60BB3C96DE5B8C1ULL,
		0xCA162FB810B7DBB6ULL,
		0x1A2029E0330B4EDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC42A84D49B58A320ULL,
		0x305D9E4B6F2DC609ULL,
		0x50B17DC085BEDDB6ULL,
		0xD1014F01985A76EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF1120B06A7B96CB3ULL,
		0x20B96CD2EE75AB31ULL,
		0x05CEEB1FD0A5C0DEULL,
		0x736A30BF9BE1172EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4482C1A9EE5B2CC0ULL,
		0x2E5B34BB9D6ACC7CULL,
		0x73BAC7F429703788ULL,
		0xDA8C2FE6F845CB81ULL,
		0x000000000000001CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9ABA0BD8271BEC65ULL,
		0xD4A35DBCD06CA6C7ULL,
		0x8B96383963E7EA15ULL,
		0x0BD878D278D38084ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x05EC138DF6328000ULL,
		0xAEDE68365363CD5DULL,
		0x1C1CB1F3F50AEA51ULL,
		0x3C693C69C04245CBULL,
		0x00000000000005ECULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x44BDB8FF3906FC3EULL,
		0x6E6F5B10D8452F4EULL,
		0x18D11AFDA09120B4ULL,
		0x183D431CFBE0883BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCE41BF0F8000000ULL,
		0x436114BD3912F6E3ULL,
		0xF6824482D1B9BD6CULL,
		0x73EF8220EC63446BULL,
		0x000000000060F50CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC6FC844DB12167BBULL,
		0xA6694C6D48335A56ULL,
		0xA94C828DBB660C36ULL,
		0x7F3E10056E0923DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7600000000000000ULL,
		0xAD8DF9089B6242CFULL,
		0x6D4CD298DA9066B4ULL,
		0xB95299051B76CC18ULL,
		0x00FE7C200ADC1247ULL
	}};
	shift = 249;
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4130D6CE979FC672ULL,
		0xE3D676ACD3738411ULL,
		0x389F5998C5217E6DULL,
		0x5203F1C3156CF71AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF19C800000000000ULL,
		0xE104504C35B3A5E7ULL,
		0x5F9B78F59DAB34DCULL,
		0x3DC68E27D6663148ULL,
		0x00001480FC70C55BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 110;
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x81B59A4969258C11ULL,
		0xE13FF1870A0718CDULL,
		0x0547FDAC623EF5F2ULL,
		0x68932A8C6D0EB2B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x925A496304400000ULL,
		0x61C281C633606D66ULL,
		0x6B188FBD7CB84FFCULL,
		0xA31B43ACAE4151FFULL,
		0x00000000001A24CAULL,
		0x0000000000000000ULL
	}};
	shift = 150;
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE625E0D6C963A8E7ULL,
		0x8197B55668C50C3CULL,
		0x11913190EF72B7A6ULL,
		0x752A6F7C239A03D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE700000000000000ULL,
		0x3CE625E0D6C963A8ULL,
		0xA68197B55668C50CULL,
		0xD611913190EF72B7ULL,
		0x00752A6F7C239A03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67E475AC5491E502ULL,
		0x217D0DE08F15C85BULL,
		0xD8B94A406E47F1B8ULL,
		0x4AC7DAE4F6AC9DCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F2810000000000ULL,
		0x8AE42DB3F23AD62AULL,
		0x23F8DC10BE86F047ULL,
		0x564EE76C5CA52037ULL,
		0x0000002563ED727BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AAC95BD0FEC985BULL,
		0x96ED71544C2AADFCULL,
		0xBBD6B5BDE4CCB5CFULL,
		0x2A44D2A2E31C3180ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD0FEC985B0000000ULL,
		0x44C2AADFC7AAC95BULL,
		0xDE4CCB5CF96ED715ULL,
		0x2E31C3180BBD6B5BULL,
		0x0000000002A44D2AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 92;
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x49D24BE6AA73D8FEULL,
		0x9EE4AA379FC716A7ULL,
		0xF3DA3F431FDB22FBULL,
		0x29050D385AD6AA5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7F00000000000000ULL,
		0x53A4E925F35539ECULL,
		0x7DCF72551BCFE38BULL,
		0x2FF9ED1FA18FED91ULL,
		0x001482869C2D6B55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 119;
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF32D70B08154BFE9ULL,
		0xB1254189274CC0C3ULL,
		0xB7FDD4E13C7BCC20ULL,
		0x7A917993B799507CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C2C20552FFA4000ULL,
		0x506249D33030FCCBULL,
		0x75384F1EF3082C49ULL,
		0x5E64EDE6541F2DFFULL,
		0x0000000000001EA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1973E8AF93C8517FULL,
		0x6C6FB76474F8E21DULL,
		0x058D1C7C66922B4FULL,
		0x4387DA3B956237DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x45FC000000000000ULL,
		0x887465CFA2BE4F21ULL,
		0xAD3DB1BEDD91D3E3ULL,
		0xDF78163471F19A48ULL,
		0x00010E1F68EE5588ULL
	}};
	shift = 242;
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5668FB6B74292D27ULL,
		0x07D1AD1BE6EE5E80ULL,
		0x79E670C9131CB199ULL,
		0x5A9931797552C0CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x49C0000000000000ULL,
		0xA0159A3EDADD0A4BULL,
		0x6641F46B46F9BB97ULL,
		0x32DE799C3244C72CULL,
		0x0016A64C5E5D54B0ULL,
		0x0000000000000000ULL
	}};
	shift = 182;
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5FF8E3800AA57CCFULL,
		0xE6058C72BA1CAAC1ULL,
		0x71CD2C6B7A1F38BBULL,
		0x7547110AF3CD7F8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52BE678000000000ULL,
		0x0E5560AFFC71C005ULL,
		0x0F9C5DF302C6395DULL,
		0xE6BFC638E69635BDULL,
		0x0000003AA3888579ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDAAFB0F54C05F98BULL,
		0xF8368CF96C8927CFULL,
		0xF546466C06A1F776ULL,
		0x19C71DFC21BAFE13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xBEC3D53017E62C00ULL,
		0xDA33E5B2249F3F6AULL,
		0x1919B01A87DDDBE0ULL,
		0x1C77F086EBF84FD5ULL,
		0x0000000000000067ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04E47A53238A8516ULL,
		0x77FE793854580FE7ULL,
		0x4D62BB83AF065303ULL,
		0x55802B09AB422282ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x991C5428B0000000ULL,
		0xC2A2C07F382723D2ULL,
		0x1D7832981BBFF3C9ULL,
		0x4D5A1114126B15DCULL,
		0x0000000002AC0158ULL,
		0x0000000000000000ULL
	}};
	shift = 155;
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D4BF1CC8C355CFAULL,
		0x9CDA098A7BA82461ULL,
		0x8914578A18CABF1CULL,
		0x008C0CAF3CA90E96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD000000000000000ULL,
		0x0AEA5F8E6461AAE7ULL,
		0xE4E6D04C53DD4123ULL,
		0xB448A2BC50C655F8ULL,
		0x0004606579E54874ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9F80FA2FEF8E7205ULL,
		0x3E61195E7ED659B6ULL,
		0x1C727E6564B4387BULL,
		0x38F2DB0FD034B083ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x03E8BFBE39C81400ULL,
		0x846579FB5966DA7EULL,
		0xC9F99592D0E1ECF9ULL,
		0xCB6C3F40D2C20C71ULL,
		0x00000000000000E3ULL
	}};
	shift = 202;
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7EDDC6C2BE2DFE97ULL,
		0x715BD8B5F1999F45ULL,
		0xCA01AA6971ACE695ULL,
		0x56F9FAD6C5C07398ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD2E0000000000000ULL,
		0xE8AFDBB8D857C5BFULL,
		0xD2AE2B7B16BE3333ULL,
		0x731940354D2E359CULL,
		0x000ADF3F5AD8B80EULL
	}};
	shift = 245;
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x21032E99A84681B5ULL,
		0x44C1562FCB936E09ULL,
		0xAA78C42495432155ULL,
		0x4596D11DAD6E212BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x974CD42340DA8000ULL,
		0xAB17E5C9B7049081ULL,
		0x62124AA190AAA260ULL,
		0x688ED6B71095D53CULL,
		0x00000000000022CBULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF18B0FE87386E84DULL,
		0xBB740505FD36C473ULL,
		0x616E317274442D09ULL,
		0x216EDA7B8DF51428ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC3FA1CE1BA134000ULL,
		0x01417F4DB11CFC62ULL,
		0x8C5C9D110B426EDDULL,
		0xB69EE37D450A185BULL,
		0x000000000000085BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B5D3BD866DB24BBULL,
		0x7E332EFC1EFAC9C4ULL,
		0xD4569B04B7AA0BCAULL,
		0x73C6264D62E71CF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x77B0CDB649760000ULL,
		0x5DF83DF5938836BAULL,
		0x36096F541794FC66ULL,
		0x4C9AC5CE39F1A8ADULL,
		0x000000000000E78CULL
	}};
	shift = 209;
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B7EB5FF52A8203CULL,
		0x53A576630D68F7EFULL,
		0x41C7613F572BE163ULL,
		0x6BFBF44890CD49CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAD7FD4AA080F000ULL,
		0x95D98C35A3DFBC6DULL,
		0x1D84FD5CAF858D4EULL,
		0xEFD1224335273D07ULL,
		0x00000000000001AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6BC44E27E73CEC9ULL,
		0x249E6EE73D51EEB2ULL,
		0x38191C6955F9EDC6ULL,
		0x2D8A1B26C4A3C1C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6480000000000000ULL,
		0x59535E22713F39E7ULL,
		0xE3124F37739EA8F7ULL,
		0xE11C0C8E34AAFCF6ULL,
		0x0016C50D936251E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AFF1912BAE978D2ULL,
		0xE78F03A62A45FEA2ULL,
		0x84C926BF0D9F5ADDULL,
		0x7F1FD6BB15F1C405ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3480000000000000ULL,
		0xA882BFC644AEBA5EULL,
		0xB779E3C0E98A917FULL,
		0x01613249AFC367D6ULL,
		0x001FC7F5AEC57C71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB7282993D3741FB8ULL,
		0x097BC671C4EC50FDULL,
		0xA1E923B38C52F4C0ULL,
		0x57605838ECA05876ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7000000000000000ULL,
		0xFB6E505327A6E83FULL,
		0x8012F78CE389D8A1ULL,
		0xED43D2476718A5E9ULL,
		0x00AEC0B071D940B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 121;
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BCBE898CB0859A4ULL,
		0x785AC602D83A2729ULL,
		0x339792240ECCC158ULL,
		0x4AEF5D48F4FA893BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0B34800000000000ULL,
		0x44E52D797D131961ULL,
		0x982B0F0B58C05B07ULL,
		0x51276672F24481D9ULL,
		0x0000095DEBA91E9FULL,
		0x0000000000000000ULL
	}};
	shift = 173;
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D3A05CEE339686EULL,
		0xACCC724A3FCCFE13ULL,
		0x55D1FCAAB6C21EC6ULL,
		0x0C3635601D82AB49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x173B8CE5A1B80000ULL,
		0xC928FF33F84CF4E8ULL,
		0xF2AADB087B1AB331ULL,
		0xD580760AAD255747ULL,
		0x00000000000030D8ULL,
		0x0000000000000000ULL
	}};
	shift = 146;
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x017C08673148A95FULL,
		0x75D1F263E19FDADAULL,
		0x56A73963B37A4637ULL,
		0x30F9900744975F44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA95F000000000000ULL,
		0xDADA017C08673148ULL,
		0x463775D1F263E19FULL,
		0x5F4456A73963B37AULL,
		0x000030F990074497ULL
	}};
	shift = 240;
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x59351C275EE5CEEBULL,
		0xCA7192026393616DULL,
		0x480905B1987261BFULL,
		0x7FCF653381DCC268ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E13AF72E7758000ULL,
		0xC90131C9B0B6AC9AULL,
		0x82D8CC3930DFE538ULL,
		0xB299C0EE61342404ULL,
		0x0000000000003FE7ULL,
		0x0000000000000000ULL
	}};
	shift = 143;
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1BC0424D27FAD283ULL,
		0x66EC426B598DE100ULL,
		0x58F96DB7550464B3ULL,
		0x75DB0701038074CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD69418000000000ULL,
		0xC6F0800DE0212693ULL,
		0x823259B3762135ACULL,
		0xC03A662C7CB6DBAAULL,
		0x0000003AED838081ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF47C6EA37AA23204ULL,
		0x96099DFB63FE866EULL,
		0x092D74A897A955ACULL,
		0x01990630233E3FA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3204000000000000ULL,
		0x866EF47C6EA37AA2ULL,
		0x55AC96099DFB63FEULL,
		0x3FA7092D74A897A9ULL,
		0x000001990630233EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x47A5B90CA9DB46C8ULL,
		0x89C61DA7426EE97EULL,
		0x7A790112AE9B2CDBULL,
		0x04F1C93B092A5CB8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA9DB46C800000000ULL,
		0x426EE97E47A5B90CULL,
		0xAE9B2CDB89C61DA7ULL,
		0x092A5CB87A790112ULL,
		0x0000000004F1C93BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 96;
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x53BA0512ECAE0F0AULL,
		0x37893F6B03BBFC85ULL,
		0x6065FB83EC2A5514ULL,
		0x320031E39DF29C17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD95C1E1400000000ULL,
		0x0777F90AA7740A25ULL,
		0xD854AA286F127ED6ULL,
		0x3BE5382EC0CBF707ULL,
		0x00000000640063C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x09A0B9415C5996D3ULL,
		0x93F696E7DFC97859ULL,
		0x66BB4FAE2486F309ULL,
		0x4591D8411904AB5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD300000000000000ULL,
		0x5909A0B9415C5996ULL,
		0x0993F696E7DFC978ULL,
		0x5E66BB4FAE2486F3ULL,
		0x004591D8411904ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67BAFC470626BF81ULL,
		0xCA410E297F71AB9CULL,
		0xD389DB71B38B43C1ULL,
		0x6E3F87705DEDFFDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x470626BF81000000ULL,
		0x297F71AB9C67BAFCULL,
		0x71B38B43C1CA410EULL,
		0x705DEDFFDAD389DBULL,
		0x00000000006E3F87ULL
	}};
	shift = 216;
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D26BA154B3B0506ULL,
		0x8DF63217308390F4ULL,
		0xAC1F65D286B6FA49ULL,
		0x2CAE5A721DDBFA88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4B3B050600000000ULL,
		0x308390F41D26BA15ULL,
		0x86B6FA498DF63217ULL,
		0x1DDBFA88AC1F65D2ULL,
		0x000000002CAE5A72ULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x498B4E7187DB7D80ULL,
		0xFF21FC156F28DAE3ULL,
		0x6A64DEA7E7A81A75ULL,
		0x62DA54D32C905E40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA4C5A738C3EDBEC0ULL,
		0xFF90FE0AB7946D71ULL,
		0x35326F53F3D40D3AULL,
		0x316D2A6996482F20ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6619763AF51B9BB3ULL,
		0xA2FCDB6FE441036AULL,
		0x079909AE2A277F38ULL,
		0x1AC03AD9006D48C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7660000000000000ULL,
		0x6D4CC32EC75EA373ULL,
		0xE7145F9B6DFC8820ULL,
		0x18C0F32135C544EFULL,
		0x000358075B200DA9ULL
	}};
	shift = 245;
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62E3AD8BC7E29D27ULL,
		0xBCAB39E8E9E92EC1ULL,
		0x1DEAEDB4F97425FAULL,
		0x6D5BB580C459386BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xD270000000000000ULL,
		0xEC162E3AD8BC7E29ULL,
		0x5FABCAB39E8E9E92ULL,
		0x86B1DEAEDB4F9742ULL,
		0x0006D5BB580C4593ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCC3CFA63695613A0ULL,
		0xD02F4347FFA9A6B6ULL,
		0x935604FD40522FEDULL,
		0x11FC4EF6B7C7C3A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x79F4C6D2AC274000ULL,
		0x5E868FFF534D6D98ULL,
		0xAC09FA80A45FDBA0ULL,
		0xF89DED6F8F874326ULL,
		0x0000000000000023ULL,
		0x0000000000000000ULL
	}};
	shift = 137;
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD489F955B5440766ULL,
		0xB1F7E5682637227CULL,
		0x6959DD22077A9BBEULL,
		0x4445618C69343932ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5440766000000000ULL,
		0x637227CD489F955BULL,
		0x77A9BBEB1F7E5682ULL,
		0x93439326959DD220ULL,
		0x00000004445618C6ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D929C9596C50DA3ULL,
		0x4FF8B85C669F750FULL,
		0xAA784F21E5DD769EULL,
		0x33E66AAB3971E5B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD180000000000000ULL,
		0x87A6C94E4ACB6286ULL,
		0x4F27FC5C2E334FBAULL,
		0xDC553C2790F2EEBBULL,
		0x0019F335559CB8F2ULL,
		0x0000000000000000ULL
	}};
	shift = 183;
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E236C1FF6EB4AD6ULL,
		0xD1CF895D4EDAAF8BULL,
		0xCBCCDF1665AD86E7ULL,
		0x2F6852D5752DBFF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4AD600000000000ULL,
		0xAAF8B7E236C1FF6EULL,
		0xD86E7D1CF895D4EDULL,
		0xDBFF0CBCCDF1665AULL,
		0x000002F6852D5752ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7E67C8B0A17E0618ULL,
		0xD7DA270F76FB7524ULL,
		0x40B58C15E23695AEULL,
		0x3C00D326ED74B60AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF916142FC0C30000ULL,
		0x44E1EEDF6EA48FCCULL,
		0xB182BC46D2B5DAFBULL,
		0x1A64DDAE96C14816ULL,
		0x0000000000000780ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x395E52EB0F0E3E01ULL,
		0x5747AA58F00AD6B5ULL,
		0xDCAAD0C3730E5FEFULL,
		0x4E4068989E6CD6FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E52EB0F0E3E0100ULL,
		0x47AA58F00AD6B539ULL,
		0xAAD0C3730E5FEF57ULL,
		0x4068989E6CD6FADCULL,
		0x000000000000004EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9239E63CA5014C76ULL,
		0xC122A0C81A08D051ULL,
		0x4CA559E87B28BEC6ULL,
		0x313ADDDA29B67B12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA5014C760000000ULL,
		0x81A08D0519239E63ULL,
		0x87B28BEC6C122A0CULL,
		0xA29B67B124CA559EULL,
		0x000000000313ADDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x469465D00B200953ULL,
		0x4B354EB24FEE1C19ULL,
		0xC5156AEDD1AF5153ULL,
		0x791CAF67D29C4649ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5300000000000000ULL,
		0x19469465D00B2009ULL,
		0x534B354EB24FEE1CULL,
		0x49C5156AEDD1AF51ULL,
		0x00791CAF67D29C46ULL
	}};
	shift = 248;
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC936542DAA26B9D5ULL,
		0x7A7AA1EFA6225387ULL,
		0xF041AC5149418D87ULL,
		0x1CA172D214B886E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA0000000000000ULL,
		0x70F926CA85B544D7ULL,
		0xB0EF4F543DF4C44AULL,
		0xDCFE08358A292831ULL,
		0x0003942E5A429710ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38E9D28A898E8ACDULL,
		0xBDDFD3E91BBDDB6FULL,
		0x85557C192C215AECULL,
		0x291322E379C70B18ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8E9D28A898E8ACD0ULL,
		0xDDFD3E91BBDDB6F3ULL,
		0x5557C192C215AECBULL,
		0x91322E379C70B188ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x667B00D22266F9FEULL,
		0x635BFF94DADD9D6CULL,
		0x865014C9DE7F34D0ULL,
		0x227A1D2CF754D1DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A444CDF3FC0000ULL,
		0xFF29B5BB3AD8CCF6ULL,
		0x2993BCFE69A0C6B7ULL,
		0x3A59EEA9A3BB0CA0ULL,
		0x00000000000044F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x591533F27A6C86DDULL,
		0x55EDD4D2A6957E04ULL,
		0x0934A2171CEA7DCAULL,
		0x021EC51484D0CD49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8000000000000000ULL,
		0x2C8A99F93D36436EULL,
		0x2AF6EA69534ABF02ULL,
		0x849A510B8E753EE5ULL,
		0x010F628A426866A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C64202092C0157BULL,
		0xD8E4F187286E6EE8ULL,
		0xC19A8C3F5BC75102ULL,
		0x394808FA895053C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x404125802AF60000ULL,
		0xE30E50DCDDD038C8ULL,
		0x187EB78EA205B1C9ULL,
		0x11F512A0A7878335ULL,
		0x0000000000007290ULL,
		0x0000000000000000ULL
	}};
	shift = 145;
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCAE5F3CC3864B555ULL,
		0xE32F3EF2092AAB8CULL,
		0xB3A634D0BFC174C7ULL,
		0x6DE37F4D4F8D7F1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x572F9E61C325AAA8ULL,
		0x1979F79049555C66ULL,
		0x9D31A685FE0BA63FULL,
		0x6F1BFA6A7C6BF8FDULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 131;
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8EFD70F89B0663EULL,
		0xB618E9E17D3AEF9FULL,
		0x2C551087E09FAA1FULL,
		0x19CE51AAA040436CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xF1360CC7C0000000ULL,
		0x2FA75DF3F91DFAE1ULL,
		0xFC13F543F6C31D3CULL,
		0x5408086D858AA210ULL,
		0x000000000339CA35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6110AAD8BAA24BF5ULL,
		0x7C8959B46B82CE11ULL,
		0xC3CE437307E6EE1BULL,
		0x3BDB7F65F6BAFE61ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFD40000000000000ULL,
		0x8458442AB62EA892ULL,
		0x86DF22566D1AE0B3ULL,
		0x9870F390DCC1F9BBULL,
		0x000EF6DFD97DAEBFULL
	}};
	shift = 246;
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC7A53E0DF9AF2772ULL,
		0xDB129A58EDA46FEDULL,
		0x03A376E1C654178FULL,
		0x1158C356FE9F1561ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2772000000000000ULL,
		0x6FEDC7A53E0DF9AFULL,
		0x178FDB129A58EDA4ULL,
		0x156103A376E1C654ULL,
		0x00001158C356FE9FULL
	}};
	shift = 240;
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02E1F12433DEB027ULL,
		0xCF9603952A95BD04ULL,
		0xCF581934512B41FFULL,
		0x675CE666F845090BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x02E1F12433DEB027ULL,
		0xCF9603952A95BD04ULL,
		0xCF581934512B41FFULL,
		0x675CE666F845090BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 128;
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE4879901D609F1ADULL,
		0xCDB8FE482FC23097ULL,
		0x486C41D6548E9C6FULL,
		0x5A55828376FF0406ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x43CC80EB04F8D680ULL,
		0xDC7F2417E1184BF2ULL,
		0x3620EB2A474E37E6ULL,
		0x2AC141BB7F820324ULL,
		0x000000000000002DULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x841F8754E6BC0DD0ULL,
		0x95B9F5873315A085ULL,
		0xA279ABC75EB3E6F5ULL,
		0x44739B96D81D22F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0EA9CD781BA00000ULL,
		0xEB0E662B410B083FULL,
		0x578EBD67CDEB2B73ULL,
		0x372DB03A45E744F3ULL,
		0x00000000000088E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 81;
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x856E4001829C70F0ULL,
		0xFD81C001247050F6ULL,
		0x31BB72D7FFBDB021ULL,
		0x33193388EA67FAF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xD0ADC80030538E1EULL,
		0x3FB03800248E0A1EULL,
		0xE6376E5AFFF7B604ULL,
		0x066326711D4CFF5EULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18CC9D0EE7EA6585ULL,
		0xB135D114382776E1ULL,
		0x98A53F6DA1F5A666ULL,
		0x769D1127738FFDF6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E8773F532C28000ULL,
		0xE88A1C13BB708C66ULL,
		0x9FB6D0FAD333589AULL,
		0x8893B9C7FEFB4C52ULL,
		0x0000000000003B4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x37590A4CB37AC4F5ULL,
		0x2A026F43515DCBEFULL,
		0xAD3E7BBFA1B10C6BULL,
		0x5D87D59562A8ED3CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42932CDEB13D4000ULL,
		0x9BD0D45772FBCDD6ULL,
		0x9EEFE86C431ACA80ULL,
		0xF56558AA3B4F2B4FULL,
		0x0000000000001761ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x060E05DB55E48747ULL,
		0x7A9542E5426430E6ULL,
		0xE630CF6A6C5A2188ULL,
		0x20BCC63D3BC10466ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xEDAAF243A3800000ULL,
		0x72A1321873030702ULL,
		0xB5362D10C43D4AA1ULL,
		0x1E9DE08233731867ULL,
		0x0000000000105E63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x86CBE1BAC3DB2D9EULL,
		0x67D06C19346BB9C5ULL,
		0xD615EB42AF7AEA33ULL,
		0x7CB10A38F5613CC0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65B3C00000000000ULL,
		0x7738B0D97C37587BULL,
		0x5D466CFA0D83268DULL,
		0x27981AC2BD6855EFULL,
		0x00000F9621471EACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D3673A968327103ULL,
		0x09C2E86594EF2B50ULL,
		0x6A356CD179494888ULL,
		0x32D61019CEB3C8E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6000000000000000ULL,
		0x13A6CE752D064E20ULL,
		0x01385D0CB29DE56AULL,
		0x6D46AD9A2F292911ULL,
		0x065AC20339D6791CULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70679991D96D1A83ULL,
		0xE644529205BDCA98ULL,
		0x1F41753F7ED1AA06ULL,
		0x3719E6B06D7D406EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x33CCC8ECB68D4180ULL,
		0x22294902DEE54C38ULL,
		0xA0BA9FBF68D50373ULL,
		0x8CF35836BEA0370FULL,
		0x000000000000001BULL
	}};
	shift = 199;
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE26655AAC6CF43D8ULL,
		0xD5615270645FEC32ULL,
		0x704B7F76A57A6A93ULL,
		0x31B7CEC202E6F17EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCCAB558D9E87B000ULL,
		0xC2A4E0C8BFD865C4ULL,
		0x96FEED4AF4D527AAULL,
		0x6F9D8405CDE2FCE0ULL,
		0x0000000000000063ULL
	}};
	shift = 201;
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1F2DF1314173B4F1ULL,
		0xF810DB302DAA92CDULL,
		0x54766E25B36C5D44ULL,
		0x499F6DFA97E06AE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x9E20000000000000ULL,
		0x59A3E5BE26282E76ULL,
		0xA89F021B6605B552ULL,
		0x5CCA8ECDC4B66D8BULL,
		0x000933EDBF52FC0DULL
	}};
	shift = 245;
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDCCC60A4B7A5A25ULL,
		0xDC16E9CB5A75CE79ULL,
		0xFFD823C105B2E312ULL,
		0x1AB21D036E2564D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x6894000000000000ULL,
		0x39E7373318292DE9ULL,
		0x8C4B705BA72D69D7ULL,
		0x9353FF608F0416CBULL,
		0x00006AC8740DB895ULL
	}};
	shift = 242;
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBCE24658EDC2941FULL,
		0xC80093D52D0419CAULL,
		0xCE7A23C56D7C5A84ULL,
		0x7CBA3D0E6D308157ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C00000000000000ULL,
		0x2AF3891963B70A50ULL,
		0x1320024F54B41067ULL,
		0x5F39E88F15B5F16AULL,
		0x01F2E8F439B4C205ULL,
		0x0000000000000000ULL
	}};
	shift = 186;
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAE97A09B17C03DF7ULL,
		0xD256BD5CDD88A30CULL,
		0x5F673BB21FAD2149ULL,
		0x6CEF9FD102BAAB16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x07BEE00000000000ULL,
		0x146195D2F41362F8ULL,
		0xA4293A4AD7AB9BB1ULL,
		0x5562CBECE77643F5ULL,
		0x00000D9DF3FA2057ULL
	}};
	shift = 237;
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9E5DC8F0ABBFB4DULL,
		0x4D4315ADF90F2FE2ULL,
		0x062B39F00148762CULL,
		0x340C34CB2DAC4950ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB3CBB91E1577F69AULL,
		0x9A862B5BF21E5FC5ULL,
		0x0C5673E00290EC58ULL,
		0x681869965B5892A0ULL,
		0x0000000000000000ULL
	}};
	shift = 193;
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0E39BC5540992669ULL,
		0x3F09151C4C399C40ULL,
		0x8582B40D09F2D928ULL,
		0x5DF3637C01F2E68BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3480000000000000ULL,
		0x20071CDE2AA04C93ULL,
		0x941F848A8E261CCEULL,
		0x45C2C15A0684F96CULL,
		0x002EF9B1BE00F973ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 55;
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F1750886C7F2A62ULL,
		0x543A0E7346126B07ULL,
		0x1A45A7F1F1C068A9ULL,
		0x3941A576247297E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x54C4000000000000ULL,
		0xD60E5E2EA110D8FEULL,
		0xD152A8741CE68C24ULL,
		0x2FD0348B4FE3E380ULL,
		0x000072834AEC48E5ULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18ADA3137AB620E9ULL,
		0xFE5B60EB579642BDULL,
		0x34BC2CE2D56D1F1AULL,
		0x5CAF1FA3032EB1FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C41D20000000000ULL,
		0x2C857A315B4626F5ULL,
		0xDA3E35FCB6C1D6AFULL,
		0x5D63FA697859C5AAULL,
		0x000000B95E3F4606ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 41;
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD92BBE8CB1D24645ULL,
		0x8F67C798777A797BULL,
		0x67788BE263DB2F49ULL,
		0x6C65BE1E8407420DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xAEFA32C749191400ULL,
		0x9F1E61DDE9E5EF64ULL,
		0xE22F898F6CBD263DULL,
		0x96F87A101D08359DULL,
		0x00000000000001B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BB1862A1AE466A4ULL,
		0x27D1B2464BE6FBD3ULL,
		0xE3C8FF51C6B38D8FULL,
		0x7FDF328D457803F6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xAE466A4000000000ULL,
		0xBE6FBD33BB1862A1ULL,
		0x6B38D8F27D1B2464ULL,
		0x57803F6E3C8FF51CULL,
		0x00000007FDF328D4ULL,
		0x0000000000000000ULL
	}};
	shift = 164;
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1167C0CD92CE5AD8ULL,
		0x08539CEEE42C3E23ULL,
		0x0EA7D5E29AA7FCFFULL,
		0x30FF9EF33D0B3861ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B396B6000000000ULL,
		0x90B0F88C459F0336ULL,
		0x6A9FF3FC214E73BBULL,
		0xF42CE1843A9F578AULL,
		0x00000000C3FE7BCCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x247D420CA89A9473ULL,
		0x16ECB0BC030C1A1BULL,
		0xCD320A653CB31E83ULL,
		0x09DEA5AE448081B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA8419513528E600ULL,
		0xD961780618343648ULL,
		0x6414CA79663D062DULL,
		0xBD4B5C890103699AULL,
		0x0000000000000013ULL
	}};
	shift = 201;
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA08CEE155007D02ULL,
		0xB477B544A8C2B7B4ULL,
		0x12B65065320F7C0CULL,
		0x04D69DA8F6900E32ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE810000000000000ULL,
		0xBDA6D046770AA803ULL,
		0xE065A3BDAA254615ULL,
		0x719095B28329907BULL,
		0x000026B4ED47B480ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 115;
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9524664A844714F0ULL,
		0x2EE7F6917762DF87ULL,
		0xE5633E8057887B86ULL,
		0x5432F7CCC05D7AE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC53C000000000000ULL,
		0xB7E1E5491992A111ULL,
		0x1EE18BB9FDA45DD8ULL,
		0x5EB8B958CFA015E2ULL,
		0x0000150CBDF33017ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99163E36C85F874EULL,
		0x330614243BEC4DFEULL,
		0x2D0953860D081AEEULL,
		0x0A660357D19659D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x322C7C6D90BF0E9CULL,
		0x660C284877D89BFDULL,
		0x5A12A70C1A1035DCULL,
		0x14CC06AFA32CB3ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 129;
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6ADCFEC67DE5822BULL,
		0x9D50EB8D35B724A2ULL,
		0x5D9C39DD133A5715ULL,
		0x35B5413E173D1A4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xB73FB19F79608AC0ULL,
		0x543AE34D6DC9289AULL,
		0x670E7744CE95C567ULL,
		0x6D504F85CF469317ULL,
		0x000000000000000DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 70;
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5950A42115380A03ULL,
		0x75C74BD21D7300AFULL,
		0xB6ADAF33E41AF96DULL,
		0x69823A5E60EE6DFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2108A9C050180000ULL,
		0x5E90EB98057ACA85ULL,
		0x799F20D7CB6BAE3AULL,
		0xD2F307736FD5B56DULL,
		0x0000000000034C11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3BA6EEC384FC1471ULL,
		0x5021C9C24EAD8647ULL,
		0xDDB13093B426FE09ULL,
		0x6E20D7E3EA9F7CA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4FC1471000000000ULL,
		0xEAD86473BA6EEC38ULL,
		0x426FE095021C9C24ULL,
		0xA9F7CA5DDB13093BULL,
		0x00000006E20D7E3EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 100;
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCE0FDF351644EDDULL,
		0x8637E0FB9AA3AD43ULL,
		0xDDF5C5C2612B67CEULL,
		0x356E1CCD22EDAC68ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2276E800000000ULL,
		0xD51D6A1EE707EF9AULL,
		0x095B3E7431BF07DCULL,
		0x176D6346EFAE2E13ULL,
		0x00000001AB70E669ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x746478AEACC32053ULL,
		0x97F47BD9FF8FFD62ULL,
		0x5AD01942964C3D9CULL,
		0x2A37ADCB3AF3B906ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0298000000000000ULL,
		0xEB13A323C5756619ULL,
		0xECE4BFA3DECFFC7FULL,
		0xC832D680CA14B261ULL,
		0x000151BD6E59D79DULL,
		0x0000000000000000ULL
	}};
	shift = 179;
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD26D54008BE4A2DAULL,
		0x0BF5EE7F293E928DULL,
		0x9F92468E64147E0EULL,
		0x02F54857D81DF8F7ULL,
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
		0xD26D54008BE4A2DAULL,
		0x0BF5EE7F293E928DULL,
		0x9F92468E64147E0EULL,
		0x02F54857D81DF8F7ULL
	}};
	shift = 256;
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAEACD2C427188A33ULL,
		0x6791F1622E217913ULL,
		0xF7590ED8736C788CULL,
		0x09C25810E10905DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59A5884E31146600ULL,
		0x23E2C45C42F2275DULL,
		0xB21DB0E6D8F118CFULL,
		0x84B021C2120BB7EEULL,
		0x0000000000000013ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9735738FCC02C38CULL,
		0x69C9B43808D185D6ULL,
		0x67EC7071BBDA2CBEULL,
		0x6D4FAD3F8A9D3BB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x71F9805871800000ULL,
		0x87011A30BAD2E6AEULL,
		0x0E377B4597CD3936ULL,
		0xA7F153A7772CFD8EULL,
		0x00000000000DA9F5ULL,
		0x0000000000000000ULL
	}};
	shift = 149;
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x54F26AAE76DACB40ULL,
		0x59A42409CF24C56AULL,
		0xB0CE3D74D2F6B896ULL,
		0x5F0AFB02213A6508ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AAE76DACB400000ULL,
		0x2409CF24C56A54F2ULL,
		0x3D74D2F6B89659A4ULL,
		0xFB02213A6508B0CEULL,
		0x0000000000005F0AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4EC9CCA214556472ULL,
		0xACACBFCF5EBB29F1ULL,
		0xE932982EB1DD0DEAULL,
		0x7F1E23D2E1003901ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4E6510A2AB239000ULL,
		0x65FE7AF5D94F8A76ULL,
		0x94C1758EE86F5565ULL,
		0xF11E970801C80F49ULL,
		0x00000000000003F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 75;
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15B02F1486051C4CULL,
		0xF6CACB86E8BA5F38ULL,
		0xE9427D13263D78A3ULL,
		0x016DEF826F2E1FD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2F1486051C4C0000ULL,
		0xCB86E8BA5F3815B0ULL,
		0x7D13263D78A3F6CAULL,
		0xEF826F2E1FD3E942ULL,
		0x000000000000016DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBA7DFFE6CCF4E169ULL,
		0x5E4BF8A8B07C2E47ULL,
		0x857BFE3DFA10E6CFULL,
		0x7F97C557435BF25AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFCD99E9C2D200000ULL,
		0x15160F85C8F74FBFULL,
		0xC7BF421CD9EBC97FULL,
		0xAAE86B7E4B50AF7FULL,
		0x00000000000FF2F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 85;
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AE7A1BB74FF0792ULL,
		0xFD52BCF94AAD5D4CULL,
		0xF9A9347522A71157ULL,
		0x148C6CB2FB30EF4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x573D0DDBA7F83C90ULL,
		0xEA95E7CA556AEA60ULL,
		0xCD49A3A915388ABFULL,
		0xA4636597D9877A57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 67;
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D1BD538B038E7C1ULL,
		0x8FA00C76D18DAD5CULL,
		0x8D55E9B88481A1E2ULL,
		0x6C2BBB015939C74EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D1BD538B038E7C1ULL,
		0x8FA00C76D18DAD5CULL,
		0x8D55E9B88481A1E2ULL,
		0x6C2BBB015939C74EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x10DA2AAE03DCD196ULL,
		0x223B056271C0D08CULL,
		0x023589323A178510ULL,
		0x68E0CDA67F8DBBF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8AAB80F734658000ULL,
		0xC1589C7034230436ULL,
		0x624C8E85E144088EULL,
		0x33699FE36EFD008DULL,
		0x0000000000001A38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 78;
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C428A4CF9E3795FULL,
		0xC3959102A9B349A7ULL,
		0x7940C94E8C58F976ULL,
		0x2FFC7EEEB8644091ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF1BCAF8000000000ULL,
		0xD9A4D3AE2145267CULL,
		0x2C7CBB61CAC88154ULL,
		0x322048BCA064A746ULL,
		0x00000017FE3F775CULL
	}};
	shift = 231;
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9313D41DCAB605AEULL,
		0x676405214F6E8EBAULL,
		0xE3EE1FEBB63FA4A9ULL,
		0x716E8294FEFA5ED2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EA0EE55B02D7000ULL,
		0x20290A7B7475D498ULL,
		0x70FF5DB1FD254B3BULL,
		0x7414A7F7D2F6971FULL,
		0x000000000000038BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC8E729A0BFD7CBC5ULL,
		0x73EF9F708B11676FULL,
		0x862933F0F224F6E1ULL,
		0x2A953CA2296DD70EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x394D05FEBE5E2800ULL,
		0x7CFB84588B3B7E47ULL,
		0x499F879127B70B9FULL,
		0xA9E5114B6EB87431ULL,
		0x0000000000000154ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9265FC3C13169C7ULL,
		0x9A366D014C8B74C4ULL,
		0x56F24261E37810B1ULL,
		0x115F7D447C710DB5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38E000000000000ULL,
		0xE989F24CBF878262ULL,
		0x2163346CDA029916ULL,
		0x1B6AADE484C3C6F0ULL,
		0x000022BEFA88F8E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35BA0BF2D3267DE5ULL,
		0x466727B5E4ED1396ULL,
		0xBBBD3C29E518D96FULL,
		0x3F4C02B9020A2732ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xFCB4C99F79400000ULL,
		0xED793B44E58D6E82ULL,
		0x0A7946365BD199C9ULL,
		0xAE408289CCAEEF4FULL,
		0x00000000000FD300ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 86;
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA94684C00A8F441DULL,
		0xF7C5DC2806491836ULL,
		0xB97C7CB793431E37ULL,
		0x611EA61C205B2910ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00A8F441D000000ULL,
		0x2806491836A94684ULL,
		0xB793431E37F7C5DCULL,
		0x1C205B2910B97C7CULL,
		0x0000000000611EA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x89EBA4CBDA3CBB7BULL,
		0xE2D59FC57939EFFAULL,
		0x01E85A5C8540E6B5ULL,
		0x2DC92983A0D886B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x68F2EDEC00000000ULL,
		0xE4E7BFEA27AE932FULL,
		0x15039AD78B567F15ULL,
		0x83621AD407A16972ULL,
		0x00000000B724A60EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 98;
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEE015AD9A29605BDULL,
		0xE6B38774AF996980ULL,
		0x86CF5DDA9A9D44B8ULL,
		0x32903D027946ED76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5AD9A29605BD0000ULL,
		0x8774AF996980EE01ULL,
		0x5DDA9A9D44B8E6B3ULL,
		0x3D027946ED7686CFULL,
		0x0000000000003290ULL
	}};
	shift = 208;
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF219A671564033D9ULL,
		0x20712601CB8A3E93ULL,
		0x2C3F55B7CE23B354ULL,
		0x04F52FD1E9FD84E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x4033D90000000000ULL,
		0x8A3E93F219A67156ULL,
		0x23B35420712601CBULL,
		0xFD84E92C3F55B7CEULL,
		0x00000004F52FD1E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7CD248FFA6B3BCB0ULL,
		0x43A76C7A919EBB00ULL,
		0xE986BA27C04A890BULL,
		0x2EF97878754C8EBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FFA6B3BCB000000ULL,
		0xC7A919EBB007CD24ULL,
		0xA27C04A890B43A76ULL,
		0x878754C8EBDE986BULL,
		0x000000000002EF97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14A636705EBE46EFULL,
		0x6B8C2A74295B39F6ULL,
		0x90E67BBD2404F81FULL,
		0x01CA90BF1C512AD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x7C8DDE0000000000ULL,
		0xB673EC294C6CE0BDULL,
		0x09F03ED71854E852ULL,
		0xA255A321CCF77A48ULL,
		0x0000000395217E38ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6FF21F5DD3A1598FULL,
		0xB32987B769D33EB2ULL,
		0xE90ACC88227BB0A2ULL,
		0x3645855AAA9A5FAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x598F000000000000ULL,
		0x3EB26FF21F5DD3A1ULL,
		0xB0A2B32987B769D3ULL,
		0x5FAEE90ACC88227BULL,
		0x00003645855AAA9AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD437D17BF58C05CFULL,
		0xA34ABB40BD263C8AULL,
		0xEBF0E31D868E3D1EULL,
		0x5FF22FFD2C3E141AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE8BDFAC602E78000ULL,
		0x5DA05E931E456A1BULL,
		0x718EC3471E8F51A5ULL,
		0x17FE961F0A0D75F8ULL,
		0x0000000000002FF9ULL
	}};
	shift = 207;
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A5A9AF9C715370CULL,
		0xBB118B32B05BBDB7ULL,
		0x12073CD1334B0AAAULL,
		0x3EB2AD08A75E9C64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x535F38E2A6E18000ULL,
		0x3166560B77B6ED4BULL,
		0xE79A266961555762ULL,
		0x55A114EBD38C8240ULL,
		0x00000000000007D6ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B59CE98FEECD7B7ULL,
		0x2F65E9EDD12C8FB8ULL,
		0x5F4C313F7F0D7DD5ULL,
		0x436182ACD4B17698ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFEECD7B700000000ULL,
		0xD12C8FB85B59CE98ULL,
		0x7F0D7DD52F65E9EDULL,
		0xD4B176985F4C313FULL,
		0x00000000436182ACULL,
		0x0000000000000000ULL
	}};
	shift = 160;
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x656C314838A210F4ULL,
		0xC31163F43CF160FFULL,
		0xC54321CB86B4D37AULL,
		0x054CE180DB593B67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB618A41C51087A00ULL,
		0x88B1FA1E78B07FB2ULL,
		0xA190E5C35A69BD61ULL,
		0xA670C06DAC9DB3E2ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 135;
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB9372153546E4C89ULL,
		0xECF8B4DB94B47776ULL,
		0x812A40C49CD4F461ULL,
		0x455E22A5D7280CC5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x26E42A6A8DC99120ULL,
		0x9F169B72968EEED7ULL,
		0x254818939A9E8C3DULL,
		0xABC454BAE50198B0ULL,
		0x0000000000000008ULL
	}};
	shift = 197;
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30FAEF18A12E3748ULL,
		0x49ABDE5778784F6EULL,
		0xF1DA8A8DF3B8B14AULL,
		0x7CD4C376B6E9CD50ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEF18A12E3748000ULL,
		0xBDE5778784F6E30FULL,
		0xA8A8DF3B8B14A49AULL,
		0x4C376B6E9CD50F1DULL,
		0x00000000000007CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAAA0008EC986BE83ULL,
		0x354CBA8E72DBF8FDULL,
		0xCE21D4F2DE441B4DULL,
		0x725A58934D754A4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1800000000000000ULL,
		0xED550004764C35F4ULL,
		0x69AA65D47396DFC7ULL,
		0x7E710EA796F220DAULL,
		0x0392D2C49A6BAA52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x79ECCE54B5F014A3ULL,
		0xA5EE7AA42909C984ULL,
		0xAD3AC07E6BBCFB4EULL,
		0x5D6CA990ACFD81D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x72A5AF80A5180000ULL,
		0xD521484E4C23CF66ULL,
		0x03F35DE7DA752F73ULL,
		0x4C8567EC0EA569D6ULL,
		0x000000000002EB65ULL
	}};
	shift = 211;
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA293C2D5E67F29EAULL,
		0xA04FE6DC4851FF4EULL,
		0xB3DCEFBE64E97734ULL,
		0x7369C140F7583B6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xF500000000000000ULL,
		0xA75149E16AF33F94ULL,
		0x9A5027F36E2428FFULL,
		0xB759EE77DF3274BBULL,
		0x0039B4E0A07BAC1DULL,
		0x0000000000000000ULL
	}};
	shift = 183;
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x61F653F06A233E54ULL,
		0x3EED9AB0CA714DCDULL,
		0x67280CE7BFDE7E58ULL,
		0x320BF66A38F15B5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB29F835119F2A000ULL,
		0x6CD586538A6E6B0FULL,
		0x40673DFEF3F2C1F7ULL,
		0x5FB351C78ADADB39ULL,
		0x0000000000000190ULL,
		0x0000000000000000ULL
	}};
	shift = 139;
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0A8C22A9A73AAE75ULL,
		0x8A0171D12ABB2146ULL,
		0xDE77F3EA313CE48FULL,
		0x5DC94EB1F9A0A0D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x308AA69CEAB9D400ULL,
		0x05C744AAEC85182AULL,
		0xDFCFA8C4F3923E28ULL,
		0x253AC7E682835379ULL,
		0x0000000000000177ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 10;
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC79EDB39DC7ADD04ULL,
		0xEECB03F0C7F0E5A6ULL,
		0x3510EBD8772BBBE6ULL,
		0x75A74B662258836FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x63CF6D9CEE3D6E82ULL,
		0x776581F863F872D3ULL,
		0x9A8875EC3B95DDF3ULL,
		0x3AD3A5B3112C41B7ULL,
		0x0000000000000000ULL
	}};
	shift = 191;
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C395185C4D1668DULL,
		0xBBC437F919668B2DULL,
		0xFE9FD17694A6DD6AULL,
		0x6CD07CA575FEDF6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8B34680000000000ULL,
		0x34596961CA8C2E26ULL,
		0x36EB55DE21BFC8CBULL,
		0xF6FB7FF4FE8BB4A5ULL,
		0x0000036683E52BAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 107;
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0A0A485898852EAULL,
		0xC5BB0065DC2C0FDAULL,
		0x7A7B88FAD4352025ULL,
		0x69953BA2CCE80E77ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1490B1310A5D4000ULL,
		0x600CBB8581FB5814ULL,
		0x711F5A86A404B8B7ULL,
		0xA774599D01CEEF4FULL,
		0x0000000000000D32ULL
	}};
	shift = 205;
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x011095EF4FA1B27EULL,
		0xF882029CC82AE7DEULL,
		0xD7284717D8A21A2DULL,
		0x5862AFE1B0007908ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x27E0000000000000ULL,
		0x7DE011095EF4FA1BULL,
		0xA2DF882029CC82AEULL,
		0x908D7284717D8A21ULL,
		0x0005862AFE1B0007ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C8D322EA37E25F9ULL,
		0xC6680D88E4F08F18ULL,
		0xA458ECC09A0DD114ULL,
		0x52806583F8ED015AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1751BF12FC800000ULL,
		0xC47278478C464699ULL,
		0x604D06E88A633406ULL,
		0xC1FC7680AD522C76ULL,
		0x0000000000294032ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 87;
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDC3E68956A2303D4ULL,
		0xD4889A2B776736CEULL,
		0xF3C7E557235AC103ULL,
		0x11A0CCE64739F6E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB51181EA00000000ULL,
		0xBBB39B676E1F344AULL,
		0x91AD6081EA444D15ULL,
		0x239CFB74F9E3F2ABULL,
		0x0000000008D06673ULL,
		0x0000000000000000ULL
	}};
	shift = 159;
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A9A73864E94B9ECULL,
		0x1CE975E8E3ED8345ULL,
		0x6C85F7EA064AEDCEULL,
		0x3581004FBF36CBD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x3864E94B9EC00000ULL,
		0x5E8E3ED83455A9A7ULL,
		0x7EA064AEDCE1CE97ULL,
		0x04FBF36CBD46C85FULL,
		0x0000000000035810ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35577691CDB3BD06ULL,
		0x5550F3334A7B0B20ULL,
		0x799FDB603BF14C7BULL,
		0x3FB346D875DE3D35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736CEF4180000000ULL,
		0xD29EC2C80D55DDA4ULL,
		0x0EFC531ED5543CCCULL,
		0x1D778F4D5E67F6D8ULL,
		0x000000000FECD1B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x676276D1C8A376BEULL,
		0x4280AF4578EC5A15ULL,
		0xD084F928662899F7ULL,
		0x7F38A9614AD69987ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xA376BE0000000000ULL,
		0xEC5A15676276D1C8ULL,
		0x2899F74280AF4578ULL,
		0xD69987D084F92866ULL,
		0x0000007F38A9614AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 104;
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x17D6CD6BCD9565A4ULL,
		0x20E6F0A2966F79BCULL,
		0xE804B6A006EB5B94ULL,
		0x6EC2C80D7B7403ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x79B2ACB480000000ULL,
		0x52CDEF3782FAD9ADULL,
		0x00DD6B72841CDE14ULL,
		0xAF6E80757D0096D4ULL,
		0x000000000DD85901ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 93;
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x67C140073D8D8A8EULL,
		0xF788823B0876756CULL,
		0xAFF4A68B8A4AF436ULL,
		0x1665E587D1517880ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0039EC6C54700000ULL,
		0x11D843B3AB633E0AULL,
		0x345C5257A1B7BC44ULL,
		0x2C3E8A8BC4057FA5ULL,
		0x000000000000B32FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 83;
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77596019AB0E1A66ULL,
		0xA168A67A653E7BF4ULL,
		0xFA6BAC0C09A1DE45ULL,
		0x21501AAF9750C937ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xACB00CD5870D3300ULL,
		0xB4533D329F3DFA3BULL,
		0x35D60604D0EF22D0ULL,
		0xA80D57CBA8649BFDULL,
		0x0000000000000010ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 71;
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF6E4AA6DA04DFDD7ULL,
		0xFC86673D6493C37CULL,
		0xA6A524F5A4E75207ULL,
		0x6C9EF3A2502B69E9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFEEB800000000000ULL,
		0xE1BE7B725536D026ULL,
		0xA903FE43339EB249ULL,
		0xB4F4D352927AD273ULL,
		0x0000364F79D12815ULL,
		0x0000000000000000ULL
	}};
	shift = 175;
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3F8B53AC2D9B8825ULL,
		0xE57F925308010385ULL,
		0x0EC5B586908D91E8ULL,
		0x1565F95E921B82CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA000000000000000ULL,
		0xA7F16A7585B37104ULL,
		0x1CAFF24A61002070ULL,
		0x81D8B6B0D211B23DULL,
		0x02ACBF2BD2437059ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23E9FD4352A16350ULL,
		0x1FC8CF0265F96C94ULL,
		0x138BA4171B4E1ACCULL,
		0x45434A3EE76260C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86A542C6A000000ULL,
		0xE04CBF2D92847D3FULL,
		0x82E369C35983F919ULL,
		0x47DCEC4C18C27174ULL,
		0x000000000008A869ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5D0F6D317FF31313ULL,
		0xEF8C24047A006721ULL,
		0x560C7655B814628CULL,
		0x18704450D8095AD6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2FFE626260000000ULL,
		0x8F400CE42BA1EDA6ULL,
		0xB7028C519DF18480ULL,
		0x1B012B5ACAC18ECAULL,
		0x00000000030E088AULL,
		0x0000000000000000ULL
	}};
	shift = 157;
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6CC5B85008AFA7AFULL,
		0x9BB4C968FAF0A0F0ULL,
		0x92A24338E0CB8A9AULL,
		0x7B99A2C54ADCCBC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE9EBC00000000000ULL,
		0x283C1B316E14022BULL,
		0xE2A6A6ED325A3EBCULL,
		0x32F124A890CE3832ULL,
		0x00001EE668B152B7ULL,
		0x0000000000000000ULL
	}};
	shift = 174;
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA80287B6BD5F6C5EULL,
		0x91CABB3B1DD03D28ULL,
		0x417AFBC80576643CULL,
		0x7E8AA0715837BAE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC000000000000000ULL,
		0x150050F6D7ABED8BULL,
		0x9239576763BA07A5ULL,
		0x682F5F7900AECC87ULL,
		0x0FD1540E2B06F75CULL
	}};
	shift = 253;
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB20E5227F32000BULL,
		0x38FCD7F4EDA0938AULL,
		0x3AC88FE8F3857C18ULL,
		0x1034A6702012B6EFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCA44FE6400160000ULL,
		0xAFE9DB412715B641ULL,
		0x1FD1E70AF83071F9ULL,
		0x4CE040256DDE7591ULL,
		0x0000000000002069ULL
	}};
	shift = 209;
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7170ECC34493447DULL,
		0x923FA9963CE01EC7ULL,
		0x1CBDF8EB7215EBD5ULL,
		0x778D7DA1EBD69B75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x61A249A23E800000ULL,
		0xCB1E700F63B8B876ULL,
		0x75B90AF5EAC91FD4ULL,
		0xD0F5EB4DBA8E5EFCULL,
		0x00000000003BC6BEULL
	}};
	shift = 215;
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE637B956B52BAFA0ULL,
		0x1F84C05747A3C569ULL,
		0xBBA82FE957657D71ULL,
		0x4EF0C2604B8217A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL,
		0xD3CC6F72AD6A575FULL,
		0xE23F0980AE8F478AULL,
		0x4177505FD2AECAFAULL,
		0x009DE184C097042FULL
	}};
	shift = 249;
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF88FC627D121D78ULL,
		0x7B8A892EBC8FDF51ULL,
		0x485C71BF78209B0CULL,
		0x72E01EBE4FCBBBF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F44875E0000000ULL,
		0xBAF23F7D47FE23F1ULL,
		0xFDE0826C31EE2A24ULL,
		0xF93F2EEFC12171C6ULL,
		0x0000000001CB807AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x255F3579603D36EAULL,
		0x018C017C15C6C186ULL,
		0x9A9E2ED8DDB13E8AULL,
		0x7ADB80B440DEBCC6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD5E580F4DBA8000ULL,
		0x005F0571B0618957ULL,
		0x8BB6376C4FA28063ULL,
		0xE02D1037AF31A6A7ULL,
		0x0000000000001EB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FF0C1CEB7FFB668ULL,
		0x02E13AB29CE392DBULL,
		0xBEBBDA09670009AAULL,
		0x7A86BC9BDF544D1DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1CEB7FFB66800000ULL,
		0xAB29CE392DB7FF0CULL,
		0xA09670009AA02E13ULL,
		0xC9BDF544D1DBEBBDULL,
		0x000000000007A86BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 84;
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF42ED04C5DC4488ULL,
		0xAC37D911CAA64F50ULL,
		0x8452A5E0E16702B4ULL,
		0x2A4259CF1599108BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0BB4131771122000ULL,
		0xDF64472A993D433DULL,
		0x4A9783859C0AD2B0ULL,
		0x09673C5664422E11ULL,
		0x00000000000000A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 74;
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04DEC665C097AD94ULL,
		0xADCDABBBF19D7D30ULL,
		0x733AFCC04BA76A74ULL,
		0x0336400E452E8CE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6332E04BD6CA000ULL,
		0x6D5DDF8CEBE98026ULL,
		0xD7E6025D3B53A56EULL,
		0xB200722974671B99ULL,
		0x0000000000000019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5EAD51439918754DULL,
		0xE6969A0CFDBA344BULL,
		0xF7E1EBD49EB00E23ULL,
		0x0C900D1F9BA91FDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC8C3AA6800000000ULL,
		0xEDD1A25AF56A8A1CULL,
		0xF580711F34B4D067ULL,
		0xDD48FEFFBF0F5EA4ULL,
		0x00000000648068FCULL,
		0x0000000000000000ULL
	}};
	shift = 163;
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8665B1CA40BA2D76ULL,
		0x96698B6B53AD41F0ULL,
		0x2A4E9EF4AC6F9C77ULL,
		0x010163AC8854A5DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x9481745AEC000000ULL,
		0xD6A75A83E10CCB63ULL,
		0xE958DF38EF2CD316ULL,
		0x5910A94BB6549D3DULL,
		0x00000000000202C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 89;
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE41EDDA87F8ABAA5ULL,
		0xBF78EAFB539C03F6ULL,
		0xD938C93519350A35ULL,
		0x1B89BA2F2985EB23ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x754A000000000000ULL,
		0x07EDC83DBB50FF15ULL,
		0x146B7EF1D5F6A738ULL,
		0xD647B271926A326AULL,
		0x00003713745E530BULL
	}};
	shift = 241;
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x074CE8849076CF3DULL,
		0x8E5AEB8D1F3F1255ULL,
		0x3CB60BA55C114CD9ULL,
		0x20C926D19D6CB2EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1241DB3CF4000000ULL,
		0x347CFC49541D33A2ULL,
		0x9570453366396BAEULL,
		0x4675B2CBA8F2D82EULL,
		0x000000000083249BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFFA6C9806B20886CULL,
		0x9ADF997D595A1E0DULL,
		0xAF0B39AF2D2CD260ULL,
		0x2B17111ACE6AD293ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x1AC8221B00000000ULL,
		0x565687837FE9B260ULL,
		0xCB4B349826B7E65FULL,
		0xB39AB4A4EBC2CE6BULL,
		0x000000000AC5C446ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 94;
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF53A89242636326CULL,
		0x4771F04357072C99ULL,
		0xD932C010060D77A3ULL,
		0x3D2A3E7289C7DF38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA9D4492131B19360ULL,
		0x3B8F821AB83964CFULL,
		0xC9960080306BBD1AULL,
		0xE951F3944E3EF9C6ULL,
		0x0000000000000001ULL
	}};
	shift = 195;
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB49A3EB92EB2F3F0ULL,
		0xDF283E690E032A88ULL,
		0xE7EAC3D8515C01A9ULL,
		0x0407C570E4F0183BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x47D725D65E7E0000ULL,
		0x07CD21C065511693ULL,
		0x587B0A2B80353BE5ULL,
		0xF8AE1C9E03077CFDULL,
		0x0000000000000080ULL,
		0x0000000000000000ULL
	}};
	shift = 141;
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x02C2A11F43C1735CULL,
		0xBC56925722B32689ULL,
		0x9EB39F8830AA9F76ULL,
		0x7601CE975BBD8553ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x8782E6B800000000ULL,
		0x45664D120585423EULL,
		0x61553EED78AD24AEULL,
		0xB77B0AA73D673F10ULL,
		0x00000000EC039D2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 97;
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF70C218B147A1FC2ULL,
		0x703AAC083FB82665ULL,
		0x2397877991684394ULL,
		0x2D87CD97C513C9B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC30862C51E87F080ULL,
		0x0EAB020FEE09997DULL,
		0xE5E1DE645A10E51CULL,
		0x61F365F144F26DC8ULL,
		0x000000000000000BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECA8E6060801FE23ULL,
		0x5708FCCC7873131CULL,
		0xD437A86351B7A082ULL,
		0x2F761CE43353B1F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0C1003FC46000000ULL,
		0x98F0E62639D951CCULL,
		0xC6A36F4104AE11F9ULL,
		0xC866A763E9A86F50ULL,
		0x00000000005EEC39ULL
	}};
	shift = 217;
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAA42B90F2D22CCCCULL,
		0x326F5C144FAA4996ULL,
		0xB03ADCFC7119086EULL,
		0x16E4DC44CB886030ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4599980000000000ULL,
		0x54932D5485721E5AULL,
		0x3210DC64DEB8289FULL,
		0x10C0616075B9F8E2ULL,
		0x0000002DC9B88997ULL,
		0x0000000000000000ULL
	}};
	shift = 169;
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB94D9E56B451042CULL,
		0x50F62CD65D2EA850ULL,
		0x5FE423F6A670CCA6ULL,
		0x2895A65DF5396DF7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x2C00000000000000ULL,
		0x50B94D9E56B45104ULL,
		0xA650F62CD65D2EA8ULL,
		0xF75FE423F6A670CCULL,
		0x002895A65DF5396DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 120;
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C3C8A8ACB2A7560ULL,
		0xC1C955CE4E8F64D9ULL,
		0xFB7ADE83E5AFAF1DULL,
		0x1B943521A9F1066EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x953AB00000000000ULL,
		0x47B26CC61E454565ULL,
		0xD7D78EE0E4AAE727ULL,
		0xF883377DBD6F41F2ULL,
		0x0000000DCA1A90D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 103;
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0CAB6D567640F35ULL,
		0xF73A4892D805C5D1ULL,
		0x19CD4598E4DE081AULL,
		0x1E899F20926F1DC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0xE0655B6AB3B2079AULL,
		0x7B9D24496C02E2E8ULL,
		0x0CE6A2CC726F040DULL,
		0x0F44CF9049378EE4ULL
	}};
	shift = 255;
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC747175A095801F0ULL,
		0x959392BCF1CC6A95ULL,
		0x2CFDB3789444B81CULL,
		0x70CAE96996930F19ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x5801F00000000000ULL,
		0xCC6A95C747175A09ULL,
		0x44B81C959392BCF1ULL,
		0x930F192CFDB37894ULL,
		0x00000070CAE96996ULL,
		0x0000000000000000ULL
	}};
	shift = 168;
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x82FF6C19A210220AULL,
		0x43A0EE5C9BE6D51FULL,
		0x68431CF77A46BC83ULL,
		0x03F502D6B6A0186EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8334420441400000ULL,
		0xCB937CDAA3F05FEDULL,
		0x9EEF48D79068741DULL,
		0x5AD6D4030DCD0863ULL,
		0x0000000000007EA0ULL
	}};
	shift = 213;
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD5F61DDC3E294213ULL,
		0xC24C8822B00D0478ULL,
		0xEAAA51C232EC71B2ULL,
		0x52C2BDB5AE5818A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0980000000000000ULL,
		0x3C6AFB0EEE1F14A1ULL,
		0xD961264411580682ULL,
		0x54755528E1197638ULL,
		0x0029615EDAD72C0CULL
	}};
	shift = 247;
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEF79AD7E2BFBCD34ULL,
		0x7AFAB397B943B514ULL,
		0x98CAB5CAD69B2EF3ULL,
		0x318CD19F5D2E0916ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL,
		0x9DEF35AFC57F79A6ULL,
		0x6F5F5672F72876A2ULL,
		0xD31956B95AD365DEULL,
		0x06319A33EBA5C122ULL,
		0x0000000000000000ULL
	}};
	shift = 189;
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x048C2A17BB4D3412ULL,
		0x48C70266CF2C1E6BULL,
		0xD464AAAD103074F7ULL,
		0x2BD19FD8A291CE7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xB4D3412000000000ULL,
		0xF2C1E6B048C2A17BULL,
		0x03074F748C70266CULL,
		0x291CE7AD464AAAD1ULL,
		0x00000002BD19FD8AULL
	}};
	shift = 228;
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31E9CD481253F339ULL,
		0xFD17CC104FF3140DULL,
		0xBFE4796249A8F588ULL,
		0x327EAF5F1196DF43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xE672000000000000ULL,
		0x281A63D39A9024A7ULL,
		0xEB11FA2F98209FE6ULL,
		0xBE877FC8F2C49351ULL,
		0x000064FD5EBE232DULL,
		0x0000000000000000ULL
	}};
	shift = 177;
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3E33350A77C3315ULL,
		0xD0481D08D5AF0F04ULL,
		0x8119DC5F50F108A4ULL,
		0x43BF81B0472FB7A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xC666A14EF8662A00ULL,
		0x903A11AB5E1E09A7ULL,
		0x33B8BEA1E21149A0ULL,
		0x7F03608E5F6F4D02ULL,
		0x0000000000000087ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 73;
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D32BFF3CCBF23DBULL,
		0x0F137F6C665886C4ULL,
		0x50A3ED0F02D15D14ULL,
		0x3186DD0C15C44F13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xCCBF23DB00000000ULL,
		0x665886C43D32BFF3ULL,
		0x02D15D140F137F6CULL,
		0x15C44F1350A3ED0FULL,
		0x000000003186DD0CULL
	}};
	shift = 224;
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6D9019453CD22D9ULL,
		0x0C470130F1B3D241ULL,
		0x11F6604FF9CBEDDCULL,
		0x65BF961438CA2AB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14F348B640000000ULL,
		0x3C6CF49079B64065ULL,
		0xFE72FB770311C04CULL,
		0x0E328AAC047D9813ULL,
		0x00000000196FE585ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x280EF7E672752F2DULL,
		0x23BD212F1BFB7911ULL,
		0xC8FC78FA869BCF45ULL,
		0x64BD578C4099C87FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xA03BDF99C9D4BCB4ULL,
		0x8EF484BC6FEDE444ULL,
		0x23F1E3EA1A6F3D14ULL,
		0x92F55E31026721FFULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 130;
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x530707B360ED2263ULL,
		0x69B88FDFD5D70DBDULL,
		0x2C2960B707B00D66ULL,
		0x352CD61FFC7212F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xC600000000000000ULL,
		0x7AA60E0F66C1DA44ULL,
		0xCCD3711FBFABAE1BULL,
		0xE25852C16E0F601AULL,
		0x006A59AC3FF8E425ULL
	}};
	shift = 249;
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3FFAACDCC33CA1DDULL,
		0xCAA639E2A82562F2ULL,
		0x6AE19DE3CEABBA93ULL,
		0x1E2154428399CF25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x3730CF2877400000ULL,
		0x78AA0958BC8FFEABULL,
		0x78F3AAEEA4F2A98EULL,
		0x10A0E673C95AB867ULL,
		0x0000000000078855ULL
	}};
	shift = 214;
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0DFB2551ED75016AULL,
		0x2DB81AA65031C813ULL,
		0x95AB2814A489C995ULL,
		0x2742646323D3D89AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DAEA02D40000000ULL,
		0xCA06390261BF64AAULL,
		0x94913932A5B70354ULL,
		0x647A7B1352B56502ULL,
		0x0000000004E84C8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2318D7F509F3297BULL,
		0x14466470C5D5B9C8ULL,
		0xCD142D9D3B69D640ULL,
		0x6B6A5D957E56ADE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0xFA84F994BD800000ULL,
		0x3862EADCE4118C6BULL,
		0xCE9DB4EB200A2332ULL,
		0xCABF2B56F0668A16ULL,
		0x000000000035B52EULL,
		0x0000000000000000ULL
	}};
	shift = 151;
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4E2B18C633A1CDEFULL,
		0x5513F0CDFE222C49ULL,
		0xE136CE690FC8F656ULL,
		0x3CFBE5EABD183F03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x7439BDE000000000ULL,
		0xC4458929C56318C6ULL,
		0xF91ECACAA27E19BFULL,
		0xA307E07C26D9CD21ULL,
		0x000000079F7CBD57ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 101;
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16E1190BECA8F855ULL,
		0x1674926BC2D868B4ULL,
		0x223F6654DC033648ULL,
		0x6DF6E9C32BE6C9EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2A3E154000000000ULL,
		0xB61A2D05B84642FBULL,
		0x00CD92059D249AF0ULL,
		0xF9B27AC88FD99537ULL,
		0x0000001B7DBA70CAULL,
		0x0000000000000000ULL
	}};
	shift = 166;
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x93777313351574FEULL,
		0x069783AB59EB739EULL,
		0x35AB372386E9CEA1ULL,
		0x0429DD8EFDC7D847ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0xE000000000000000ULL,
		0xE93777313351574FULL,
		0x1069783AB59EB739ULL,
		0x735AB372386E9CEAULL,
		0x00429DD8EFDC7D84ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 124;
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000200000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0002000000000000ULL,
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
		0x0000000000000002ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 80;
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000008ULL,
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
		0x0000800000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 236;
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000008000000ULL,
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
		0x0000080000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 144;
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000080000000000ULL,
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
		0x0000000008000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000200000000ULL,
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
		0x0000000000200000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 116;
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000000010000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000004000000ULL,
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
		0x0000000040000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 132;
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0000000010000000ULL,
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
		0x0000000000000100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
	if (res) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0200000000000000ULL,
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
		0x0020000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 252;
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	curve25519_key_lshift_inplace(&k1, shift);
	res = curve25519_key_cmp(&k1, &k2);
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