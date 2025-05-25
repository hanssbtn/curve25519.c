#include "../tests.h"

int32_t curve25519_key_cmp_high_test(void) {
	printf("Key High Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0,
		0,
		0,
		0,
		0x40F1606039D690A9ULL,
		0x3DEFF442139CD05CULL,
		0x3293F9FCAAFE3EE8ULL,
		0x4AA32F2DA878486EULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0,
		0,
		0,
		0,
		0x7A4E6B330B0C65CFULL,
		0x066BDEDB479837FAULL,
		0x8BF17799140CB6D2ULL,
		0x1003D5E3260E0865ULL
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
		0xE19094480301874EULL,
		0x7EE77B56FC9798C6ULL,
		0xD876D0FD87E7B8DDULL,
		0x7FB3598AE7B1338FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2AABCDAAF0A62D1EULL,
		0xC63E552F3C35DD13ULL,
		0x7F8A28E6462A4848ULL,
		0x026F35E041C39D4FULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEE367DF78D29116FULL,
		0xAA3038D83B41172FULL,
		0x525C6A133C18DB5FULL,
		0x7D250A90DBD7EC77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16E529B2D5F160B5ULL,
		0x60CBD6F525714C5DULL,
		0x5A82DC0AA77A7CBAULL,
		0x11AC1CF14D279B8CULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5A35265FBBA555C5ULL,
		0x826FC2DE24DB7ED5ULL,
		0x22DFFA552E0F7C0DULL,
		0x0ADD5A08943277D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2A6825CBB4FCD569ULL,
		0xA58F96C2D5849325ULL,
		0xBD0CA53790ABD42CULL,
		0x0C53ACB8730CA753ULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4001F9EA243A6B18ULL,
		0xB43BB20E5175D497ULL,
		0x3D35991BB7C9F411ULL,
		0x0430E02725FC65BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4001F9EA243A6B18ULL,
		0xB43BB20E5175D497ULL,
		0x3D35991BB7C9F411ULL,
		0x0430E02725FC65BEULL
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
		0x8D0A1A1F3CBB5DD1ULL,
		0xE803ACD8AF62615EULL,
		0x2BEAFD40CDD1795FULL,
		0x65124B068B87D684ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7163C316427A9E0ULL,
		0x3C12BA981E9A4B55ULL,
		0x6EF198FC749FF506ULL,
		0x1CBDE4FC42535D23ULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x11E58DB6BB12ED03ULL,
		0x1F15F2EF1C7EE51EULL,
		0xE893727F8D19DA70ULL,
		0x7EC1BD4D46C0D7BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6970AA2CF57BD92ULL,
		0x34713722CE7FFD0CULL,
		0x9451AC57B3CAED83ULL,
		0x40FDC8F702BCB9A1ULL
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
		0xB2E9C3E33EEEED68ULL,
		0x3683DF6497CBFC58ULL,
		0x77B81F9AAAFD58F5ULL,
		0x164059E0A591FD6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBFCBDE4812904F3EULL,
		0xC46F4D3E3A154235ULL,
		0x996706C3D2F214BCULL,
		0x61D8089D79B23922ULL
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
		0x9B926ABF062FEB63ULL,
		0xB02A1FB0A2A94F03ULL,
		0xE794238066D2B48BULL,
		0x242412DB64604CB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B926ABF062FEB63ULL,
		0xB02A1FB0A2A94F03ULL,
		0xE794238066D2B48BULL,
		0x242412DB64604CB2ULL
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
		0xACF3A4AD94467767ULL,
		0x0E7AC6A38016B789ULL,
		0x1705507D7628AC70ULL,
		0x5E0D4B9A5F0E5DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2DA1B855CF6218F4ULL,
		0x3DBC8D89835646AFULL,
		0x7862C8AEB06BD53BULL,
		0x7FE15E46134BE44FULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDA5A3B235FB799A5ULL,
		0xBA68903BDDE02C70ULL,
		0x445D630568842CF8ULL,
		0x6461B7815F26DAF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x485B8BBFE4DBD70FULL,
		0x6DA5C7E2F13CDC7EULL,
		0x6A239A27D1366778ULL,
		0x692CE3AA95099FFFULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE3494B8255A1CBFDULL,
		0x4DB21483D0BB61DAULL,
		0xB561D09D1CBDBAA6ULL,
		0x088729085D34E7F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB17D60AA1E6CF41BULL,
		0x6517F22A036FC949ULL,
		0x4B8365D50E67FAADULL,
		0x4F4E85766F479241ULL
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
		0x7B4FA027B51CAA22ULL,
		0xB688CD7D9D9C4C9CULL,
		0x5BD83D9DFBCAE05BULL,
		0x12D2BA95B1730813ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7B4FA027B51CAA22ULL,
		0xB688CD7D9D9C4C9CULL,
		0x5BD83D9DFBCAE05BULL,
		0x12D2BA95B1730813ULL
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
		0x768E64FAD6185347ULL,
		0x701F68D48054B190ULL,
		0x81217224C093AE6DULL,
		0x1403CF6BA5F15976ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF8687167C3484AA8ULL,
		0x82CB2D04D935CE69ULL,
		0x884F3F1BA43CC4A0ULL,
		0x10B34488AC85872BULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE3DC5C3AB56EA5E0ULL,
		0x5289EF972133FD75ULL,
		0x5D506F3C44F34FFCULL,
		0x0D1428E7115402D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5A53969828C688F6ULL,
		0xDC8D2E0F60755592ULL,
		0x9A9C8B168A1E7419ULL,
		0x2AFBB4825ED59268ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC96D39BB58271AEFULL,
		0x38C063CF4E9282E1ULL,
		0xB255D236B3B454A4ULL,
		0x1D3C6ACB727E30ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF377810B89DA7EEULL,
		0x996B288C00281E05ULL,
		0x86D8D6FD91374476ULL,
		0x1CABDB97D627A1FFULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD511C9AD51F3595AULL,
		0x08394008DBA430FCULL,
		0xFABD0B9CBDCBF76AULL,
		0x160876E8B01FC310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD511C9AD51F3595AULL,
		0x08394008DBA430FCULL,
		0xFABD0B9CBDCBF76AULL,
		0x160876E8B01FC310ULL
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
		0xBB9B79FF58E6FA74ULL,
		0x70F78DDD74C33391ULL,
		0xF3D1B9B50AD142ECULL,
		0x1645EC2EAF33F05EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F3A3534BBCB994AULL,
		0x0EE8CCF874D03AA1ULL,
		0x8069E9F7F0640C89ULL,
		0x7169E17FA9FEB679ULL
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
		0x828E62E47180C6CEULL,
		0x14C4CD98DE73E2F8ULL,
		0x2EB46CA05BF128F0ULL,
		0x1F9DEAE64678E9B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BE83D01D6A7A858ULL,
		0xC204122FC5272EABULL,
		0x022BC2EAA520933BULL,
		0x335C0BB74AED28C7ULL
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
		0x5C056FD39915E67AULL,
		0xCB55A665047F9174ULL,
		0x389CBA02DADE3C7DULL,
		0x25A8CEA176B5F749ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC4AC63EB87FFB4AULL,
		0xBDBE51C6BDBDEF0FULL,
		0x9EAD81B069F62742ULL,
		0x033375988D7FD0F0ULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9718755937B7193CULL,
		0xBFFD96361D87A8CCULL,
		0x9B0B2870B038F545ULL,
		0x0BFE9DB1C7BDA00EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9718755937B7193CULL,
		0xBFFD96361D87A8CCULL,
		0x9B0B2870B038F545ULL,
		0x0BFE9DB1C7BDA00EULL
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
		0x7B21F48802BF7E5EULL,
		0x1F35A9C8771A6008ULL,
		0x8A08772C92D86AE1ULL,
		0x29D7D36CA4EBB737ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6605AB0FF492EB06ULL,
		0xEBAEA35C784A9334ULL,
		0x2B032C302FDB4825ULL,
		0x3006D60B59283F4DULL
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
		0x54D15DD5EFE591FAULL,
		0x67E792D80AD32871ULL,
		0xC71F362602564114ULL,
		0x5B53281BD1E641F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x26589E9632C9ACB9ULL,
		0x794E85A54CF61EC9ULL,
		0x1E1F748B51E8639AULL,
		0x42C54DC31A84FCD1ULL
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
		0x2943127CD1588EBFULL,
		0x43E6A6E3300C6B6CULL,
		0x053E832FB97ACB63ULL,
		0x04199C57C00A860CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB6C7F446AA31A1C2ULL,
		0x7CB6606382B3168EULL,
		0x684EB12D6794D490ULL,
		0x2A943ECABE9501CDULL
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
		0xA929F348FF98102AULL,
		0x92D105C29ACA3D62ULL,
		0x626BD0CDD3081878ULL,
		0x0D165640C0B3B14BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA929F348FF98102AULL,
		0x92D105C29ACA3D62ULL,
		0x626BD0CDD3081878ULL,
		0x0D165640C0B3B14BULL
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
		0x9AD8C2A4EB1CDDF5ULL,
		0x8AFE64A499F5030AULL,
		0x41AC00201CB4D17CULL,
		0x5180F28B8AB8670CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14408199D13A6782ULL,
		0x5BCFFCE02CF2F0F0ULL,
		0x28B7D365D2DF4AB0ULL,
		0x1E428CD530B6E4A2ULL
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
		0x2019A686A3B81FA2ULL,
		0x6D4CF17993C674A4ULL,
		0xDD29DF3D7988A16BULL,
		0x49044F7840D84C11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE03E630FFCDF2647ULL,
		0x8D68F5E67A8B754BULL,
		0xF3075A583F6DFFCCULL,
		0x1552ED3C7B241FDAULL
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
		0xA976FEEF0C4E6782ULL,
		0xEE4187C4C161BDF8ULL,
		0x547E287454B1895AULL,
		0x52F53987EA456430ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD87FBF8390FD072ULL,
		0x554D9EFAF19907FDULL,
		0xC2DB3377D64F33A3ULL,
		0x1D17676BCC836563ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2EAB723CB0F85ABFULL,
		0x4C188433AE81118EULL,
		0xCF482DDC246FC59DULL,
		0x4C10C3867CA46FF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2EAB723CB0F85ABFULL,
		0x4C188433AE81118EULL,
		0xCF482DDC246FC59DULL,
		0x4C10C3867CA46FF7ULL
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
		0xF2E7F5BC42F04A08ULL,
		0xDDA38AE4F3D3993DULL,
		0x7A7383DCCD6DAB0FULL,
		0x2C20AABC17DD61CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF00F55E76803CCD7ULL,
		0x1982A1B0FCE21CB1ULL,
		0x9BD4E8C749385EE1ULL,
		0x5686D4748EB84140ULL
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
		0x4D828D3161F21097ULL,
		0xC6A778F5FEA756D6ULL,
		0x957E0B210CFF7234ULL,
		0x7EC63BB4990BF478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2F6A434E12B7D5E0ULL,
		0xEDEB498924A529E3ULL,
		0xCAD77095EA23702AULL,
		0x412078A31CA3872FULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7BB2A934A3A59B7DULL,
		0x2F6DDEE7DFA68E29ULL,
		0xCC76CE1D16CE8065ULL,
		0x0FB9CECD1AE893D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF73757B38AE605EAULL,
		0xD84A97733A4DB8ADULL,
		0x6C32828E8010D4F3ULL,
		0x063601E179481BABULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4A4132CF698A3EE2ULL,
		0x53162D103069C951ULL,
		0xB7DC296B3B21B912ULL,
		0x73FEB13B87363B5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4A4132CF698A3EE2ULL,
		0x53162D103069C951ULL,
		0xB7DC296B3B21B912ULL,
		0x73FEB13B87363B5DULL
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
		0xFB3E6D0C9DC11308ULL,
		0xA57FA4B6FD8366F0ULL,
		0x0FDC9F67113C2B27ULL,
		0x35A8F3DE05DA3DD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4F63DAD2C24E176ULL,
		0x7C25CD263E9061DEULL,
		0x87A40E9B00726C64ULL,
		0x489C7624C89A151BULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x33B7EFCD64798BA8ULL,
		0xE785A50FC3246620ULL,
		0x6E7A69B4FC7FF37CULL,
		0x370277D98C91B5DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x391F063052D49F6BULL,
		0x6B3760C72AD0635CULL,
		0xD3DAC4C26DE4430AULL,
		0x2F2916EF0752049BULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC8DF77D7B72390D8ULL,
		0x078F16093FE1D2EBULL,
		0xC91D9D557DCC7F25ULL,
		0x6475300D9FC14E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB9997503BE514A2AULL,
		0x8530DD2CBB149D5CULL,
		0xBB83924F299472D7ULL,
		0x44C438417C15B31BULL
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
		0x5659F7EE6684F5DBULL,
		0x239536762146711FULL,
		0xB8B005CE4CC982C3ULL,
		0x74B90F8CEFBAA855ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5659F7EE6684F5DBULL,
		0x239536762146711FULL,
		0xB8B005CE4CC982C3ULL,
		0x74B90F8CEFBAA855ULL
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
		0x938ABE4048E100BBULL,
		0xE412FC0493544ECDULL,
		0x1F1FACE5AD717303ULL,
		0x494B0C666CFADCEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDC74410C2442741ULL,
		0x53417DC046F95D43ULL,
		0xEE78ECB3C9226EFBULL,
		0x3688C31AFA0A62BFULL
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
		0x32BF56514A37B050ULL,
		0xAF64EF4C40E85B48ULL,
		0x12041E3DFA7D82BAULL,
		0x2E69B285CC1B36FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x742A5D5B960B01AAULL,
		0xBAF172D69C397A54ULL,
		0x1F14C42915487B1CULL,
		0x03215BC3A0B29AAAULL
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
		0xC921D5B23991BE67ULL,
		0xE1BEE0B644D000A4ULL,
		0x7542C05636254737ULL,
		0x27238D1F229B5476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x60794BB283236266ULL,
		0xA83074680580AD22ULL,
		0x7C9348D2B9B17917ULL,
		0x5C993E2FBF1E75E5ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCEB783057ACC5557ULL,
		0xF22079EADD2C856BULL,
		0x500A01FDB37A2D5CULL,
		0x77BC517378832EE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEB783057ACC5557ULL,
		0xF22079EADD2C856BULL,
		0x500A01FDB37A2D5CULL,
		0x77BC517378832EE1ULL
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
		0x48E3C21418C85F16ULL,
		0x33F9E34AC84FE651ULL,
		0x44D7841DE6E42600ULL,
		0x3BEEBD6060FF6AC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CF58B5CB8C170D7ULL,
		0xFAB4464AB943F5C9ULL,
		0x711E27B78604BCCDULL,
		0x7EDBD0EB4AE5B1DDULL
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
		0x1681659BC4224B7CULL,
		0x35884E8F1F8987AEULL,
		0x01C47FB9AA4A461DULL,
		0x363CE365437E5B7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8632440FE9B00822ULL,
		0xA45CA606AF043A81ULL,
		0x2D1908A0409DE4C2ULL,
		0x161285185A3DEA25ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x067424451FB9DD9DULL,
		0xC34B487604D79DDFULL,
		0xFB187B1C641DFCDBULL,
		0x7E276351BC85ABCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x232FBC1238311F39ULL,
		0x88BD40DAA908D13FULL,
		0x782E1BA2E3F88FB1ULL,
		0x5E98EFB6926D5E57ULL
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
		0xE32F0501CE4A6616ULL,
		0xF452302463CDD671ULL,
		0x7473D6CD1EA50BD4ULL,
		0x231F2E7FCAE1F562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE32F0501CE4A6616ULL,
		0xF452302463CDD671ULL,
		0x7473D6CD1EA50BD4ULL,
		0x231F2E7FCAE1F562ULL
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
		0xDD3CE6086B66CDDEULL,
		0xA6C1FE76B2D2D64AULL,
		0x43211FC491350378ULL,
		0x0C28BC40E797E5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA9095CA845E6103AULL,
		0xFDA704C2CFC66E4DULL,
		0xE8E744493EF204EAULL,
		0x702C581C13A1BCA4ULL
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
		0xBEF07B59EFF7F4DAULL,
		0x0CCC37DC2961071FULL,
		0x3335A115CEFFF479ULL,
		0x4603E29313366A44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x39A4CB6ED6D7F921ULL,
		0xA6ECC85F79BAFBC5ULL,
		0xAD79AC328C0EB791ULL,
		0x34654D009605D9A8ULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x602E8DB0AA4D853BULL,
		0x1443504AE8C49ED7ULL,
		0x084C5DCB3ABADE1DULL,
		0x296A31D615C5C7A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x39B6C95DD8D3B849ULL,
		0x992D2237AED65515ULL,
		0xB9C0025FDB2F0629ULL,
		0x01D0746E5E49ACD4ULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF77151D72D0818FFULL,
		0x1BDCCC834E12C427ULL,
		0x407759B2D3EB7A56ULL,
		0x4FC8B17E25AABE3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF77151D72D0818FFULL,
		0x1BDCCC834E12C427ULL,
		0x407759B2D3EB7A56ULL,
		0x4FC8B17E25AABE3FULL
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
		0x5BA05E2399509E0DULL,
		0x1745B7EDF91F5472ULL,
		0xA5D4FEBA1B322BECULL,
		0x07F41387F3B1E80AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x46E4F11D0BB2297DULL,
		0x5BD0E2E46F620904ULL,
		0xD308820C1B499420ULL,
		0x3CC468C0252B14D3ULL
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
		0x467ABF3396ACA1E5ULL,
		0x2378980B5DFC4438ULL,
		0xEAD103F9738F5672ULL,
		0x1C8F243A76736D23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4CE9A15C69BBEE1ULL,
		0xCF086E316EFCD532ULL,
		0xCAE43E76B382CD0BULL,
		0x52618DD4B92C8783ULL
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
		0x82937C7CBD579CDDULL,
		0xEE76CADD5FCD168BULL,
		0xB296D547A842D11CULL,
		0x19D74D8E363ADCABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBDD4550D8B0AA50ULL,
		0x69336AE7975A7E4DULL,
		0x8B91CDFEBAE6E5E4ULL,
		0x241E5694710DC74AULL
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
		0x8625042AFAA8ABB4ULL,
		0x57D9DBBD366CAA96ULL,
		0xF98E60F505878FB4ULL,
		0x0C3115DF029610D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8625042AFAA8ABB4ULL,
		0x57D9DBBD366CAA96ULL,
		0xF98E60F505878FB4ULL,
		0x0C3115DF029610D4ULL
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
		0x7110ED5702543529ULL,
		0xFEDDC5AE974ACE03ULL,
		0xF38CFAB9A393EB2AULL,
		0x5118FB129D4682D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x27DAB221375DC49EULL,
		0x3E56968894F99136ULL,
		0x7A70F039A9A6B614ULL,
		0x4F59FB5EE1E2B402ULL
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
		0xCC7185958E885D00ULL,
		0x221357F7F08E5E15ULL,
		0x94213F237C458B3EULL,
		0x3CFB73307455F824ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x080B7C5CB26235A5ULL,
		0x500C1660E34C506AULL,
		0xB9DA4BEDECB380E1ULL,
		0x7BC3C0AFCE7D50AAULL
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
		0x059F2557E6414D7FULL,
		0x118F88740ECCD3B2ULL,
		0xE9FCD7C302C24923ULL,
		0x29CEFAD9115D8B05ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x74A79CD250DAB276ULL,
		0x209ABECDE9AB2972ULL,
		0x5DAB5EB8F26083E9ULL,
		0x11432B3306E81868ULL
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
		0xE9A4F20B0F3286C3ULL,
		0x98BE28299E32DE47ULL,
		0x6F1045073A15D6B0ULL,
		0x4A946AA4095CCFDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE9A4F20B0F3286C3ULL,
		0x98BE28299E32DE47ULL,
		0x6F1045073A15D6B0ULL,
		0x4A946AA4095CCFDDULL
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
		0xE722A3994908D40EULL,
		0xE84A7E700B62EE50ULL,
		0xD35F282257B0B7BBULL,
		0x0F5FA1FAFEA7C1CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE6EC4A20711FCBFCULL,
		0x6DDF6BBB7FCBAEB4ULL,
		0x99715D1F3E8A424BULL,
		0x3C0A70DC168CE9AFULL
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
		0x0AAA8893564298D0ULL,
		0x27C44E81382E1043ULL,
		0x3CDD08B55F95029AULL,
		0x25ABF7BB0E4370C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D108389EAC47A63ULL,
		0xBFF1DC6E7818B17BULL,
		0xA13483911A9219EAULL,
		0x0CBC89408956D0CFULL
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
		0x48EA569972D58609ULL,
		0xDDF6A2242B4F000EULL,
		0xC865A959635A78A9ULL,
		0x6BC053EED253B77AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA848BD864FD03177ULL,
		0x25981440B2DC1F59ULL,
		0x5318D9CA337AD1EDULL,
		0x3D0E826789B317E0ULL
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
		0xDEF85624E4F9B97BULL,
		0x4759FD0D39842920ULL,
		0xFE75AF75060EBEB5ULL,
		0x649B7D3BD38A6DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDEF85624E4F9B97BULL,
		0x4759FD0D39842920ULL,
		0xFE75AF75060EBEB5ULL,
		0x649B7D3BD38A6DCAULL
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
		0x16CF7DB898231D67ULL,
		0x604902600FB31B6CULL,
		0xC0513ABCFE01718BULL,
		0x7CAE1F5D7309D73FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2596650795D7A464ULL,
		0x460FDC0E478DEF5DULL,
		0xCF35F91CCE200C3EULL,
		0x494A96049619D3C3ULL
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
		0x8C91075CBDEA8656ULL,
		0x0543B2744250EE4AULL,
		0x05E010220FA0826AULL,
		0x27639901F594F40FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E1C82B4D9DCDD76ULL,
		0xE6ED31FC16522E0FULL,
		0xA8C5A7EFF8B14A38ULL,
		0x4F2DB0AF345831DCULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1BDE99F87FC11051ULL,
		0x916F649A3DA685E9ULL,
		0xFD59481289097DDEULL,
		0x16C56E77FBD990E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6BF562BA3AADA02CULL,
		0x78400F4B44463B19ULL,
		0x9B55583344A9F52CULL,
		0x51BBB98514456F8AULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA81E8317DB6E98DBULL,
		0x5DA0D3A5C319175FULL,
		0x81EB4E39E1B8E6A5ULL,
		0x3AD159E683059C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA81E8317DB6E98DBULL,
		0x5DA0D3A5C319175FULL,
		0x81EB4E39E1B8E6A5ULL,
		0x3AD159E683059C99ULL
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
		0x394ABAF045FAEB04ULL,
		0x29A9862669BDFEB6ULL,
		0x827DF37D7B688BF9ULL,
		0x1C60E51C31F2AFE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD152DD8C8C8C6208ULL,
		0x886363C24E6E1E3EULL,
		0xB70BC75948E2DE93ULL,
		0x1BEA2EE6AD2827D5ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0838A29EC8EE9C0BULL,
		0x3D1996750211B43DULL,
		0xEC6BDC1B04C432FBULL,
		0x1A91F32B34F88AF7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87B234C83580C7E5ULL,
		0xBC94E07F2BA1E2F3ULL,
		0xB47AC4BB337F2D95ULL,
		0x248119440B8B653EULL
	}};
	t = -1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE43A3F83BC9BFA8FULL,
		0xECE978100C7DC553ULL,
		0xF715D8CDB0DB0692ULL,
		0x658BC565A81D68DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7CD2FB620B3E1DDEULL,
		0x0D36D88E2DB637AAULL,
		0xD05958B8D435805DULL,
		0x25664037AC813FB5ULL
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
		0x191367B8C88DE5FAULL,
		0x2812E9D03C31A1A3ULL,
		0x5FEEA2FC059F14A0ULL,
		0x16A0A2D098D201FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x191367B8C88DE5FAULL,
		0x2812E9D03C31A1A3ULL,
		0x5FEEA2FC059F14A0ULL,
		0x16A0A2D098D201FDULL
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
		0x40E9BA7092A53A5AULL,
		0x08F6AE97DD90EDDCULL,
		0x97BD10739CE709B6ULL,
		0x7629E4A9737DA38AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEDE0C18695711CE3ULL,
		0x6621320C75509D0EULL,
		0x5D9430F7E8CBC790ULL,
		0x6030CEFEB4E7722EULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5BA123DA6F79A8BCULL,
		0x037216C2DC574AA1ULL,
		0xDC3C7AD373AF1E1FULL,
		0x25FE9CCD827FB5CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3C29F62E7D0D6BB0ULL,
		0x0967E09E82AED308ULL,
		0xB3255EF76867FE3AULL,
		0x157A8CE3512C037BULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x32C4029DD90C7891ULL,
		0xFDF7359E3CBDA07FULL,
		0x476DAF3C7D2D45A0ULL,
		0x3EDC96F67B053032ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09FB6E7FE12A8163ULL,
		0xA344855B28EC34F5ULL,
		0x28EE92353D375B98ULL,
		0x24D46A178024B26EULL
	}};
	t = 1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFFCAB254491A339FULL,
		0xAE634176714FF71CULL,
		0x495716BFB41B3BBBULL,
		0x2CFBD0ABF2601882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFCAB254491A339FULL,
		0xAE634176714FF71CULL,
		0x495716BFB41B3BBBULL,
		0x2CFBD0ABF2601882ULL
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
		0xA0FCE991835F329BULL,
		0xFA97AFA1A6255411ULL,
		0x7242C0F2CA9092DBULL,
		0x213B7487DAF1BAA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8F8639B29A3D0434ULL,
		0x8DFBC44DFB161F17ULL,
		0x8CAC63A2B7871A26ULL,
		0x3FD29D06991FCCB3ULL
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
		0x4DBA79E20EDF144BULL,
		0xBFFE91043EAEA4B3ULL,
		0x815A6B997AB0AFC7ULL,
		0x7BC5FB42D97FEE52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE904F42F6FFDF18ULL,
		0xFA55AE1AC9732572ULL,
		0xF67E1C1821656B1DULL,
		0x5F76F42E5D35A32EULL
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
		0x182B8DCA54904EEFULL,
		0xC3C257C9A6BC53C7ULL,
		0x4E5A73850FC889CEULL,
		0x5A6936E5617CCA99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4479B7C4D2D6067BULL,
		0x6120D8A80B9D6C51ULL,
		0x4594EAC64ABC13BCULL,
		0x6E6CA965D8B49F38ULL
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
		0x4CD761618E8BF308ULL,
		0x00241CD865DD5926ULL,
		0x7FD037318E01B465ULL,
		0x7AA942AFB7AF7EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4CD761618E8BF308ULL,
		0x00241CD865DD5926ULL,
		0x7FD037318E01B465ULL,
		0x7AA942AFB7AF7EF0ULL
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
		0x3F724A2F3875133CULL,
		0x22532541751D0C60ULL,
		0x9E80869541E3AF29ULL,
		0x700E219C4ABB2E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB50CAC32A5579F30ULL,
		0x345A8D36C7EFCC88ULL,
		0xF459BA94F4E988C2ULL,
		0x164D358D839AECF8ULL
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
		0x161903D5A41E0DE8ULL,
		0x76FA806F106D0495ULL,
		0xA394F2B1C1D6ED94ULL,
		0x520ED20FFA11F740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF5D555FD454A1DEEULL,
		0x826D8CAF3FB02BA9ULL,
		0x34D3DA7586258BABULL,
		0x31103EC411FE2476ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x05E5DE75CB8755B4ULL,
		0x743C3D31CE76F43FULL,
		0x81383DD26C746524ULL,
		0x3C71E204E1BB576FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x504CE69F0321F64AULL,
		0xF7C11C9ADB208EFDULL,
		0xA087ADA400BABEC9ULL,
		0x239581DC3E9A5D32ULL
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
		0x98CF0876E4BCFD2AULL,
		0x63361890192F233EULL,
		0xC76D843B0F8B773EULL,
		0x00EC040151C19C8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x98CF0876E4BCFD2AULL,
		0x63361890192F233EULL,
		0xC76D843B0F8B773EULL,
		0x00EC040151C19C8DULL
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
		0x0F6EB521DCE19709ULL,
		0xF345DEFF53745C0FULL,
		0x1D78AC82ED6DA77BULL,
		0x074A23D1BEBD3370ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x149F1F5B5CF48034ULL,
		0x6C69E739390424C7ULL,
		0x4BEAF8E868B8D342ULL,
		0x7A4D8AB82F356009ULL
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
		0x1DAF3042F15F3615ULL,
		0xB5ABC1E321F70108ULL,
		0xA19E50952D6B53E9ULL,
		0x4A780A24C4AC0D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD22A839408F1C471ULL,
		0x4808EFBCFB3909F0ULL,
		0xDEB3C02C15AC2E03ULL,
		0x3EED3C9262F75628ULL
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
		0xB61213B5A962CAB7ULL,
		0x7C48512EE08A0AA1ULL,
		0xE4CD13FCA95FEEBFULL,
		0x4B635795829DE29DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEA46974C13D8DF22ULL,
		0x5734970C3D8EBCD8ULL,
		0x6B640DEE28474147ULL,
		0x7E99C847138D4572ULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6CAC18E9F1472744ULL,
		0x99B302B49C5892F8ULL,
		0x33CAE73E0ACC58AFULL,
		0x03E09FC19EA317EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6CAC18E9F1472744ULL,
		0x99B302B49C5892F8ULL,
		0x33CAE73E0ACC58AFULL,
		0x03E09FC19EA317EDULL
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
		0xC650048ECEFBA80EULL,
		0xC5B2ED32ABE275BBULL,
		0x46035C9D1C48ABD2ULL,
		0x43908092188D44C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6A000E66D0415CFDULL,
		0x0A6E000198A3969BULL,
		0x3ACCE62998F905C0ULL,
		0x4357DF1DF37A0518ULL
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
		0xF717C4516C3D852FULL,
		0x909F42DC39B6662BULL,
		0x2C56EA1EC87C987EULL,
		0x3B8434EE8FD08DC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4949D5616280CB7EULL,
		0xCDE2670AA2F91A03ULL,
		0x6F007CAC07EE66C3ULL,
		0x757F14569940A77AULL
	}};
	t = -1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD3C2B50DCDDAF745ULL,
		0xF8CD9964B5DF52EAULL,
		0x400C1303FA9EDE94ULL,
		0x2931EEADFDABAE1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1D20A84CBF27B03AULL,
		0x5DF46ED926EA0D49ULL,
		0xF1E1E609DC46C055ULL,
		0x2DEBFDA3A50EBE36ULL
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
		0x2373ECBFB9293CEAULL,
		0x770F0A80A48E67D1ULL,
		0x53DF1C1CACD2F07CULL,
		0x205218F7E39C0299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2373ECBFB9293CEAULL,
		0x770F0A80A48E67D1ULL,
		0x53DF1C1CACD2F07CULL,
		0x205218F7E39C0299ULL
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
		0x9A8ACAA2DDC048E1ULL,
		0xD3761B647E505404ULL,
		0xFCEF2585A5C79A1EULL,
		0x07763D829B8E615FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5118584514BB32EULL,
		0xE8C720D92E0CAC8CULL,
		0x24114356AC609A65ULL,
		0x3A879676323351CAULL
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
		0xB3C98C12CC7B52E4ULL,
		0xEFB8A86804786E09ULL,
		0x5CD065792D24C871ULL,
		0x380528696C9F0785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x813A687DB1FBC4D3ULL,
		0x82C035BD8F118185ULL,
		0x2871C789CDF6276DULL,
		0x78C8C33E86429301ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5196C3366B459AB9ULL,
		0x486C4A5EAA77F83BULL,
		0xFEC32F6E6260E3B4ULL,
		0x2758698B3C24D1DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBB434ECA6F25298ULL,
		0xC38481E7EB1F05F4ULL,
		0x77A701AB4B2C9971ULL,
		0x643423BDA22E2702ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD7D2F37D13B6D692ULL,
		0xDE2E487C82053A8AULL,
		0x17AF7B1357F60367ULL,
		0x3522E90DC5549C6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD7D2F37D13B6D692ULL,
		0xDE2E487C82053A8AULL,
		0x17AF7B1357F60367ULL,
		0x3522E90DC5549C6CULL
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
		0x726C00096774C0D1ULL,
		0xE5DCBDF55BD7D70CULL,
		0x59704F264FAF6932ULL,
		0x478723DDEE9AB41FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F2344D5A9754827ULL,
		0xF9649149E3B8394EULL,
		0xD71B5129CBCA633AULL,
		0x1C7CCF06745823DAULL
	}};
	t = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFCD425E1ADC430ECULL,
		0x5EC3A97D6BA5501BULL,
		0xF74EC975CB0EDF23ULL,
		0x1CBC9608129DBE2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67EC85006055B600ULL,
		0x142537804252D658ULL,
		0x0BB28AB95BF4E8D1ULL,
		0x4F7A2AF8EEDA11D3ULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x72F9379C06EA623CULL,
		0xF686B5744B8FFA5BULL,
		0x3A5352F695812311ULL,
		0x0751A24AE7BE42A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6DE9FEC98D472175ULL,
		0x17D953A57741EC19ULL,
		0x7477E497D6F2C528ULL,
		0x170DBE899B21D6ABULL
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
		0xF5375D2E920BF447ULL,
		0x41997DD62C3E9AD3ULL,
		0x91DBB1070747AEE7ULL,
		0x03271D01B8E289E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF5375D2E920BF447ULL,
		0x41997DD62C3E9AD3ULL,
		0x91DBB1070747AEE7ULL,
		0x03271D01B8E289E9ULL
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
		0x89F5A6859958B88AULL,
		0x9262E652FE8CA67BULL,
		0x7DE815990F04DEB1ULL,
		0x0351D0D5979C55BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x98AECEEFD0D99EA9ULL,
		0xCECD63242CD7F331ULL,
		0xA1E9C60C0DCB8E41ULL,
		0x2CA55568DC19C930ULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8F8DF25CE576D1B2ULL,
		0xC694D7E2A8D6E338ULL,
		0x0FE9F71C9FCE70F2ULL,
		0x71BAFE5BA3DED11CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2084A42406478C0AULL,
		0xB38BE0922394E82AULL,
		0x99A7BD080984F36CULL,
		0x09B48E749D00D943ULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x58CB1F543B417649ULL,
		0x922ACD7288E21803ULL,
		0x4524FF760BCC3CCDULL,
		0x48C6BE136260A32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1FC8F3B890133D54ULL,
		0x0536AEF2B0627EC3ULL,
		0x7D6B1E34DD22D3DAULL,
		0x0EF83DA753394453ULL
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
		0x615964BBD6D02F47ULL,
		0xBAEF8F2B018F68A3ULL,
		0x874B0C441E5AE4C4ULL,
		0x19328CE18B3DF45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x615964BBD6D02F47ULL,
		0xBAEF8F2B018F68A3ULL,
		0x874B0C441E5AE4C4ULL,
		0x19328CE18B3DF45FULL
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
		0xD6B02B20E84CD343ULL,
		0xC4CD000871E870A8ULL,
		0x0AF8945F56E11D21ULL,
		0x06C5210B5467AB2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC6CF761F0E9CC3DULL,
		0x9B62063CBA8BAAE9ULL,
		0x0623FED7DC82FE02ULL,
		0x7542E93A1F4BF6C4ULL
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
		0x2F47F9E4336A2DB8ULL,
		0xB13A47E5C47382ACULL,
		0xCE8E87055F355A88ULL,
		0x2614AFAD9BC5BBFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2F7670D6FC86CA29ULL,
		0xC104D15F87EE98BEULL,
		0xB1DAD309002DB7D2ULL,
		0x38541E5AD187785EULL
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
		0x032D42E2E442A543ULL,
		0x537DAA8E9A3C7DD2ULL,
		0x7D1E71670ED1E912ULL,
		0x56D2F1DBE51D38E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC32EA0FBBED9F0DCULL,
		0x135A097320B74754ULL,
		0xD0378C6738B9E846ULL,
		0x3646A0EB27643951ULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2B0359F07860B9F0ULL,
		0xC358B6EE43D8C2F3ULL,
		0x3775795A6CF677CAULL,
		0x0F4313E157BA11EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B0359F07860B9F0ULL,
		0xC358B6EE43D8C2F3ULL,
		0x3775795A6CF677CAULL,
		0x0F4313E157BA11EDULL
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
		0xDC4E539ECAE65E2DULL,
		0x4F57FAC7473A6C9BULL,
		0xE1942C2E490356D3ULL,
		0x39EEBC8EE675CADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF39A32F9D99B652AULL,
		0x371A638EFCF39905ULL,
		0x31E020EC8C121097ULL,
		0x72F1359255CD2547ULL
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
		0x14BE2DC992133AD3ULL,
		0xE5631EC18987248DULL,
		0x7E2662B5FE1B60B4ULL,
		0x10A23E1E05AFAF54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA3718804705D9CBFULL,
		0x9C887BF5DD134360ULL,
		0x8460B419590A9A55ULL,
		0x0A1117C0A34E2A13ULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB3087BDCAEEDA814ULL,
		0xC00C0012128CDFDDULL,
		0x8C149445F498C88DULL,
		0x41FDF50ACC5ABB16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x545691728ACB637FULL,
		0x1653BCCDCF94D07AULL,
		0x70EE8B765D257B17ULL,
		0x22691FA29718856AULL
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
		0xC9CE091DA9664B49ULL,
		0x956DCBBB16976040ULL,
		0x4279C95048C52CCAULL,
		0x5C3D4D5814EEB502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9CE091DA9664B49ULL,
		0x956DCBBB16976040ULL,
		0x4279C95048C52CCAULL,
		0x5C3D4D5814EEB502ULL
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
		0xC0C91CC4482E4C47ULL,
		0x1A170C252191CA84ULL,
		0x31055B1331C874BEULL,
		0x2A73AA54CDAD8DE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCD39791825EB35D6ULL,
		0xB294F4506CACAD5FULL,
		0xBEDB99E72E2E5AA7ULL,
		0x297BD0943FEB5037ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9BC68073FA16C919ULL,
		0xFAB6CD2BE31C1E3CULL,
		0x2F5C2EF4ED6C1521ULL,
		0x1C4B6E4533A64EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x812FCF3A05687870ULL,
		0x45257ED58BDDCE56ULL,
		0x5BC22296F0A311CCULL,
		0x0C089585CE3CE267ULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA3813704739F2AF4ULL,
		0xA52DB44218352812ULL,
		0xE04B6BDFF07BA746ULL,
		0x66E671E5A999FEADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x364F2CE09949D6ABULL,
		0x5F713B627C1C96B8ULL,
		0xB03C17CFB2F57E8CULL,
		0x6E7ADBC2E32FD0D6ULL
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
		0x57365D0644F4DC32ULL,
		0x2A654D2159AB6B06ULL,
		0x2D9C23D220EA843BULL,
		0x26560E66A6BE9026ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x57365D0644F4DC32ULL,
		0x2A654D2159AB6B06ULL,
		0x2D9C23D220EA843BULL,
		0x26560E66A6BE9026ULL
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
		0x556E2F9DB5D1A253ULL,
		0x5DF69AD89385EB45ULL,
		0x5B6934EE669D64E6ULL,
		0x6E7FF87C680B98AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D8FBF882A923A34ULL,
		0xDB271A72CD3283A0ULL,
		0xE11F5D2475816D60ULL,
		0x5D44823FE9CE7DBCULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6DE2BB98CAEC8635ULL,
		0xD735DCC582954160ULL,
		0x83C22662CCF8B271ULL,
		0x3CC357DE3516A96CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66ACE83037DAEFBDULL,
		0xE84591E2B124AFD9ULL,
		0x87EA78F0915EB8E2ULL,
		0x25FE08E48584F40EULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC815027E89AE4963ULL,
		0xAB6F7D9BF82683ABULL,
		0x0E06670574E7F523ULL,
		0x6CFB263BB3CC21A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2F8D21B9D791DA79ULL,
		0x0BE860586066F7C2ULL,
		0x2907960EE2AFFDF3ULL,
		0x4E35C936333DA369ULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA24BE2AD05AB5C90ULL,
		0x67E64A0DD2062FF0ULL,
		0x2C4B0491F302E48AULL,
		0x7D497B2B6EF8B266ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA24BE2AD05AB5C90ULL,
		0x67E64A0DD2062FF0ULL,
		0x2C4B0491F302E48AULL,
		0x7D497B2B6EF8B266ULL
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
		0x1BC0EB080C159EDAULL,
		0xB83B84EDACA721CEULL,
		0xCA3FFC30B04FC359ULL,
		0x2ED6E717CA6C0BC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC043C79DE4411650ULL,
		0xCD36E4EA8DC31C05ULL,
		0xF6D8428BF3E73729ULL,
		0x5468C0D1E37DC973ULL
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
		0xB397173CB1F63AA4ULL,
		0x31CFF2E542158060ULL,
		0x15B86816B45AFDB2ULL,
		0x0F72F4F233B9FDFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD8178F7C33B3364ULL,
		0x5161204AD38A77BAULL,
		0x24AF022D8EC9F300ULL,
		0x7A44D94D7FAC210FULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5C8061243E1C178EULL,
		0xFCF5594F31F15CA2ULL,
		0x1CB27A4BF315C4A3ULL,
		0x2D6901D5710C4BADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7E0E40981FF4732ULL,
		0x276C00B0787F4CCDULL,
		0x58146902B33C8020ULL,
		0x3A56E15E17B7A071ULL
	}};
	t = -1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x855EBBAB837118AAULL,
		0x46A579FED76B2C74ULL,
		0xEEAA8B6CCF7AE28FULL,
		0x7B67276FF3D682F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x855EBBAB837118AAULL,
		0x46A579FED76B2C74ULL,
		0xEEAA8B6CCF7AE28FULL,
		0x7B67276FF3D682F7ULL
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
		0x31B5221E5EB0A443ULL,
		0x69A6394AA4C91F3BULL,
		0xF9C0DB4A67294E2DULL,
		0x3DC908BFDBD9F373ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1883583FCAE49BF6ULL,
		0x1F88DED289B6F447ULL,
		0xAC586A836F10D12AULL,
		0x5C193626F73D7542ULL
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
		0x7FB5A6C0E0719C09ULL,
		0xA92251765E522AB2ULL,
		0x7A789086A993D153ULL,
		0x465A10792E644565ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7CBE20AE4C17260DULL,
		0xD792A4DF9D434A8FULL,
		0xBA6DAFF64F214EFDULL,
		0x5326C6A7C8317F5CULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x29CFCD0B920C9070ULL,
		0x4E55C3E717897F8EULL,
		0x2931E75C2F4202CEULL,
		0x35E98006C56807F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0D0B5CF82B4D3D7ULL,
		0x239A1C518B81F10DULL,
		0x5FF3DDA398C0BDC9ULL,
		0x15EAAF3477C52391ULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA13BBE9E38BACDB7ULL,
		0xEE69AEE25D805BFAULL,
		0xED0C6FC8FB905411ULL,
		0x04CBC71F639B35D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA13BBE9E38BACDB7ULL,
		0xEE69AEE25D805BFAULL,
		0xED0C6FC8FB905411ULL,
		0x04CBC71F639B35D7ULL
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
		0x7CAB3E288CCE8E9FULL,
		0xBD0CA16986B33896ULL,
		0x42B3652A194A09F3ULL,
		0x6E63B9E5FFB48E23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F578649628BC449ULL,
		0x8AB57881B45CA6BBULL,
		0xFD436BB3F6D67670ULL,
		0x16F4395560C31503ULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x027F120C8EC7D086ULL,
		0xD9E258C923616EEFULL,
		0x9EF8B04FA12B4D30ULL,
		0x5D16063CAD5C913EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B225412352A31A2ULL,
		0x37F93F1A24F2433BULL,
		0x1C0699DEDE777B67ULL,
		0x5584C5DBD9935BB9ULL
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
		0x74CD716100696D44ULL,
		0xB95D4E48A2571D7DULL,
		0xCCB2BF06B0E428AEULL,
		0x2D24DA06AD038C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x34AA947BCC38DBDEULL,
		0x924129B106B7CC66ULL,
		0x432C75D169822A3EULL,
		0x6657321DB171D51FULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x32F64F9A89CD1BC8ULL,
		0x96D7E2173B853632ULL,
		0x2971A3A6D165A122ULL,
		0x3A0DA6589F5690C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x32F64F9A89CD1BC8ULL,
		0x96D7E2173B853632ULL,
		0x2971A3A6D165A122ULL,
		0x3A0DA6589F5690C4ULL
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
		0x146857775E1EA6FDULL,
		0xAB086C655CE4CBA8ULL,
		0x989B3D5565742140ULL,
		0x7081092C7D65D32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEE30AC0D95D5A1DULL,
		0x1A71325F5E8A6161ULL,
		0x915443CF0CAA8AFAULL,
		0x4A780A3D57BF58CBULL
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
		0xB3C7438486BF77C0ULL,
		0x46F27105DC9705B5ULL,
		0x5598594FCE9F4B44ULL,
		0x08476C2582136A34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x111C12F37B9AD0FCULL,
		0xD3634092D28C8297ULL,
		0xCE24BA35A9C5ABA6ULL,
		0x31F9D3F50BC2605CULL
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
		0x6E67888C7DD08BBFULL,
		0x48B69FC417B75923ULL,
		0x0E9638DBCCB40239ULL,
		0x59E6588546FE647AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C3497968ED15B59ULL,
		0x4B4612319FA17C38ULL,
		0xECC0EBD04A32667DULL,
		0x27660F8FBD916EE8ULL
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
		0x0CCA4FB9B93358B3ULL,
		0x9F7E7CA40DE6C7DFULL,
		0x5302ACB793F5D8DDULL,
		0x390C967FA0EE892CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0CCA4FB9B93358B3ULL,
		0x9F7E7CA40DE6C7DFULL,
		0x5302ACB793F5D8DDULL,
		0x390C967FA0EE892CULL
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
		0xC618969B686DFC51ULL,
		0xBB1938CAD3A61D13ULL,
		0xE1E595623CE62AEEULL,
		0x18B6A1FEAF45B9B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09A407E16202375AULL,
		0x2536183BB95B9DDDULL,
		0x6016B3EC798EA6F8ULL,
		0x76221127B71261BCULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x79F663BD9C228531ULL,
		0xCAC813EAA50562E9ULL,
		0x3CA147BB887D613AULL,
		0x6F37BBD7127A7885ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8A314939C516121FULL,
		0x7085792067F1F2E3ULL,
		0xF40C3115FE30EC7CULL,
		0x156B947F12DE348CULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB5A0AF0A346B8CB1ULL,
		0xF788ADFEF0D85539ULL,
		0x2DFAA2D87925F9F4ULL,
		0x547E526A074BB92EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09C42F53EA048216ULL,
		0xB1A01F3C722BE19FULL,
		0x4DD417BE28D2E2D3ULL,
		0x173C4006A9A91DBEULL
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
		0x32B4BF5334A4C653ULL,
		0x8393690B8CDE5A1AULL,
		0x54AF5F266B35CFF7ULL,
		0x2E493B1017C21BABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x32B4BF5334A4C653ULL,
		0x8393690B8CDE5A1AULL,
		0x54AF5F266B35CFF7ULL,
		0x2E493B1017C21BABULL
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
		0x07669C06D9FE1220ULL,
		0x7863E106DF925220ULL,
		0x71BC4236FC7A3B95ULL,
		0x4FA7B8FAD2BA6DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90F3733135409702ULL,
		0xC2C80F478D0DA14EULL,
		0x5E6B9BB644B93925ULL,
		0x195625A0E4764FE6ULL
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
		0x53FDCE0B0A5D160EULL,
		0xC2811F2A7E79BD2CULL,
		0xB7F5694B44BA9E14ULL,
		0x11504CF9B73E37EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE649674B5629353FULL,
		0xE678798756BC59B5ULL,
		0x3321ED5C58D08C9AULL,
		0x5D959DD24D9C681AULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0A83BCE9B64E0725ULL,
		0xA88387081110EE4BULL,
		0x1CB82EFD6052778EULL,
		0x3D4431492DACDF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7DD92AD8202CDACEULL,
		0xF7C511055A880017ULL,
		0x485983BBDF92847AULL,
		0x66C652DC6E38D8FDULL
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
		0xC57EAC9A44252F0CULL,
		0x520ED11E92161C8EULL,
		0x3F3D2D8A78DCC282ULL,
		0x301F2D82FA37AB95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC57EAC9A44252F0CULL,
		0x520ED11E92161C8EULL,
		0x3F3D2D8A78DCC282ULL,
		0x301F2D82FA37AB95ULL
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
		0x513ECC4A84086B9AULL,
		0xD3F88E379F747F3BULL,
		0xE6597670F2C4F679ULL,
		0x341F1314AC770016ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA4D076AE0A5C06C4ULL,
		0x7A2A79E333D3C8B4ULL,
		0xBBB368F8723752EAULL,
		0x78CAA1CC543A21C8ULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC76890776C252221ULL,
		0x2BCBC54223403D79ULL,
		0x6039CAE603DD39E0ULL,
		0x6161AA1880767F13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x561BD9D4375BB39CULL,
		0x04A1D3A7BFE342C1ULL,
		0xE20F381425985BBDULL,
		0x42399974741AC099ULL
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
		0x63288BCEFA6B1268ULL,
		0xA56144AA63A8A137ULL,
		0x45D6CFC23E4BF11AULL,
		0x3E5C3C7E515621A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x58A0921EBF86D11DULL,
		0x3FD14812F89EB17EULL,
		0x4D18920DF4BF6A9DULL,
		0x0DE16CAB4F4C8348ULL
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
		0xA5DE9C9B688A74C4ULL,
		0x857FB24C7BCF82AAULL,
		0xDFF8C199B84CDEA4ULL,
		0x11D0CEC8D0589D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5DE9C9B688A74C4ULL,
		0x857FB24C7BCF82AAULL,
		0xDFF8C199B84CDEA4ULL,
		0x11D0CEC8D0589D4BULL
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
		0x2F27065A94888180ULL,
		0x0D94A1ED927BF9D0ULL,
		0xDE9791B4907C11DDULL,
		0x3482F460FDBF6754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF4EEFBEC9C32F831ULL,
		0x27AB12D3664A998CULL,
		0xC1BE5ADFFC348156ULL,
		0x3F18F66AA44FF251ULL
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
		0x7737B9370219BE7CULL,
		0xE61B8B2E76E3D2EFULL,
		0x9451F61EA9B7B994ULL,
		0x3532424764D3EC47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x91167AC2C89307FAULL,
		0x3E610F81DB23E33DULL,
		0xA5E441C0CC0C456EULL,
		0x45134D4141D159DAULL
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
		0x746D19C711EBE7C5ULL,
		0x0F721C59594C8C62ULL,
		0x87C3B844F74AA16EULL,
		0x3D5E8B414C968696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83B75937B2C9C59EULL,
		0x810E8C24FC95A2CFULL,
		0x2B98CD31AE4C6635ULL,
		0x7A9D4D53916FADC6ULL
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
		0x650923637DFD320EULL,
		0x64905BE806FD25D6ULL,
		0x04BF149647E09525ULL,
		0x51290C3D0A657F34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x650923637DFD320EULL,
		0x64905BE806FD25D6ULL,
		0x04BF149647E09525ULL,
		0x51290C3D0A657F34ULL
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
		0x313433CB703763DAULL,
		0x919BAE7039665276ULL,
		0x4F1CBEE5DF56CFE6ULL,
		0x684575A626F58D83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1EBF41435FCB35ACULL,
		0x25EE5E0B59CB83C9ULL,
		0x45A229C0CA73C944ULL,
		0x605E9A70EFED522CULL
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
		0xAEECAEA0A52FDB85ULL,
		0xE62D1FCE2498C22BULL,
		0x9174AE3D80667D97ULL,
		0x2B0CBF2A93B64627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D74787595FD2C07ULL,
		0xAADA64946B2AA772ULL,
		0x60EEB0585E98C9B8ULL,
		0x427EDE758784C869ULL
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
		0x25A2695BA95E1BEEULL,
		0x4423F234FBA71207ULL,
		0x90759285740D6B92ULL,
		0x05FCD7FAFF3A809EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6635606E94A85FAULL,
		0xCC181A5DAEB16F63ULL,
		0x594F5D93A28DB3FDULL,
		0x53BD67FE82909521ULL
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
		0x3EA1A1B33E6750E6ULL,
		0x36F1951A9FBA0097ULL,
		0x2235E3F95D995687ULL,
		0x31F7CD14422486EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3EA1A1B33E6750E6ULL,
		0x36F1951A9FBA0097ULL,
		0x2235E3F95D995687ULL,
		0x31F7CD14422486EEULL
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
		0x29E790A68348A936ULL,
		0x6F4B0034B1A2E712ULL,
		0xFBB47BFF8996BBE5ULL,
		0x409DCEDA109EE9B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFCB51BDB85B234B2ULL,
		0xE80CABA9AD28BC6BULL,
		0xDABCE6245AF64F16ULL,
		0x2083E2E3F3419160ULL
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
		0x6EF1EE9ED498D552ULL,
		0xB1ADA643E07E7D9BULL,
		0x53A15BFC87F33D64ULL,
		0x75163EEE5AE05F08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1119F5073BABEFB3ULL,
		0x89CEAADAF06069F2ULL,
		0x77D39BAC5E0675A3ULL,
		0x726563FB40D5F17CULL
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
		0xB2E5C2419089A5E1ULL,
		0xEB2DD49DF2AD4741ULL,
		0x51DC326E50E5EC11ULL,
		0x47DE107473141C57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBE2600BCB0460C4ULL,
		0xD3B099267C4175F9ULL,
		0x1E2E366E9117BCDEULL,
		0x37E52DF88F82DAF5ULL
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
		0xCB975A58411EAD73ULL,
		0xDA89AC496623A9DBULL,
		0xB45CD1F87FEF543EULL,
		0x71D25CD9655234B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCB975A58411EAD73ULL,
		0xDA89AC496623A9DBULL,
		0xB45CD1F87FEF543EULL,
		0x71D25CD9655234B7ULL
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
		0x4C191FAB34FD1160ULL,
		0xB6C7402C7A8E98DBULL,
		0xC40034D4617D34AEULL,
		0x2A3B10097DB685C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x050F41133F6B3F79ULL,
		0x6CA6211BB0377424ULL,
		0x557BBC75D6A3A0D4ULL,
		0x36864B6DF0FE7D37ULL
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
		0x8AD92FC23D49B41BULL,
		0x4C33A223C8500737ULL,
		0x2B550541BC3F6EB2ULL,
		0x6832A42C3C156B64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06C46D9214A4737CULL,
		0x5AC8E2AA8BB00B95ULL,
		0xF41EC3D9F797D64AULL,
		0x19870B22258EAD55ULL
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
		0x682DD867A4A115DFULL,
		0xEF6F81746EB3FD73ULL,
		0xC6F0F3DE7A7662C2ULL,
		0x3901622E8ED906C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E6E4BBE6F3818E8ULL,
		0x9523E6B2819778CEULL,
		0x8143FFCFEDF54100ULL,
		0x50EE43E706702EB7ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x74F88BD848D74C03ULL,
		0xB1584562F55FA78DULL,
		0x5D19B2FC8D90CD20ULL,
		0x6609B8A5786DC692ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x74F88BD848D74C03ULL,
		0xB1584562F55FA78DULL,
		0x5D19B2FC8D90CD20ULL,
		0x6609B8A5786DC692ULL
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
		0x173B1B73B705F0AEULL,
		0x3EC57C5515C2DC23ULL,
		0x69C64F775D7F508FULL,
		0x07AC1BE87F298C31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4C05BAC7FA10CA8ULL,
		0x225E22618FF456FFULL,
		0x99049C4AA2B0E880ULL,
		0x0F88D4E2386CC2CBULL
	}};
	t = -1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3227F46BAF5C86F5ULL,
		0x5CFC836B685C6813ULL,
		0xC45FA33D0274271DULL,
		0x2B0EAD1786A1D02FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2B04D2620EEAFFBULL,
		0x1B933A299706F363ULL,
		0x2915A91C7A882125ULL,
		0x45E7CE6E3886084AULL
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
		0x47829A12DE1244C6ULL,
		0x4E95DA9D964B92FFULL,
		0x62C9678A5258E17CULL,
		0x2697D41ABA1EE17EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA53B467FF8AB8F4ULL,
		0x99ABF94798CA0A70ULL,
		0x83904F87A849467BULL,
		0x1B103783A622B4AEULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD614AED092420151ULL,
		0x1625785341DAF4C0ULL,
		0xD00AB6AAC1B238BCULL,
		0x761677C0560DB89CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD614AED092420151ULL,
		0x1625785341DAF4C0ULL,
		0xD00AB6AAC1B238BCULL,
		0x761677C0560DB89CULL
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
		0x1E7170CF9CA2D78BULL,
		0xCE17EC017331E93EULL,
		0x00AC9CF8F84D9CD1ULL,
		0x05ACAD917EA35D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x52177A5FA29754ACULL,
		0xE108C8431C3171FBULL,
		0xDE5045BCDF30D3B4ULL,
		0x346CBD595209BC4DULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x37035AB1E377D1C7ULL,
		0x2B38AD8A4356D60BULL,
		0x518C5295D1935791ULL,
		0x0543029C1375017FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6EE72B27D0989274ULL,
		0x0F63513D0FF7AE5CULL,
		0x5AFF68EE676BC1CCULL,
		0x45494E6FDEF79F96ULL
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
		0x615990817FF499FAULL,
		0x22DCE32113B726F1ULL,
		0xA8B08301E721CABEULL,
		0x6416709874424A2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x67ADA99D050E0C02ULL,
		0x577CB67CBC367AA1ULL,
		0x1B3FAE2636CC5471ULL,
		0x111559D3DEDBB3F8ULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB1554E4406568E50ULL,
		0xC468E0B840D94C75ULL,
		0x15B36A5DE3DF9EFBULL,
		0x3D0F0ADF279095DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1554E4406568E50ULL,
		0xC468E0B840D94C75ULL,
		0x15B36A5DE3DF9EFBULL,
		0x3D0F0ADF279095DCULL
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
		0x49B59B25B020B5E3ULL,
		0x4FABE3D1363FBBB8ULL,
		0xF20ACE304C2BF3A6ULL,
		0x07414F3C23915CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x977F7357F2F0E9B6ULL,
		0xCA34209F17287BA5ULL,
		0xE6094B3DF9E74D54ULL,
		0x66EBFF4D3F160D0AULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCFBA551C9CA0BA07ULL,
		0xB39DE8CC56A3DE54ULL,
		0x23DB311BF806D64BULL,
		0x35A6C6A2543B541BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBE03B240E76F0BE3ULL,
		0xE6B3A2B3DF6A1D22ULL,
		0x2355AC09A1F710B0ULL,
		0x74E5BBE220684113ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFBCACD5DDF2C335BULL,
		0x2BF91F37D4F3B5DCULL,
		0x7CE40C05F5AB9ADFULL,
		0x3A19A4C860E760C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC84FA5ED49F1689ULL,
		0x7EA3D90432DDB204ULL,
		0xD9BD5B0DEB711B77ULL,
		0x2BB465C34F98BD83ULL
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
		0x77E735D46528A166ULL,
		0x0932F9C8156CEE40ULL,
		0xF630FB807FD2AB2AULL,
		0x736B83FECDA51DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x77E735D46528A166ULL,
		0x0932F9C8156CEE40ULL,
		0xF630FB807FD2AB2AULL,
		0x736B83FECDA51DAFULL
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
		0x502E7DE904D86454ULL,
		0x0196F453F770817AULL,
		0x53D73DAECF948449ULL,
		0x7A3107FEDE1849A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29D96A035040FBB4ULL,
		0x44BBD2B982D46B52ULL,
		0x902C487D4AB8AC49ULL,
		0x6C971C04AD2F4963ULL
	}};
	t = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2EC8A49791FBA263ULL,
		0x0DB57CBA6C0701D3ULL,
		0xE721784BEE8AB3BEULL,
		0x77640EB61A4614B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x63F32671AD21CCC5ULL,
		0x4B6526AFFBF41180ULL,
		0x2D21AA3120ED5931ULL,
		0x74D2218DDCF63CADULL
	}};
	t = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x14BF21CD83A70536ULL,
		0x9012DB6C2F09D217ULL,
		0xE57EE4338C83FA14ULL,
		0x44CC9A973C9E899DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC523870FC5E9B27ULL,
		0x7847AB71560127FDULL,
		0xE65CA231CD14C19FULL,
		0x27141219BD02BD77ULL
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
		0xFC81FBA82BAF5207ULL,
		0x08E8112CEF45DEBFULL,
		0x0D562703C9268CD5ULL,
		0x7B3826B6880A873CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC81FBA82BAF5207ULL,
		0x08E8112CEF45DEBFULL,
		0x0D562703C9268CD5ULL,
		0x7B3826B6880A873CULL
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
		0xC9E6C9CBE673A009ULL,
		0x6036B51B98D52E67ULL,
		0xF1C85A44891D266EULL,
		0x1FAABE9A9806D22FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A89369F0FD3C7F3ULL,
		0xED2E0DD690A7FDDAULL,
		0x4B0B7E7E4351D6A4ULL,
		0x79C44718D5B9E791ULL
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
		0x76C1D451046B8130ULL,
		0x656F77F65F6C4D41ULL,
		0xB009B60BB148C5B1ULL,
		0x704E27134784A744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBDC0E3518619E605ULL,
		0xFEC9F31AF7E6D50EULL,
		0x323D2009AFA6E463ULL,
		0x320AC5093852EA71ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0CF1D739FD33D480ULL,
		0x21A75F7684016B51ULL,
		0xA8E97AB755618415ULL,
		0x50442891873021DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7C726150CE98B0EAULL,
		0x8EE63C9F0C3E887BULL,
		0xC586C91AB40F36F2ULL,
		0x60902D17C2AE1128ULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x38B32CE7491DCAC8ULL,
		0xB7401564B74190A1ULL,
		0x4B8441EA21AB9EFEULL,
		0x3B220B9D6146AD82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x38B32CE7491DCAC8ULL,
		0xB7401564B74190A1ULL,
		0x4B8441EA21AB9EFEULL,
		0x3B220B9D6146AD82ULL
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
		0x5CE838CCAEDD9939ULL,
		0xFEDA95AE9DB506C1ULL,
		0xB05F600CA4DAA5DCULL,
		0x2C6637CAB6DBCA49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x79AA46C5A4DCA7FAULL,
		0x58BE26C3211FA95DULL,
		0xDA7B9D74874F142EULL,
		0x0D1ADD238C3E38D1ULL
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
		0x679F414E0E82A3DEULL,
		0x62B9D25E0C5441B3ULL,
		0x3B68A974BD118A67ULL,
		0x6BE48C5E8A3BAA6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB1D4C85BACEDF96ULL,
		0xA77AB466B144BC9DULL,
		0x5BACD36C463696B0ULL,
		0x79E3F8977DE63DF2ULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD55C45BA32830452ULL,
		0x1CD21FBAFBA35A87ULL,
		0x5CE3FC2352A153D5ULL,
		0x3D85C13E9EF326E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F5F74BE0274D1D9ULL,
		0xC914479DB60ACE27ULL,
		0x71AC96A33EEA1BC1ULL,
		0x4A45D712AC44A414ULL
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
		0x086CD3C83AE694C9ULL,
		0x580B4FE442E53AAEULL,
		0x25BF9EB610728084ULL,
		0x4827193ADB34A804ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x086CD3C83AE694C9ULL,
		0x580B4FE442E53AAEULL,
		0x25BF9EB610728084ULL,
		0x4827193ADB34A804ULL
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
		0xCA613CB3728583DCULL,
		0x317B9D6166E7BB7FULL,
		0xC47E37862C0584E2ULL,
		0x2702445409AA40E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x63E3D7BE480BFAF4ULL,
		0x5A07E2EF363D238DULL,
		0x1EC9A11FE740D0B3ULL,
		0x22CE404EC7A16806ULL
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
		0x899F3813EFB6E1F4ULL,
		0xA078D4A58FAE2247ULL,
		0x7B84F432B23A7168ULL,
		0x0E95F4430B95B90CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBCBC3F5C9D70DE82ULL,
		0x38FA2C3DFFB472CEULL,
		0x3C5C6582CE762D9BULL,
		0x666C4661E7CEC3C4ULL
	}};
	t = -1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8CA580D0529E42DEULL,
		0x53C428B210437F21ULL,
		0x45EAD50BFA137411ULL,
		0x79E3B665A6BA0C0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC97EE6092A41969BULL,
		0x06226C5EFBC7C2ACULL,
		0x7ADDA2C65F22B121ULL,
		0x28C38BB5A5705B30ULL
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
		0xA9F86B0C1E40092CULL,
		0x4209ABAA76908C3AULL,
		0xBC7DE149DD983DBFULL,
		0x5041450F62B35429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA9F86B0C1E40092CULL,
		0x4209ABAA76908C3AULL,
		0xBC7DE149DD983DBFULL,
		0x5041450F62B35429ULL
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
		0x389101724A2395CFULL,
		0xCAE88D7E7A4A5500ULL,
		0x9CA52A504227695BULL,
		0x7D733ED4BB94C339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB595990320D6AAE0ULL,
		0xFBFA2508507B902BULL,
		0xB8C10889F240964CULL,
		0x0F8850ED3A2D3157ULL
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
		0xD3220908D2DE6681ULL,
		0x024A1EBE3CB0A86EULL,
		0x7DEA8C9449BDB758ULL,
		0x48D5E3218566E4FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83F8A64401CA2393ULL,
		0xEB112F4E03E81EBEULL,
		0x5404EBEDD413F125ULL,
		0x38841EB72CA500BEULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x604E92DE512BE448ULL,
		0xB348DFE29BBF9351ULL,
		0x3DC1D25B7F9C22C2ULL,
		0x79F4E5710EAC3CE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCED07D2FE0EEADD3ULL,
		0x4D2F2FEF3F16A62FULL,
		0x865B5FDFA5336C82ULL,
		0x15790B95137DBAB6ULL
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
		0x49B7525121B1E8D7ULL,
		0xDE9097C54C8FFD3FULL,
		0x1DCF801550CEB097ULL,
		0x2251461B91C5D831ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49B7525121B1E8D7ULL,
		0xDE9097C54C8FFD3FULL,
		0x1DCF801550CEB097ULL,
		0x2251461B91C5D831ULL
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
		0xFBCC9954D7AA7E34ULL,
		0xC0EBA41E5561E48EULL,
		0xE2C0EF7028A1E9EEULL,
		0x3F443EB9ADCC3579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x066853FF6AD217A3ULL,
		0xBA4B9472112154DCULL,
		0x4874198D62A86483ULL,
		0x0203AB509B86CEF6ULL
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
		0x5C92F3D27365FAAAULL,
		0x8324EBB7BBEE0C2AULL,
		0x0DFB2F980BBD5DD6ULL,
		0x394547224318ECCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x13F3B5453C2FD873ULL,
		0x6EC7DE87A2E1B3F2ULL,
		0x092FA6F0800D437AULL,
		0x7848AC1679AA869EULL
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
		0x0466B6C91902739CULL,
		0x4CB4525EE3B45A29ULL,
		0xC9486CA32B13BAF1ULL,
		0x2EA6B010C15E330BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7FA9C1B5E6BC19E3ULL,
		0x2198720925FF3550ULL,
		0x345CE23C30D7332DULL,
		0x457FB61B8179FCEDULL
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
		0x07A20D5FE4732AADULL,
		0xFE3A5915E9E6480EULL,
		0x9134014CD7C52EAFULL,
		0x5237CB1D42075A16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x07A20D5FE4732AADULL,
		0xFE3A5915E9E6480EULL,
		0x9134014CD7C52EAFULL,
		0x5237CB1D42075A16ULL
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
		0xA59679BFE1C7265FULL,
		0x0E21E6898C94A1D4ULL,
		0xC83E0959DC56707BULL,
		0x4FE35FA59FFEBD28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F356668EB541A56ULL,
		0x28F3B226654A5C48ULL,
		0x2F28B7F4869F1021ULL,
		0x7D89AC6BE105ABF8ULL
	}};
	t = -1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9CC84E98D98B44AFULL,
		0x3B80B5B9B2393D9AULL,
		0xF79E9164494F0343ULL,
		0x06072D618DAABEDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x935F78C98891A11EULL,
		0x7584D25920BC5611ULL,
		0x8518A14DBC1254D8ULL,
		0x1FD446C08AD925BEULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x87CC3DA9EAFF1CE5ULL,
		0x1FF0D6C3A465C40DULL,
		0x643A18AB9FB29009ULL,
		0x76D56FF4149E7033ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x024C6EBBB45B597CULL,
		0xE56762C450B10022ULL,
		0x5F11D5C24CA4B77BULL,
		0x45A96F7EB3E5A48DULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9DA833CB7CC1EBC0ULL,
		0xDF11A7E1E3DA12A2ULL,
		0xC11BFA44BF4C4265ULL,
		0x21BA2879030E1940ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9DA833CB7CC1EBC0ULL,
		0xDF11A7E1E3DA12A2ULL,
		0xC11BFA44BF4C4265ULL,
		0x21BA2879030E1940ULL
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
		0xA46E3E676185B605ULL,
		0x3A9C2B0B29A8FFF3ULL,
		0x7D42DD62C2F58798ULL,
		0x353F95BACD41FCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x926697A22D45422CULL,
		0x50F9037F5816C477ULL,
		0x53CB06134557B5A6ULL,
		0x46FBDE7632A92E7EULL
	}};
	t = -1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x99ECF6E124CA8C4DULL,
		0xECA92B6A4428ED5AULL,
		0x5724C9DFD7B276C6ULL,
		0x3C11BD71802A55E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E4F94FE06FD0B5EULL,
		0x30F959BF54434A3CULL,
		0xFEF57C799B7228DFULL,
		0x02060305DB4721D3ULL
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
		0xAFDC32A6587966C9ULL,
		0xACEFD88E32C09E72ULL,
		0x48709053E69090EAULL,
		0x24FF0BBA92303463ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x45B4A36ADF980275ULL,
		0xDBB9A47ED70FFE26ULL,
		0xD60A02F8B69725DEULL,
		0x70C9C67F58721988ULL
	}};
	t = -1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8D03405E930734C2ULL,
		0x3B6E4315DAE64AA4ULL,
		0x86302F26DF5F5530ULL,
		0x389D93BB12D89CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D03405E930734C2ULL,
		0x3B6E4315DAE64AA4ULL,
		0x86302F26DF5F5530ULL,
		0x389D93BB12D89CD4ULL
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
		0x17CB588A4F96EFCBULL,
		0x59570AED0B3930FAULL,
		0xB17D73B0BD726E23ULL,
		0x2F36A142D05027C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7DD8824824F4077ULL,
		0x54A469591C63996FULL,
		0xF100BC36DBBE2655ULL,
		0x3232DB86BD131477ULL
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
		0x902B0E6D7BB8B10CULL,
		0x17DA15DE06C7EA78ULL,
		0x386FE41C356A0E07ULL,
		0x505ACD1E19111E44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF684E2E48D5FAF3DULL,
		0x7C22769B8C92ACB9ULL,
		0x829CC855EB3D638EULL,
		0x501B4D9CB27547B7ULL
	}};
	t = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBC5D723661CEC580ULL,
		0x4DC36E4318DC9E7EULL,
		0x307AB49F00FD800EULL,
		0x368714FA1BF63A46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBE7D7A3DB1666EE4ULL,
		0xBB0B24A96B302BF5ULL,
		0xFE50F855713F95F2ULL,
		0x786D834EE2E6A0DEULL
	}};
	t = -1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9EC7DD4A96E4822EULL,
		0x6C551CA8591372BEULL,
		0x258B828F6D8A1E44ULL,
		0x2A2E6EA5F5F8C3BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9EC7DD4A96E4822EULL,
		0x6C551CA8591372BEULL,
		0x258B828F6D8A1E44ULL,
		0x2A2E6EA5F5F8C3BAULL
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
		0xBE7C2F9556896BA9ULL,
		0x0E64C7A94F799E46ULL,
		0x43B362ABF3204EAEULL,
		0x007C09EF4122B157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x52CAEBDB6DDBFB67ULL,
		0xF5EC9011F9002DB6ULL,
		0xAD5686F7EC1E0236ULL,
		0x48292F932B317247ULL
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
		0x25902DA74CFF195DULL,
		0xD6935A8B833C8866ULL,
		0xF08545FD493DC77AULL,
		0x3479E7B515E22EC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01F050DF71ACFAC0ULL,
		0xC43C2FD5AD562437ULL,
		0x0B111EC161B12FA3ULL,
		0x4C9F7166E62CE44EULL
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
		0x95C8A9000C551ABAULL,
		0xFBBC09EA8DDE75FBULL,
		0x3E27DFFBB5EA65C6ULL,
		0x60F4071FF7F1FD95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x42B14E7F96C9770EULL,
		0xD1687B36E0F148A3ULL,
		0x53E3F701D51C3EE4ULL,
		0x26B657502AE52431ULL
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
		0xF2B3DD2F657F38B9ULL,
		0xC41121C4808788CAULL,
		0xEEBBDC847381BE0CULL,
		0x1F9943E496C8C413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2B3DD2F657F38B9ULL,
		0xC41121C4808788CAULL,
		0xEEBBDC847381BE0CULL,
		0x1F9943E496C8C413ULL
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
		0x6024A6E8D1D05FF7ULL,
		0xA7829BFDC3EE4EACULL,
		0x8210184A142CF950ULL,
		0x64333C6F5413A44CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x26E4C31A5F688879ULL,
		0x7AEA579C7EB53F1EULL,
		0x26E3A937CB7F2542ULL,
		0x071092BA91A06DE9ULL
	}};
	t = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x35E9E9EDFE218236ULL,
		0x70059928C78DBD0AULL,
		0xBA811C3B4335B3B5ULL,
		0x7F2E30A48847C66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF1769C10D941273AULL,
		0xA098441FEF7C1077ULL,
		0x45398A883642E82BULL,
		0x064AA0FFB5ACC5A0ULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB1F9A7F359144DBAULL,
		0x57BB2BCDD25A3076ULL,
		0x5A551CC23105600EULL,
		0x5C89357146CB234AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE20D891D7C95CA1AULL,
		0x944116237D991ED1ULL,
		0xB3FEE192B9974FBCULL,
		0x1B19BCC957FCD7CBULL
	}};
	t = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9C303794067F6CEAULL,
		0xD5F615F8502B9871ULL,
		0xB7C28663716D0468ULL,
		0x4FBEDC2F938EE0DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9C303794067F6CEAULL,
		0xD5F615F8502B9871ULL,
		0xB7C28663716D0468ULL,
		0x4FBEDC2F938EE0DFULL
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
		0xDD08FCC47A87E1D5ULL,
		0x318F5085690287D2ULL,
		0xCC0BF3D2F3E2C8EDULL,
		0x7BA9489E644AA727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3D1C76136B2D039DULL,
		0x698928B4B10E35DBULL,
		0x4D8F93F486D12470ULL,
		0x73AC894016F17660ULL
	}};
	t = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x057C9FA3D65BC9C1ULL,
		0x463441BB2E48CAD9ULL,
		0x0B9CFB22E0BC288CULL,
		0x404A6A83BD2F6795ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41EDA959FEF317EFULL,
		0x8B31363ECA4EB7E0ULL,
		0x84510D083C262CEAULL,
		0x3F2B0A1857EDEB25ULL
	}};
	t = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3D7175448783738CULL,
		0x3A2EB97A09D52F02ULL,
		0xB6EE90898200EF58ULL,
		0x11B2B5EA868A5F04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x025964F178C4C08EULL,
		0xFE986441053E6FD3ULL,
		0xF39B79F18AC01F6FULL,
		0x0489C95F953FEB9CULL
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
		0xA172A451BCDE35EEULL,
		0x10CA9AAFD023193FULL,
		0xB17ADBAC05FCA606ULL,
		0x111BE0BBE50C06A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA172A451BCDE35EEULL,
		0x10CA9AAFD023193FULL,
		0xB17ADBAC05FCA606ULL,
		0x111BE0BBE50C06A2ULL
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
		0x67367A3448768BC5ULL,
		0x6BA1A803AE41AB72ULL,
		0xFE94AE144CB0745AULL,
		0x363BBC6D4FE7E910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D4D668E98A43709ULL,
		0x085FBB083F3BE100ULL,
		0x27B4FC1874F26B9DULL,
		0x040EDC78EEB40E38ULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3669CB43FC500CAAULL,
		0x91D965BC4E685641ULL,
		0x3648733A49FB9DFFULL,
		0x43509859ABC3024EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53A4AC3AF38DB5A9ULL,
		0x104D954C911B1F96ULL,
		0x859DB616F90BB1DDULL,
		0x1A1139D486B05159ULL
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
		0x02D436C5B66655DCULL,
		0xB80BBBF9A8BF916FULL,
		0x64E8A78A512B5990ULL,
		0x4337FB25F88024DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC090F4B9C64EAAB4ULL,
		0x26768FC0039ADC65ULL,
		0x350794DA7E997F63ULL,
		0x46E96A7679294A79ULL
	}};
	t = -1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFE2956FFE887F5DEULL,
		0x5FF92800C98B1B7EULL,
		0xA6EDF3AE390251BCULL,
		0x3F4681514AEC355FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFE2956FFE887F5DEULL,
		0x5FF92800C98B1B7EULL,
		0xA6EDF3AE390251BCULL,
		0x3F4681514AEC355FULL
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
		0xABDD4BADF9C66707ULL,
		0x7AAB506B44F521E1ULL,
		0x8781279190CB1CA0ULL,
		0x6AAB9706AB285AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA61A0A0D7B20441ULL,
		0xA331750666511777ULL,
		0xA566DC54C4A05FF1ULL,
		0x66CA00276DAFC233ULL
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
		0x73DD36EE61BD763DULL,
		0xA3FCADF323998DB3ULL,
		0x0D0A9DC181284F11ULL,
		0x45A7566B6C1EBA61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9992966A2D255267ULL,
		0xD96E5C96BC8F46C0ULL,
		0xADB976FA2574DFEFULL,
		0x7BFE18494A6E5690ULL
	}};
	t = -1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x89B9C27EE782AB11ULL,
		0x35173CE2716B414EULL,
		0xCA0F7F326D6E24B8ULL,
		0x61AC1B275FDE3597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA491606A462F8048ULL,
		0x931D7F01918261DEULL,
		0xF4C06FC834A53521ULL,
		0x0ACBBBB5F787B988ULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x72C71794E522C860ULL,
		0x5CE9B37751B39E31ULL,
		0x4155D1139EADCDB3ULL,
		0x646F0D72248AE815ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x72C71794E522C860ULL,
		0x5CE9B37751B39E31ULL,
		0x4155D1139EADCDB3ULL,
		0x646F0D72248AE815ULL
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
		0x4B9CF90DDB1AC3F3ULL,
		0xAC201AE551ECB300ULL,
		0x99EFDC40E4D582CFULL,
		0x131425F3647B4FFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9E3C0B551CFD62B5ULL,
		0xBEABE58CA4E63466ULL,
		0x63330C39890CD5ABULL,
		0x4DF28A24ABE1F149ULL
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
		0x98698638C85AAB70ULL,
		0xE2BC998C10165EDBULL,
		0x019C668C6090F945ULL,
		0x33E6D4C5C90AF4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x581CEFC3E5C4953BULL,
		0x07986A80D05DF22CULL,
		0xF430834AE50873F7ULL,
		0x6F1928755928B16AULL
	}};
	t = -1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x604644C436BFED03ULL,
		0xBDA9AAA359FB6B54ULL,
		0xB83063F31EC0BC9EULL,
		0x6A6E3213A9DC537AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6525803BBC4542DFULL,
		0x8ADB40B22846E15CULL,
		0x3BD6F94D34853B0FULL,
		0x45E344D3E8D2AE65ULL
	}};
	t = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x8F05331C06A9E81DULL,
		0xD1AD0A5F206A62B2ULL,
		0x196AD2E2BD7E22FCULL,
		0x3B7A1AD3F1A69973ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8F05331C06A9E81DULL,
		0xD1AD0A5F206A62B2ULL,
		0x196AD2E2BD7E22FCULL,
		0x3B7A1AD3F1A69973ULL
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
		0xB52103F7D04282BEULL,
		0xF353AD917D59D7F2ULL,
		0x4EF5948544E81198ULL,
		0x5C609EFCB85D84D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D98E8E56E0CE777ULL,
		0xB059EAE97DB3F4B8ULL,
		0x647C06F91802BCFAULL,
		0x197B8126EC0AFDAEULL
	}};
	t = 1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5B5B0D2E943C4FF0ULL,
		0x233F17986100790DULL,
		0xB7442A300EFD272BULL,
		0x020A7C474DDAD3FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x72B464B231534604ULL,
		0x9D3BE61BEE886A2EULL,
		0x45C9DEDCA8A16C39ULL,
		0x4E93D40E7F4BD6A4ULL
	}};
	t = -1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF4054CD5B7FC40FCULL,
		0xAB0D9BA0AAC4EFA5ULL,
		0x4BD24A429D13BE8CULL,
		0x5C78982B8FABF136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3CD9F12456355AEEULL,
		0x8A01EB8F40DAB658ULL,
		0x2258939A9650C7C0ULL,
		0x6D111AF2C9CA10A5ULL
	}};
	t = -1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x022D9B71BD76792EULL,
		0xF7AC98AB8FC773F1ULL,
		0xD79D8BAB36C833B7ULL,
		0x2ABCD486BD2ED299ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x022D9B71BD76792EULL,
		0xF7AC98AB8FC773F1ULL,
		0xD79D8BAB36C833B7ULL,
		0x2ABCD486BD2ED299ULL
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
		0xBDA992154D0C0D2EULL,
		0x9BDA4767E3E72E45ULL,
		0xDBFCAF671D46B2E9ULL,
		0x7007DCC625BA22E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4716FCEF6E900E9BULL,
		0xF8E8EDF3B25419A8ULL,
		0x8F69E9943FFB7EEFULL,
		0x65BD2B4E4891D9A3ULL
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
		0x052CE6F22DA7885FULL,
		0x1BF3D3702A7C740CULL,
		0x94B3C260DF27E633ULL,
		0x5AFE97C5A24AE1FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC1AC870972EB5E1BULL,
		0x4DB99A386DFBEF3EULL,
		0x8C5ED33181D0A982ULL,
		0x10F87FBFD8A56694ULL
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
		0xEBD1F8D7AA3FDE34ULL,
		0x063207657B2F6FB9ULL,
		0x23E4D9511479FF05ULL,
		0x0921109D4D0E82A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F4273C51F7503BCULL,
		0x8CE49CE9BB8D9754ULL,
		0xEDABACC1F7898312ULL,
		0x4CDE66954DAEBE23ULL
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
		0x9BE9F2257AC5B582ULL,
		0xB0DD6EE915CB9990ULL,
		0x0F791B1E4448E565ULL,
		0x3A262FF6BE0607E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9BE9F2257AC5B582ULL,
		0xB0DD6EE915CB9990ULL,
		0x0F791B1E4448E565ULL,
		0x3A262FF6BE0607E1ULL
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
		0x05D3FA1EF7032CACULL,
		0xFB8BC50605AA9FFCULL,
		0xA841E0B9CCCB6DE0ULL,
		0x5AB8647E1BBD167BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x916CE0AD5D91E223ULL,
		0x60DB7B00737F205AULL,
		0xB57E76A9E2CAA11EULL,
		0x34734DF69138DA03ULL
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
		0x60BFE5A7A7AFD6C5ULL,
		0x02CF77305FB6EF39ULL,
		0x6D9962049AB58BCBULL,
		0x430D70A1549D35BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x968F29B52E7C2912ULL,
		0xB7B76438D69DC3A2ULL,
		0x60AA25F4BC0E631BULL,
		0x17796F2E1239A9ECULL
	}};
	t = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5D020C98E3D6238CULL,
		0x2DE42F4FE2F220FEULL,
		0x54264913486EBE1BULL,
		0x5011D276A7F4F4E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBA18B661E4B3372BULL,
		0x5C340F7D0BD781EDULL,
		0x32E845548B5621DAULL,
		0x3B60925ED1F25594ULL
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
		0xA253C9B509A135F6ULL,
		0x26705442F13D3302ULL,
		0x610A2F20ACF98F41ULL,
		0x6D8E5EA7E9797A3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA253C9B509A135F6ULL,
		0x26705442F13D3302ULL,
		0x610A2F20ACF98F41ULL,
		0x6D8E5EA7E9797A3DULL
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
		0x6BD11870BDF63DC8ULL,
		0x159F90D6C9EBD494ULL,
		0xE8E61E5AC80D6F5CULL,
		0x018565FA313EA502ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA78D87293D595C4BULL,
		0x31D9BD58851E8C8FULL,
		0x9E2631D1A225F902ULL,
		0x38B40A3A0438AB47ULL
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
		0x03193DBA3D6DEB8DULL,
		0x70F5BFA8F6536F2FULL,
		0xF9FAAF1319B3A4DBULL,
		0x4207B4D9AA487BEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3312689AC5BA3DF1ULL,
		0xF32E89ABB709CF06ULL,
		0x7775D7CF76AAEB9EULL,
		0x3A789B43213348DBULL
	}};
	t = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0640A5E1F5084D78ULL,
		0xC06A784E9674A5B1ULL,
		0xBFEA427769E270B5ULL,
		0x60C223C3FAE417CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2BA7FB9C16486317ULL,
		0xBC0898F6B0F8BE0DULL,
		0xECDB4BC9FD49952EULL,
		0x2F042EFEB597C00DULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x31B86DD78214F5D9ULL,
		0xABC210788D965195ULL,
		0x8BF51ABDB05ABF11ULL,
		0x6AD63197B99EE0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x31B86DD78214F5D9ULL,
		0xABC210788D965195ULL,
		0x8BF51ABDB05ABF11ULL,
		0x6AD63197B99EE0F7ULL
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
		0x5940567BC361FDD7ULL,
		0x58D029A41F191E3BULL,
		0xC892AFAE6D68A360ULL,
		0x181B0864E16B64ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE3CAB51FE1CD951DULL,
		0x15848025E5108D9CULL,
		0x614054D5FE4A6EC2ULL,
		0x0C93D4608959AF70ULL
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
		0x5B8C3E72F3D2FD41ULL,
		0xB5C1CD364349BEEFULL,
		0x71795ED8F115A051ULL,
		0x2842884F0E0DC852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59AA69411DE974EAULL,
		0x5905D86A0F09373DULL,
		0x2D18394BE4DFDA38ULL,
		0x454BE6B01DDF5540ULL
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
		0xD322DA9A9B7568C0ULL,
		0x7B41DA332B6F6602ULL,
		0x48E22E9912D8B12FULL,
		0x77C2B1BD434B114EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4CA4215ECA7D1B19ULL,
		0xFEDE17B7B2A08146ULL,
		0xFFB7E7098DB37553ULL,
		0x12AAD13AED7C5A17ULL
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
		0x007C55EB159B8FBBULL,
		0xCB666BAC8650CDFDULL,
		0xFE867A28E18B8BCEULL,
		0x009F3A8E655C843EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x007C55EB159B8FBBULL,
		0xCB666BAC8650CDFDULL,
		0xFE867A28E18B8BCEULL,
		0x009F3A8E655C843EULL
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
		0x18F65DFD7060CF0FULL,
		0x2F8972E5F05D180BULL,
		0xFFE981776FFD4451ULL,
		0x3F06D0A61C7E6F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2D1532384FEEA348ULL,
		0x071FEEF2C7633951ULL,
		0x5C961F7E9085E857ULL,
		0x0EEB383C3A7898B8ULL
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
		0xAC3BBC365754070BULL,
		0xB882DF3DA8D9E845ULL,
		0xDFF3058A1F858597ULL,
		0x05AFE1B42D71A76BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x93DA6892F1609BC5ULL,
		0xC0BA7F5CB46EBBAEULL,
		0xC39F155651220A28ULL,
		0x7B73E8DAB1229251ULL
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
		0x59305A6945913893ULL,
		0x49644EA4807B2C62ULL,
		0x3207E1C6C275DDD4ULL,
		0x6866A26FCABB09BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3956E43C4DF220D0ULL,
		0xCFE6B32E077D9744ULL,
		0x6C0D4898A143FDAFULL,
		0x57A1FBB7E58E5DB5ULL
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
		0xFBA476B97B97DB64ULL,
		0xC12DE1249F2B1E0AULL,
		0xA8C010DBA585E0FCULL,
		0x1B9DB8E3F82175C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBA476B97B97DB64ULL,
		0xC12DE1249F2B1E0AULL,
		0xA8C010DBA585E0FCULL,
		0x1B9DB8E3F82175C8ULL
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
		0xEA75879AD194AE8CULL,
		0x84E83AD2273E46A4ULL,
		0xB18AA5CFC248D3A1ULL,
		0x609D3817DE773AA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3D27EC244EB2DBBAULL,
		0x09404555F162999AULL,
		0x49F18EC2E6373264ULL,
		0x4D2B9D494DCA3822ULL
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
		0x1FD0582E244EF9F1ULL,
		0xEF46CE7457F3AEC2ULL,
		0xD0DECCA901E15DCAULL,
		0x48B43B9D7BB126D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x514336F35126B922ULL,
		0xE8A6468D1AB6CFC4ULL,
		0x0DE32AD511C4F752ULL,
		0x352312DCB21BB826ULL
	}};
	t = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4D7344F51C08D2B6ULL,
		0x962AD10E4F0F61A8ULL,
		0xC55D8FF038739C4EULL,
		0x59CC5200A3CFBE76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF4F06F2AD273A303ULL,
		0xCD934F858F6F0C4EULL,
		0xFB2D01FA8BFC8B4CULL,
		0x23DDFC6BBAC170A0ULL
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
		0xF316AB5D3DF6BD0AULL,
		0x59E4FCBF0340E88EULL,
		0x397EB31187D56211ULL,
		0x27FFAB94C8C7952CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF316AB5D3DF6BD0AULL,
		0x59E4FCBF0340E88EULL,
		0x397EB31187D56211ULL,
		0x27FFAB94C8C7952CULL
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
		0xC1E4D38A8FCACB85ULL,
		0xF67FCA254DFC56C7ULL,
		0xF1FDD0C5F9D15818ULL,
		0x41D93BD7A5C92420ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41D7D0EBB8E1DE68ULL,
		0x249D38E4D699B33AULL,
		0xB59D9A6E3ACA9D76ULL,
		0x66E4BBED2E99A2B3ULL
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
		0xFBFD8B7E0022A286ULL,
		0x13EE1CBC4ACDA1B1ULL,
		0x879D0DB010C21308ULL,
		0x7D9FA82FB7ECFA43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC9203B66F7A6DBACULL,
		0xBB695AA4F932B8FEULL,
		0xDFD91696206234E5ULL,
		0x13F231E4020223A7ULL
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
		0x9AE2C082B70914FFULL,
		0x4C7D519AEA54C5B8ULL,
		0x40FB5BB8C05F7226ULL,
		0x0A6BD5D6B8CB7B0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x13B65CDCC0896465ULL,
		0x53EBEB6A69072315ULL,
		0x655FC77D4C0C83EDULL,
		0x28760A76702A2B47ULL
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
		0x364F59F3786F9794ULL,
		0x0718843357B049D6ULL,
		0x38F75727E1B05C81ULL,
		0x420255ED81CFB7D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x364F59F3786F9794ULL,
		0x0718843357B049D6ULL,
		0x38F75727E1B05C81ULL,
		0x420255ED81CFB7D2ULL
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
		0x5AB1263837775BD5ULL,
		0x6BAF179B5803372DULL,
		0x7C817ACA7AF26A26ULL,
		0x4F8E962424423EF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4369283E0BCA67E7ULL,
		0x0B8B6CA208CE8A58ULL,
		0x115FAB7C395FF7EAULL,
		0x20F62B3A80DC26ECULL
	}};
	t = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x72569657A75F053BULL,
		0x81B33F6AF5C819F1ULL,
		0xC5A67636A81801F2ULL,
		0x7F0AA58A2A0093FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAA1E4A25B751FB8DULL,
		0xFA54FD05F63C3707ULL,
		0x8DB4E039613058C4ULL,
		0x6D2CF718C1671126ULL
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
		0x8E9B9FE5D9625D64ULL,
		0x5464700876979D6EULL,
		0x23E64753A9B282A6ULL,
		0x20D4470F45DB0E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7A1886768A86A5CAULL,
		0x63198C4D86433D91ULL,
		0x5154D4CE5A594B81ULL,
		0x03F1DF996BB847AFULL
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
		0x38420C01819330FFULL,
		0xED794A09F19EC562ULL,
		0x5688228FB8EEF565ULL,
		0x336AFB965EE54067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x38420C01819330FFULL,
		0xED794A09F19EC562ULL,
		0x5688228FB8EEF565ULL,
		0x336AFB965EE54067ULL
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
		0xB4C68BC76D54333CULL,
		0xF96ECA15D9C20D6EULL,
		0xA42A42FFDD8650F1ULL,
		0x61FDB393DF281A29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x64F1EDF1BA0ACE3AULL,
		0x42DEDE48E0663915ULL,
		0xC3C9BDF9FABA4F2DULL,
		0x7466B8C0000E55CDULL
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
		0xA3A1BA2B809148A8ULL,
		0x4FBA584CF2754066ULL,
		0xA52D76DD5A976CD7ULL,
		0x6177D6DA1AE957A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x68110A12A8D03083ULL,
		0x6D9C4C714E98D7E9ULL,
		0xF7FE7A5718C359BCULL,
		0x437EFAAD6CB3FD1FULL
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
		0xCE4EC5AB3C0A923BULL,
		0x52B389CB4F9D3DEAULL,
		0x65EAE4345F5B297FULL,
		0x14DC8A56C9DEBF0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAC7FEE3CEE2D2F08ULL,
		0x34EF8B21FEDB58D5ULL,
		0xE7558A1A601EBD36ULL,
		0x07C778CF456C7D18ULL
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
		0x22EFB06FA842E38FULL,
		0xCBF9FE45B5522F12ULL,
		0x57A5439FB399AD7FULL,
		0x2232065969283C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x22EFB06FA842E38FULL,
		0xCBF9FE45B5522F12ULL,
		0x57A5439FB399AD7FULL,
		0x2232065969283C1BULL
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
		0xCD05334EF6673094ULL,
		0x9643476ECA63F767ULL,
		0x40ADD78C836EF98BULL,
		0x6B4C19A9680314EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F3509C7E1409F38ULL,
		0xAAB0EEC1D56B318AULL,
		0x5F3D816118C80F3AULL,
		0x00D72A8EF7851F1CULL
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
		0xB6098151DA9D1148ULL,
		0x3D1AC846ABBC8B4BULL,
		0xAAEBE63FD1D1B25EULL,
		0x5A07D0148CFC56B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E3BBBD415204961ULL,
		0x8A74207445827600ULL,
		0xDDD70EC99611BE9AULL,
		0x6449509E258EDBB7ULL
	}};
	t = -1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x954573B57B349EA8ULL,
		0x77B441CEDEF74BB6ULL,
		0xD5C5227F9F46969AULL,
		0x2CA65ABCCC26D1D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F2D77D00DBD5EA8ULL,
		0xC4092A6459273F48ULL,
		0xAAC0A64551ADCF9AULL,
		0x535FB16566E16F2FULL
	}};
	t = -1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x10DBA450A173EF57ULL,
		0x86DF1B3A866C7A3EULL,
		0x82BED757C4E7CCB0ULL,
		0x1354B43378380E69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x10DBA450A173EF57ULL,
		0x86DF1B3A866C7A3EULL,
		0x82BED757C4E7CCB0ULL,
		0x1354B43378380E69ULL
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
		0x094A1AFC375B133DULL,
		0x08C97A3B2982B4BEULL,
		0xE9450DC3650A5DDEULL,
		0x6FCEF41BE171B3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7019765187456979ULL,
		0xD3A18CAA7B478DFFULL,
		0xC360AC92A4F7D5D6ULL,
		0x11C742022EAD99BBULL
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
		0x3C69DC6ED2DF235FULL,
		0xD0A8454F70C7276EULL,
		0x2363584C8EEC0327ULL,
		0x7E6DC74B526B2485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F1110063A2B7D7EULL,
		0x16B56F4F0E58DC0BULL,
		0xE852B5C37352CBA1ULL,
		0x4CFDD02F1A97D101ULL
	}};
	t = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD8B2AA88224DD776ULL,
		0x747C92336E2E156DULL,
		0xA84FB64155E03B1AULL,
		0x5E503628B298BC69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9BEA32A010BF4B36ULL,
		0x298B28BFCB8D23CBULL,
		0xEFD06AE637785C13ULL,
		0x51D5E46D40D2D642ULL
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
		0x1F1C01B892553C44ULL,
		0xDA381048DF2DA4D1ULL,
		0xAA836E4E32D1E924ULL,
		0x0541EA343F8D5486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F1C01B892553C44ULL,
		0xDA381048DF2DA4D1ULL,
		0xAA836E4E32D1E924ULL,
		0x0541EA343F8D5486ULL
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
		0x6A3B729B9069798AULL,
		0x8CC412422B24C8D2ULL,
		0x7A73FE507592905FULL,
		0x0E3A6E0BACBAF68EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x492B024496F13CE7ULL,
		0x3F887FB1AB276110ULL,
		0x10AA4353F8B2CDB3ULL,
		0x6EBBC20C011CC8FDULL
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
		0x050B40A2C36B89C0ULL,
		0xE6876A8F76D92801ULL,
		0xDE1F463D21A04EF7ULL,
		0x5EF4FB42488B8A82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D95FBA63C94DEDCULL,
		0x30E17CE475188804ULL,
		0x2ECFBA42A3C2A2DFULL,
		0x5FEE8FC1C505EA9CULL
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
		0x8A69E66B71C64449ULL,
		0x3D10FC2E7F408786ULL,
		0x8BCD4D92A8D1C791ULL,
		0x2636B5185BABF26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCCA5E82C9BABD5CFULL,
		0xBB0B2198743538C7ULL,
		0xD89AAFDB32BCBB53ULL,
		0x197BA68E6D2F431FULL
	}};
	t = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2FF47C07E5B18132ULL,
		0x1F9AB554B86584C0ULL,
		0x0EBEA284EB8E35D9ULL,
		0x0F55A609CC049695ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2FF47C07E5B18132ULL,
		0x1F9AB554B86584C0ULL,
		0x0EBEA284EB8E35D9ULL,
		0x0F55A609CC049695ULL
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
		0xBAF1B85BE8E26B67ULL,
		0x2C1E4AA56A96B114ULL,
		0x77FC668D890AE58CULL,
		0x57FEFD90BD1C640CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2EC493E36BB6C00CULL,
		0x89C540E8CAE3BF69ULL,
		0xE8BFF8C715B321C6ULL,
		0x03CE915F784952EFULL
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
		0xA6E0D9A4F049E1B8ULL,
		0x95D3D23A2A6D428FULL,
		0x470E4F193DBC4BA2ULL,
		0x5D93D520D1CDAD79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDCFA4FF911362AF3ULL,
		0x00C90193DEAD2B50ULL,
		0x26B47016FBE0F6DAULL,
		0x15BA9C2B8EB14501ULL
	}};
	t = 1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF7D0E8B80F15302EULL,
		0x6ACEF54BF3D38607ULL,
		0x7D716F195C88A748ULL,
		0x3A51E86AD283CE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53FBCA207345A7EAULL,
		0xC99CBD4C0A80C9D7ULL,
		0x8D2A64D2DCCDB119ULL,
		0x278C52E5A111B138ULL
	}};
	t = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD1FFFAD3B78DFEE3ULL,
		0xFE06DA66F9E4CB4EULL,
		0x344DE5607FA894B2ULL,
		0x65FA5AB3768CA5E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD1FFFAD3B78DFEE3ULL,
		0xFE06DA66F9E4CB4EULL,
		0x344DE5607FA894B2ULL,
		0x65FA5AB3768CA5E8ULL
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
		0x608AE5E192A0D868ULL,
		0xFD0EA158C0476D77ULL,
		0xCF702B367F98C9C1ULL,
		0x2B9E46647C6837D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5ECF72D287DA61ADULL,
		0x153BC8CE1746BB91ULL,
		0x520DB9593E2F929FULL,
		0x658F9595D46CAD0CULL
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
		0xA6E0FD03AA301099ULL,
		0x57C9CA418A30A8C6ULL,
		0xAD32ED17740C0458ULL,
		0x039A986EB5D00B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D37E5DE47FDD303ULL,
		0x8EF8B7231BADB7C5ULL,
		0x2855E45DE78B4CF6ULL,
		0x3644248ADB91C7E8ULL
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
		0x6C700F68D12735BDULL,
		0xB18BC231D4E135F3ULL,
		0xB95F40D3F1C1F205ULL,
		0x4DDF728CE4EA67CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5AE40675945E457FULL,
		0x368E208BDE657CC2ULL,
		0x0C447382EFEA3329ULL,
		0x44CEBDAAB2D3D4ABULL
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
		0x7570A94792F695D7ULL,
		0xD0896931874543DBULL,
		0x3F9A47A18A8C198CULL,
		0x2CE9BC990AAC5143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7570A94792F695D7ULL,
		0xD0896931874543DBULL,
		0x3F9A47A18A8C198CULL,
		0x2CE9BC990AAC5143ULL
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
		0x44971B78DFE33FC6ULL,
		0x24E20A7357863E76ULL,
		0xDF7617A9DF11FA92ULL,
		0x0A0827957E7E651CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD3BD3773E839996EULL,
		0x8B3BAFBB3B44A11DULL,
		0xDBA25C8C0181CAA2ULL,
		0x1A404B2FA8543702ULL
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
		0x9E687AD290437A50ULL,
		0x49CB4BC1EA50D9B2ULL,
		0x8EF4A8897C3EF47CULL,
		0x3F2C18CB06972252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6339D52D742AD9CAULL,
		0x87BE5B3D188FF31FULL,
		0x9290651C0F66E8ABULL,
		0x3125FE0A2387ECC8ULL
	}};
	t = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEE02EF29DB9A4C56ULL,
		0xD8B448E0D0CC0B9EULL,
		0x183BE8899E0A64FDULL,
		0x2DC104CBD30F417BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD29505E567281C67ULL,
		0x99B34BC32E5A222DULL,
		0xFA1DA0BE592103F3ULL,
		0x37E57E1B40F26B24ULL
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
		0x10E2BEF908B22E29ULL,
		0xCAB2EBA8BA55A0A8ULL,
		0xA273FC76C5A5EB3CULL,
		0x662DD3551D8E807EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x10E2BEF908B22E29ULL,
		0xCAB2EBA8BA55A0A8ULL,
		0xA273FC76C5A5EB3CULL,
		0x662DD3551D8E807EULL
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
		0x141B4EC4A3DE1735ULL,
		0x78C75119EF4B4533ULL,
		0xB240F010435658A2ULL,
		0x5A360942617C93EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6D5AE325D71B1692ULL,
		0xFA29DCFEDECE9C74ULL,
		0x4137029EA4FF2FACULL,
		0x62225DE71C2DF29BULL
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
		0xE2F73455310CA363ULL,
		0x885207BDE07816C5ULL,
		0x65DC057DDDD77EDFULL,
		0x0E0DBCCE387AA339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA1C5DA2C9E392A7ULL,
		0x4E01B3EA3ADACB73ULL,
		0xE01B39D77E7C9BBDULL,
		0x0E29C84298795BE2ULL
	}};
	t = -1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFBC1447C553AB139ULL,
		0xF3695D3E6C8BDF73ULL,
		0x24A00702652995AAULL,
		0x7D29E1C19A07BFF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBEC30554447C90E8ULL,
		0x577D17CC11D87DB3ULL,
		0x543D2E10C390A791ULL,
		0x2F26B3D186CABADEULL
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
		0xD5039F4D7128875FULL,
		0xE4C22F7FBABD04CAULL,
		0xA0DE85069493336EULL,
		0x5CBF7A83D201B442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5039F4D7128875FULL,
		0xE4C22F7FBABD04CAULL,
		0xA0DE85069493336EULL,
		0x5CBF7A83D201B442ULL
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
		0xE82010EDCCD5055AULL,
		0x8A6F83A5FE016E6FULL,
		0xD8298B2534417BB7ULL,
		0x0C6D045A70A17874ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4051505D4135F869ULL,
		0xE5DB81731C2F9303ULL,
		0x1BCF609E7280DF87ULL,
		0x2B565D21C3763433ULL
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
		0x87877B02F738D082ULL,
		0xD37627FE6C143548ULL,
		0x3C31B96097B012ECULL,
		0x18CA329C22541075ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x68D98B2DA32CCF85ULL,
		0xF5454ADCFCB878B2ULL,
		0x9AF76C25E0AA1113ULL,
		0x3AAC634338EDC329ULL
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
		0x8D4828CF6746F186ULL,
		0x966B503742BDDD71ULL,
		0xFCEAA194CF68A4C5ULL,
		0x18E6A51A3FDA4C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBB79F1C6E55046C7ULL,
		0xB4334661521F67BEULL,
		0x8ABECA36E76AB4B6ULL,
		0x5D9BF43FBD247C76ULL
	}};
	t = -1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x92D2AB75752AAB2AULL,
		0x26CD7AD16F5AF137ULL,
		0x6D30688606F5AD32ULL,
		0x4B001DEBAF52DF0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x92D2AB75752AAB2AULL,
		0x26CD7AD16F5AF137ULL,
		0x6D30688606F5AD32ULL,
		0x4B001DEBAF52DF0AULL
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
		0x958A13A6A333663FULL,
		0x761C749E2BC938A3ULL,
		0xAFD61AC04AF185EEULL,
		0x674528C830337A32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4CC668805F2FB4EAULL,
		0x5F79A2BB43F154CFULL,
		0x8E0385A4A3030CA6ULL,
		0x514EBC0DD0765BDCULL
	}};
	t = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x95500DEECEFBADDFULL,
		0x0B2572CFC5F0CB2DULL,
		0xD2A1B413AC97616EULL,
		0x6938313751E16B80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5E439667D9290C5ULL,
		0xA20A87EA4D0690BFULL,
		0xCB9B0E0CB511289BULL,
		0x434460E98ACD2C1BULL
	}};
	t = 1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9FDB55062782BC83ULL,
		0x78B763F93C126F6BULL,
		0x65CBED6625F54B61ULL,
		0x0E3C4254DD706587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E1A78C751C3115FULL,
		0xDFB9ACA15EF9DFC2ULL,
		0xE85B4BB5A9778E5EULL,
		0x5AAE055409A870F0ULL
	}};
	t = -1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFCBA8816550AA02CULL,
		0x2587B5DD41947DDAULL,
		0x0AF679AFCA308C63ULL,
		0x3C87A902699EA350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFCBA8816550AA02CULL,
		0x2587B5DD41947DDAULL,
		0x0AF679AFCA308C63ULL,
		0x3C87A902699EA350ULL
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
		0x4DC355E459008E59ULL,
		0x1E9809F3B712B2D6ULL,
		0x047206F7DEF3295EULL,
		0x090D41A730D4847BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x95BDD679A87E4913ULL,
		0x237516FFE85A7BA6ULL,
		0xBE700CB75DCA6DE6ULL,
		0x23923F83FEF23BAAULL
	}};
	t = -1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE82FF755EF1107BBULL,
		0xC4738B7B7747D940ULL,
		0xDDAC81C17947A6B9ULL,
		0x75A42ED744E85FADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x026004DF5BF26218ULL,
		0xA996EDF1E617291BULL,
		0xA43E749AFF96D84AULL,
		0x025D4B76628630BAULL
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
		0xC23F64221DD2BAFBULL,
		0xE714301EFC7D6051ULL,
		0x37F53813992BD707ULL,
		0x25A0601033FF313AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD837938DF3FD76CULL,
		0x7FD3B8C1E99CEF35ULL,
		0x94D17CD2DDD579BDULL,
		0x2C4ACF0D0A082795ULL
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
		0x1E731CD31D934BB5ULL,
		0xF785D9BA7AE32FCAULL,
		0x513D5DB4CD446BEAULL,
		0x14D98314C3840916ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E731CD31D934BB5ULL,
		0xF785D9BA7AE32FCAULL,
		0x513D5DB4CD446BEAULL,
		0x14D98314C3840916ULL
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
		0x4A2183EF10CE1215ULL,
		0x102DBEA06214F0CDULL,
		0x28526188BD27B2C7ULL,
		0x44754F37D5F7A293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8A56D05435C414BFULL,
		0xD184E8D04CAC21DDULL,
		0xB205DC6705080F31ULL,
		0x342ECE5265ED1BE7ULL
	}};
	t = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDCECE7DB43BEB982ULL,
		0x7AD50C4840BEAEE6ULL,
		0x1E7490CA4EA70EC6ULL,
		0x2FFDDE1D4AC1CDF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5814C81BEE8AE82EULL,
		0xCF77CC39D33DB00EULL,
		0xAB2F6B6C096CF36CULL,
		0x58C137C162B1B0BAULL
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
		0xFE39EBC609748D40ULL,
		0xE218FEBFA3D99BF3ULL,
		0x8B147ED8ECC40CBAULL,
		0x0518F4A496B54ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x05A401A73A3AAF6EULL,
		0x58DC40A806A9BAEDULL,
		0x10F5748F5B158439ULL,
		0x5F0593D1AD20F2BEULL
	}};
	t = -1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x558158DED17A02ECULL,
		0xA48D28D84CE73E7FULL,
		0x28CA80A61703CA7EULL,
		0x1FBE0CA2BC62D76CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x558158DED17A02ECULL,
		0xA48D28D84CE73E7FULL,
		0x28CA80A61703CA7EULL,
		0x1FBE0CA2BC62D76CULL
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
		0xCBCEC2C792691004ULL,
		0x680DC71A5A66EFCAULL,
		0xB45D5D064C5C95C0ULL,
		0x30CD5A9CC1CC58FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEE95AB17210774BULL,
		0xF25C55FED5D61BA7ULL,
		0xC44215B22497C416ULL,
		0x30D5C7E801EE0BD7ULL
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
		0xD6C0587C377C8227ULL,
		0x6445D379168EE86CULL,
		0x444CCBB327A267C9ULL,
		0x4404C94944B85828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCC013F04944F07CCULL,
		0xED3821C1E6CF0A9CULL,
		0x39594F45FBF9087FULL,
		0x681CB607F0847606ULL
	}};
	t = -1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2C0BE1666D415AA5ULL,
		0x88682A91E42B434EULL,
		0x40822022197A3EDAULL,
		0x7D77D814EB7DC9E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB9C9D541909AFEB8ULL,
		0x7C4B2AC6A2BFCE1CULL,
		0x2234984CACF91E31ULL,
		0x628E0344B6E2246FULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD55B6E4BB7F524D4ULL,
		0x2C1EB8A9DA27E450ULL,
		0x4EC6D8921CA28182ULL,
		0x5FCC461EBA9D159EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD55B6E4BB7F524D4ULL,
		0x2C1EB8A9DA27E450ULL,
		0x4EC6D8921CA28182ULL,
		0x5FCC461EBA9D159EULL
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
		0xE753352E9B291799ULL,
		0x74278EE580DEB018ULL,
		0x8BCDA6CC62AF6B4FULL,
		0x15AB73CACA9A34CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B945A1F75CCDA8FULL,
		0x2C4EB7B18369EC6FULL,
		0x6FF3BE67B66E1B2BULL,
		0x1602819FA1A0F3BAULL
	}};
	t = -1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2F6F20EA4DEC49A9ULL,
		0x6F6FA0D6F15E2E9DULL,
		0x7B9D1E3563014761ULL,
		0x58BEB30F9EB8752CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x524403B1DA48C221ULL,
		0x42D65659A27EBC9AULL,
		0x970B241E16EF7674ULL,
		0x1126FC42EDAE63BFULL
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
		0x798B83FC50D14D0DULL,
		0x0A781F5792328EC0ULL,
		0x42404DDC77FF47ECULL,
		0x6B55C4CEAF0D8681ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6BE0539A61EC58EDULL,
		0x80E0DD60A48BCA56ULL,
		0x4FDAB0C544850F2BULL,
		0x447636E6CECA9A7EULL
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
		0x8E17FFBA16A0EBBEULL,
		0xF44C267611E57782ULL,
		0x84048AA140201872ULL,
		0x72E5780D0AE8E4F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8E17FFBA16A0EBBEULL,
		0xF44C267611E57782ULL,
		0x84048AA140201872ULL,
		0x72E5780D0AE8E4F8ULL
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
		0x37A784F804ECF4FCULL,
		0x093D8CE695DA31F9ULL,
		0xE5F9EA356E5654D5ULL,
		0x708C0631DD6CDEA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFB5044E50C7B1B53ULL,
		0x21B5845FBB7B5A7FULL,
		0x21FD673B9F30CCC0ULL,
		0x2A3F857254B59FFAULL
	}};
	t = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x342FE9A5BA9F99C1ULL,
		0x34572BFD143C1FA5ULL,
		0xEBA6EF1C42E7063DULL,
		0x1FBBE50196607CEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D0886E47DA875FCULL,
		0x5902445A617CA05DULL,
		0x7ADB6B3383DDA93DULL,
		0x10C75A3E2E8F56B2ULL
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
		0x5AEB61D00729DBC7ULL,
		0x88C98581623B64EBULL,
		0x113403B0C0F3C219ULL,
		0x2D12E6DA7587134DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC260B02D2BB97A6DULL,
		0x18A9DB019CAF7232ULL,
		0xB29872B52C81E451ULL,
		0x30D8B4322A5F63C9ULL
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
		0xD7C0A59290937983ULL,
		0x2DAD861106E2529AULL,
		0xD1E30C3B404C6C60ULL,
		0x1163CD2523670CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD7C0A59290937983ULL,
		0x2DAD861106E2529AULL,
		0xD1E30C3B404C6C60ULL,
		0x1163CD2523670CC6ULL
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
		0x55543DAF119CF627ULL,
		0x5C2CE07B827B8276ULL,
		0xAC2CB6700DD35598ULL,
		0x113FCFBAF34796ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB50AD335CA538913ULL,
		0x776A43853BFE615AULL,
		0x505816D794BCC2C5ULL,
		0x0C6669D40637F216ULL
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
		0x74AF8131C2578254ULL,
		0x6C5E82D792264370ULL,
		0xB265205A7FFB32F4ULL,
		0x6E71434BDC03213FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDD67EAE312E18A3EULL,
		0xAF690DF4C83F2749ULL,
		0x63F6393DF040986EULL,
		0x4D74EE528B6C712CULL
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
		0x5EE8FE565430974DULL,
		0xA5F78D6678667B2FULL,
		0x75404F41F98330B1ULL,
		0x0F58707D0EBD5382ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB0A9206A13910A4BULL,
		0x5C0508996BCFA615ULL,
		0xC0379A620AE77E51ULL,
		0x2D2387D7B0FF030EULL
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
		0x4696AB0CA330C3FEULL,
		0x9DCDD04DEE2E7839ULL,
		0x782D9326C8DCC748ULL,
		0x7C42B6B150676589ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4696AB0CA330C3FEULL,
		0x9DCDD04DEE2E7839ULL,
		0x782D9326C8DCC748ULL,
		0x7C42B6B150676589ULL
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
		0x5542B22D1A77393DULL,
		0xA1B860D5F90F725AULL,
		0x5685A3DE1B5EE429ULL,
		0x24FA7EA4B6FE6EB4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1F8F4342E2DB63DFULL,
		0xB7DFDE4DB84EC0B3ULL,
		0xD343DD7EAB32486AULL,
		0x7410E95085261835ULL
	}};
	t = -1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB5A77228D4ADC811ULL,
		0x6CC6A5697378DC56ULL,
		0xDFC4D843D44EE99CULL,
		0x7B5D9C9D6E4274A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE4DFB3E77A652AB8ULL,
		0x2809C5230758B577ULL,
		0x16C8AEE7A96B921BULL,
		0x24D530AFC68C437CULL
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
		0x1CF4A0022CB08F74ULL,
		0xBEACEAEE323CA6F5ULL,
		0xEC4701253C4BD4BCULL,
		0x2B656E7F56EE13FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC1006780036C925ULL,
		0xCF392C5879DE901CULL,
		0x97841AD3C76DABD4ULL,
		0x452E4D51521778C8ULL
	}};
	t = -1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x13145264724189F2ULL,
		0x7744BB8D339745FFULL,
		0xBDFBF0FAAB3BA047ULL,
		0x18DCBF21FA99E674ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x13145264724189F2ULL,
		0x7744BB8D339745FFULL,
		0xBDFBF0FAAB3BA047ULL,
		0x18DCBF21FA99E674ULL
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
		0x19F45D04935D4E49ULL,
		0x774F5C01443046DAULL,
		0x896B620CDE2FA490ULL,
		0x2E546160E84D893CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x326E47329B45254FULL,
		0xF12DE3050F353563ULL,
		0x620FED40A741B41AULL,
		0x127AA02629FE62C3ULL
	}};
	t = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1AB4AC409686CF9DULL,
		0x3A50D43509EBEC73ULL,
		0x495708D2672D0BD0ULL,
		0x006B640FB69BFC28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x292F453030CEE4FCULL,
		0x23C20540007BBD46ULL,
		0xE82B5D474B5E36A7ULL,
		0x5C51262214E69319ULL
	}};
	t = -1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD3DE4D8DEC42ECBCULL,
		0x3A1AB1D9A0715885ULL,
		0x4AAFA6CBD8688A1CULL,
		0x71FD5BF5019CD59AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84296481C3CB1812ULL,
		0x4DF29094593C16BAULL,
		0xB4BC7C262B169F65ULL,
		0x50818DDCE6496A76ULL
	}};
	t = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9CDFB44486866443ULL,
		0xC816859C0E72E978ULL,
		0x0A3E817AC06E1FCBULL,
		0x34ED561E7F0C0B23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9CDFB44486866443ULL,
		0xC816859C0E72E978ULL,
		0x0A3E817AC06E1FCBULL,
		0x34ED561E7F0C0B23ULL
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
		0x5D966C128B7D37A2ULL,
		0x22F189428CAC3C75ULL,
		0x45BC8C3341DAA52AULL,
		0x631CC8C50B5596B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD469A8B15224BF39ULL,
		0xF17A3401531EF696ULL,
		0x64A7EE39622ACC3AULL,
		0x6752620764DD8AE8ULL
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
		0xE246C2A050130A99ULL,
		0xCDC416B0BAC3B06BULL,
		0x5A940BFAAB246CF8ULL,
		0x42675ACCA3072F67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF46BCCBA3DACEA14ULL,
		0xDB8D74F2281CCF73ULL,
		0x50A2D61C25963C42ULL,
		0x6AB0253A0C5BDEC9ULL
	}};
	t = -1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x91328010AAC6E8B6ULL,
		0x07E8578ADA9A8CFEULL,
		0x8D819689FBDD5B19ULL,
		0x71EE09A738D097CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9170E3114CC799EAULL,
		0x00626C0BDF9EE86AULL,
		0x3D9A2F2C5E6D75C0ULL,
		0x4E8F6B3974B82C24ULL
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
		0xB9BFB6896EB066F7ULL,
		0x05A9044AB3FCD7DAULL,
		0x90BE56C9D4CF329BULL,
		0x0ADB7571DA214109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB9BFB6896EB066F7ULL,
		0x05A9044AB3FCD7DAULL,
		0x90BE56C9D4CF329BULL,
		0x0ADB7571DA214109ULL
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
		0x5225DB5F9BB7EAB9ULL,
		0xDFB1203FD3BF5063ULL,
		0x5C27648AA2FC0DCEULL,
		0x4E5FC79FFF7DE238ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE749286F272980BULL,
		0x3674D46EC068B94CULL,
		0xD104F2BA439EBA52ULL,
		0x07418A004D2CED86ULL
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
		0x03A0F3679F7E08DBULL,
		0xC7EED47075DF7A02ULL,
		0x562747D5689ABE8BULL,
		0x3192830CF676A019ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5EC896E642595684ULL,
		0xAA7B3378303957F8ULL,
		0x5B099DF476DC8246ULL,
		0x5EBBC55E0477B21CULL
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
		0xD0941D14FD1F01C2ULL,
		0xD61E23E4FA929C6CULL,
		0x835AFDC9FE96E43EULL,
		0x6CB022F6E54AD5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x01D4ED28417CB1CFULL,
		0xA917E2C169A6BEADULL,
		0xA476F6E676222020ULL,
		0x038C2A0954F3D81EULL
	}};
	t = 1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA8C309DA2A6F5935ULL,
		0xF5B0C44EBAAD0B70ULL,
		0xD07B527D44BFE2AAULL,
		0x247FC321A78651FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA8C309DA2A6F5935ULL,
		0xF5B0C44EBAAD0B70ULL,
		0xD07B527D44BFE2AAULL,
		0x247FC321A78651FAULL
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
		0xD424749725BFC45CULL,
		0x6B1EAFB7ED803340ULL,
		0x453799BC12ED0518ULL,
		0x789936FDCC9C4774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F8F7D24712E159CULL,
		0x5124E741E6B4AE88ULL,
		0x0343BE76F22FBB34ULL,
		0x234F8DDB7A2DECADULL
	}};
	t = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x057A9334B422B13FULL,
		0x49BF3E3AB355D5ABULL,
		0x30AFA802BE3CB01AULL,
		0x3D9567CC82460B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44BA0F64D3E1BC47ULL,
		0x3F16D88A747421FAULL,
		0x2059E30E1E80513BULL,
		0x600314E7A48CC8B0ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA6FB34ED34983198ULL,
		0x5F76E7C8FF55F84EULL,
		0x33BB05DFC06865F8ULL,
		0x5D0D13BB3F5E706EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D67B50682164A10ULL,
		0xEE9918A53D655608ULL,
		0xE2079A5D8B114419ULL,
		0x7EBA853C99BEF7F9ULL
	}};
	t = -1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xBF2F0FF7A57B8FC3ULL,
		0xBD1CFC715028C74EULL,
		0xB6B034BA8FFB783FULL,
		0x4B323B4A7FE6D2ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBF2F0FF7A57B8FC3ULL,
		0xBD1CFC715028C74EULL,
		0xB6B034BA8FFB783FULL,
		0x4B323B4A7FE6D2ECULL
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
		0x9FAC2BA6995D117DULL,
		0xE6C2197ED5814521ULL,
		0xEE63F42021994F77ULL,
		0x4EB1AA3652A43987ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x770A1A1FCD4D3908ULL,
		0x6A1028D218523225ULL,
		0x999422527047B089ULL,
		0x66045BA6F321B6D1ULL
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
		0x8B94C9C396988E9EULL,
		0x5ECC2FC04C3630E4ULL,
		0xA8ADD779D641453EULL,
		0x5FD861A51C0A00E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA35641BE5F4D4EF9ULL,
		0x0B8E6645F99F03E8ULL,
		0xF7A5C676CFC1345AULL,
		0x0A257AE0ECB85ABFULL
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
		0xD8E674ACFC137EF8ULL,
		0xEF0594E968708E5CULL,
		0xBA213899B5C650BCULL,
		0x5F196D5083856A92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9DED743C4B1B44C5ULL,
		0x396A2FB54B361EF2ULL,
		0x0A9081CF7F0C376BULL,
		0x21D3E4F81D3E6BF6ULL
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
		0x7585EC67693D061CULL,
		0x1F0968F124DCDADFULL,
		0xF3CF4018D8B2FD5DULL,
		0x5162365A3CF8FD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7585EC67693D061CULL,
		0x1F0968F124DCDADFULL,
		0xF3CF4018D8B2FD5DULL,
		0x5162365A3CF8FD81ULL
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
		0xDA501925357E5DC4ULL,
		0x2295D5F297A0C74AULL,
		0xF50237521B8132A5ULL,
		0x0F8037E88847CD0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB56E44F55415F2A7ULL,
		0xC784F5736D8ED771ULL,
		0x7597CE3BED983862ULL,
		0x10ADB61104D9EE6CULL
	}};
	t = -1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEDA9730B80B33930ULL,
		0xCF22262908D97E29ULL,
		0x53BD9AB16B465CA3ULL,
		0x6BD16BFC7FCF64B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x756397CD9EF7B2CBULL,
		0x4195967920515E7AULL,
		0x0762ABD677ADDD2DULL,
		0x04C2C4AF389A9A7CULL
	}};
	t = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1BE1FBE31292F8B3ULL,
		0xEBDB22051EC403A1ULL,
		0x312C10E1FA33DA13ULL,
		0x4C01DFEF3F00CAACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9AFA0675EA9A54A2ULL,
		0x516C0E509C161613ULL,
		0x343075865162755BULL,
		0x12C19725913C4943ULL
	}};
	t = 1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x64DD6FA9BE8B6516ULL,
		0x94D2548B53F0180CULL,
		0x49AF50F43C6ACD0AULL,
		0x34DB7E671810AD64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x64DD6FA9BE8B6516ULL,
		0x94D2548B53F0180CULL,
		0x49AF50F43C6ACD0AULL,
		0x34DB7E671810AD64ULL
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
		0xB428A7EECCB7948AULL,
		0x173A09FFEA28A1F5ULL,
		0x8B395C8E8EB16B3DULL,
		0x0CB787F8D3E1380BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5C4AEB165E752BFULL,
		0x006D9C96937A2772ULL,
		0x11DEB9D9097BCFA4ULL,
		0x3EB67AAB366E89DAULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x23D654B86A646E40ULL,
		0xE0A90B4EAE927FEAULL,
		0xB9309B1A0AED9A21ULL,
		0x477AE5280EEA9D53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B06199868D3F33DULL,
		0x71F01509F4316EE0ULL,
		0x81C4F505B5DA33C5ULL,
		0x1767053D49F87128ULL
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
		0xFC97FA88E767FF50ULL,
		0x3E8F2D63F8E4F926ULL,
		0x7E4BC7D7FB6F1FF6ULL,
		0x04DF575579E3F649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x488D560451D35F5AULL,
		0xE7E7FDDA423B99EEULL,
		0x1B27270433974FF2ULL,
		0x071D8811FD73430EULL
	}};
	t = -1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFBDC723B3C9E6F1FULL,
		0x1AD56FC597BE7296ULL,
		0x7EF626B8365FF57FULL,
		0x15E03D6EEF11A37CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFBDC723B3C9E6F1FULL,
		0x1AD56FC597BE7296ULL,
		0x7EF626B8365FF57FULL,
		0x15E03D6EEF11A37CULL
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
		0xF9E0FA3E0C18E680ULL,
		0x125292687C90B8B7ULL,
		0x25B54AC4BCBD05C6ULL,
		0x0B51B7FE9D7A2FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x578A36DAF3F9DBD5ULL,
		0xD63D3DDBA0580163ULL,
		0x9CACB4B2A624A51DULL,
		0x6E6D58B0D7AE5D66ULL
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
		0xBF28792ED235A02DULL,
		0xF9297FE1AA05DA43ULL,
		0xF866C12203E68796ULL,
		0x5701822B8F8865D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5774636C506BD037ULL,
		0x021D2D91D61509E5ULL,
		0xA0D01A5FB52506BCULL,
		0x1602BA067C5B9122ULL
	}};
	t = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCD41DA46EC639119ULL,
		0x5C8CEDB0298CD417ULL,
		0x539FF17C945037AAULL,
		0x76BC68E4527F5010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B92BB92A77463B0ULL,
		0x97B2F9FAC996E48BULL,
		0x5B34853372B662D8ULL,
		0x137218F4F09142C5ULL
	}};
	t = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7946672867C7A658ULL,
		0x0FCC84E5103D9DFAULL,
		0xD258B4147BC5B3F3ULL,
		0x53F50F3E50064481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7946672867C7A658ULL,
		0x0FCC84E5103D9DFAULL,
		0xD258B4147BC5B3F3ULL,
		0x53F50F3E50064481ULL
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
		0x451F1F6A7083F88EULL,
		0x792489B02A0F9B43ULL,
		0x7B3BF918CDBEE75BULL,
		0x7FF081B8C54227D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E5B82C61DC34688ULL,
		0xDCC9FBC76F7B2E96ULL,
		0x8D628E158DAE10CCULL,
		0x1579416DC62CCA6AULL
	}};
	t = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x364FCB78EB706108ULL,
		0xEB9A2BC469D40034ULL,
		0x4FBAB6EEED3378FBULL,
		0x2493DD338FA40ACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBCEF5F9ED650283CULL,
		0x47735EB293F4386EULL,
		0xF8A2C351166D186AULL,
		0x6C735E4229C86387ULL
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
		0x00CB5698F1296B1FULL,
		0x6D9409A8CE65F846ULL,
		0x26249AD7319B0F39ULL,
		0x717A3448F2C6D66EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x622B6F873554872DULL,
		0x101EE4DAD38C63BDULL,
		0xBC113FDEEC4BFD6AULL,
		0x0E4CF28C5E27DF8BULL
	}};
	t = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC1F5C1219DC20351ULL,
		0xBB107628CCF2F769ULL,
		0xBFD2ED6D1C9EC5ACULL,
		0x1EE60B5563A8E1DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC1F5C1219DC20351ULL,
		0xBB107628CCF2F769ULL,
		0xBFD2ED6D1C9EC5ACULL,
		0x1EE60B5563A8E1DCULL
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
		0xD226E097633B6D33ULL,
		0xAD6EB8D867079772ULL,
		0xC0334F05B6DA1EBDULL,
		0x1E11714BFA8A32BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC83B703B714A24ECULL,
		0xD102636D692F7974ULL,
		0xB92533F05E36C2E5ULL,
		0x709CFB0B94EF1234ULL
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
		0xF5D3CC8C423F566DULL,
		0x02B5F8FC0C295634ULL,
		0x0FB3DEE3331E03C7ULL,
		0x63CF25EC75C4AC0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE28E318D414D0D6DULL,
		0x72D96F99FC9A6F3EULL,
		0x6B70914AFFC6CF3FULL,
		0x219F1BC3130C9AB8ULL
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
		0xA21B76E34F9AD788ULL,
		0x62613E6A527894FFULL,
		0xD36B521D1AF24FB5ULL,
		0x756612B0F30489E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4363296FC38B6DC5ULL,
		0x9C6F7C901BAF1159ULL,
		0x6570C219F025E042ULL,
		0x10E744F3B264A91FULL
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
		0x2B9EF390D1BDECC0ULL,
		0xAFB6A9DF7C00A098ULL,
		0x05FE9E848FD1968CULL,
		0x19B9958AB7515AFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B9EF390D1BDECC0ULL,
		0xAFB6A9DF7C00A098ULL,
		0x05FE9E848FD1968CULL,
		0x19B9958AB7515AFDULL
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
		0xF9305F176502555EULL,
		0xA83294011B554321ULL,
		0xB8F7B52CDADF7F99ULL,
		0x34DB69BCF23F8905ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B706041151A0691ULL,
		0x1D6797064E1FFA74ULL,
		0xE77726E4758E4EEBULL,
		0x48BD83EDC915F634ULL
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
		0x0EE816AD57165435ULL,
		0x0F7942333CE7AC80ULL,
		0x2497A1CEA941C488ULL,
		0x049AF8EFAD051380ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x369BF0094B992121ULL,
		0x261A9E27976CEB95ULL,
		0x9EB3A0272B1DDB86ULL,
		0x370A03F5C082F8AEULL
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
		0xD1EB529E5729BC76ULL,
		0x169B40D5720F0D75ULL,
		0x018FD03DB3D08239ULL,
		0x1C4A4B73CDE0A3A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF757AC4CD62EC35BULL,
		0x4DE742F357D6BF53ULL,
		0x3E79C1D2AD1014C6ULL,
		0x5F8F6C8998DF2FF8ULL
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
		0x4D34C5587018653BULL,
		0x1F6550E5CDF44030ULL,
		0xB0A9592C5C9BDE1FULL,
		0x77144977404A542DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D34C5587018653BULL,
		0x1F6550E5CDF44030ULL,
		0xB0A9592C5C9BDE1FULL,
		0x77144977404A542DULL
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
		0xEDF46EE465C2AF0AULL,
		0x166A758A6F5F33B8ULL,
		0xF561DC36095C902EULL,
		0x3AF6363649AFADDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x39447564D7224096ULL,
		0xE2F9D4E430E12972ULL,
		0x756C709AF776C8B1ULL,
		0x223C1639539DA2BAULL
	}};
	t = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x25EDEBFFD000E0E3ULL,
		0x855813A2260DD7DAULL,
		0x0F4056F3044CE0CAULL,
		0x5D513FA29B9A6053ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3A98B0E97F2413F1ULL,
		0xCCB509695500CFEDULL,
		0x0329C13AE44340CCULL,
		0x2556222263650702ULL
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
		0xDF3C9F468A4111BEULL,
		0x977A902C79097191ULL,
		0x2A713593B980C437ULL,
		0x0EA0BDF110C8FB40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4808C51A3D3F1D6AULL,
		0x5314BE141924729DULL,
		0x2C5BC5DEBF7A6B34ULL,
		0x205D1DD313C2F76FULL
	}};
	t = -1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x52FF2CB75F695FF1ULL,
		0x9787B50F81FFC451ULL,
		0x0AEEA5471C310814ULL,
		0x1F9A9D1511522F9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x52FF2CB75F695FF1ULL,
		0x9787B50F81FFC451ULL,
		0x0AEEA5471C310814ULL,
		0x1F9A9D1511522F9BULL
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
		0xB4AA8A25922BE1F4ULL,
		0x1CE50B7ACBCBB0E0ULL,
		0x2D523A00F34DD657ULL,
		0x36596133E968F26AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x47BD2B4B8FF27054ULL,
		0x2634907A312B0466ULL,
		0x2E07E51F92570ECAULL,
		0x01764151C150C0B8ULL
	}};
	t = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCC614F37F8455613ULL,
		0x4A811344940412A6ULL,
		0x2B60C6BEF00D8F13ULL,
		0x4168B6F555FF38DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF16ED0DCE83CD1F2ULL,
		0x5A69440066FD6BB2ULL,
		0xC5715B18AC18E967ULL,
		0x09B60E1423AC6DF2ULL
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
		0xAFEFF91BAF13028AULL,
		0x7162EC688D102B97ULL,
		0xE1A762A21A6371D1ULL,
		0x2DC608AF03C37FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x97B0EFDE77A28B94ULL,
		0x3A8C8EAA6724AE5EULL,
		0x672A6238A4CEE0F7ULL,
		0x7A0F41B2CCC29C82ULL
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
		0x5D3851AAF6189B76ULL,
		0x0A979184B56D09C0ULL,
		0xDEF5973610632EACULL,
		0x5EE3552D2F492F30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5D3851AAF6189B76ULL,
		0x0A979184B56D09C0ULL,
		0xDEF5973610632EACULL,
		0x5EE3552D2F492F30ULL
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
		0x29D1353048BA1D44ULL,
		0x181C1DAAC5DF81B9ULL,
		0xF9F4EE964C6B6262ULL,
		0x334D8C45C1066FEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC95D80C20763AE06ULL,
		0xC9B740B0EA93FA63ULL,
		0x24BD2A947F7997E5ULL,
		0x3616C211CD1A2237ULL
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
		0x4505E683334CF8B6ULL,
		0x12E16FD232F9313EULL,
		0x9AECF448FCCFD888ULL,
		0x5F2B9690D7355248ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x23970E1A588316D6ULL,
		0x57086B2E02B15871ULL,
		0xE9855DFB7697D5F5ULL,
		0x76BEE9228F3DD834ULL
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
		0x6CA0A733814C0700ULL,
		0xFD856916089AEFBFULL,
		0xF649D6B5748BCFC6ULL,
		0x0DBBA0B795946B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x261284AC6DE51D76ULL,
		0x6F5DE54F1F206759ULL,
		0xA9D415058BF0DC23ULL,
		0x0135A51BCD05C65DULL
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
		0xBBB8207762BFE6EAULL,
		0xC6B3256E75D7E817ULL,
		0x28C22532C59B365BULL,
		0x4C6AFE8DF0CE6608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBBB8207762BFE6EAULL,
		0xC6B3256E75D7E817ULL,
		0x28C22532C59B365BULL,
		0x4C6AFE8DF0CE6608ULL
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
		0x503195361F9D6936ULL,
		0x2568313172A5E72EULL,
		0x41EA5AB98D5C3AD3ULL,
		0x3F2C4513373B5754ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB653B70BCD717A3EULL,
		0xD2B62928AAF3A847ULL,
		0x09B6DC435F45EB0EULL,
		0x4423263DDDFFE281ULL
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
		0xC850B4B2FF2800C5ULL,
		0x2DF0B738F9B00FDBULL,
		0xCFC4545CA7BBB404ULL,
		0x0794C76EDF09E14EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x799B1C936BAE3444ULL,
		0x92A461D351213681ULL,
		0x764A818A599B2C4FULL,
		0x4D6AA10229905F57ULL
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
		0x5D964E1508061904ULL,
		0x387CB719948737A5ULL,
		0xB5B801CE591BD9B5ULL,
		0x77941575556F6B24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x25C1A73430D2546CULL,
		0x06DD6D040A3CE15DULL,
		0x4D5797C99351F954ULL,
		0x45A23DC0A81F0295ULL
	}};
	t = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x433CE1BAD68BE89FULL,
		0xEBE9764003409BA6ULL,
		0xF31A45467CAE1D4BULL,
		0x078498E5888FCDFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x433CE1BAD68BE89FULL,
		0xEBE9764003409BA6ULL,
		0xF31A45467CAE1D4BULL,
		0x078498E5888FCDFAULL
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
		0x97D974AB28FF57BFULL,
		0x8CA1FAE3BA6F575CULL,
		0x5CFA6146851A8E29ULL,
		0x7381B4C5FF15B7FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF326A445574FEAD6ULL,
		0xB7373B42A8477246ULL,
		0x0A8528D8975AA649ULL,
		0x531FFA66583F4E98ULL
	}};
	t = 1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF1331C92B752AC18ULL,
		0x78F3D69558569368ULL,
		0x627498319021BF33ULL,
		0x27EDD55A53DE1B25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD15C47331C337F92ULL,
		0xDF102F81A7231031ULL,
		0x48E554D8428D346EULL,
		0x1DB7F85B4075D930ULL
	}};
	t = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1308B4B37D4A66EAULL,
		0x092B885559AA18CFULL,
		0x10866633084E31B8ULL,
		0x572D87168734112EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x73313BCD4159BFCDULL,
		0xABECC907BD5AE3A5ULL,
		0xA49EF9F2279797CEULL,
		0x4FCDA3BF92D560AAULL
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
		0xB9F36B09D092CBA2ULL,
		0x68D8BEFF445578BCULL,
		0xA67A29F3E8CD34AAULL,
		0x020FD5B83AE32721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB9F36B09D092CBA2ULL,
		0x68D8BEFF445578BCULL,
		0xA67A29F3E8CD34AAULL,
		0x020FD5B83AE32721ULL
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
		0x6F344573618EB808ULL,
		0x93AC30219BE3EA33ULL,
		0x40EF4FDCD31AE90DULL,
		0x40FDD6794E1AB44DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6E65610505B2205EULL,
		0x68A98FCF56BEBAC2ULL,
		0x5D1211B142F8387FULL,
		0x797AC1D7B68604DAULL
	}};
	t = -1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD6DD9C4AFBF8EEADULL,
		0x0AE376D188670901ULL,
		0x2F77C75813ABE297ULL,
		0x3B633E46A79E1492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6228FCC6CC24E320ULL,
		0xE6898E4579EA5FC9ULL,
		0xCA0ABCB0E40ABE40ULL,
		0x1E20CEC275463F1BULL
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
		0xEFCFF0B22A98846CULL,
		0x688DA44704A9F77DULL,
		0x495AD79281E7875CULL,
		0x48B07F48C3C9694BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCCC2EE2AE1AE2AC2ULL,
		0xF1598140DE315FA2ULL,
		0x0F05235AB22A3694ULL,
		0x29A364591E006CD6ULL
	}};
	t = 1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCA99E9909AADA9D7ULL,
		0x9D8E44DFC6ADF492ULL,
		0x5C4AAF801FC50C82ULL,
		0x740AC24B847E96A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCA99E9909AADA9D7ULL,
		0x9D8E44DFC6ADF492ULL,
		0x5C4AAF801FC50C82ULL,
		0x740AC24B847E96A6ULL
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
		0xA7E0CFAB86A7811BULL,
		0xFA4623B52B52164CULL,
		0xDD43F4D385E25B77ULL,
		0x591F2FF5AF4DEE91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x04031C2E78501775ULL,
		0x79C7058D1A6DA300ULL,
		0xF6AA9721672AB517ULL,
		0x5EE4E96F5B8FD638ULL
	}};
	t = -1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3F6B5DB5640B978CULL,
		0xEEEF373B9BBA2F78ULL,
		0xFF7CD9348E590CC3ULL,
		0x686044BAB8C0E26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCEEA5DA450D0F9A1ULL,
		0x4963EE6731BA656EULL,
		0x36328A9716E0EA17ULL,
		0x5F26ACF513800636ULL
	}};
	t = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6AA0279CDB9A845BULL,
		0xB41E8EF2C44B61A1ULL,
		0xE728008D80141BD0ULL,
		0x53359ADD99D0AC80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3DB511042450D675ULL,
		0xCCF1EC5F73308556ULL,
		0xBFC770031927FC17ULL,
		0x0E77CCE6512ED4EFULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE3A3F1896CDA358DULL,
		0x12907A6D36E73008ULL,
		0x2ABAD89E750EED19ULL,
		0x6F9B8C6C525CCF34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE3A3F1896CDA358DULL,
		0x12907A6D36E73008ULL,
		0x2ABAD89E750EED19ULL,
		0x6F9B8C6C525CCF34ULL
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
		0xBDF792674B22A03FULL,
		0x1E62F173DA6FE4D2ULL,
		0x3D0F6196D0E37FC8ULL,
		0x101CA86A004FA397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CF363CA0AE14A43ULL,
		0x17C28F25BEF6F91AULL,
		0xA9E7A0116B36B675ULL,
		0x2B5FDCF42DAE55BEULL
	}};
	t = -1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB072B4A15AD211FDULL,
		0xBAE539C66D410FDEULL,
		0xA5A5EC1B53E53213ULL,
		0x1B7B9134C03C8B7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5A03405FC11DA629ULL,
		0x518DE32B7303D62FULL,
		0x82368A33FAD7A664ULL,
		0x2269BC2ACEAA725FULL
	}};
	t = -1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9EAC9605AAA12036ULL,
		0xCC1B53E4B10D6E20ULL,
		0x6F99E6779EA43CD9ULL,
		0x20AD51AA07A27244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x57C1CAA562AA1635ULL,
		0x9FD8B976222AB5D9ULL,
		0x5A7BAA9B01CC28BAULL,
		0x7BB18B4D4560FDE8ULL
	}};
	t = -1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA7132F00EA73E323ULL,
		0xCF9879CC047A4A20ULL,
		0x158DC6DD847F45AEULL,
		0x6E2F896C936F1608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7132F00EA73E323ULL,
		0xCF9879CC047A4A20ULL,
		0x158DC6DD847F45AEULL,
		0x6E2F896C936F1608ULL
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
		0x333422FF8580E37DULL,
		0x78D0F545C8CB056CULL,
		0xD5351E97223A37B8ULL,
		0x1DAFF7DFB1849878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6EE507563A95F4E9ULL,
		0xA87BCC62050043CAULL,
		0xFDA280669F41F5D3ULL,
		0x5DABF2F6360DDBE4ULL
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
		0x63D1249BAA106C23ULL,
		0x3E640CF83A811115ULL,
		0xD9966E2259E0A101ULL,
		0x06BC280897AD671CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD1EBD0A43AC472C7ULL,
		0x33E22D9BFB4F61ECULL,
		0xB83E64E5DAF7BA63ULL,
		0x63C1CE24B44B093EULL
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
		0xF2E4BC57A96A5559ULL,
		0xCBE6D04C9BB5D98EULL,
		0x3FE54654B172A4AEULL,
		0x73863DCBF811D4ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8804BE06A1CF76EFULL,
		0x8FE9512816CA8E6DULL,
		0x641665BC015C69F6ULL,
		0x24B3272868F3FA62ULL
	}};
	t = 1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5CD057318F650E1BULL,
		0xACDC67BEED25D638ULL,
		0x3ED345361892D4FDULL,
		0x1CB209DF0910C88BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5CD057318F650E1BULL,
		0xACDC67BEED25D638ULL,
		0x3ED345361892D4FDULL,
		0x1CB209DF0910C88BULL
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
		0x392E64D47B23FFC4ULL,
		0x56A98D705A3AD33BULL,
		0xBA9E8199D4D9E78BULL,
		0x104A4B1474CD5ABAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x07042EDFC6539621ULL,
		0xF39763886D3D55BBULL,
		0xFABB1347325B5289ULL,
		0x63A99B2AA903BD8DULL
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
		0x206D437FB751873DULL,
		0x3748CEA5E6B57CACULL,
		0x20C918B9532CEF1CULL,
		0x67E39D8F3F9768C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B19A76AE691A48CULL,
		0x775FEDF97840AABBULL,
		0xE52929545F963AF5ULL,
		0x4D46FC1A3B045D01ULL
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
		0x686DC788FF0AAC78ULL,
		0xAEE5329018A33ACBULL,
		0x9873E6912CF41A72ULL,
		0x792AE41B98F46982ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6FB69649546B4DADULL,
		0xA0BBA984CE2F19EEULL,
		0xF98594256006FE2CULL,
		0x38B81007B3B6F481ULL
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
		0xEF6FE0EAF3465FA9ULL,
		0xB145373BDD6AAB55ULL,
		0x60D64A12426E1825ULL,
		0x08736692C00AFEE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF6FE0EAF3465FA9ULL,
		0xB145373BDD6AAB55ULL,
		0x60D64A12426E1825ULL,
		0x08736692C00AFEE6ULL
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
		0x5BA0CF52BBC579A8ULL,
		0x17374695D9B7A92BULL,
		0x8F335D654D486C37ULL,
		0x401FF487ED5EF410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCDDC08DC3E175838ULL,
		0x9849E5C30DFBD405ULL,
		0x2FEC494C2CB25CF4ULL,
		0x675336D7501A7657ULL
	}};
	t = -1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x764BEB56B1CCF2DFULL,
		0x210538D26116D147ULL,
		0x2BAF095B1E0B94DBULL,
		0x4C0E939C072C22B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x360325C5B45EEDF7ULL,
		0xEA8F0E1A8CC8EB7BULL,
		0x3C44DBE6119BCF2AULL,
		0x6049CB126B8F9FC8ULL
	}};
	t = -1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEA54783B3A98AEBBULL,
		0x6382CD712097EC39ULL,
		0xE5FDC5C1D41ED76DULL,
		0x7C44D1E3A663C289ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x36D680EF09F2F0ADULL,
		0x5C604926F99996B5ULL,
		0xD2BCA62F7B1144CCULL,
		0x1DD614F2F35622F0ULL
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
		0x62BDFB809C485645ULL,
		0xA57ECAA8CCB960B6ULL,
		0xC2AABB3342C794A1ULL,
		0x0EAF0FFBC330634BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62BDFB809C485645ULL,
		0xA57ECAA8CCB960B6ULL,
		0xC2AABB3342C794A1ULL,
		0x0EAF0FFBC330634BULL
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
		0xB9C13D9612D2ECA7ULL,
		0xFD83A8634387A8EAULL,
		0xF310A0B64067DE04ULL,
		0x3332CA4B5F71F8E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x78DDF5DD89FDA86DULL,
		0x9611A7221AF5F2F1ULL,
		0xB567138FB06A576DULL,
		0x0C113BA3D29D905BULL
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
		0xE21111D4520C7A09ULL,
		0xDDDAB964332B383AULL,
		0x4C4B23E340533EBFULL,
		0x5BDC9FD3ADF9A798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x325D609205FD1B1DULL,
		0x38081716058733D2ULL,
		0xB152897AF1687BE7ULL,
		0x22D6E71B46199874ULL
	}};
	t = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x382A6C5AD73841A5ULL,
		0x07363DD4D9501D7CULL,
		0x675BE05BE1BD7492ULL,
		0x09375749034E7693ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDC9C0AF491FF6A6ULL,
		0xC584A63EC3C3B4DDULL,
		0x56DCFDCC774004F3ULL,
		0x2D41532FA728AEF5ULL
	}};
	t = -1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2E3DB8DB88A2732CULL,
		0x2D994AF762DA9D3FULL,
		0x8BC9DC7CBDD916B5ULL,
		0x4478DEB2466E2232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2E3DB8DB88A2732CULL,
		0x2D994AF762DA9D3FULL,
		0x8BC9DC7CBDD916B5ULL,
		0x4478DEB2466E2232ULL
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
		0x7A9A1103836B3418ULL,
		0x1746109948E309D9ULL,
		0x5D1E1AA69C51070AULL,
		0x7F51FF94CD9745FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0BE1843632CBDBB3ULL,
		0x7AAD65565A2111D4ULL,
		0x0A9DFD0CA83DB40CULL,
		0x34AE23E3BC2F26DFULL
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
		0xBEBF28349E30220BULL,
		0x620A8A68FBA3535EULL,
		0x335D9FF3EAD9852DULL,
		0x22245F32C41589DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC6C2F314FC0BA0DEULL,
		0x5ECA50DF2C95AEC1ULL,
		0xF7926F1BFA3C3D32ULL,
		0x4B94C1D3CB23F96AULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xAFA4D53D47D843EBULL,
		0x4B3E63BE701AC70DULL,
		0x521098A8FE759831ULL,
		0x71252096887BF4ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x954915A34DFB6A18ULL,
		0xB994B268D7743573ULL,
		0x2A0390E02AAF72B4ULL,
		0x073409B32875667BULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDDB558B8BB27F6E0ULL,
		0x586C606986843F1DULL,
		0xAE720848A0AE1E59ULL,
		0x48596141014CD3EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDDB558B8BB27F6E0ULL,
		0x586C606986843F1DULL,
		0xAE720848A0AE1E59ULL,
		0x48596141014CD3EEULL
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
		0xF9B138B7C3584A2EULL,
		0x120521538C9DA34EULL,
		0x0CB920C20F217184ULL,
		0x0CD51197E97740F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA14CE6C8BA1B7244ULL,
		0xF234D1598C2C8767ULL,
		0xD2348DF8C23DF727ULL,
		0x7AB3E9F9A7352002ULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x10DBA151974F2A79ULL,
		0x333F73F15CED3411ULL,
		0x30356C2CC08AB617ULL,
		0x7648D3BCDD65FC16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA2BBE88B80385C62ULL,
		0x377B352FB5872781ULL,
		0x159329A24F592FA9ULL,
		0x2B472D03C5260477ULL
	}};
	t = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x768B54E8D9A7BD25ULL,
		0x6FDEC68CFB1613F6ULL,
		0xAC499C2CB9F8CEABULL,
		0x56A2E913A16A39EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD791EA986517B772ULL,
		0xC9C87CE29D1A9C52ULL,
		0xD2BD9531D9F35117ULL,
		0x36F861EF473F0AD5ULL
	}};
	t = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA55F468CC5A75FB2ULL,
		0xE4A9289F85740B45ULL,
		0x18BFB2A4B257ADACULL,
		0x23A3D242B50533A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA55F468CC5A75FB2ULL,
		0xE4A9289F85740B45ULL,
		0x18BFB2A4B257ADACULL,
		0x23A3D242B50533A1ULL
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
		0xBF199513ADBF8F51ULL,
		0x50F6156E0AA21DBCULL,
		0x1F1945FA9D7F0CA7ULL,
		0x16E05E1D626E2B1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3DCBF196D0D57D70ULL,
		0xBE955E52DCD7E4A5ULL,
		0xC017C0493303EFE3ULL,
		0x4385CF7C56DB2CDAULL
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
		0xF0BFF951A59B0AEAULL,
		0xF68CD4995DBCE427ULL,
		0xD51A807C31AF77F7ULL,
		0x642BAA59F67BE7F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3D89DDB6F5DC6768ULL,
		0x4A7184697EC58472ULL,
		0x4796C5B27F6F81DEULL,
		0x51C9355D6C26E491ULL
	}};
	t = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4995B148086F6D1EULL,
		0x03342F0783AB72DBULL,
		0x74E17FD4D1FCE1DFULL,
		0x43E5E0A7722ADE14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4261033007644264ULL,
		0x78B51733BEC95E58ULL,
		0x29222E88B671FF00ULL,
		0x7AC2F87B9D65F6EBULL
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
		0xE31D9AD79CC15AC6ULL,
		0xA7AB37A8D5810FF6ULL,
		0x3B1A540880715223ULL,
		0x383AEDC83C2F299BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE31D9AD79CC15AC6ULL,
		0xA7AB37A8D5810FF6ULL,
		0x3B1A540880715223ULL,
		0x383AEDC83C2F299BULL
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
		0xFDAC6715BD3303DCULL,
		0x73DF739CE22F5551ULL,
		0xEE0073523B0A8B90ULL,
		0x109621DADF7AA608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33D0C3E4C17EAAF4ULL,
		0x55F2E2BC4C3AE439ULL,
		0xD73F650EC1BD5962ULL,
		0x46D48760C479572DULL
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
		0x49868EFCF1069493ULL,
		0x2103C33EE1BB736AULL,
		0xC9CBA6ADCA171EE7ULL,
		0x6E156F3D36FAD017ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD4BA52607F1872DULL,
		0xEDE7B7BB3DF70893ULL,
		0xA01218EFF3D31B2DULL,
		0x7CAF654968C6D0F8ULL
	}};
	t = -1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x84E126E4C1C2D1C2ULL,
		0x215B863F541EDDEEULL,
		0x14ECD0086E36F224ULL,
		0x7C7481746F1F5C31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x66723491F3B24472ULL,
		0x7FE8E4D8A5A440BEULL,
		0xCA05F708108D2F6DULL,
		0x34E66B2A30027819ULL
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
		0x1FF8FC656B089BCBULL,
		0x618611CF4FE741F5ULL,
		0x0986532859CA541AULL,
		0x46CFC9F35768DD15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1FF8FC656B089BCBULL,
		0x618611CF4FE741F5ULL,
		0x0986532859CA541AULL,
		0x46CFC9F35768DD15ULL
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
		0x3301A62967E6DC04ULL,
		0x0B746750C4CEB10CULL,
		0xDCC26A1C7EDD5F9FULL,
		0x690AAE641CF3B4D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD5AB425139B2B0E2ULL,
		0xF8D07958E5EC2332ULL,
		0x3E5EEE9BD333F639ULL,
		0x1EE70BB883377917ULL
	}};
	t = 1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x603305BA0ECB1F14ULL,
		0xBD7D1348EEBE1F6BULL,
		0x62B0E7E316529670ULL,
		0x223D64713E780BBDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6836E05B2C0670CCULL,
		0x58DCF3D56B435F0EULL,
		0x150587E68227496CULL,
		0x026332D60026284FULL
	}};
	t = 1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFA3E7D3685E13E21ULL,
		0x6B813EA611688B0EULL,
		0xD8F556E7117EDDB2ULL,
		0x2FCF5F99707A9FD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1CAAAF1E06C2BEBFULL,
		0x566825807D38D781ULL,
		0x175884ABA0A583AAULL,
		0x49AA40F982B6A375ULL
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
		0x6D5067C188A1C605ULL,
		0x283D0C3F762EA38FULL,
		0x9378C15D6DE20669ULL,
		0x5BA07973E534C26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6D5067C188A1C605ULL,
		0x283D0C3F762EA38FULL,
		0x9378C15D6DE20669ULL,
		0x5BA07973E534C26DULL
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
		0xF0F7A2C40F256E24ULL,
		0xB2250C308C68F2B7ULL,
		0x45B9E8ACD92DC138ULL,
		0x2CD5E1C18DB34D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xACA71366C8BD3BD1ULL,
		0x50FA620CCE5C6488ULL,
		0x10F2C2920F5DA474ULL,
		0x665E0E30D8E09EF0ULL
	}};
	t = -1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFC6E68B9592D53CBULL,
		0x54CE0E9BAE823A49ULL,
		0x2529EABA1F93E757ULL,
		0x3C18DC719549FC53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE515DEED63B377A5ULL,
		0x866B4B4853F97625ULL,
		0x845D841E6F4E5E03ULL,
		0x57076B83E979A97BULL
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
		0x044D4B8E530C32ABULL,
		0x5A8A5CB736C60B1FULL,
		0x2D3A2CDD44ABD426ULL,
		0x1A998C41E21C178BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x428C4B3DAAB60FBAULL,
		0x33C12EE49BE9A583ULL,
		0x6C1390746BD7BD07ULL,
		0x5C716538124BA5D6ULL
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
		0x0B0C0C236B033860ULL,
		0x7C148CDBCD349B69ULL,
		0x04359D74532C0D51ULL,
		0x681E8E9137B6D99FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0B0C0C236B033860ULL,
		0x7C148CDBCD349B69ULL,
		0x04359D74532C0D51ULL,
		0x681E8E9137B6D99FULL
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
		0x38D6E67E1CB2A1D8ULL,
		0xD7AB7D06B1EB74A5ULL,
		0xC300DE4A7F9DA129ULL,
		0x780221AB82968735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x90D5F1BDCDD99675ULL,
		0x9F5F42F9ECCC831CULL,
		0xC3FA0F4BD7943BB8ULL,
		0x485BBA049D50E020ULL
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
		0xE4D56FF65A094BB5ULL,
		0x2A6A9B23B8334194ULL,
		0x2FA5F4BF6B77A512ULL,
		0x0142803476CFD3BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBE0832FA19F7084ULL,
		0xA45D287143541F8DULL,
		0x1C920D54603F5D4AULL,
		0x04C219EEC6E66CB0ULL
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
		0xFA11DC7A140AA4DFULL,
		0x25CD925DED596FA0ULL,
		0xB91911CAB1AED31FULL,
		0x62558EEF819B97F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5DC60C5F0069498AULL,
		0x00ABE7ADD5CA3689ULL,
		0x7E76494487C4BE69ULL,
		0x731F2C7FFCD20604ULL
	}};
	t = -1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0A4B45419B99357FULL,
		0xA28CF1C32A5DA8D9ULL,
		0x96FFB8F79E23B201ULL,
		0x2E71E171D0BCCC44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0A4B45419B99357FULL,
		0xA28CF1C32A5DA8D9ULL,
		0x96FFB8F79E23B201ULL,
		0x2E71E171D0BCCC44ULL
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
		0x9003F940583FDA56ULL,
		0x749C01F7CD667540ULL,
		0x0EC2C5C06B7240CCULL,
		0x5FE6B0B74E5F6205ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20E0C8125EEEBC2AULL,
		0x8860DD6A77B5A75AULL,
		0xED91DE1A97A3856AULL,
		0x1DC10C2D8E3E1A81ULL
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
		0xD32613284C657CACULL,
		0xF322FDEDA8115D8AULL,
		0x840302457498DFB8ULL,
		0x5B591C0CCBA6A47BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5DF7C9BC3CA22A24ULL,
		0x7B3510A834A49695ULL,
		0x7110EE375D86FD91ULL,
		0x7BE150FEF3C0020AULL
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
		0x13FB4773C29CD1E8ULL,
		0xE7EA48BA27E06DFBULL,
		0xED6C9226C013564AULL,
		0x597DCE8267144D7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x182A0F6D754C1501ULL,
		0x61E55A4C8CEA6229ULL,
		0x0C624723E4094EEAULL,
		0x62DD25AE2108DCE9ULL
	}};
	t = -1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x116997042B34A0AAULL,
		0xA964DB442C92273BULL,
		0x695D8FA8922A270EULL,
		0x4B9E399D6038CFE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x116997042B34A0AAULL,
		0xA964DB442C92273BULL,
		0x695D8FA8922A270EULL,
		0x4B9E399D6038CFE4ULL
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
		0x7EC8C6BC7EA9576FULL,
		0x1BCF7120CB8DBC24ULL,
		0x4A75257C22C27398ULL,
		0x2E1A7B9B51436599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC2AB32410667C434ULL,
		0xCA2BEC790624E3FFULL,
		0x1298B375A34A2214ULL,
		0x7680C7A4B0E370EBULL
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
		0x084076C6741394AEULL,
		0x0FDE493A1CF75B26ULL,
		0x18C52319178CD3DEULL,
		0x5A867CC4E8F4A789ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE5172CED93D6A543ULL,
		0x9DA4B8FE71EB006DULL,
		0xA189657D6F81DB7CULL,
		0x7AD74C97BFA8B490ULL
	}};
	t = -1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x531F20AB156FE292ULL,
		0x7A9F33997C839653ULL,
		0x1E356E1F5CE2C743ULL,
		0x038E5249E69CEA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x765C6B1CB619995AULL,
		0x80E53AE937203E4EULL,
		0x89BD1D7347EBFD70ULL,
		0x498EC9D06DBC3A3CULL
	}};
	t = -1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA49DCE49929A9F7DULL,
		0xA0DED27B9FD6C918ULL,
		0x56354D61C1CEA879ULL,
		0x744F3339E79713EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA49DCE49929A9F7DULL,
		0xA0DED27B9FD6C918ULL,
		0x56354D61C1CEA879ULL,
		0x744F3339E79713EDULL
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
		0xDECFD7A7ECC48BD9ULL,
		0x39C7B78CAC0436CAULL,
		0x93FE08EB5C5B0CFAULL,
		0x581746B84F474456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3F33B559448074CBULL,
		0x1FA8992A5F0501E5ULL,
		0x43BB2BEE1B5B9316ULL,
		0x1356AC09A3F6C1F7ULL
	}};
	t = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x04E1FDE8A492878FULL,
		0xAA2A7A61927C6CF7ULL,
		0x9EF4DAF8B0DAB3BAULL,
		0x4C44FD3298DC7956ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7D111D3BD0BB1784ULL,
		0x1F6E944E3569A48FULL,
		0x874272E21D939430ULL,
		0x6325D0855E6CC0F3ULL
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
		0x776596031796665CULL,
		0x2002A6E0145DDEA8ULL,
		0x96F773FE1FABA114ULL,
		0x095DD51BEA21F01FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAEEC5BE6F7335FECULL,
		0xB65744B7CAF2C99FULL,
		0x5BCC2A01F3EDE2FDULL,
		0x1ED1B30877F7A34CULL
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
		0xB4D23596A70C2485ULL,
		0x35F3BAABE7BC8C7CULL,
		0x25F4F7CF3B6BD551ULL,
		0x232273B7A1B01E6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4D23596A70C2485ULL,
		0x35F3BAABE7BC8C7CULL,
		0x25F4F7CF3B6BD551ULL,
		0x232273B7A1B01E6EULL
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
		0x92D0A2E6B721E0B5ULL,
		0x4F20290B10889840ULL,
		0xE48371302E01BCA5ULL,
		0x09BEB7F65EABFB99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E5FCEBE0CF974E0ULL,
		0x4B5217DAE4B9D5A2ULL,
		0xD799BB4CA9FA05EFULL,
		0x59E67C3F5E14C419ULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x743D297AADA337EEULL,
		0xA9EB25AB9D9B866FULL,
		0xAF2F920A9A45F567ULL,
		0x3D1D69B82B82DD83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF36AF6727652561ULL,
		0x15018F165D1BE32FULL,
		0x3C3402F0EC7F7CB5ULL,
		0x005D38645EC61227ULL
	}};
	t = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCDD62A69427DA61DULL,
		0x2431EB77D98B9877ULL,
		0xDAF63D690EFC5CD0ULL,
		0x1AC564EA160A6321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9A2A7546FCB0CED2ULL,
		0x0B75AEC8481B47B8ULL,
		0x39994506D16C909BULL,
		0x2634A52902012399ULL
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
		0x8D91FEC001FB40B6ULL,
		0x83235B59404C3923ULL,
		0xA0CAB3E016DAFA8DULL,
		0x748E3D49C45674D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D91FEC001FB40B6ULL,
		0x83235B59404C3923ULL,
		0xA0CAB3E016DAFA8DULL,
		0x748E3D49C45674D3ULL
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
		0x1B61347E898C7B63ULL,
		0xDEF36DDDE53E501FULL,
		0x5EA63284AE762509ULL,
		0x6C8B8F1310B50BFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA76DC013D60780E7ULL,
		0x38287101C76E493EULL,
		0x00B4162187108F40ULL,
		0x5FEE21FC97BA80B2ULL
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
		0xB45583E7B36249A2ULL,
		0xC7BE60DDC24BEABFULL,
		0xA16660252E465A77ULL,
		0x567D4CB0EEE31364ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF7D0CB29E305B8EBULL,
		0x2005692E1D335430ULL,
		0xD65405CEFEFDCCE7ULL,
		0x1C9E9F4F4181265CULL
	}};
	t = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDC12EA190F588D23ULL,
		0x1C1FC1DA3F589981ULL,
		0x5AE4AEDE080F8B6AULL,
		0x44FEC0ECA34107EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x08F762F82D2CDF87ULL,
		0x2BF8639AA86B9F9DULL,
		0xC0946523D234ECE3ULL,
		0x4EB62A4A93382FE8ULL
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
		0x73130CB86F3C2DEFULL,
		0x4E20DE5526B986F0ULL,
		0xA805F3A097A5D967ULL,
		0x07E83CFEE7EED9ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x73130CB86F3C2DEFULL,
		0x4E20DE5526B986F0ULL,
		0xA805F3A097A5D967ULL,
		0x07E83CFEE7EED9ABULL
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
		0xA14E9A8D232BFAEAULL,
		0x261736828470BE6AULL,
		0xC90D4F06147E276EULL,
		0x1BDC0B0A18E14326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33BC42E034636DA9ULL,
		0x678A9635122C5552ULL,
		0x6CB53367F2E5C090ULL,
		0x6B4205D25150F7D3ULL
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
		0xC27241DEF9D16D0AULL,
		0x3F9D3BEA3D66B38FULL,
		0x02BFD8861B88DA99ULL,
		0x0785B077D33E4EAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA98A833CA90560F5ULL,
		0xD8A741AB2E893EDEULL,
		0xE228523E5E2307CFULL,
		0x0F9585ABBAF8721EULL
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
		0x5BF0E2F895F5B5C7ULL,
		0x2EE82C2334956443ULL,
		0x9228C4F4140A7EF5ULL,
		0x5FCB3A2C2F3E2A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB8F0C1702F54F2C9ULL,
		0xCFFDC2B83C971570ULL,
		0xE2314CA9AA5D8CE5ULL,
		0x1A7421159FEB6C10ULL
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
		0xF8B3A25FA42AF7DAULL,
		0x4F66E5B59435E0CEULL,
		0xDD1101481F3EBD90ULL,
		0x33C6DF4C0F9E1B11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF8B3A25FA42AF7DAULL,
		0x4F66E5B59435E0CEULL,
		0xDD1101481F3EBD90ULL,
		0x33C6DF4C0F9E1B11ULL
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
		0xA7BDCF4C8C91EE64ULL,
		0x4AC02AF1F5CC9849ULL,
		0xF9B2C34726D28888ULL,
		0x160A798FE7B3D419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E2337685FF59B84ULL,
		0xD7E9453FCDE3C79CULL,
		0x670397C76F056B29ULL,
		0x6BC8D8ADA84523CBULL
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
		0x2AF51D717681D7CFULL,
		0xD3957956E851A495ULL,
		0xE1121489FF992B7BULL,
		0x44D709DF686CA5D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x255719E79DF6A06FULL,
		0xB69E3178BEFFDF21ULL,
		0x1CAE79BDB5C89754ULL,
		0x6F1ED9A46C44AB0FULL
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
		0xB872BD7AEBB72B8AULL,
		0x90EED1261C22C70AULL,
		0x8DDEDFC53E496C66ULL,
		0x74E196200FE8B720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4156812915297457ULL,
		0x131B9F654E8ECB6DULL,
		0xD55EAC7C1A834224ULL,
		0x242E92D72C87E20FULL
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
		0xBEF110F246A1AA7DULL,
		0x8661F11A10F3ED3CULL,
		0x3566215DA4375968ULL,
		0x6AF4DF8E3877E742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBEF110F246A1AA7DULL,
		0x8661F11A10F3ED3CULL,
		0x3566215DA4375968ULL,
		0x6AF4DF8E3877E742ULL
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
		0xC4B7C290FFD2D165ULL,
		0xE1CDBE03FE236979ULL,
		0xD2E7B07D0AED15C0ULL,
		0x73593265FE404614ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1C46B6DD048DB728ULL,
		0xE58FF00B83E348D2ULL,
		0xB654A8C147E98AA5ULL,
		0x6CDB4DCD2B1AEB3DULL
	}};
	t = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x73922D5762323E83ULL,
		0x7D01582513BD0BE8ULL,
		0x0BC42AEF00C990ECULL,
		0x651A39963744BD8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF660ED82C0FB8AFCULL,
		0x937C245FD8124B8CULL,
		0x811CE9D2FD00DF1AULL,
		0x694628D669025C58ULL
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
		0xC99F5A7C844BDA68ULL,
		0xA81CCE4C0D00E3A8ULL,
		0xF3B745994D5C9005ULL,
		0x33F5704D0F0366E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD996B2F93539137CULL,
		0x2FF7011AFB9925CFULL,
		0x335194E86A1E1407ULL,
		0x27A445818919EB09ULL
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
		0x6F807D73F4EED8B3ULL,
		0x737CD29E484389EFULL,
		0x8FCEC1A22868B610ULL,
		0x4FDCD726865CC7E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6F807D73F4EED8B3ULL,
		0x737CD29E484389EFULL,
		0x8FCEC1A22868B610ULL,
		0x4FDCD726865CC7E2ULL
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
		0x2F686D52DB8B45FBULL,
		0x4845604EEFDC3302ULL,
		0xEA49F54C161D802BULL,
		0x37969BFA04E906D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA15E77893CF9F9D7ULL,
		0xA32FAAEF2CBAAE5DULL,
		0x6EEE0EEEF0E1EE39ULL,
		0x3BB2FDB6643E1A83ULL
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
		0xCEAA125B178DF0FEULL,
		0x3560046EB2741530ULL,
		0x01BD0DCD44D3852DULL,
		0x14C05FFACD1D8FA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF5DB074BCD6B7BBULL,
		0xBF0BB6A8D408A2D7ULL,
		0x63A2C35D52234805ULL,
		0x35A73EE01296AC23ULL
	}};
	t = -1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x995A5BD9B5243037ULL,
		0x4F5E573EAB50A828ULL,
		0xF565EBB20938F8BFULL,
		0x7C5E8D6086547662ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4ACFDFF694B1672CULL,
		0xAA8B225E271CED1CULL,
		0xD20B13E2BE9093D7ULL,
		0x2F3C9CD232C729E4ULL
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
		0x84B4FBD2BCDD7DEDULL,
		0x4DD06BB91E6CB853ULL,
		0xB68BF32DA1D0D3B0ULL,
		0x0660F2842564AE52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x84B4FBD2BCDD7DEDULL,
		0x4DD06BB91E6CB853ULL,
		0xB68BF32DA1D0D3B0ULL,
		0x0660F2842564AE52ULL
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
		0x8847AD7DF1AD384AULL,
		0x83853E0F45BB66F5ULL,
		0x4C419C7006C28AD6ULL,
		0x68853D14CA77997FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x719A6E66C697D8F0ULL,
		0x5A5DE920CA3B332AULL,
		0x42F1916481A00355ULL,
		0x291E581B37FC001EULL
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
		0xF522E15964E374ABULL,
		0x4C523B11FFF19C63ULL,
		0x316AF4BA17B8D04FULL,
		0x730AE57AC822988DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6D1A8CE60C343219ULL,
		0x7C413F58FD2B5750ULL,
		0x15D2902FE5A34F7EULL,
		0x5B2397D4D0CAA34BULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDDE714934CDBC9C1ULL,
		0xE5390D1E0AB5FC92ULL,
		0xBF1AFC4B38B2862BULL,
		0x1C326BBC41D5D92AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E63FF83FEFCE0F4ULL,
		0xE3643E2487E99C0EULL,
		0xB2D79CA4ACFE857BULL,
		0x5EB4B529D6CAA941ULL
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
		0xF36E86C54C8D8245ULL,
		0x3068AE8067990235ULL,
		0xEAB4427D66E2A635ULL,
		0x514F8CFCF4F61445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF36E86C54C8D8245ULL,
		0x3068AE8067990235ULL,
		0xEAB4427D66E2A635ULL,
		0x514F8CFCF4F61445ULL
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
		0xEDB2847C82951596ULL,
		0xAE29AB961EB91956ULL,
		0x12BA7E2C2075AED0ULL,
		0x0991121683ABA153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA2ADBCAFF9B73E12ULL,
		0xBB6C16BE076814B0ULL,
		0x8B8F0C99D52D3487ULL,
		0x08B94A93ABB017CCULL
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
		0x773FE62091858885ULL,
		0x175431A589D40440ULL,
		0xD5C32AEC15984792ULL,
		0x234E12AE17EB8D3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF9363646E93BB2DCULL,
		0x6912B72C943EF87BULL,
		0xC727BA5CFD040ED2ULL,
		0x1EFB53337E86F0A6ULL
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
		0x7990D2AD6605C594ULL,
		0x2A74D64762AB5A1DULL,
		0x355683AB94CC5CF9ULL,
		0x628E9B3C92439D1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62D652FEDFA1FA5DULL,
		0x05B602D04BCE018EULL,
		0xA228869CBE32DC36ULL,
		0x4D19C8725519505AULL
	}};
	t = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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