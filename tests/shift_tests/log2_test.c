#include "../tests.h"

int32_t curve25519_key_log2_test(void) {
	printf("Key Log2 Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x9F9C8B11EF2E60B1ULL,
		0xCE6519C8B4AEEB50ULL,
		0x60CFC6AA47FEE83DULL,
		0xB1F082ADC359AFD2ULL,
		0x4CCF9A659D0C40F8ULL,
		0xB61C2D4AD749E6A6ULL,
		0x2FC7EFCC6572DF1BULL,
		0xCA71CDEA6059E595ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	int64_t la = 511;
	curve25519_key_t r = { };
	printf("Test Case 1\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k2, COMPLETE);
	int l2 = curve25519_key_log2(&k1, &r);
	int32_t res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x08F6046CD13D0F4AULL,
		0x47C73982B2B233E9ULL,
		0xFDBD2D103B2FD4B9ULL,
		0xB60CA95F6C2A416EULL,
		0x6F03601781DADC8FULL,
		0xFE138D33E47987EAULL,
		0x700241698FD4B35EULL,
		0xAACF7685B5AA573CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 2\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA5E673C0ECEA3876ULL,
		0xDC403E30F9AD2E62ULL,
		0x8BC6C814A63AAE8AULL,
		0xD5688A238194418AULL,
		0x3B430506F727C0E3ULL,
		0xD9D61093662CDA47ULL,
		0xF8B44CE0E5D5D7D0ULL,
		0x2CD85C8D693A2F34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 3\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBD825B3842F11B26ULL,
		0x8FBCAE1C0401558EULL,
		0xCA0C38A941D0C8A0ULL,
		0xFDD78D5E28B0179AULL,
		0xC37F688CB2202C73ULL,
		0x7D856F65E912DECDULL,
		0xDF24F7D3FD74F841ULL,
		0xD8DA5B8B26FA5230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 4\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF702AC0E14EA1A96ULL,
		0x9D40385D25BE2FD6ULL,
		0x32BD0C3BC4B77A57ULL,
		0xF9FF8EE1B4CB61C2ULL,
		0x8C19C8D86E9D83D3ULL,
		0x22E3040E9A231452ULL,
		0x3B85F03304D5C5B8ULL,
		0x576CE8A32B6220F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 5\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC6E09B1FDABF5165ULL,
		0xF078F07ACE3198E8ULL,
		0x29E8C2C88B0EB6BBULL,
		0x8D751895164A315BULL,
		0x0C81B5CFCC5874D4ULL,
		0x3FFF1DD293A274FCULL,
		0x49ED1C9BF2724EC5ULL,
		0x8ACEDF7611FB5514ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 6\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF750FACF7455A0E2ULL,
		0x39D4B0690C95D0B7ULL,
		0x700DC6ED9BCB8481ULL,
		0x82591DB76C7EEC44ULL,
		0x137D514F54700ECDULL,
		0x4FFCDC521F1A90D4ULL,
		0x6D11BCAEA890A213ULL,
		0x3FF326EC1EA789F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 7\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2A66D631CD6F3426ULL,
		0x2735157FB999B263ULL,
		0x35FEB00E59B87E2EULL,
		0x545BB99E382E0B5CULL,
		0xCD8B51662CC2E684ULL,
		0xB191DFA38B6054ACULL,
		0x5B88C18C78777651ULL,
		0x547F322D807329C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 8\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x42F358CDE8FEF3ADULL,
		0x478FF44CD9F1195FULL,
		0x28C428631B9F5DA9ULL,
		0x6F0D0291D48CA707ULL,
		0x556A2D7EB1676D45ULL,
		0x6A5BB209932B9432ULL,
		0xCD96BB5B76B88725ULL,
		0xFA763BBDB4FF5CA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 9\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD01AB2B2AD5E3FEDULL,
		0xD32D1570C0E08500ULL,
		0x87B586484865F44FULL,
		0x3F335C4D5700C74EULL,
		0xEBCF695AE9B17315ULL,
		0xF2A31D12EC86E657ULL,
		0x54E2CB3DF985AD59ULL,
		0xF1C6848E1623A9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 10\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x76CC9C721336AAD3ULL,
		0x10AD24412F3DC567ULL,
		0x307D7B3563E4EDFAULL,
		0x4AF9E0DD61F5E921ULL,
		0xE392A39A80CAB639ULL,
		0x70E44461FD3B5B56ULL,
		0xDC410C96549467B4ULL,
		0x9F030AAC856B5227ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 11\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9B7718B2F3790F89ULL,
		0xCCAE0687F2E87EDBULL,
		0x26FABCA2E152CA87ULL,
		0x1EAD4D3154AB0AC4ULL,
		0x5E970AFF3C913644ULL,
		0xF774F8B1E1D8399DULL,
		0x2FDDD779AEBA57FCULL,
		0xC13B3FDD7F51CC8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 12\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCCBDD87BFC34BA41ULL,
		0x6E628C3BBFD19E49ULL,
		0x67753661FD58791BULL,
		0x754C7758EF6693AAULL,
		0x3226EEB4FD2033B4ULL,
		0xA496674DB1545FCFULL,
		0xB417DF4A15E92AD2ULL,
		0xD44EE1A42749394FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 13\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5F56E089B719CDD4ULL,
		0x0A37DFD9D10D3617ULL,
		0xF561EB31AAE94A8AULL,
		0xE1F7FF4A3DD5636CULL,
		0x0C39E5A93C07561DULL,
		0x40F23E0BE9F02FEFULL,
		0xD5EF268BE3EEDFBBULL,
		0xC8BB158B19A0DC67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 14\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB51D324BEB5B811BULL,
		0x7D8679F50CFEF985ULL,
		0x3BE543B540AC0921ULL,
		0x86574C0A88654442ULL,
		0x70A5CA9172445484ULL,
		0x352907B471DF00FCULL,
		0xF7531469B37AFE62ULL,
		0xF44290F44C7C41A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 15\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x897F214988CC7CBFULL,
		0x676261C4F97A6436ULL,
		0x2C4C948FB70081EBULL,
		0xCE46B2758549AEE2ULL,
		0xB2F691EC0FFAD987ULL,
		0x28617D03635AFD28ULL,
		0x9B6674F837C8A259ULL,
		0xE74C06AA9F605AA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 16\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF248516EE1E152DBULL,
		0xE48480A2657F6EA8ULL,
		0x529C6681C9BC1D3BULL,
		0x0DB0CD47C917E399ULL,
		0x2299FF0DF36662D3ULL,
		0xA400796CDCA7D5D7ULL,
		0xC9B780E0EBBADAAAULL,
		0x2F87E371D063BEE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 17\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1F0F68446624EE00ULL,
		0x1987C58EF159D9C4ULL,
		0x9C3549E315812148ULL,
		0xB1CACCFB378E5CC8ULL,
		0xDD214AE06A69C98FULL,
		0x09A8CAC57DF60F4EULL,
		0x5C9E0E6FE993416AULL,
		0xEB64B4A639D8985FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 18\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA01E99078BB2D287ULL,
		0x89215976D6DD7BECULL,
		0xC743451A9CD140EFULL,
		0xFAF083611DE86AFEULL,
		0x5841E9F46F498BB8ULL,
		0x10B21BC57C6D4E49ULL,
		0xF3B2D1D081D4D0DCULL,
		0x8F08049494FF1386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 19\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF61855B0945B82B1ULL,
		0x30F6A981BC003545ULL,
		0x983BA32F40FAB6C9ULL,
		0x8E7D5E08A31F25A0ULL,
		0xC2D6ED74086CACDCULL,
		0x6A60CEAAB22A2F2FULL,
		0x81A8358AFE9C58C0ULL,
		0xF04E2DBA131FF323ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 20\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB777EC10934BC077ULL,
		0x446E01462E4156EBULL,
		0xB3D57C097A36CB8BULL,
		0xE2217BE16DBE82C2ULL,
		0x5EFD1A77345654A3ULL,
		0x5612DE4CBB434B62ULL,
		0x45DC8E097628F18DULL,
		0xA7A37B2E7AF8C8BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 21\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x46814AF37FBCF22FULL,
		0xB97AC43626303C44ULL,
		0x9E67FCA9E3405936ULL,
		0xF76623BA504408E9ULL,
		0xD6D202B4F0BEB6EDULL,
		0x1E6F8BA1540D8D69ULL,
		0x7ED91B0682E7CB4BULL,
		0x36724A48B476DA89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 22\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x406D5BB63EB906ACULL,
		0x2D1D266E496C8C0CULL,
		0x0B919C47E2DA91C6ULL,
		0x0BE2DB86146E5AD6ULL,
		0xC335C7FD8C072205ULL,
		0xE97AAC52475D18BFULL,
		0xBA35D7E555659539ULL,
		0xED5BF09927F2D286ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 23\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF20827A12D61CFECULL,
		0x707C50D97D0F8292ULL,
		0x8217A395627FDF9BULL,
		0x2318F60A0A476C5BULL,
		0x181F9EE481DF8A21ULL,
		0xB4F6A4D615E70269ULL,
		0xBCE72EDC687BEFE4ULL,
		0x44C62A87B2AC60B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 24\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A638883BBA6CF94ULL,
		0x0F3ED094C9D7F87BULL,
		0x9FE4C2466FE3FCC8ULL,
		0x6575E65988B2458BULL,
		0x0C50FB86F4FA80FDULL,
		0x66EEA4385926105AULL,
		0x96FBE8DF20455FFBULL,
		0xFEDC2E3709248FDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 25\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8DCF787F6DDCBB29ULL,
		0x6DEC6BC3981EAECBULL,
		0x9F68B8341F56D6A0ULL,
		0x7D2CBAA29D8F4913ULL,
		0x868EA8395EF88B34ULL,
		0xCDBF66CCC0CC81EEULL,
		0xD73FE4BD7A397C49ULL,
		0x94867E52CC1B7AE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 26\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE44193DAD2A4E15CULL,
		0x92568F75B3496B06ULL,
		0x35EDC1F4A34489F8ULL,
		0x2FD73C7D7B4A1BABULL,
		0xC795E3A5D520A22FULL,
		0x8FB6BB0683616800ULL,
		0x525DF17D5DE0B0D9ULL,
		0xEF6D62D8257FFDC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 27\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x93977AC4E4B9488FULL,
		0x5749980CA12188C5ULL,
		0xD37C019F8FC95695ULL,
		0x0553A40973CAE702ULL,
		0xB162A6462A890E60ULL,
		0x32BC474E3AD18CCCULL,
		0xEE53B42B479FBC79ULL,
		0x5469CC578FF5726BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 28\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD3015053EFE5AF7CULL,
		0xD6F9712690852DFAULL,
		0x82F059FCC9B3F809ULL,
		0xA83BD4B551EADE53ULL,
		0x34CB954E9A8619D0ULL,
		0x0ED8076097842B9EULL,
		0x99D6FB74E1E8F902ULL,
		0x6424B1698BEF3BDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 29\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5136BE6B46AA136BULL,
		0x687B680B3D6B3F72ULL,
		0xDCB45321E0516830ULL,
		0xA16810D071E02FF6ULL,
		0x0B284248B08104A1ULL,
		0xA018A3AD74A6BE50ULL,
		0x6CE8332C4CE4333FULL,
		0xD2B58E5FDD9E0C95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 30\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3201D6502555F022ULL,
		0x724A8800246EE07DULL,
		0x76EAFD30019C4C47ULL,
		0x6A712749C5227E11ULL,
		0x93A263288AA4DF41ULL,
		0x278D1B95EB9693EBULL,
		0x5480C93F262C9122ULL,
		0xB9B0B1A5F532B136ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 31\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA47067BB148E168EULL,
		0xAF1949479EA7E75AULL,
		0xE674E48F33989C5AULL,
		0xC300E49FCE7CB805ULL,
		0x4F264AA449C9F018ULL,
		0x825680C3AD6E14F1ULL,
		0x3D382F6F8F268650ULL,
		0x83BF5ABC35C0D619ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 32\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0F2A26BA328FD17DULL,
		0x1C532C30A2F2F51DULL,
		0xFC8C98527AF27402ULL,
		0x34E91E01FD6573F7ULL,
		0x2BBA34E4BBD2589FULL,
		0x422B3FB3BDAA0A52ULL,
		0xB18D268F24E8FE97ULL,
		0x5098C0656EFAE85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 33\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x50736C8A97952583ULL,
		0xF14425A8FCD1FE53ULL,
		0xDE065546DCABC941ULL,
		0x8BC042C52D80993EULL,
		0x23273584EB7AC20FULL,
		0x7C17B41AA7C1FFC8ULL,
		0x16E9E196EFFEE8BFULL,
		0x25D571E5E8E0B5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 34\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE9B536E163AB7C50ULL,
		0x0133791F4E70B0FDULL,
		0xDBE9FDA001B8BFE3ULL,
		0x8E11D557C31B2B5DULL,
		0xB3BE012D4D53F97CULL,
		0xD7FD057D7F2459F6ULL,
		0x0D7AFB5A394663FDULL,
		0x43D0F2302802BAB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 35\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x41628DDE2AA5DABDULL,
		0x93546D7CFFC17A90ULL,
		0x436D37DE03092D57ULL,
		0x288B976979F2CA8EULL,
		0xF3B566F453EE6361ULL,
		0x3F7432E196C6BA39ULL,
		0x80FECF1C3FA0204DULL,
		0x0AAE50547F096EBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 36\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0A562C279115B2F4ULL,
		0x144323CB89BB2262ULL,
		0xE259D07713B0EC9CULL,
		0x9322A8BCB11C277DULL,
		0x060DF22F3FDF3288ULL,
		0x09CC139515F7B15AULL,
		0x8DBDDFA289C18D99ULL,
		0x2458B3189F754D47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 37\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2FB9DD5C45935CDDULL,
		0xE1D407DAF11D717AULL,
		0x8081CA9E43EC0C32ULL,
		0x9F1625FE466A02FAULL,
		0xF766255FB8D1BC85ULL,
		0xA403122ABBE8051FULL,
		0x4770AED1AD7E3F5FULL,
		0x187A0B60C07960D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 38\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x720DBFF2973CF9CBULL,
		0xBEACE6D924B8CB07ULL,
		0xAB65593B8942DF30ULL,
		0xE10EED3E99604FBFULL,
		0xAFDEE81DDBDC9717ULL,
		0x8AC393D925D02649ULL,
		0xBF1AD2D1652A7C6CULL,
		0xD493C6BA06F63546ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 39\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB3002BE00B62A442ULL,
		0xC476486BB56748F8ULL,
		0x0891046AEA368A8DULL,
		0xFFAC9183B61A1E16ULL,
		0x648916A181E82EBFULL,
		0xE4A0F741380BBACDULL,
		0x0DB20CB0DDC061B4ULL,
		0xBEB4B1A84BF0E564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 40\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFED108B18CD8C52CULL,
		0x295AFB531924208AULL,
		0x2458AFB9EC55F069ULL,
		0xB33FEFDAABDA2331ULL,
		0xB6F61FF75D04E6ACULL,
		0xEC1539BECA1BD195ULL,
		0x34FCB805C71EB573ULL,
		0xAE8309EE9A0E1DF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 41\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA326A15AD718F130ULL,
		0x910D5760B64F3800ULL,
		0x4792D85E04E7332AULL,
		0xF33F2AF4775466BEULL,
		0xD0420A4FDFB5278FULL,
		0x0678FB4EAA49A53CULL,
		0x6F88DFA74F01B1F8ULL,
		0x3E0E96196B3BE37BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 42\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x740B121AE50698D2ULL,
		0xA89D3281936632E4ULL,
		0xB7A247688DD29F3BULL,
		0x0DC7D5A974EAA877ULL,
		0x68F3A21153162025ULL,
		0x3C96C3930DE044C1ULL,
		0xCE85A4D0892DDEBAULL,
		0xF3B94E09DC0A484AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 43\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x839426D9A31919E9ULL,
		0x67B03759E2082B6DULL,
		0x82375F94E7CAE3D7ULL,
		0x21A75C3E5E59984CULL,
		0xD39A7FCC3AF7EADEULL,
		0x586508D70F7145C4ULL,
		0xC15A7BB352AC9FC0ULL,
		0x39CC3859EE9092B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 44\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x27326BC544DB65B3ULL,
		0xA87E8554E7BAFC2EULL,
		0x107432168F246489ULL,
		0x9DD03835AD55876AULL,
		0x186E644821EB2A47ULL,
		0xF211CC00A717B446ULL,
		0xB22CA0F9C5F11C85ULL,
		0x3E41140252712948ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 45\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x28A3DE524844C943ULL,
		0x0F97FDB1B87DEBD8ULL,
		0xCE7CFC0113359E9DULL,
		0x348EC4372FB84AF6ULL,
		0x671D9D54D8E625E3ULL,
		0x9CFEAC8E11EDFEB2ULL,
		0xAD82E6A474693A4BULL,
		0x130C5FA4E2294854ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 46\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2C373F264716A2F9ULL,
		0xF7D61142C653E91EULL,
		0xE9A745EA9BF4F43CULL,
		0x2F8BAFCF827328B5ULL,
		0x805F9FCA80D03747ULL,
		0x8672F2D1CA708984ULL,
		0xE9F23A60F90F327EULL,
		0x1ACE241EA94F0F3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 47\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x43CFC90B23E54F24ULL,
		0x99160F4D1F8668B5ULL,
		0x11B68518E9CA9204ULL,
		0x5C12D9A8961B311FULL,
		0xCB1691AEAB385D1BULL,
		0xFEF35FA1722AAD30ULL,
		0x435A1AA3BA948F3EULL,
		0xF9ADCBF64C3327CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 48\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8D236F4212EE5B84ULL,
		0xBA7379C4B22F8806ULL,
		0xD82608E655668347ULL,
		0x4D6E742A38129ED7ULL,
		0xF538C0A72629F60DULL,
		0x53BD7B5B742BC2CDULL,
		0x0A045BCBE0F38EF5ULL,
		0xC5A5DB03E8D14B09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 49\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7E966048638B250FULL,
		0x703FD65A4FCE7982ULL,
		0xD59908E10D9BB8BCULL,
		0x169443F53448854AULL,
		0x5AFB744062D4FAC6ULL,
		0x749057B619EFA31CULL,
		0xF1FE67098C71500FULL,
		0x3441CEDEACE10CFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 50\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCA7D5A976201841DULL,
		0x8BFF0CAE68DFEE57ULL,
		0x5D1DE13CDC11D371ULL,
		0x926DDD12DA73918AULL,
		0x520792C79E4BC017ULL,
		0x01C3C2EFFC365D86ULL,
		0x837B09153A3FE7ADULL,
		0xDBF28AB3E6203E2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 51\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x11072E0CA54BA07CULL,
		0x703E43D0493E7E19ULL,
		0x28CFFABE0FABFACFULL,
		0x65433EE76AA7E58AULL,
		0x26AC4786BBA84D43ULL,
		0xE088800E2C58E350ULL,
		0x5DF674DF0113056CULL,
		0x2E8EEB2AA566A0A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 52\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x25F2CD91F2F97854ULL,
		0xF6CB88E7DB41554DULL,
		0x0FCB86DE859D5162ULL,
		0x1C49C6B56BB25DC5ULL,
		0xB763DF7FA120A139ULL,
		0xF30C6BCAA6371362ULL,
		0xFB635D226C952D37ULL,
		0xF404D48112376F76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 53\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x27D8B9993E08E95AULL,
		0xF4E102EE9F6A1747ULL,
		0x3319EE8A43E9E07CULL,
		0x2B8C6EE0F8AAB453ULL,
		0xCB1F8FD24C58074DULL,
		0x09D848ED7F470946ULL,
		0xCE588386F38FEAFEULL,
		0x7612904F83851433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 54\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF9DFFCDBC2572E0BULL,
		0xDD2AAF850192A76FULL,
		0x020158D23577C5DFULL,
		0x5999592FA5E0E18FULL,
		0xA9B22CD4370254CEULL,
		0x6AAAF4520A4B1ECAULL,
		0x993B53EABEC51CABULL,
		0xEC9C0202543AA100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 55\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA7D321F645603AD5ULL,
		0x69564940181CED01ULL,
		0x00DE5D0395319C4CULL,
		0xBE86323745BF2D99ULL,
		0xE7555B08398674CEULL,
		0x78D16F7438262904ULL,
		0x4FFE4569AE10CDDDULL,
		0x160B9C3E5F3D3D57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 56\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEBDB550AB463CA17ULL,
		0x64C622B61C1C26AAULL,
		0x40F6931C3D7A8EB1ULL,
		0x9AC31635D17F89B4ULL,
		0x99CDB7E73518B112ULL,
		0xE393254A73D772F3ULL,
		0xC234146015A134A8ULL,
		0x638371AD6AC479B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 57\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x44BD28C3332A833BULL,
		0xE09A3B6DB7E17A49ULL,
		0x29409B3437D5812CULL,
		0xF199E3BFFAC71BAAULL,
		0xB5AC8BD1218324C2ULL,
		0xD892771AAFC3FD5AULL,
		0xB7352980286BAFE7ULL,
		0x4ED7D784FFAC670EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 58\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7F8B8A975F96B0D2ULL,
		0x18F4E94AC9223BBCULL,
		0xDAE60C0AF10821D2ULL,
		0xCD5132B7153F510FULL,
		0x00E1E4958B8D2A48ULL,
		0x5173A95B5003B891ULL,
		0x338EC6DB1C15C2EFULL,
		0x6A521936D60950DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 59\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x95801F80EF91D379ULL,
		0x46AEE1FA42EB3646ULL,
		0x43BE05F76F6C5ADFULL,
		0x85662F1B7F10ED2DULL,
		0x8AFDBDFE70AFF018ULL,
		0x7C915B3D3705D131ULL,
		0x9276609C38949889ULL,
		0x6DB53ADCFF51F9CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 60\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3C9EC054338C184EULL,
		0x44D7EB7A8B0B1491ULL,
		0x9FD0184B01BA95DDULL,
		0x3D71A87CAE20E587ULL,
		0x59801FB5C6D1C0FEULL,
		0x0BFA49BDB3524264ULL,
		0x2DCEAEA1FD0F2EC6ULL,
		0xBB863394A3E6AD5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 61\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2919808D7CF7F3B7ULL,
		0x2526462CA552F52DULL,
		0xEC022AF2E9DAF156ULL,
		0xCA405B64721004B3ULL,
		0x48B7DA004F102529ULL,
		0x643563A103915107ULL,
		0x4B2D924CDDA1E5FEULL,
		0xFC2951CBF685E99BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 62\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF2AD478C99044965ULL,
		0xFAFF164B65672E6EULL,
		0x9C79D13FEF8CF261ULL,
		0x416E46EE6BF403C3ULL,
		0xBFF2ADEEF47C0208ULL,
		0x67D8600CF8D74571ULL,
		0x87B409EA7A7DEF8DULL,
		0xF31252BAE1B6F2CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 63\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC9C1A7CA855C4499ULL,
		0x025957AA024122DEULL,
		0xA166383B37A69852ULL,
		0x162CB07028BE7EF8ULL,
		0xE19042BC3468BD1DULL,
		0xCA9E03A1CD296B1BULL,
		0x6B629C7546BB38E9ULL,
		0x906DC7EEEEC619E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 64\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBF757D78968A9252ULL,
		0x820FA9E45E9BC034ULL,
		0xCA19B897D105BF77ULL,
		0x49A04D91416134BDULL,
		0xA68F56526F8CCDD5ULL,
		0xE5267E6FD3422F48ULL,
		0x495F58A640642266ULL,
		0xF870E084B14EBFB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 65\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x47A1C0A40B9E1B80ULL,
		0x4ED9A24C4AD45643ULL,
		0x8F07316B5CAADAE0ULL,
		0xF7DD23E88D6D8740ULL,
		0x4BAEA8EDD0353DA0ULL,
		0x81CF8D03C1CD9638ULL,
		0xA0221F817FC2DBA8ULL,
		0x197FF3E7CDE3925CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 66\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x28F752C384B7C5DFULL,
		0x575C924E17E28357ULL,
		0x2DB5BC41C3D36BF0ULL,
		0x30361BA043D7024EULL,
		0x11614B04459DD4C4ULL,
		0xBF3815F053BA7DB0ULL,
		0x94A0D28CE0854099ULL,
		0x66F131E5CF8C2C45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 67\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB8C587C9C97F256ULL,
		0x45722BF68E5C4C5BULL,
		0x8DAA8BEA81B2FCA3ULL,
		0xEC3CA87116BD1CADULL,
		0x3A37BE0B35DB3E04ULL,
		0xE907C7EFA09D7BCFULL,
		0x483AC0091FC9616EULL,
		0xCA7AF5A3C377E33FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 68\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB8275F8616BF3C65ULL,
		0xCCF159F94CAA02ABULL,
		0x9613FAC88B94D34FULL,
		0x8A8AAB697F7B6E9DULL,
		0x819010267F6A9200ULL,
		0x72A6816D8340B7C5ULL,
		0xD472483D46890691ULL,
		0xF4975A0D91A62B68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 69\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x62F681800D35AF81ULL,
		0x6F2BCB1E53654335ULL,
		0x4403A9EAC76E691CULL,
		0xB16193ACBD41B7EFULL,
		0x2708F57A1B30DD51ULL,
		0x4305FB33E005B12CULL,
		0xB0CE84CAD97A1F4CULL,
		0xD2F69272609CA38AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 70\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5DBAC14F0AB57AA8ULL,
		0x462D46938FB70B51ULL,
		0x20EBDD93FC9F7AD2ULL,
		0xE271858F26BCB88EULL,
		0x52AD0B5C9AE6F06EULL,
		0xC80798D9F29A9CC1ULL,
		0xFF8A915935DE71FAULL,
		0x2721A367B48AB965ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 71\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCE2F761B2725639CULL,
		0x6823586F1221B157ULL,
		0x20A705066758DA8BULL,
		0xAFF4A4D18FBAC5F8ULL,
		0x8B9E59604EC8481AULL,
		0xB671E6E17E123B81ULL,
		0xEA3EEDD5745107D8ULL,
		0x6CE027769629EB1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 72\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6FA5DA7F3C7C47D0ULL,
		0x272969081D5B93DBULL,
		0x528F41F8D171818AULL,
		0x972B50725119E66BULL,
		0xBF7C49CAECE6EE6CULL,
		0x6B55FE9798A59785ULL,
		0x4A3CAC31383BC4FCULL,
		0x18B38852A128D84CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 73\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x43015C69126F69E5ULL,
		0x69D13926DB05FD0AULL,
		0xEB1F007F140A8ECFULL,
		0xC3778CCD41FA0F86ULL,
		0x6A5033EBEC93485DULL,
		0x6D307DE027E0BF7BULL,
		0xFC88B7CEC5FBD33DULL,
		0x38FB75980D700727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 74\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1036EDEFEB8B84E9ULL,
		0x31B81E00972568ECULL,
		0xA9364AE7A239153FULL,
		0x96A9EF5438604A32ULL,
		0xFC4E0B913304BA32ULL,
		0x9CB55DBCD9CCC2CDULL,
		0x3DC2857CCB82F12DULL,
		0x6689CF3F86505E68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 75\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE0B23C8D5A8C5DE1ULL,
		0x5E86465A4CDC5CA6ULL,
		0x6005582C892744B2ULL,
		0x7D7DE2499B8FE7F5ULL,
		0xE11AD3A27B924A89ULL,
		0xADFA922761D700F2ULL,
		0x29D21F13F1E5CE3BULL,
		0x6141F513EE721DB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 76\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xFD0420A5A622BB9FULL,
		0xB5D85C76E1A800BCULL,
		0x8645925F7AAABD52ULL,
		0x4F7FCA0C0F37D3ADULL,
		0x532B41469FA62942ULL,
		0x09DCE229413246A5ULL,
		0xBE0D382D98E64FA4ULL,
		0x1B4F4D8A912A068FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 77\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1C5551AEE3116872ULL,
		0xE4477A6FECA5B827ULL,
		0xBD82601D6D134F8FULL,
		0xBF50929F34E498B2ULL,
		0xFCD6E4758A492B85ULL,
		0xFA24F59D26F51CB2ULL,
		0xB221A72D81FA41EDULL,
		0x88D67CBF378D75E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 78\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x315201DF14E2C805ULL,
		0xEC31D4FC9081A6EEULL,
		0xC1BD4F7CF674FD9FULL,
		0x9EDABAA206641283ULL,
		0x88A5CD6BF5A8A533ULL,
		0x5B4DDA87A1DA28FBULL,
		0xCFB637B91AE10BA7ULL,
		0x75EB8DC17C473675ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 79\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2CB49B6A8C2E9338ULL,
		0x948B84FBC07CF745ULL,
		0xF4DA2CE3A6537706ULL,
		0xD631D9F05874F664ULL,
		0x6A13FE9F7C2BD14CULL,
		0x5EB0A41291BBB7ECULL,
		0x12DB360C132B7D98ULL,
		0x649C57CD17472806ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 80\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8BB798893DE0EDB1ULL,
		0x5B104FFFD42EC4ABULL,
		0x77950B766BF04A5FULL,
		0x6149D3E75088E12FULL,
		0x4C377AA82FD4437FULL,
		0xEF3123735A9B9D2AULL,
		0x752F10C6061BC8F1ULL,
		0x29CA66C397E1378BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 81\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90AA1DD270B4FD4CULL,
		0xB21A435BE4CCB4B9ULL,
		0x0590454EC9F749A2ULL,
		0xC3161B331B15E303ULL,
		0x1FE6A42E1FF78F62ULL,
		0x0FCC07F076B0C509ULL,
		0x0095E920CCD6E102ULL,
		0xDB837462D6A268B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 82\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC91AB193CDF5EF64ULL,
		0x1C6EAFCADA1A3EE8ULL,
		0xF5474AF404BAAB6DULL,
		0x51072F1AFB701EBBULL,
		0xC1483354759B7A76ULL,
		0xBB4E9E7C535CF6B2ULL,
		0xDB7F9081DC8E7BD3ULL,
		0x46C268C80E9F58BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 83\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB66CE53360F4A111ULL,
		0x73B7C3816DC58E75ULL,
		0xA22F51F1B0948EDDULL,
		0xC806D698204E726EULL,
		0xA29FEB508DF09E7FULL,
		0x9DE6365838FFBDC0ULL,
		0x929D93298EEF50F3ULL,
		0xD126247243C4C703ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 84\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFD6CE29CBF63719CULL,
		0x759E69033B159769ULL,
		0x697F566F75541C72ULL,
		0x7C10279CD642964BULL,
		0x7B5842D3062912AAULL,
		0x14C6340E0A88B629ULL,
		0x7A7CE65EEDEF336EULL,
		0xFCF0572FBFC2D15BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 85\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3FFE82345BDEDFD0ULL,
		0x4B50D4E8542DA43FULL,
		0xFB1DF2052E91647CULL,
		0xD964827D88C04E48ULL,
		0x56A4EA33C70FB642ULL,
		0xB1D0DC82076C9611ULL,
		0x1E2DC97A167DAE5FULL,
		0x25093069CD20356AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 86\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x11EA7D0F4CC081DFULL,
		0x5B7E17AB337EB15CULL,
		0x85F23BFDB0540530ULL,
		0x22D8D3CACFA31D7CULL,
		0xAF4F38EAAF6B82BDULL,
		0x4FE8D2A227D7E903ULL,
		0x96DAEAB0BBD9A5D0ULL,
		0xEE146661799645A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 87\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE2B61BADA6E0E4CAULL,
		0x56AEE3131289A039ULL,
		0x5BC08192046E9E4CULL,
		0x50D2F4B328EA6690ULL,
		0x6CAB6FB8CD06FA04ULL,
		0x61F57569048667EBULL,
		0xF88D5D7E2A978AB6ULL,
		0x7C02EFBCA20776D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 88\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x928EFCE91CE73C2AULL,
		0x1F9810801C4BACDEULL,
		0x95273840BD06CCE9ULL,
		0x563F65C725EE2C3DULL,
		0xC16EDF0217AEE9BEULL,
		0x1D706CE6AB8FE1D4ULL,
		0x9143C686A8666EA0ULL,
		0x901AF98C3FD4E503ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 89\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0B104A41D3E60AF1ULL,
		0x9E3E76FE4977B2E1ULL,
		0xA59F25B4A4C73F24ULL,
		0x060400B1EAA2D7D7ULL,
		0x2964FACA44EF83B5ULL,
		0xA0E8150F90DEE8E7ULL,
		0x1E29A017824D0F52ULL,
		0x93AB5BBF286709EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 90\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4A5E9E020CAB933ULL,
		0x1A5401504C3E512AULL,
		0x6811B5834B652172ULL,
		0x8A46F8FDD5034F12ULL,
		0x9E6892594418AC9EULL,
		0xFCA7FB164B8F4B6FULL,
		0x4080AB7C82382C53ULL,
		0xB8F2DD545403855AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 91\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x79201D4AC9FA8BAFULL,
		0xC6412D2D169FE114ULL,
		0x9463388B90862C45ULL,
		0x50B5781EA4AD160FULL,
		0x088BC657847D4BB8ULL,
		0x31479ACF084121D6ULL,
		0xF487145AB0833A1DULL,
		0x2165FBEFA82CF5DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 92\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4D02A307F2BCD6FDULL,
		0x69570EAB2D4E6AFBULL,
		0x266AF2283FEFE256ULL,
		0x0F04FD2E5C283F72ULL,
		0xC6B579758A85E678ULL,
		0x605D9B49CE488F0BULL,
		0x4FF368D1CF3A55CDULL,
		0xC4AA43B3661116BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 93\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAFE9E492E3D0F4F6ULL,
		0xBCC88E89F922261DULL,
		0x0FDBBD174A75EF3AULL,
		0xB196CAB9024576ACULL,
		0x87D75BA04F28F80AULL,
		0x619ADE6465EABE7AULL,
		0x7647D59436B0EF2CULL,
		0x9DB80ABAC6E5F7D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 94\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5FA5DB7414F8B305ULL,
		0xA6CD82B371B21E4CULL,
		0x220E5AD86B47C32FULL,
		0xC057816870AC2E5BULL,
		0x5A954427EC9D5CD3ULL,
		0x916FFEF481AED637ULL,
		0xA83310CC782D7965ULL,
		0xB5C3764050A3AD49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 95\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x21CE43968CF23106ULL,
		0xFD5F124871422CE2ULL,
		0xABB92151436900F2ULL,
		0x2EC3EE0C8B450147ULL,
		0x6E2D48CEEA63D378ULL,
		0xDD808256C62CFD2AULL,
		0x10557879A8D582D4ULL,
		0x905A38D08A8EE346ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 96\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x45F17EB091F8288DULL,
		0xD9113871BA81C80EULL,
		0x19ADF8489F0C60EDULL,
		0x4F890770742BDB3EULL,
		0x7951FDE6CF5AEEE7ULL,
		0x38B433CA089B5462ULL,
		0x98262417A85C4F3EULL,
		0x202FAFE91D897995ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 97\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x17B9270C7698D94BULL,
		0xEB46E9359040825AULL,
		0x7ECA309691F9FD4FULL,
		0xDEA7CC8D85E8F36EULL,
		0xAD56566947D946D3ULL,
		0x9725D7F6E5D3B7E7ULL,
		0xD868964012797B3CULL,
		0x0DAF54648E3F5BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 98\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x610461CD896FB0A5ULL,
		0x115BEED91B428FCAULL,
		0x8185D8F97E378CC6ULL,
		0x13EDDF056FEF783EULL,
		0xC7CE4050EEAC1D32ULL,
		0xB4ED89046BC3716DULL,
		0x76446ED7F3E362BDULL,
		0x620813815F30FA6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 99\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8204A48A5AD5F50DULL,
		0x6FC7D4CF27EF7846ULL,
		0xD756C2269E79F84AULL,
		0x541E07B315578DB0ULL,
		0xF2509EFD926D6CBAULL,
		0xC8297C090DC4377DULL,
		0xCFC97A622597D096ULL,
		0x8F5B8B9A8284A3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 100\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6FB89AF9AA7CE482ULL,
		0xDD9F8818CD11549DULL,
		0x09299E126788C1A7ULL,
		0x06FD2AACF1EEA1BCULL,
		0x6613C721B60AFA55ULL,
		0xFF698F3FD9E17952ULL,
		0x0EE905D19998F4DCULL,
		0x33DF2C0A4859A127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 101\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB0F081ABD1C72F24ULL,
		0x3364C5EAAF4B0A05ULL,
		0x543CF08B26AAF9FAULL,
		0xFE900FF11D3B02A5ULL,
		0x72129C8CEC423CB2ULL,
		0xA5D3897169C76FC2ULL,
		0x729E36BE272A489BULL,
		0x5A50D5E0F234AE6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 102\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4CF918807B39DBCEULL,
		0xF5F8007026ACCAC0ULL,
		0xCFE1B79FE56224EAULL,
		0x3B4394BB20C2196BULL,
		0x187CBB31E5C12D15ULL,
		0x97282CFC9AB90FE5ULL,
		0x75BF06B849C16276ULL,
		0xED208D4058C40478ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 103\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4CCAA3C4655F8EDAULL,
		0xE59C5A3D39E66E80ULL,
		0x9179DA99AF2A8207ULL,
		0x027C7011AE47DC15ULL,
		0x1D2256B2E8F9001CULL,
		0xB6889BD3874E4AF0ULL,
		0xA3A0D44BD37D7D74ULL,
		0x2D5951E4B6498EA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 104\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD068281606C81F89ULL,
		0x645DBE73119BDF4EULL,
		0xD2F480550941A605ULL,
		0x2ACB21C64C7A6B5DULL,
		0x279D90507FB239A1ULL,
		0x0EDA1D4BFC0F6FD7ULL,
		0xAD403E07B1D9C231ULL,
		0x7B3809A3CC9461C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 105\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE2AC372FB58BD288ULL,
		0x0B8057B34DCF32DEULL,
		0x8F0797A603D39160ULL,
		0x1310A6B16EF34597ULL,
		0xC730BA8EF6C4D28CULL,
		0xFB11C43FF9F9979BULL,
		0xDDFC72EAD44D36FDULL,
		0x7FBB4AE32ABEE914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 106\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE6B675D6EAA1F415ULL,
		0xC229703631B11F46ULL,
		0x78C566D1D445F116ULL,
		0x6B51E709B32C2C0AULL,
		0x9CD10BF11A37D1B5ULL,
		0x18445486964C4C2BULL,
		0xD233196408D6D767ULL,
		0xB59FA70126CD8433ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 107\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF4EC7A8339198C6CULL,
		0xB4C5242F77E1CB43ULL,
		0xE657E9A124CCADB4ULL,
		0x2381126339D06EA3ULL,
		0xB3D074030D5BB516ULL,
		0xF6AFE47BB256F5ABULL,
		0x4DABD3AA7EF3E670ULL,
		0x65391CA8254934C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 108\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x137610474A142E17ULL,
		0xAFBCA0779E3F0278ULL,
		0xA955E9EAA97E0237ULL,
		0xF85F1A2E23FDD44CULL,
		0xE79DA6417D841F66ULL,
		0x39EE3986459B2962ULL,
		0xF07C0B9C81743AE3ULL,
		0x277CF3F3464A5CD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 109\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCAC7328E6AD1B66DULL,
		0x5D08FAC2A0C99C8EULL,
		0x33B3D9C7B8BC1217ULL,
		0xA958919C4B8E50FCULL,
		0x8866BD3584172DC8ULL,
		0x6D3FCDA99D562385ULL,
		0xAE07498A75B9C0FFULL,
		0xE94812D92AC4B659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 110\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x36DB437C2C7964F3ULL,
		0x8F793BC3041D507BULL,
		0xE5A1A94DF271BC07ULL,
		0xF4D5EA863DC00FD3ULL,
		0xF9241E760A0E55EAULL,
		0xC5DE8569C60168A5ULL,
		0x86C0B53FB6BAF131ULL,
		0x6D114BCA18873461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 111\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x683A7AB672264E95ULL,
		0x3E7D64190F44F19BULL,
		0x997285093AAD276DULL,
		0x0A27C452F3E8EC8BULL,
		0x8F3C9544AC711272ULL,
		0x900AAADE10EAC8F6ULL,
		0x6936ED5D511F1BA4ULL,
		0x78998ABBED04C688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 112\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xB47835020545DA56ULL,
		0x077E52CEB1946B0AULL,
		0xA99E05C84935DA9DULL,
		0x416593A7AC461B96ULL,
		0xCCC8DE3F7A6D5A35ULL,
		0x4EB9F4D6D0C320D1ULL,
		0xF4276869219104B1ULL,
		0x0AD4A3356DE4BE5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 113\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE6A91BDF98955912ULL,
		0x8C78C777F19D27D3ULL,
		0x06108FE5E2E8712DULL,
		0x90B7BC402AD41D74ULL,
		0x21F4D747E089F510ULL,
		0x5E3D6F08ACED55CEULL,
		0x425CB32CB81AC869ULL,
		0x0C147A9E7878BE13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 114\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x10D4E4B1AD3868CEULL,
		0xAA134B24CEECEFCAULL,
		0x352BCF983324D1C1ULL,
		0xF957202FC95E3623ULL,
		0xC7EE21BF5C2F87A1ULL,
		0x771FF6F85821C0BEULL,
		0x310078BFCA239F5EULL,
		0xF4EB5602943CC6C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 115\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEFFAA1240C58738FULL,
		0x2599EA86BBB4A3D9ULL,
		0xF168EDBDD18B3192ULL,
		0x04042B8D2E0D7A99ULL,
		0x341A3BD9E29FC3ACULL,
		0xDF8641CDC09CB094ULL,
		0x77F3686D21FABF68ULL,
		0xAE503A577B6DBA7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 116\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x24071BE454574DD8ULL,
		0x46406E35FE39D58CULL,
		0x24011527AEBF7AEFULL,
		0x6B8E335326BDCF8DULL,
		0x85E1DB641B38BF09ULL,
		0xE3578DF0CEF95C16ULL,
		0xA7F269FECCF0D7C9ULL,
		0x5D88B9F37A3ECD35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 117\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x77422A374DF44EAFULL,
		0x61823A253A3E337FULL,
		0x700FE4BED2525F2BULL,
		0xDBC0E75199564E85ULL,
		0x0794222E9FCEAB5CULL,
		0xAD412774E3E5BB5DULL,
		0xCBEE946A317C4A8FULL,
		0xE209D0B9F72E9A6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 118\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x849C6073C414610CULL,
		0x7E985F1DD298EAB8ULL,
		0x7D8588353A3F9A60ULL,
		0x5638923161E5816AULL,
		0x4EE817F1C28687CDULL,
		0xFF6624F48051EA76ULL,
		0xD14BA7AD230C24A9ULL,
		0x04AE5B01B5FE2C77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 119\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB79CBA9D92A72085ULL,
		0xAA942097E4FE6E0FULL,
		0xE235D7AFC802B20DULL,
		0x7FC45FE9883BDFC7ULL,
		0xF525C7A4793082F0ULL,
		0x0E2675CF8C78D5BDULL,
		0x2C5D170BB49BB4ABULL,
		0x25A8D73DF04AFCF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 120\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x411500F261173D2CULL,
		0xBFA5097BFC96DDCFULL,
		0x63E55DF977267B27ULL,
		0x5C711294175D2D10ULL,
		0x77F8AD642A6CA319ULL,
		0x7FB18C0F3FE7D0E5ULL,
		0x8992001264B0A02BULL,
		0x519DDE30CBF234E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 121\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x39944B1B8E3B1ACCULL,
		0xFCB6D8E67B26D487ULL,
		0x5808E94ACD61533BULL,
		0x669D4AA83990EE17ULL,
		0x115F2CF28A2567F7ULL,
		0x2DBAA7560A709CC1ULL,
		0x3C10EAFF30154714ULL,
		0xB3A2C0B2B35095B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 122\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDE1D54DA7D08469FULL,
		0xFCDDBB909FC641E8ULL,
		0x3500FD808D2002A6ULL,
		0xEA6BF9FAC52BCCDEULL,
		0xE1D0B5B153C76B75ULL,
		0xA0F414D747345524ULL,
		0x5B3D39B2E81DCAAFULL,
		0x915E80CB6D36DD24ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 123\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6ED3F323F2913404ULL,
		0xA322ED42CA2AEB94ULL,
		0x16B36174BCE6851EULL,
		0x5DA8EAC23F36DA01ULL,
		0x57820D7A718B1342ULL,
		0x18E87EF49DE6E9ECULL,
		0x1E6D74DE614AEB5EULL,
		0x42221503A2963BC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 124\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEDFF120D5E3263A2ULL,
		0x1D17AB44B34ABF0EULL,
		0xC4634A58451F896CULL,
		0x62761B8600759E5BULL,
		0x522E2F4DA7BDA287ULL,
		0x59B531AD7E788DD6ULL,
		0x62D94A0246B31FE2ULL,
		0xE30C61A2FD087F09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 125\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEDFA173F51251475ULL,
		0x6E88E12505B4D910ULL,
		0x732A5CCAE96157E0ULL,
		0x227C596303265BF1ULL,
		0x71C601FBBA416819ULL,
		0x84FE94427E7838A0ULL,
		0x078291CAE3AAA862ULL,
		0x6B112F1E0B23DBE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 126\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFD0C140731E5AAE9ULL,
		0x471A25E365DD0FFFULL,
		0x43949C161F67D9BDULL,
		0x5715C8F78D51D48FULL,
		0x507AF2352BB06EC3ULL,
		0x964D50BD1F887796ULL,
		0xE7C14370FE14C32FULL,
		0x2DA32BBD81A24707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 127\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xFFCDEB795E0DEB0FULL,
		0x9201972AAF51D867ULL,
		0xAA3CA7518FA8EF5BULL,
		0xFD98359BB3F760B0ULL,
		0xC9F4ADE7BD9677A1ULL,
		0x1E9931C15CF60344ULL,
		0x5DD7F4327B980537ULL,
		0x0A63FBF332FA7A7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 128\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x105E5944B8707DECULL,
		0x6AC6F77BC018C82CULL,
		0xCB5AE5D8E0629F7CULL,
		0x518221AF481D3F3FULL,
		0x63289B9FC25A5B84ULL,
		0x3B2B59C02AABB243ULL,
		0x9B68F91E71F79AB7ULL,
		0x66F68CAB0D452284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 129\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5D3D29990D4A8F89ULL,
		0x3F1D7B02EA7FD64CULL,
		0xFE7CCE4B1C2EDE9BULL,
		0x49992D5AE901AD96ULL,
		0xAE619744248B07ADULL,
		0x85331C2010253413ULL,
		0x237954C04AE2F980ULL,
		0xE689861C9CD8A5E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 130\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBFFE75C62F2B3F5AULL,
		0xEC00ABB64F5F810AULL,
		0x38FBE7E70FD0DB18ULL,
		0x34F2E0EFB65CC8EBULL,
		0x82E406F8047E170BULL,
		0x7A7BD44EF3F8FB81ULL,
		0xB0E859781A7C14FEULL,
		0x9B4776C448A03356ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 131\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9439AE607915E2EDULL,
		0x2F98E9A2A7D6309BULL,
		0xECB3DBA9A72EDA3CULL,
		0xD90CABD019C497CAULL,
		0xB0741EC198734ECDULL,
		0x98046C26AD1CBB80ULL,
		0x0E749EEC36792FCAULL,
		0x45EE312A00A03100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 132\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC228AE45B028352FULL,
		0x597DF14529BE2B00ULL,
		0x19BF4E2F44FB975AULL,
		0xFAA9AFA55A49C50EULL,
		0x93277B134076DA6AULL,
		0xEF4108B53405E93FULL,
		0xD78DD0FE0BFF16BFULL,
		0xF40C66B4C48D49E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 133\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4BA71AF18319857EULL,
		0xE25C788DADE2E4D2ULL,
		0xDDAC656342C84F6CULL,
		0x67F68243B80A81CEULL,
		0x1E599471F2888F08ULL,
		0x35777BD664A8BDA5ULL,
		0x41934237768E4A2EULL,
		0x9BB16FB5F759AA08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 134\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4617E5BF440171AEULL,
		0x2D3C7B7B1847FE40ULL,
		0xD2492233D8313BEDULL,
		0x8B0A1D9595499C1EULL,
		0x8ECEB02D93656C72ULL,
		0x3C046AB31CDC15A4ULL,
		0x9339C2603AC9191EULL,
		0xA7228A7640F86977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 135\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE76C305A25D638ACULL,
		0x71E44F2C3C0A6F0FULL,
		0xD38E10B7EF20A967ULL,
		0xB5F59A8F779181AFULL,
		0xA144720058EC742AULL,
		0x7203032AB433EC79ULL,
		0xBF5CC6785B813ACAULL,
		0xC64801B5B2EAFEBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 136\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90870BA15D238E0BULL,
		0xAE4527DD3F88F34AULL,
		0xA598F63C9CF31AF3ULL,
		0x0CC5E00DD5AAD016ULL,
		0xB00C121E8C34A053ULL,
		0x9F0E5A5F0103C2B6ULL,
		0xAA221B10261715A4ULL,
		0xE4773D4AE87519F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 137\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5271D2F8C094429EULL,
		0x19ED62F7C72061D3ULL,
		0xB0F3C0C9671F291CULL,
		0x939C99CC6D0C9BFFULL,
		0xB0680958F033FD8CULL,
		0xB9666A5259A3141FULL,
		0xE3B21C23B16E89ABULL,
		0xF42453D98EB63E22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 138\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF7430E61E580FDA9ULL,
		0x10963FA8143EAA9BULL,
		0xF76273368F1FF8C5ULL,
		0x32B4CD9FD8326B1EULL,
		0xE209688B6A7308A8ULL,
		0xE537D7559128A090ULL,
		0x1F1B95083A7B20D9ULL,
		0x6C3D8246CCB3D1CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 139\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x38BCA9C8CFEF914DULL,
		0x7BC243AE283CF111ULL,
		0x9580E23EDDDF1453ULL,
		0xD8B165BF6B3FC448ULL,
		0xC984864CFB274D92ULL,
		0x4956C448A5566CD2ULL,
		0x26689B7C6FEABD85ULL,
		0x4D49AE79A52BC440ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 140\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x06F4C8F134B58E0CULL,
		0x700CD6BB6852F2DEULL,
		0x56A0D915428CFD6CULL,
		0x0BBEB7DAC2D0FCB2ULL,
		0x78D9CABD3B3DC238ULL,
		0xBA3ECB015D453B21ULL,
		0x4555C59960ABCF4DULL,
		0xB1B8724469C786ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 141\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x90038F53DD5570C3ULL,
		0xF5DD76EB6F146417ULL,
		0x02EC8F6542443FE8ULL,
		0xE159479569CD8965ULL,
		0x18F9AE169D61BD91ULL,
		0xEDB80F602BD49C5AULL,
		0x2A8427BC375B9F2EULL,
		0x172141D6E32155ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 142\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x44229EBF3B678865ULL,
		0xA7F1AAE30CF99F78ULL,
		0xECB259C44DB1A09CULL,
		0xCB5400203391F8E9ULL,
		0x99E78359D0B06216ULL,
		0x1A9E81A0B06DABE5ULL,
		0x353CFD77C53D11C2ULL,
		0xD852464AC6763207ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 143\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0DAD5263E757E917ULL,
		0x1BD76D44DB6EFC36ULL,
		0xF31F09BC305F50B5ULL,
		0xDCF9198199FF9A00ULL,
		0x263CD67A636ABD5CULL,
		0xC19B2D43465B3C94ULL,
		0x7F171E6EC094F392ULL,
		0x76ED71F6ED21A19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 144\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6C09950CE01C02DBULL,
		0x8A5FBBCD21923CFAULL,
		0x0273C0DD071B6D45ULL,
		0x270A1EB95F223E4DULL,
		0x2BA362260C962A94ULL,
		0xC229DEE931B3D54BULL,
		0x8C73D97E67B08D6EULL,
		0x15AC285DCAB0E6F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 145\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3130EC271E756822ULL,
		0x52562BFE43E118FAULL,
		0x6168111442E6CAEEULL,
		0x1C81534BEE277263ULL,
		0x135B18F8E3F05F5BULL,
		0x4F73906DFEC45BE0ULL,
		0x62FFFBF12FD7D7DDULL,
		0x6B9DF12674B75EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 146\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x969B265AC62EE326ULL,
		0x17909A0BECCBDA6CULL,
		0x59BCC7E28C298D96ULL,
		0xA861B2156140A782ULL,
		0xA495DBA61B287F31ULL,
		0x33139E1CEB783339ULL,
		0xF349F6EEC1E56A8AULL,
		0x728332291F3B1A91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 147\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBC7F98E35EC2DC60ULL,
		0x422CB90756CC6FC8ULL,
		0xAC42062315CF743DULL,
		0x47C4BAA584E7DF7FULL,
		0x69D3FDF31C39F355ULL,
		0x8BD264C8213B0007ULL,
		0x16902282719801C9ULL,
		0x41E885DB69F218E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 148\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAE284B0AF42DC287ULL,
		0x6BC6BD0A5E3F4816ULL,
		0x17DA2C2114B9A608ULL,
		0xB90661CFE355B0CDULL,
		0x945EAA3363D908C1ULL,
		0xF0300B66CCC30BDDULL,
		0xF2339D223F92D8F6ULL,
		0x5CC6EE2B02CA7185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 149\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFAEBB24DEC219F0AULL,
		0x213D28520C1EDCBEULL,
		0xDE158A50EF1A065CULL,
		0xEE382F9C024D2196ULL,
		0x619241FD99DEEAB5ULL,
		0xBBF9F229B76810EEULL,
		0x7FF057A99BFAE261ULL,
		0xB2072CA5397D4D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 150\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8DAF4D87BA7A0E24ULL,
		0x760661A15982274DULL,
		0xCE509B44AA8B21C8ULL,
		0x3E80F758658AE283ULL,
		0xFDC35823FA4EBA4CULL,
		0x26CE80959C57B647ULL,
		0x2E04329AB9232FDDULL,
		0x38414B3BF0478E83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 151\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3069A0C022193010ULL,
		0xEA009853C044798EULL,
		0x647D85CE01CA4D48ULL,
		0x8E48989E9102FCB3ULL,
		0xF352FB11422B3EF0ULL,
		0x414397B387F4336AULL,
		0x14603CBDB7EBFA08ULL,
		0xC36B47711514718EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 152\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4647ECC4686C47E7ULL,
		0xA18B8DA037302968ULL,
		0x94E30445FF71731DULL,
		0xB6BA89FC1176CAA6ULL,
		0x9A7BD9B640EE7DC8ULL,
		0x1D008ACAAB468329ULL,
		0x762DE81797F4BDA0ULL,
		0xF45887D870DC5F6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 153\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5974738ACE78F012ULL,
		0x5BD84F8DA90BBE92ULL,
		0x6D812A0D5072B35BULL,
		0x9F8731591CA7C9CAULL,
		0xFBF5F3E8D1613F6DULL,
		0xE9E1EA485CD1DCF8ULL,
		0x09596777D679A60CULL,
		0x8C6D6C21D9B519ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 154\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE6490A4BE5D40737ULL,
		0xD85B9E86851AC0D4ULL,
		0xC50825857A8E3395ULL,
		0x0A297200AF3DD531ULL,
		0xB5DAADE9DB48F4C0ULL,
		0x2BB20D5978E4991AULL,
		0x69E3CC584103EF0AULL,
		0x51337E0DFDE9579CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 155\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x773EA1DA4EFF5741ULL,
		0xB79292D26BAB3252ULL,
		0x293A9E0D83582C56ULL,
		0x8004D712FEA40CEDULL,
		0x8C0CBA88CC2B44DAULL,
		0x159B25DCED4BF743ULL,
		0x8890649FF14F61B3ULL,
		0x5358090EA4E59B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 156\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x4E881C398F5399B3ULL,
		0xAEB1D50F9DE6964CULL,
		0x2C6B427DCB259929ULL,
		0x4795ED82849E57E1ULL,
		0x617A44815F103409ULL,
		0x512A5518CEFF8E58ULL,
		0xB27BB1F2CB0B15A3ULL,
		0x0FA8FE6AB1FC73A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 157\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x87D29DA8CA6FB709ULL,
		0xA0812B55246255DBULL,
		0x657DAEB21E42C832ULL,
		0x35B55379878E444DULL,
		0xD2AD7565CF3B3450ULL,
		0xC9314C36E84EA533ULL,
		0x14BBBDE1D9C3A8F3ULL,
		0x8F466B70EE81D659ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 158\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x445D39154CB505BBULL,
		0x3F33811F5D7EA7C2ULL,
		0xFB8271939DFEC329ULL,
		0x699C15BA893E4A50ULL,
		0x7DD9902B0765F0E7ULL,
		0xDCC7464F37C8302AULL,
		0x6BD16E2B6E8AF862ULL,
		0x8F3488F2CF92876CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 159\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCCA47BCA3B9C711EULL,
		0xDD988767EB9D7551ULL,
		0x0E2C8E2A9F45F073ULL,
		0x47152A9ADD5EEAF8ULL,
		0xD063D77CD5C040F3ULL,
		0x3AD354509F19E29CULL,
		0x88E860A4535F0442ULL,
		0xB39FE9A7FBD26DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 160\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2E40E9A306689DEBULL,
		0xE6D663E97116D4A1ULL,
		0x5AF86E50B432D41DULL,
		0x356E5CF8EA08B863ULL,
		0x02D8104359B05AF3ULL,
		0x7124A47A4E8504F9ULL,
		0xC2F33CED1FC1DB4EULL,
		0xEFC9CDE606AB2496ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 161\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9A542C8652DDCF2CULL,
		0x51BC6381F3330C9FULL,
		0xDFD6D6441A602C4DULL,
		0xBC1855C3A136ED38ULL,
		0xE94DFE21F5A907FBULL,
		0xDCA0C66E6C5343FCULL,
		0xF39FBA93A35225ADULL,
		0x9FE296074FE82288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 162\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4087EEFAFE2EE926ULL,
		0x4E3A45984F2E5166ULL,
		0x91BAB558984A15B7ULL,
		0xF3618527AB189BE9ULL,
		0x7B39F4DC2CED0A21ULL,
		0xC05ACDEE9B8EB1C3ULL,
		0x344165CEFE69785CULL,
		0x495AF6D364C96C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 163\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB4F260E532026517ULL,
		0x495C52805AF719E7ULL,
		0x524F15897F487E85ULL,
		0xEF714EBB66DA5CE6ULL,
		0x1AC6ABD943F1C14AULL,
		0x48DB9D1A8D4D01E8ULL,
		0x2833F29400D3DDF7ULL,
		0x73655558347D8538ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 164\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE0882A78E400827CULL,
		0x887B0D31728FB54DULL,
		0x9518A0BEE2A27644ULL,
		0x580C6B241B1D2F19ULL,
		0x1B6C766C6FDE082BULL,
		0x649C20F58C4AFC14ULL,
		0x93A2C5E4BFEA083CULL,
		0x6EC5ED6C9CAD9529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 165\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x069118720816AAF5ULL,
		0x2119C6E2ABC289C0ULL,
		0x8D2F10B0B3720FF6ULL,
		0x75CC9ED7496BC7D9ULL,
		0x8ADBDF7F41A8D76EULL,
		0x306B74B591A8B938ULL,
		0xCA73BF35A107A78DULL,
		0x51E61CCD41371284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 166\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x467F05047FCEEC93ULL,
		0xD231D621CDAC20DCULL,
		0x9DD741FEEA0EF4B9ULL,
		0xEB196B65BBFF464AULL,
		0x6199E0E1EBD0E58DULL,
		0x7C9BFE34C138E3A6ULL,
		0x66DBBBAFD1714B17ULL,
		0xB5E8E0DF824CFC25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 167\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF03DDE8FAE5B512AULL,
		0xF27F20E8CE665A7BULL,
		0xDC9CAC22A7B7B374ULL,
		0x1881D06E80F03260ULL,
		0xE5E7E6E7CAB7E263ULL,
		0xA14AD08273C2E14DULL,
		0x43C1CBDFB1D52ACBULL,
		0xD81AF73951E01E0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 168\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x385CC33F75B8D2A4ULL,
		0x094534DB12DAE0AEULL,
		0x33508664AE7215AFULL,
		0x44BF6FD72A07A5C6ULL,
		0xAF6349ABE8B810CEULL,
		0x968FDE2D52AC76DEULL,
		0xC41336466239339EULL,
		0x76B589E6E4A98CC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 169\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEA5C5B16C9053074ULL,
		0xAB83EE214BF9C82DULL,
		0x282FD8449BDD3A4EULL,
		0xAC75FCDE9A3DBB90ULL,
		0x683D37347D58A875ULL,
		0x1E0541211E20F4BAULL,
		0x2C568A3B8AB7044EULL,
		0x44C79A8599BD8B9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 170\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0ACDE5CB90782BDBULL,
		0x7919801A52A56953ULL,
		0x4DDF73167440E389ULL,
		0x10AA0FE28AEE0358ULL,
		0x4B513DB1F46C5812ULL,
		0xAAB658039DD4D7C1ULL,
		0xE3A7D59AE2E983D4ULL,
		0x740C5FB0E2415DAAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 171\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x3F6DEC3FF1B32AEEULL,
		0x8E2CA96275FD82BBULL,
		0x3A43DE9DAB00F7F5ULL,
		0x8C09611242336FF7ULL,
		0x85F9BB4FC5085DC2ULL,
		0xADD363837204A267ULL,
		0xF0ECDBF1BBD92DBFULL,
		0x19C4F367E9D7F15DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 172\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x742D2AEECC79DE94ULL,
		0x6D2982FAC4A3884DULL,
		0xB7E8BB817E931EA2ULL,
		0xE575391755886EA7ULL,
		0xE023039060701215ULL,
		0x189B9D9E934045C1ULL,
		0xE339BB793F4BC82FULL,
		0x397CA1016B19BB54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 173\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFD8896CB9626A7CBULL,
		0x1631718C04B79F08ULL,
		0x551AD756593F08F5ULL,
		0x01857B56FFCAE598ULL,
		0x2ACB0FDDEF969A0BULL,
		0x2B9D9DB24EE4A3F6ULL,
		0x25F0558BAA21C672ULL,
		0x5B879F916E00A872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 174\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x00C99767197C0041ULL,
		0x60B1C4CA26609032ULL,
		0x00AC362A060AE49BULL,
		0x9540C9091B70FBF9ULL,
		0x362BC7D8FCCB8BFDULL,
		0x80A5276AFC9589D3ULL,
		0xE9D79164242524EBULL,
		0xDEAA577508518BF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 175\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x136D77B3F602C611ULL,
		0xFA472A2D61E87948ULL,
		0x2A531579C871D66BULL,
		0xF61F037D417C0E66ULL,
		0x53E5D83E8CCFF8CCULL,
		0x2230944DDC381605ULL,
		0xBF509FCE3B77632AULL,
		0x8D641BBD354E4BFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 176\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x47A3F91EEE09928DULL,
		0xDF4D6DD3CD3511F4ULL,
		0x112AFEF0C96927BBULL,
		0xBA4C48BF688E7A60ULL,
		0x758BC5FF8551270AULL,
		0x53C63B13AF1290FEULL,
		0x55A918041F01EE75ULL,
		0x45B9248C3C6EF18BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 177\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x964962379BD34EFBULL,
		0xFBE82F25C42D5C41ULL,
		0xFDA78F732F378DAAULL,
		0x6263289CE5725592ULL,
		0x098DE4974CDC4F20ULL,
		0xB7888FFE7CCB4C10ULL,
		0x534A2BD336058D47ULL,
		0xACF10A2457F72635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 178\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x658B7C030124F2E2ULL,
		0x0DF9B5D9625B2A38ULL,
		0xFD5CAD73D13D103AULL,
		0x116A52928457E333ULL,
		0x02D89F220374233AULL,
		0x4FD66ED6FC020C69ULL,
		0x1AB2BAE6060901C6ULL,
		0x3C17545A42D54A7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 179\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x86D90218BDE3FBD2ULL,
		0x349C57B911C5BBF0ULL,
		0x4FD1D7471741A251ULL,
		0xDE2C3A53F3E410CEULL,
		0xF7CF6248DE843B96ULL,
		0x35838D5EB8856B8BULL,
		0x28C44C4DF6781B31ULL,
		0xBCC866B5447A9B6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 180\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x56D35C14658435A1ULL,
		0xD565788C60B0051FULL,
		0xF4B877DB54C1E68DULL,
		0xAEBC38B113E70975ULL,
		0x94C3DA5BC98988FDULL,
		0xF9E1147D948C6F07ULL,
		0xC7E22C61DBCCBDBAULL,
		0xC857A300E45E7F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 181\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x995B25434F9A6EADULL,
		0x40081A0FD16D5DB1ULL,
		0xB2104B69FF5B016BULL,
		0x18BBBB2A6A67D79DULL,
		0xF69391875150C088ULL,
		0x76085C4ACCA0126CULL,
		0x320D9473E74D9251ULL,
		0x9DB6F93232290CBCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 182\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE5CC4F3735073EEAULL,
		0xC5E2AD2AED4703F6ULL,
		0x3145DEFF1B98F8FAULL,
		0xB11621352D5EA742ULL,
		0xF2E045FE36C660F2ULL,
		0x2DA70D9287E9B8D0ULL,
		0x87E54F6CA60883E4ULL,
		0xC500323E90658DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 183\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD30A6BAE0EE31734ULL,
		0xBFE54E04487C1E79ULL,
		0x275C53CFE7CD8812ULL,
		0x9FAFB683AB454C24ULL,
		0xF707258DB91D79EFULL,
		0xE247303ADC032F32ULL,
		0x5C8A6EB6EFF6F377ULL,
		0x7CFAC3C2C40BF9F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 184\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x2D0722309D313BDEULL,
		0xC373B2BB26A13020ULL,
		0x0E5CA218C4328353ULL,
		0x415E4194148EDCC3ULL,
		0xB2880B2912B1E35AULL,
		0x223D8B92E908695BULL,
		0xCD3A375422485299ULL,
		0x0367DBA187FD23B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 185\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0F46168DEDC0FFB4ULL,
		0xEBB0DE2039188F8BULL,
		0x1A946741B3A2E68AULL,
		0xBC7D475EB2B09E4AULL,
		0x1AEC24F323512158ULL,
		0xBB8CF3DA768B7797ULL,
		0x53465158FE624DB7ULL,
		0x15A1C280B6A72713ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 186\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF96821C60E4642A5ULL,
		0x1CD8D6D243C9D022ULL,
		0x002357CEA145B0A4ULL,
		0x1D741DFF3CE49623ULL,
		0xCF87FC40C54FC062ULL,
		0xD440AD475B9EEDFAULL,
		0x5A8BA6F4452270C3ULL,
		0x285E532C64F0555DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 187\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1927991E849A6798ULL,
		0x3013165516C4709BULL,
		0xA63B77A7178AED60ULL,
		0x7C86A440EB510893ULL,
		0x9D00781CAF9EE765ULL,
		0x44A39FCF9CD51F37ULL,
		0xE34CDDC756947CD4ULL,
		0x10513A6FA808855AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 188\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB30E69E45742929CULL,
		0xD40F4950799BF711ULL,
		0x18576E7D615BD1E0ULL,
		0xAEB04D1D51E1C617ULL,
		0xB9C380CF2A4C8157ULL,
		0x1E74019417E3120AULL,
		0xFBADB5C6FC433161ULL,
		0x36E41C865E2799D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 189\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF396119A2AAB2FCDULL,
		0x351AFEABC7A4B26FULL,
		0x4A2083434DC4D538ULL,
		0x070C675227015D00ULL,
		0x08245550367ED51BULL,
		0xE6F327C91593368DULL,
		0x2DC7D7B3A9B19EE6ULL,
		0x350CD97FDD5861C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 190\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE2131F269DA5A0D7ULL,
		0xC83AF11C2A2877C7ULL,
		0xF4F5BA74BB931C3AULL,
		0x90256F1CA0426E96ULL,
		0xD08E8DA2AE8536F0ULL,
		0x666888BD0ABA2AFAULL,
		0x67E088679290A9ABULL,
		0xA8874523331C0579ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 191\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0350105FA8B279E1ULL,
		0xF951E07BD9337486ULL,
		0xD54823A5ADAD8130ULL,
		0x3DB6E33324515E62ULL,
		0x2FD09A8F5A281104ULL,
		0xE086C8119CB1316DULL,
		0x1227F64C6209B4F1ULL,
		0x6238988EF760266AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 192\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE7712135F612B0E7ULL,
		0xD9E4E6B1D7C491DDULL,
		0x9C4D3F4508C553EFULL,
		0xB20D35656A19DE34ULL,
		0xA8A3A9A1981EE2A0ULL,
		0x8A1CAC29DD3950D7ULL,
		0xD6650439AE746ED9ULL,
		0xE6A9364FAABEBC91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 193\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x56038E4E742DB9A4ULL,
		0x14F45FC567336792ULL,
		0x83145DBBB8341600ULL,
		0x040616404677068FULL,
		0x7CEE185DEE666FECULL,
		0x72686AC1BB586D94ULL,
		0xAD8D3673791977A4ULL,
		0x8BEA9BAACC90367AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 194\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6F1129EB59E42B4FULL,
		0xDD85E8A83679834BULL,
		0x78E34BA9B429CB02ULL,
		0xEEEFD2A7D694B270ULL,
		0xDE7B2D1339639DE1ULL,
		0x3513B46281125ACEULL,
		0x5487B7E215FFD589ULL,
		0xB301963300E48599ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 195\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x911857012A5F814AULL,
		0xD81AE6BD68CAA9FFULL,
		0xE8548C5518320D23ULL,
		0xA1FA5665B3A1E116ULL,
		0x6FDB51C1585A4A54ULL,
		0x6AD2F0D188FAEB13ULL,
		0x95A78A09D5050ED4ULL,
		0x63AE152018D6593DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 196\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3FE2316F6543CA8EULL,
		0x7373F56FDB7CC133ULL,
		0x3CFEB9864FEC3240ULL,
		0xB367E1C371B8FF7FULL,
		0x6FDBB07388EDF4BBULL,
		0x5DEDB5B9F94F45D7ULL,
		0x6E28FD5516E16410ULL,
		0x6FB0CA0838BE24C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 197\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0AC02356BF81D5F4ULL,
		0x7F76B9B3BBC02B6EULL,
		0x552C08E2530D10D6ULL,
		0x3495DC924893F43EULL,
		0x6800C350DB180B79ULL,
		0x524797906D8EBA7DULL,
		0xDEC5808EE90D58E9ULL,
		0x2991741B8CAA13DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 198\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x57A217418E35B3E1ULL,
		0xE7D3A637E09149D1ULL,
		0xBFDD3168E084CA89ULL,
		0xAA3D379881A64A61ULL,
		0x22766750BA4BF2E6ULL,
		0x062CBE3E3B0B1E3AULL,
		0x47AAEA9723912BA0ULL,
		0xC2DDCD8DC04201ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 199\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF1F56348527E4D5CULL,
		0x4E77CF91FD93DC32ULL,
		0xD414EDF8CECEF651ULL,
		0x639A2442B8607F8CULL,
		0xB9FE4335ED429AC7ULL,
		0x44612E028E993B3EULL,
		0x5A53A33F5E9452CCULL,
		0x6052C336F8C2C84AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 200\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 200 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -200;
	} else {
		printf("Test Case 200 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x31757F4732ADBDA2ULL,
		0x4451500AE18968B4ULL,
		0x54681F791180F22DULL,
		0x7A20CA3C797036D3ULL,
		0x6CF0C31B016E7C6DULL,
		0x92EF7A3F815D13D6ULL,
		0x32B966C3FDE52EE2ULL,
		0x7CA41CB4C6E37999ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 201\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 201 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -201;
	} else {
		printf("Test Case 201 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x83DE4480C189BED0ULL,
		0x1C89C447199E71D7ULL,
		0xD6AEA49F351F970BULL,
		0x8B27DB0F2BE49197ULL,
		0x053E3098FC4E45FAULL,
		0x6ACB045396B24978ULL,
		0xC9F8C90BABD8210CULL,
		0x5EF5DA8E000828AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 202\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 202 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -202;
	} else {
		printf("Test Case 202 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7ABD62DAC383A758ULL,
		0x48ABD00D1715DB5CULL,
		0x18FD4CA9147A517DULL,
		0x32EE405643F6AFDDULL,
		0xA3B4B256E29E5E7BULL,
		0x51F721987E7EF7B8ULL,
		0x273926A665546FA6ULL,
		0x92F3FF3AD7F4D774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 203\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 203 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -203;
	} else {
		printf("Test Case 203 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x96B3068A84A5B7A9ULL,
		0x51512F4570952604ULL,
		0xBF5D4D3EB899E8ECULL,
		0x94969F826757BD6BULL,
		0x80D75AF6A47C5806ULL,
		0x0F7AB939073C0F37ULL,
		0x56A5FFC1FC4459CEULL,
		0x7924C2BBBF1B0AD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 204\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 204 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -204;
	} else {
		printf("Test Case 204 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0A829CE513F02155ULL,
		0x45431AB26083024EULL,
		0xC0DA32331460E787ULL,
		0xE9762A0117CDEE33ULL,
		0xB96FA7BD410239ADULL,
		0x039DAB50D2E3CA3AULL,
		0xB68994D2173D32DAULL,
		0x345874E0B0B34118ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 205\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 205 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -205;
	} else {
		printf("Test Case 205 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA0AF658E3CA4C572ULL,
		0xF0DCD12ECE86A4B5ULL,
		0x5A73ED4CEBD44CB2ULL,
		0x08F46ED36AAD2495ULL,
		0x955AB69D92481AAFULL,
		0x6E4D0631BF0F7794ULL,
		0xB34FAC0041097475ULL,
		0x171CECA3CB69ED78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 206\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 206 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -206;
	} else {
		printf("Test Case 206 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5C269583DFA6C125ULL,
		0x4ED08292F947D8E3ULL,
		0xF02E5140290C3E68ULL,
		0x5DC04A00CED519DAULL,
		0x696FED77A1EE6F2BULL,
		0x84814B588FB1A72BULL,
		0xE88F440357BFC778ULL,
		0x7AE24C996B6B4C62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 207\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 207 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -207;
	} else {
		printf("Test Case 207 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD0F001476F7904EAULL,
		0x425D52A86873AE3CULL,
		0x12CBDC8F70223BD7ULL,
		0xDD5A222B770DC447ULL,
		0xC2B3FE8DD461C59FULL,
		0x8CEB738EE282B3A6ULL,
		0x80C3144E3627D9CEULL,
		0x26191977F9DD6780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 208\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 208 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -208;
	} else {
		printf("Test Case 208 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x723AE0799D0C9F9AULL,
		0x1524BA6312B34FDCULL,
		0xDC18129C997819DFULL,
		0x70F5C9648E78923FULL,
		0x27F8BB32A7AB8626ULL,
		0xEBD022FC1C52B011ULL,
		0x7FDACF840026C6DAULL,
		0x32E88AEEC978F6EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 209\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 209 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -209;
	} else {
		printf("Test Case 209 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0x4AD055698D42FB66ULL,
		0x8C69D3CB7F35AA59ULL,
		0xF2CA1207327FF7A8ULL,
		0x8C047AEA6AFDBFE0ULL,
		0x264E91378078ADE5ULL,
		0x1F45DFA482D79B30ULL,
		0x2A11E8FDAAE6EAF7ULL,
		0x01BB457353A8D316ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 210\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 210 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -210;
	} else {
		printf("Test Case 210 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB4AC1988BB100956ULL,
		0xC3ECE0FF072D847DULL,
		0x4CAB27BBA162DF89ULL,
		0xA24A1F69656355E3ULL,
		0xDCE1B2DA95A3A7C0ULL,
		0x2A192DE2FC714BBDULL,
		0x2E1EDD97E5E59199ULL,
		0x34002FA4C2ED783BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 211\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 211 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -211;
	} else {
		printf("Test Case 211 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3B5C81CE271F2DAAULL,
		0x640122172C327A30ULL,
		0x8EA89FDF4C40450BULL,
		0xCDB0C774AB1BC944ULL,
		0xEB3F881DD98BD207ULL,
		0x05BF5727C846427AULL,
		0x1AC1C6AE6FD94EBDULL,
		0xABFE19F47B9E9FC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 212\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 212 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -212;
	} else {
		printf("Test Case 212 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A42C43666946747ULL,
		0xB3541F647C99DB59ULL,
		0x958E2123E9935DC5ULL,
		0x9F012956195E49CFULL,
		0xF4AD3EC4D361D130ULL,
		0xEB152C4CEE594D22ULL,
		0x40C8F0FA2FF95788ULL,
		0x81FDD0FDF9DECC33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 213\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 213 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -213;
	} else {
		printf("Test Case 213 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCDBFF3CE7DFB5AE9ULL,
		0x12489ED4BFC60538ULL,
		0xE79F182AC62C80B7ULL,
		0xCFF5E8F1386E4532ULL,
		0x6BE878DC6C68E707ULL,
		0x492A5DAC7007068DULL,
		0x5B3467ECC93C3B84ULL,
		0xF29C950FAAC93007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 214\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 214 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -214;
	} else {
		printf("Test Case 214 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x58FD49150B6A838CULL,
		0x56F06B4E5FCC6B8FULL,
		0xAAB68C6E0CF7A691ULL,
		0x6E385DFCAAA0C84BULL,
		0xC2A3BD2BE5C9C4B2ULL,
		0x682A8D07CAA56D74ULL,
		0xF1DCF0A914A354CBULL,
		0xE09A9CFAEAF99401ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 215\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 215 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -215;
	} else {
		printf("Test Case 215 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBC55FA2890AF87BDULL,
		0xF182B52B93108A59ULL,
		0x0086A2394785244BULL,
		0xD265ED33332120F2ULL,
		0xEC14643F1463A86BULL,
		0x20461E2BFEA17C56ULL,
		0x2894E8F0FD3E04E6ULL,
		0x94656E6D40F839E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 216\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 216 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -216;
	} else {
		printf("Test Case 216 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2FD310348C72E7B2ULL,
		0x257EB15DB2FB69EBULL,
		0x4BD01EC3C88A92DAULL,
		0x8EC4A950598C980FULL,
		0x61DC930FE1A969CFULL,
		0x5E5A55E0640F01E0ULL,
		0x73351D0EC9140277ULL,
		0x699E1D01C21404A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 217\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 217 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -217;
	} else {
		printf("Test Case 217 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6D2849149BEB162BULL,
		0x15B1E9DF24D1D568ULL,
		0xCFD0340FC1AB8617ULL,
		0x20DD538700442064ULL,
		0x06511197A7B9B484ULL,
		0xED79DB65A52810F5ULL,
		0xC3A277BEF5FBDC51ULL,
		0xB77589D72CBE69A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 218\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 218 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -218;
	} else {
		printf("Test Case 218 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x59FBACEC38B01C13ULL,
		0x8AC741D1A405FD3CULL,
		0x3FB1FB10C3A1957DULL,
		0xFB7DF79B13637DD6ULL,
		0x5770E1000AC3E3A8ULL,
		0x0DC8E541B652F057ULL,
		0x91BF765D1B876470ULL,
		0xB1CD3D06AE8AE516ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 219\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 219 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -219;
	} else {
		printf("Test Case 219 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x27BD068250DDB4DEULL,
		0x1346AF5D64DD936BULL,
		0x1C59A28DAB538A02ULL,
		0xABC85173C1CF9165ULL,
		0x0E67C4FC8E678A75ULL,
		0xBA0BF01253881907ULL,
		0xA70A82D2560DCCC4ULL,
		0xD60E1FD13BD3BE9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 220\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 220 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -220;
	} else {
		printf("Test Case 220 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6C2ADD94CF7757C4ULL,
		0xACA44FFBF103F162ULL,
		0xECC77A01E61FD1BBULL,
		0x5CA97C6F15B1DE81ULL,
		0x0C8468EC009593BFULL,
		0x868506F93373D401ULL,
		0x94E82C66A8772D49ULL,
		0xF5DC3EF517B5357AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 221\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 221 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -221;
	} else {
		printf("Test Case 221 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x152BC66125E78832ULL,
		0x461DA1F401F508F5ULL,
		0x1CFC151C581BE3AAULL,
		0x751CA9B0C8C7FFFFULL,
		0x86937C354CE8A624ULL,
		0x38916759D365BE19ULL,
		0xC0B227BA5B7E6AF4ULL,
		0x76EF62BA032E0C40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 222\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 222 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -222;
	} else {
		printf("Test Case 222 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x81A0662C29429DD1ULL,
		0xB37DC1FFF74915D4ULL,
		0x28B33A2FA68AFC59ULL,
		0x9D410E4C305B2388ULL,
		0xD928D23BD6875854ULL,
		0x3F05318146344841ULL,
		0xF599529A661AF280ULL,
		0xDBC05AEAF3B5A2D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 223\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 223 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -223;
	} else {
		printf("Test Case 223 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x60122075CDC70BFBULL,
		0x5031759C89A85CCDULL,
		0x9BF087989D28A4D9ULL,
		0x25F5A978AFA97653ULL,
		0x97E2182294EE588BULL,
		0xAF897E9543B83882ULL,
		0x9A782DF841178E6CULL,
		0x800FB32F3548649BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 224\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 224 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -224;
	} else {
		printf("Test Case 224 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB02DFA51ABA04276ULL,
		0x07AC8E814FF5C0CFULL,
		0xB4BB1D226450B10CULL,
		0x226EDFC52547887CULL,
		0xC5A1E5896D42FBACULL,
		0x275B9BA98AAA178DULL,
		0xB2D4F1C9BB651CF6ULL,
		0xFDCC2F403556648CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 225\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 225 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -225;
	} else {
		printf("Test Case 225 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3B0D922BCE0A5A15ULL,
		0xBDB2DA3B8065134FULL,
		0x032679F82F3B8BFDULL,
		0x834BE211905EEF98ULL,
		0x7973E510B566EBF5ULL,
		0x52E280D8807078A6ULL,
		0xCFA388BA009F7F5EULL,
		0x50EE9AE64EC9D0EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 226\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 226 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -226;
	} else {
		printf("Test Case 226 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE63B1FFCFAAD44DEULL,
		0x229322877E6995F9ULL,
		0x1F606B448FDD7205ULL,
		0x78963F456DA50D28ULL,
		0x4D7EC0461986ADC6ULL,
		0x4C25BE199C04226DULL,
		0xE0EC986A96A9C486ULL,
		0xC36EAB42CBF452C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 227\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 227 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -227;
	} else {
		printf("Test Case 227 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xB2FC578092195A54ULL,
		0x800E3986FD3C4524ULL,
		0x5A57ECAB060E6D16ULL,
		0x078E5174092CA715ULL,
		0xDD6B8B0A37B1F6BEULL,
		0xB540BF7CD4D7CD7DULL,
		0xD5A2DC8C3705C331ULL,
		0x06273678240D23BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 228\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 228 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -228;
	} else {
		printf("Test Case 228 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x46DDFE0803281A94ULL,
		0xA5A8FB58CF88BAFCULL,
		0xF8FB0D6BC6AD76A4ULL,
		0x79DC23D05C4A5EE8ULL,
		0x11C92725EC3F1769ULL,
		0x94DEF77BF8491F53ULL,
		0xB2247D1E30158A2EULL,
		0x94BB0FDB6699E9B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 229\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 229 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -229;
	} else {
		printf("Test Case 229 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4BEEF3A284B2C3EAULL,
		0xE604E3B134738CC9ULL,
		0x57D8B9A87A17785CULL,
		0x38D1C1760B974B64ULL,
		0x4964EA006EDC7066ULL,
		0xF950B460D328CC33ULL,
		0xD0581EB700368771ULL,
		0xC2D673BAB24818E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 230\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 230 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -230;
	} else {
		printf("Test Case 230 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1B166BB050C32B29ULL,
		0x9FD202B752394C64ULL,
		0x34196B21F785E5D3ULL,
		0xEC702CEA16CD0B57ULL,
		0x2353E891E744019BULL,
		0x93DB9FAA6533E7B5ULL,
		0x0256AC66EF5E588DULL,
		0x5DEF1938A96E282DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 231\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 231 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -231;
	} else {
		printf("Test Case 231 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC948882D88A7B7DEULL,
		0x67ECF4451B6459DBULL,
		0xE90EFD8FBD41E4A5ULL,
		0x0875DFF332C41571ULL,
		0xC7E4E6006E099DFDULL,
		0xA30D1342B4881845ULL,
		0xB4925204C05BD0C5ULL,
		0x93A41E51DD99DCA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 232\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 232 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -232;
	} else {
		printf("Test Case 232 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB56730371270FFADULL,
		0xEBB915971CBE6710ULL,
		0xC86DFC6615B10988ULL,
		0xFF1F8D2819CBCBBBULL,
		0x1A08DBE402907B22ULL,
		0x172D28A28105E6E8ULL,
		0xFF57B539592FFD56ULL,
		0x4D3222C63F9BE17DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 233\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 233 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -233;
	} else {
		printf("Test Case 233 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x78B902B015F932D2ULL,
		0x95F97693CE824838ULL,
		0xF09AA0D0D1E700D5ULL,
		0xAEF1DBBF89863863ULL,
		0x0FA4BF3AF7CF146EULL,
		0xD95D4A40223D3354ULL,
		0xB0E20B0DF1E43ABDULL,
		0xAAA563408A52E8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 234\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 234 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -234;
	} else {
		printf("Test Case 234 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD4A058AFE1580E6CULL,
		0xE1B530233BDF4038ULL,
		0x0494577871B7449AULL,
		0xC7E8E7674800B856ULL,
		0x8BF8218CA27A343CULL,
		0x6CAF857250FCE641ULL,
		0x5882A179DE6A06AEULL,
		0xE71BA2FDF22798BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 235\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 235 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -235;
	} else {
		printf("Test Case 235 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8C021161C6FE2268ULL,
		0x12EA0CA5B5B396F7ULL,
		0xFF92F7EDBD476E2FULL,
		0x89651CB5BC583D68ULL,
		0x3654C9D0809AA687ULL,
		0xF8B053E61CBA5238ULL,
		0xA4477B2D74D2260AULL,
		0xE71E68AFDDDF9AB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 236\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 236 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -236;
	} else {
		printf("Test Case 236 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFDBB54AAA3AB560FULL,
		0x3B4EEB51E522D9B7ULL,
		0xC8FCEDB4A283FD39ULL,
		0xCDF660D00A6A4AA1ULL,
		0x2A79300F9F1AFA24ULL,
		0x14F6245485D2A9A8ULL,
		0xAE43826F08375023ULL,
		0x2929307A398AB2DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 237\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 237 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -237;
	} else {
		printf("Test Case 237 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x65C062F589E84492ULL,
		0x4B12AE5343EBE3C1ULL,
		0xAA7EB475B8939CDAULL,
		0x89B252C5A370A207ULL,
		0x510F28CFBF78E81CULL,
		0xE52F845920736FCAULL,
		0xB6AB851100983D02ULL,
		0x54D2F73CA791CE8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 238\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 238 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -238;
	} else {
		printf("Test Case 238 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3D74C2BF7A120271ULL,
		0x750F6FACE08F4409ULL,
		0xE3E0A600EBA748C4ULL,
		0xC2A358F22DD2B34CULL,
		0xB435046C8F9675CCULL,
		0x829F4FE6F8103257ULL,
		0x4BA89539FBD7AD48ULL,
		0xB0947387F6888ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 239\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 239 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -239;
	} else {
		printf("Test Case 239 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x75683C217CA5EA11ULL,
		0x2F7CFD67C22610FCULL,
		0x70BE3AFEB2FC58EFULL,
		0xE3538B7CFC38584AULL,
		0x4347D7970EAAEA01ULL,
		0x5567CAB1200091C8ULL,
		0x5A14172674246A33ULL,
		0xF70DA9639A9DF649ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 240\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 240 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -240;
	} else {
		printf("Test Case 240 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x95356480C98186C9ULL,
		0x171676DF1C1CC461ULL,
		0x16F89BEA28C929DAULL,
		0x66406D5685CB8632ULL,
		0x25531C7F6E123A33ULL,
		0x1C8B00B1C25186C4ULL,
		0x0433393676321B26ULL,
		0xFE6BAC23B9AEDC6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 241\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 241 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -241;
	} else {
		printf("Test Case 241 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7BF740854DB53046ULL,
		0x92EC489809458452ULL,
		0x206D65E0D0721AA1ULL,
		0xC97B8DECC0C21683ULL,
		0x00672DDD2654677FULL,
		0x6CF0129E344B4B7EULL,
		0xD9A26A6D5062B2B5ULL,
		0x58D0E6CDF16DF77DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 242\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 242 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -242;
	} else {
		printf("Test Case 242 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x14559AFC70322DFBULL,
		0x6AB3065EAD0E3033ULL,
		0xB0FE5AFE37D49E37ULL,
		0xFA9725664DBF4087ULL,
		0x40E262BE6E62856CULL,
		0x3AFFD13FF9AA477EULL,
		0x0F08F48A573E0EE5ULL,
		0xA85223E222028835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 243\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 243 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -243;
	} else {
		printf("Test Case 243 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA08499CCFCD610C0ULL,
		0xEB4879D2A77F2B12ULL,
		0x3700DCBC7912DF5FULL,
		0x96A2DB8E70A50E7EULL,
		0x43B353E5992BE22EULL,
		0x70C85C60B9C7AC61ULL,
		0xC879E4344999BFCEULL,
		0x4502C7D1AC8C3525ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 244\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 244 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -244;
	} else {
		printf("Test Case 244 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB4AE17D39E2337F2ULL,
		0xA2681D60A909AEC8ULL,
		0x14B71A11BD3E1E9BULL,
		0xDC29082F3254F368ULL,
		0xD785A2EE2DEBA131ULL,
		0x271A7B1E03B32402ULL,
		0xC9529EB5C9AFD3CEULL,
		0x389BF25352F95719ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 245\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 245 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -245;
	} else {
		printf("Test Case 245 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xCC09EEAD060A19FDULL,
		0xACEE5950F071E605ULL,
		0x95C203CC869DDDBDULL,
		0x3EBD66BBE212A782ULL,
		0xA955E036C99F9274ULL,
		0xC6035B74A4B488B6ULL,
		0x5499A71D17A6B049ULL,
		0x02E022F19AFC1C6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 246\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 246 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -246;
	} else {
		printf("Test Case 246 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0F97EF7C2FBE12B2ULL,
		0xD98C8B7DF0C78A56ULL,
		0x073BEC33C63238F5ULL,
		0x1F4727FF3C8957A5ULL,
		0x77FE017C7A9E1F8AULL,
		0xB8FD5B13ADCF1CC6ULL,
		0x419C27F5773B925EULL,
		0xFE3849F6DC0D8E52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 247\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 247 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -247;
	} else {
		printf("Test Case 247 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB1CBEE183D02335EULL,
		0xB46745355055E7C3ULL,
		0xD9218809515EABCDULL,
		0xF4A1AF6205A7CC68ULL,
		0x7D163F85E677CD0DULL,
		0xFC0861364D13EF43ULL,
		0xEA0BBB0AC22A2DA9ULL,
		0xF0B25B73E293C7D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 248\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 248 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -248;
	} else {
		printf("Test Case 248 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xB64A8D71D028B0D8ULL,
		0xEA1F49AF4412618CULL,
		0xFEDCD617E26A4F07ULL,
		0x9FCD6539305AA524ULL,
		0xA7E81F2E2BBFECA9ULL,
		0x816F981738FADC90ULL,
		0x2CB232E5F1432717ULL,
		0x030193F427688504ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 249\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 249 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -249;
	} else {
		printf("Test Case 249 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB873F03A9DBC82A7ULL,
		0x5C4CFE25794B3922ULL,
		0xD7FC24F9F0FB9057ULL,
		0xDE914AC718B49C46ULL,
		0xA0CF5D147BBA6C96ULL,
		0x4AE5AD217C68EB44ULL,
		0x11790041F6E796F4ULL,
		0xDD537255821EA056ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 250\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 250 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -250;
	} else {
		printf("Test Case 250 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF45BE54E7648B92BULL,
		0x44CF601B3849A731ULL,
		0x60F8BCC93BD80648ULL,
		0xA070E3BEC0A2ABA6ULL,
		0xEE89736C1028E321ULL,
		0xC1B637EA97B9CD67ULL,
		0x18F487F69AFB2CE9ULL,
		0x3B1F5B187DD9475AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 251\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 251 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -251;
	} else {
		printf("Test Case 251 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE23C8E86DFA3DCC4ULL,
		0x9399B99E6530A3ADULL,
		0xC07555A324876084ULL,
		0xA62B1180D7E52BA5ULL,
		0x48710E9D28414CCDULL,
		0x61DB6C0FEE18C02BULL,
		0xE7BAE353266B7572ULL,
		0x740F1265FC995AF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 252\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 252 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -252;
	} else {
		printf("Test Case 252 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB9D8CC3855E455D2ULL,
		0x752914214495AF8EULL,
		0xE3A5DC5EF81A3242ULL,
		0x692BE66035CED31AULL,
		0x026A14E464DA6A14ULL,
		0x6EFDCCFA4BD524DCULL,
		0xEC5BB75FDE389B76ULL,
		0xF8106DDB02C35325ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 253\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 253 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -253;
	} else {
		printf("Test Case 253 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5C71834CC48C51E5ULL,
		0xD4477BFF761D9495ULL,
		0x15264C8DB1FB4EA4ULL,
		0xCF851C18023CC98EULL,
		0x8AC26A131EBA7237ULL,
		0xAC03329A8C686F3DULL,
		0x9F3B6499987167FCULL,
		0xBB3938F60E286E45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 254\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 254 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -254;
	} else {
		printf("Test Case 254 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB3857B48621B9EFBULL,
		0x2CA4989C6336B808ULL,
		0xB755A1671FDA1337ULL,
		0xA99176BC35F12F7AULL,
		0x2969A42C6933324CULL,
		0x11B0A5069E30819EULL,
		0xC203C67CB2045D80ULL,
		0xE3C2758DFAAEC182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 255\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 255 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -255;
	} else {
		printf("Test Case 255 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC85617FFC2F7202EULL,
		0x00FB9A20743ED237ULL,
		0xD23F39F335DFAD9DULL,
		0x0697CE8A5F8426F2ULL,
		0xD2B053E72FA57FAEULL,
		0x499A6815921C72C7ULL,
		0x1C41536CC09DCDC2ULL,
		0xE1ACC7A7B1F67FECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 256\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 256 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -256;
	} else {
		printf("Test Case 256 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEF3A0BC6706B7CB0ULL,
		0x6BCD183361C1C759ULL,
		0x78312806E4462C8CULL,
		0xB0F5FC83B464257AULL,
		0x5DD3C0CA2186D661ULL,
		0x797619FEC347F7CFULL,
		0xDFC28AE91BE60254ULL,
		0x76ACF71783B2F8A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 257\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 257 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -257;
	} else {
		printf("Test Case 257 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CBAB58C16BCDE67ULL,
		0x270BB1BD70362902ULL,
		0x001DFFCD82CE8369ULL,
		0xE9589A88BCC5D993ULL,
		0xD05E18618DB5BD7FULL,
		0xDF5446B91E2AA675ULL,
		0xED0DF3099AB0C03CULL,
		0xDF60870D953B90E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 258\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 258 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -258;
	} else {
		printf("Test Case 258 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x43CDDEDB72BC3473ULL,
		0x4D5FE6C65FA520F7ULL,
		0x4E94D76DED5942EAULL,
		0xE70970A94EB65BD7ULL,
		0x5824630F7C259AC7ULL,
		0x7E8E288B02AAF4C7ULL,
		0xB16D1DC813395700ULL,
		0x60906FCDB2448AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 259\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 259 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -259;
	} else {
		printf("Test Case 259 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA715113A841D1E60ULL,
		0x50252021573A3A1BULL,
		0xAC2590EFE561DD26ULL,
		0x4C1C971975B9ABE7ULL,
		0x233C6EE7CC2CA458ULL,
		0x98B685DD5BFBB846ULL,
		0xF20B00925F2E8C06ULL,
		0xBDA52AAC9F9D2C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 260\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 260 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -260;
	} else {
		printf("Test Case 260 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x25A342B41173EA7BULL,
		0x52AD4B691E0D147AULL,
		0x97F8D1B756B9D8E6ULL,
		0x21B4CB52F64FC736ULL,
		0x67B661435B53C4E8ULL,
		0x267CCB2EF700D410ULL,
		0xC12DD43219C5A1F0ULL,
		0xFF8D6EBA919F5BC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 261\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 261 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -261;
	} else {
		printf("Test Case 261 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBCE203EA1D5502E5ULL,
		0xC79B3BC58FB4EB05ULL,
		0x5E10C35491DD8B95ULL,
		0xE035B96440C8A990ULL,
		0x099692829D0E0233ULL,
		0xD01621DF17BECDCCULL,
		0xF3BE223761F5F243ULL,
		0xD1A440C69FBE4B56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 262\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 262 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -262;
	} else {
		printf("Test Case 262 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x53A308465994B795ULL,
		0xAEF8AA65481974D8ULL,
		0x89676504330C70DBULL,
		0x6E2CEB8761DC9A1DULL,
		0xAF125A89AF4C7D57ULL,
		0x4E8612B38ADB624EULL,
		0x5064A213939F4E00ULL,
		0xAEFC2137A7C91128ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 263\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 263 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -263;
	} else {
		printf("Test Case 263 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5971EAD2AED0EDD0ULL,
		0xB5BAD8AA972A7C82ULL,
		0x1D5989F0EBA77DC9ULL,
		0x93D7C5E29D112514ULL,
		0x8DAF1F1A793CFD79ULL,
		0x7A51DC3B50C99DAEULL,
		0xD57DA1AD529A523FULL,
		0x82822FAF61578314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 264\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 264 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -264;
	} else {
		printf("Test Case 264 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8DF6BACE17E5F792ULL,
		0xDDBEAA468DF0BC5FULL,
		0x03B58DC98F4EAB53ULL,
		0xF7EA7F12E5256C89ULL,
		0x686B54007EFA17EFULL,
		0x25E92DADAB366616ULL,
		0x677F90B116211126ULL,
		0xB7AAA7C720465DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 265\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 265 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -265;
	} else {
		printf("Test Case 265 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x610868D6ED25353BULL,
		0x6529261F6184F06FULL,
		0x626DCC53CD3C4341ULL,
		0xAC108BFB485AC7DEULL,
		0xB3EE69114066786BULL,
		0x1E2CF8C090885BE9ULL,
		0x87EFC708293B72A7ULL,
		0x6801ED0127E2740DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 266\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 266 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -266;
	} else {
		printf("Test Case 266 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x954D45756D1C44ECULL,
		0xE4C39FD8FA3CA922ULL,
		0x606EA19F5B0C0412ULL,
		0xAC2B5B2EF11318A4ULL,
		0xD8170448DAB61832ULL,
		0x3756A58F5C357E78ULL,
		0xF86A44664B380B42ULL,
		0x6B7C7BC19E4A376FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 267\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 267 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -267;
	} else {
		printf("Test Case 267 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBBF7A92E706A2A4CULL,
		0xAF045C09BEB019EAULL,
		0x5849123416997D1CULL,
		0xBDB8174E82CA394FULL,
		0x4C003AE1ED9F96C8ULL,
		0x3E57449033CC8E65ULL,
		0x9FD76252B2A50901ULL,
		0x207EDC554F665730ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 268\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 268 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -268;
	} else {
		printf("Test Case 268 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x840B0C2E9A606123ULL,
		0x99A40738A4928B4DULL,
		0xFCD0AE384C0E0705ULL,
		0x9C8252499DB603F9ULL,
		0x22E49FCA2C5E1A80ULL,
		0xC18506DF001E14C5ULL,
		0x69C76F934867A17FULL,
		0x1864599DD412D429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 269\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 269 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -269;
	} else {
		printf("Test Case 269 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5DD07CA8BB0793C7ULL,
		0x91D401361CF32820ULL,
		0x0DFCA77C30846651ULL,
		0xD13F980058B6FA48ULL,
		0xD5143223033FCCD1ULL,
		0xC641F5B3FDD578F4ULL,
		0x27F9964C535D3925ULL,
		0x3B0B641C87203913ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 270\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 270 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -270;
	} else {
		printf("Test Case 270 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x9E161B15520DF549ULL,
		0x97D4FDE59382153AULL,
		0x680E6C83CFABC44DULL,
		0xE6A80781EC237BF6ULL,
		0x32E6B2E0DB40E22FULL,
		0x2BE8E51AA7CEF184ULL,
		0xCA89705CC4974442ULL,
		0x0367C0E5EB920C1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 271\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 271 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -271;
	} else {
		printf("Test Case 271 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x29BF1AB578B27402ULL,
		0x475F756D256E081BULL,
		0x024983394D348ED8ULL,
		0xA8EDD5A28A455A59ULL,
		0x3E5F122148F50F8DULL,
		0xDC8539FD87D46FDFULL,
		0x37AE8AD09AF923F7ULL,
		0xFF752B9BBCA2F348ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 272\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 272 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -272;
	} else {
		printf("Test Case 272 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9EDCCBD38326434CULL,
		0xD6F6AE37943AB024ULL,
		0x633BF718A6579446ULL,
		0x3B19A6F4904F0943ULL,
		0x16595188E79F62CFULL,
		0x4DE6A4D57F7F1836ULL,
		0x0C398A53FCC834EEULL,
		0x4446800B3E711149ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 273\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 273 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -273;
	} else {
		printf("Test Case 273 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF0502C8B08D991EFULL,
		0x0CA658BC23963FE2ULL,
		0x0EC2B98743CDE32BULL,
		0x8D3934A81E5388FBULL,
		0x63251FB6ED0208D6ULL,
		0xE1032FC035F5720FULL,
		0x2F457A73945EB99AULL,
		0x6D2B09E5CBC5305CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 274\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 274 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -274;
	} else {
		printf("Test Case 274 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC31D77368A0DEAAAULL,
		0x999AE0379E98D6E5ULL,
		0x23F3DAF34AC81D2AULL,
		0x027486C5ADB30791ULL,
		0x0ECF961D45F3B657ULL,
		0x1FF585DEB98EAB39ULL,
		0x85A3BA928D972A9CULL,
		0xF534E9B76B63A8DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 275\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 275 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -275;
	} else {
		printf("Test Case 275 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA6D33BAE9C5B078DULL,
		0xE988915E59E25560ULL,
		0x76D808CA6DC618A6ULL,
		0x7192A5F76B46A52DULL,
		0xB621300DC40A7CDAULL,
		0x89CCA79458DEFFAAULL,
		0x6D2B55BFFA782746ULL,
		0xB029CD40371B5C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 276\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 276 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -276;
	} else {
		printf("Test Case 276 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x97AFDC0F3A656CC3ULL,
		0xAC97BB63177DFFB2ULL,
		0x93E7138A77D9A3E4ULL,
		0x56F07AC56799A829ULL,
		0x830864C33C53F70FULL,
		0x7A94CAFAC8C28D7CULL,
		0xAA63C155541E699EULL,
		0x4FA6BF7D13C0A1AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 277\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 277 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -277;
	} else {
		printf("Test Case 277 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x76C346B60A037FB2ULL,
		0xFD15BC3E92828E9FULL,
		0x5B651F8D9C087DB9ULL,
		0xC273A1A13CAA8F0AULL,
		0x2E473B2861597A00ULL,
		0x5CC5A5D0241A2FF1ULL,
		0xC8ECB990903F0F57ULL,
		0x96FCD5BA8271A562ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 278\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 278 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -278;
	} else {
		printf("Test Case 278 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7B4E7DA19895DEAAULL,
		0xF71834CCCD386B1DULL,
		0x85FDDCFEE00DA698ULL,
		0x1A566749C18F1C9EULL,
		0x8B3F4BEBF570D712ULL,
		0xFEBC40E35E4C17C6ULL,
		0x12A64CCCB6092B89ULL,
		0xAFE9ED40F7E82E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 279\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 279 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -279;
	} else {
		printf("Test Case 279 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x93394954C1DC48BFULL,
		0xD871D19A80F5D71DULL,
		0xEB568432F15316EAULL,
		0x02D02DA1846015AEULL,
		0x87C9EE5B011C36DAULL,
		0x5610836A92B1435AULL,
		0x15E703B281AE2055ULL,
		0x9B26723CBA0A811CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 280\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 280 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -280;
	} else {
		printf("Test Case 280 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF638A3BA318A59ADULL,
		0x8D8266D5D3AA0873ULL,
		0x68264774760D9798ULL,
		0xE1DBF01B1337C435ULL,
		0x9C386C913E7184B3ULL,
		0x8791802443B6D9D1ULL,
		0x84F8E458234D35DCULL,
		0x45CC4DC4B6BD3480ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 281\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 281 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -281;
	} else {
		printf("Test Case 281 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDADCA2BB1F42EA18ULL,
		0xC0D03F0381D3F393ULL,
		0xCC5001EF48AF6B91ULL,
		0xD4A0EAA1163A7A2EULL,
		0x3F1FBAF922D11451ULL,
		0x5F552A26AADA481FULL,
		0xB648E21E3EB40DE8ULL,
		0x6C697408FD16D872ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 282\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 282 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -282;
	} else {
		printf("Test Case 282 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x68EF1BBD3B9C4AF6ULL,
		0xAF92BD5B4D5573D6ULL,
		0xAF0AE009A0BE30BDULL,
		0x9822C93C35918FEFULL,
		0xA86E1ECE16168004ULL,
		0xF4889261162D9102ULL,
		0xA88CE52B3B37AF62ULL,
		0x48B235F7A3907152ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 283\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 283 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -283;
	} else {
		printf("Test Case 283 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAD51FDF5A62E7D15ULL,
		0x2CBA0E8B6C2C22F2ULL,
		0xB2C621134E9B6FADULL,
		0x0A1C585BD0DBE7A7ULL,
		0xB409BFD93ED0D4B9ULL,
		0x0A7177103B817A8AULL,
		0x1E4F7D48B63764DBULL,
		0x98873A2C4FA314B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 284\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 284 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -284;
	} else {
		printf("Test Case 284 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x41A914B49D31CAA0ULL,
		0xB0A2E226EBB451C6ULL,
		0x3BF7E46D1D42059EULL,
		0xDC0FE1240E02FF53ULL,
		0xC03D64FCCC514D2CULL,
		0xD79406834006A650ULL,
		0x289EDB78AB41B41DULL,
		0x38DF02BEBF88E166ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 285\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 285 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -285;
	} else {
		printf("Test Case 285 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4608C58EB84B4BA9ULL,
		0x33351E1FBA5920ECULL,
		0x04CE78B9B22A42A7ULL,
		0x2A7D2B9568A2324CULL,
		0x8F9858FDB954A37FULL,
		0xC6F68FC52015D143ULL,
		0xCBECD4395B7AA168ULL,
		0xF628F605F6851441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 286\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 286 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -286;
	} else {
		printf("Test Case 286 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x25C5597A5C2CBCCCULL,
		0x7AC89333EED592E5ULL,
		0xE2432B7A357E0E5BULL,
		0x0CE060A3E7C67BDEULL,
		0x6D2DE9D87697075AULL,
		0x2550342DEA9565C4ULL,
		0x871E51DDAA530B07ULL,
		0xB61785F97CED3BB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 287\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 287 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -287;
	} else {
		printf("Test Case 287 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6D4FC88BA94B3EF7ULL,
		0xFCC6072F4BD97278ULL,
		0xC4551E0B89ABFB6CULL,
		0x01E311039D28ED3AULL,
		0x11E7CBC1DB03A29DULL,
		0x14EF1F879C25FDC9ULL,
		0x1489DCF63D4991C0ULL,
		0xD60F5EA386A6B2B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 288\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 288 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -288;
	} else {
		printf("Test Case 288 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3B731680F287AB90ULL,
		0x585DE503E97A11EAULL,
		0xDFB0B35A6735C276ULL,
		0x66813304879021C4ULL,
		0x6A658C8298552749ULL,
		0x75A4CBEDF487D5FCULL,
		0xE50DE831172637A8ULL,
		0x4728936651DC5494ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 289\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 289 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -289;
	} else {
		printf("Test Case 289 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB4AAF63771307F9AULL,
		0x7957C2588354D1F2ULL,
		0x0F686C856A7D9277ULL,
		0x2225C54230657F3DULL,
		0x14179BB44BFF9264ULL,
		0xAE3703F7A0A8D3BAULL,
		0xA42965812884D2C8ULL,
		0xD5854566BABE5467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 290\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 290 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -290;
	} else {
		printf("Test Case 290 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE1EFA75AA9ACA5EULL,
		0xF80A74832F5CAD68ULL,
		0xA58849218BF80445ULL,
		0x865BFCE349DFCBFDULL,
		0xC019601634FDB44CULL,
		0x4353BBF26391F1E1ULL,
		0x52FA4DDBCEDDC2E1ULL,
		0x9203A5C552C7CB94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 291\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 291 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -291;
	} else {
		printf("Test Case 291 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1257A3168F697DF9ULL,
		0x4712AE9D196056B9ULL,
		0x7D583754CE44970CULL,
		0xBA22D06B29EDAADCULL,
		0x41502320B902E5E2ULL,
		0x185B0E3C5C2C1CD4ULL,
		0x6F5104E0FC4F2C87ULL,
		0x8B8FDD11CDB0FDA2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 292\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 292 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -292;
	} else {
		printf("Test Case 292 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE78EE95DC46FB1D1ULL,
		0x11847903DDAB8CD1ULL,
		0x3A0C5210197E30CFULL,
		0x40E4F02E5B630127ULL,
		0x3C6FF97CD366E5C9ULL,
		0xC3600266F8A9B7BBULL,
		0x01BCB25482F048BAULL,
		0x362620B5E22CC0DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 293\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 293 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -293;
	} else {
		printf("Test Case 293 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x53F246106F54B024ULL,
		0xB80699A04AB6D08DULL,
		0xF8DB8CDC365A5F9CULL,
		0xB2D7474200977DCFULL,
		0x8114437AEC854F7DULL,
		0x1D81BC7429682F7AULL,
		0x504C64315FD2CB6AULL,
		0x1BAE5F15F1E92423ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 294\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 294 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -294;
	} else {
		printf("Test Case 294 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x49344306533C7871ULL,
		0xEBB587D7C9BCAE15ULL,
		0xAFABBE730A3F924CULL,
		0x4809C6B3BD22E4AAULL,
		0x0329FB12CAA9F9FBULL,
		0xC6B3C87854D0DCA0ULL,
		0x146E74E66792300CULL,
		0xC690947E964C8AB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 295\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 295 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -295;
	} else {
		printf("Test Case 295 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDCE87C88BEE5F2DBULL,
		0x33537BDBFB1AD311ULL,
		0x7F2C2594698415E8ULL,
		0xF449FEE14EEFD953ULL,
		0xEFF3371A557CA1FBULL,
		0x9714E77F35644C88ULL,
		0x8B2FE80D16D75F0EULL,
		0x98E039996B0C7F6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 296\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 296 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -296;
	} else {
		printf("Test Case 296 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD54B7C6B90525F00ULL,
		0x1E2F66F7BB13A029ULL,
		0x8A7791CFCDA3BD8BULL,
		0xDC9D31755A63E5C8ULL,
		0xC941BDE415E2C508ULL,
		0xABDD2D77690E4188ULL,
		0xD9B7C5793F051AF8ULL,
		0x5356941421AA3F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 297\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 297 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -297;
	} else {
		printf("Test Case 297 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x20078FB88C58030AULL,
		0xD6326585EF1E77DDULL,
		0xAC3EFF027C8C4EAFULL,
		0xB24736B4A37CF10FULL,
		0x7CB85A80A1855EC0ULL,
		0xA0BAFE0D9BD32FBCULL,
		0x8410DF3B3D4C94C8ULL,
		0x966A8ABF9B0930FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 298\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 298 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -298;
	} else {
		printf("Test Case 298 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAB06BA7BA43D0722ULL,
		0x5063C3027895903CULL,
		0x0C68B335A3E08855ULL,
		0x2ABFE241D6C9BC33ULL,
		0x13F6D63B3671DC18ULL,
		0xE0DA8FE19F570943ULL,
		0x87788A5CC82929B8ULL,
		0x968CB0F4F46FDDDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 299\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 299 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -299;
	} else {
		printf("Test Case 299 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x08A2191010E8058BULL,
		0x13BA02B879EBCD92ULL,
		0x5BEDEC9308D49C5DULL,
		0xE6A166D2291DC183ULL,
		0xB4240585FAFE52E2ULL,
		0xE229F36954C88C69ULL,
		0x7CFEE5A2C7B551C3ULL,
		0xF4EC6455F9AB89B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 300\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 300 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -300;
	} else {
		printf("Test Case 300 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x7E5D6A0328F41B5FULL,
		0x0A07D37E943F4351ULL,
		0x1F7C4F97FC5EE43DULL,
		0x187D4BA3DA75D6A1ULL,
		0xBCF321C2BB496C8BULL,
		0x8B12C0A4E288F01DULL,
		0x906B942ECF44FA2EULL,
		0x0D12DB6641FB1E90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 301\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 301 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -301;
	} else {
		printf("Test Case 301 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE3134FE8BE34F840ULL,
		0x1544FEB1B6B844B6ULL,
		0x99C0CA02C77134EAULL,
		0x4B24C18DD7E174E0ULL,
		0xC3E966F69EC29401ULL,
		0xACA8C68D4564442BULL,
		0xF3289BAE5922573CULL,
		0x5E8F264A3A3CE43EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 302\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 302 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -302;
	} else {
		printf("Test Case 302 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0B36383ADCEDE461ULL,
		0x34CC7192D6C4803AULL,
		0xADF695E1CA131142ULL,
		0xA4D6CE95BE5349CBULL,
		0xB17458FAD9F110B2ULL,
		0x74A43B79F6672AE3ULL,
		0x8401A17489874283ULL,
		0xDCB4C4B95436A5CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 303\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 303 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -303;
	} else {
		printf("Test Case 303 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5CC1A5CB0530D027ULL,
		0xCA92E07B0E45A7E9ULL,
		0xE471C792EDC4BAB7ULL,
		0xB609404B1B0AC3BBULL,
		0x109F90E73B8BC230ULL,
		0x2F01FDC5CE2BACA3ULL,
		0x7EA453E4DA4B3514ULL,
		0x68CF8C2A71515878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 304\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 304 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -304;
	} else {
		printf("Test Case 304 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED90E162E017BC8DULL,
		0x1055DD6A840EBBEEULL,
		0x72F1A0E7C7282A5CULL,
		0x2B1D04C53F4708EFULL,
		0x5B7E7539409F2A11ULL,
		0x584DDE1DBC2FFD1BULL,
		0x07DF8B48AAA54049ULL,
		0xA1B66B6737E4E856ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 305\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 305 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -305;
	} else {
		printf("Test Case 305 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDDD0EAC76B922F5BULL,
		0x39CB4D79A3F242CDULL,
		0x89C60DA9F46C7213ULL,
		0x066762C20F9E0DACULL,
		0xB7F044A1E9556F78ULL,
		0xACAD8D4FB26792D7ULL,
		0x2433C2A479FA0D34ULL,
		0xAC28E37CBF2787A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 306\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 306 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -306;
	} else {
		printf("Test Case 306 PASSED\n");
	}
	printf("---\n\n");
	la = 501;
	k1 = (curve25519_key_t){.key64 = {
		0x10A1C04527F954AAULL,
		0x434D00C400B26173ULL,
		0x7461F71D25748739ULL,
		0x28E576F7BACD9288ULL,
		0x47D862C291B9E104ULL,
		0x4A9BEC2B05D3F0E8ULL,
		0xFB355821BEEAE787ULL,
		0x002BD2582130951EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0020000000000000ULL
	}};
	printf("Test Case 307\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 307 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -307;
	} else {
		printf("Test Case 307 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8D42673D11A5BC8DULL,
		0xC8929256A377B440ULL,
		0x21472872202C8628ULL,
		0xFD07F5097D583F4AULL,
		0xA7FFBBBDD2D5B126ULL,
		0x07C020D672FF14DEULL,
		0x825FC928C417904BULL,
		0xD225A25D990F06DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 308\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 308 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -308;
	} else {
		printf("Test Case 308 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4117DA92721CF902ULL,
		0xA5FFB9B0A21C1318ULL,
		0x3744DED994B206A6ULL,
		0xE0C89E3704D95BEBULL,
		0x8C6FDE30AA60E532ULL,
		0x7BEEEA9A2D491532ULL,
		0x75B9191E8F1CAE0FULL,
		0x124B78561FD17ECFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 309\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 309 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -309;
	} else {
		printf("Test Case 309 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x54EE0339C7D37A41ULL,
		0xF7E9528B0944CF83ULL,
		0x7E79BAFF1FD0824FULL,
		0x21EEA5040E5D434DULL,
		0x2F7845844D7E9725ULL,
		0x7C69BD842A2013C2ULL,
		0x134843BC7B455B81ULL,
		0xCECA80D7E88DC0CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 310\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 310 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -310;
	} else {
		printf("Test Case 310 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x78A4FE6DFB939D86ULL,
		0x3C50AAC361AB9916ULL,
		0x938CF323CFB8268BULL,
		0xB178952CF54FE7A3ULL,
		0x1EDBDB734F38968EULL,
		0x638E2A77EDE08F44ULL,
		0xD072CCAE8EFD561FULL,
		0x93274172B1B16506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 311\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 311 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -311;
	} else {
		printf("Test Case 311 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0C57362016EA999CULL,
		0x3FBDA5DAA1605095ULL,
		0xD7B7BB5F305509C7ULL,
		0xC24E51C2BE4F724AULL,
		0x8EF4F490DED8997DULL,
		0xCD49E054382D26F8ULL,
		0x49C48113D69BC1E6ULL,
		0xE8BBE9508CEA2C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 312\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 312 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -312;
	} else {
		printf("Test Case 312 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5F8CAED1C3CA160BULL,
		0x37D7AE344A110062ULL,
		0xB3D0C9D38D0F166BULL,
		0x130B0D6DD211C4A4ULL,
		0x2E6561216B3081D5ULL,
		0xFDDDA1F5D619E3E1ULL,
		0x060B724BBD342DDAULL,
		0x5C05C0E7C1AE072BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 313\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 313 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -313;
	} else {
		printf("Test Case 313 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB1D41199C9C2664AULL,
		0xEF258CFD387A1968ULL,
		0x050A8CDD9ABAF551ULL,
		0x11DD214AB633A9BFULL,
		0x5D3ECAA63E5356ABULL,
		0xBB0C4F6B7E2BA921ULL,
		0xFBC05FE94C2B8AFBULL,
		0xFAEB1F50EC68734DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 314\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 314 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -314;
	} else {
		printf("Test Case 314 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8C51240C84CC836AULL,
		0xCB65A2D9D498A19FULL,
		0x3C9C9ECE02ABF7C9ULL,
		0xF6FDB479759701DAULL,
		0x8B8DF3510DD051F7ULL,
		0x92D4CB49CB45B117ULL,
		0xD8F51687FB465F5CULL,
		0xEEBD82B4A4766B58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 315\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 315 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -315;
	} else {
		printf("Test Case 315 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB7F1322D793F2B89ULL,
		0xDABE3AEB50B815AFULL,
		0xB43DCD305D3C871AULL,
		0xAB292278A4A54C7CULL,
		0x412B5FF474D3264FULL,
		0x01E45C8D14945CC7ULL,
		0xBBF15CE16643EB3AULL,
		0x1962607C95ECBB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 316\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 316 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -316;
	} else {
		printf("Test Case 316 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBF82BD8E2B9A4181ULL,
		0x28082D8CF2E66564ULL,
		0x0C31FE97588BFD7FULL,
		0xC4756339A648F0EDULL,
		0x3EBB674A0AEEFD72ULL,
		0xCEF701967523EE91ULL,
		0x1E02AF85B04055A2ULL,
		0xB409652E32FB73ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 317\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 317 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -317;
	} else {
		printf("Test Case 317 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2DE4A35320ED303FULL,
		0x1CEFC894BBED4C23ULL,
		0x47BAEBE1E62535F2ULL,
		0x5707F0A0311C9B76ULL,
		0x6D39EB5DE7EAEFAFULL,
		0xDD488D0C86DBF790ULL,
		0xDCAED065C347B963ULL,
		0x1518DFED6FB12234ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 318\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 318 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -318;
	} else {
		printf("Test Case 318 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x22842A541B5E98D7ULL,
		0x6AD6F3AB78B61A77ULL,
		0xCC4B9E24D8F8AA8BULL,
		0x9D8B22FA50BD6BD3ULL,
		0x2CE51735410F038CULL,
		0x468D260A63D3B148ULL,
		0x99F5C622E7FA1CF4ULL,
		0x1F9916215A6BE9AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 319\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 319 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -319;
	} else {
		printf("Test Case 319 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3A08246807731C30ULL,
		0x91E2F00A47CA3D62ULL,
		0x1C72641856449BDCULL,
		0x23B03EFAFB1275F0ULL,
		0x2565FBC5993ABCD0ULL,
		0xBF3F50EC4B20043AULL,
		0xCA62698123628FFFULL,
		0x3846CEF6DE34B272ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 320\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 320 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -320;
	} else {
		printf("Test Case 320 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3D88C27467EB4C1DULL,
		0xAA48A79B43886786ULL,
		0xA4051F8ECF722745ULL,
		0xF93F27193598E7BCULL,
		0x4887424707037CDAULL,
		0x79653E182529B7BDULL,
		0x382234861460A5A3ULL,
		0x48BF0913D1F939FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 321\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 321 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -321;
	} else {
		printf("Test Case 321 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE47DC185ECB3BC83ULL,
		0xD704A5EC042F95C6ULL,
		0xECF766254E82B7A1ULL,
		0x9EAFAB08C3A37F49ULL,
		0x664EF38B084AF852ULL,
		0x318710E52031E525ULL,
		0x4058592CFE1C5F08ULL,
		0x2F7A7016547D7314ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 322\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 322 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -322;
	} else {
		printf("Test Case 322 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x64A0AC42FA78E178ULL,
		0x8D9B582670D9C170ULL,
		0x867262C2001171CBULL,
		0x576EEFDEABD6A254ULL,
		0x0849FA7A720C1226ULL,
		0xB53BC6861ED97A75ULL,
		0x5B932A21D4BE61A9ULL,
		0xE78F3BDDB43E7628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 323\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 323 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -323;
	} else {
		printf("Test Case 323 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD541113EF6875B77ULL,
		0xC0834B722076C717ULL,
		0x75046F73ED0C2940ULL,
		0xB7E61B5EB09854CDULL,
		0xD175CEA6D71B261EULL,
		0x96D57FE92F6DE697ULL,
		0xB6E772B1BB4DA8AFULL,
		0xE203568423A42C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 324\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 324 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -324;
	} else {
		printf("Test Case 324 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEBE75BA9E17D1437ULL,
		0xBA0593B5B0B3F7E9ULL,
		0xE8EE633C39B66725ULL,
		0x2078136E29B9AAF5ULL,
		0xA5A99BF02A06840CULL,
		0x0A50B18F01A5FA27ULL,
		0x649041E82C6D943FULL,
		0xA83F8EC58056E3CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 325\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 325 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -325;
	} else {
		printf("Test Case 325 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x74F5D4FF80D05043ULL,
		0xC14339BD8D41406BULL,
		0x104A74085086D061ULL,
		0x6E665BBDBC262578ULL,
		0xB707A7E8AE7558A6ULL,
		0x1F8AA869D86FE0FFULL,
		0x8C23B93ED7A7DE49ULL,
		0xFE009D9BA972E52DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 326\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 326 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -326;
	} else {
		printf("Test Case 326 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF667A339C1EF3EF5ULL,
		0x087B5CAD8F17E934ULL,
		0xA12C96DC42E17B85ULL,
		0x57AC0AE488F27580ULL,
		0x920909C2743AA6BCULL,
		0x4C5DB68EE654452DULL,
		0xF1A6E7038B2ED199ULL,
		0x9D54575310DFB26CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 327\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 327 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -327;
	} else {
		printf("Test Case 327 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x203392DFC335DA2AULL,
		0xA39908882581B745ULL,
		0xF9BA2108B4CEAA4DULL,
		0xD202E79887562AB3ULL,
		0x3178BC0A24446B43ULL,
		0x8ECF8EB5D2918E92ULL,
		0xF522661B52CC7D63ULL,
		0x684912C1331ED070ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 328\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 328 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -328;
	} else {
		printf("Test Case 328 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC4A3682C973A4C19ULL,
		0x867FAAFBBF7C143AULL,
		0x9F2496AB953DB571ULL,
		0xD907D0E60DB2F000ULL,
		0x0AC507C6DE86B019ULL,
		0xAE1FD8795EB7C39FULL,
		0xD3B8BA4CA57C8B21ULL,
		0x1710FD7CD9C09506ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 329\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 329 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -329;
	} else {
		printf("Test Case 329 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC70AF8513EA9E620ULL,
		0xCD38CC5CEF9D72B5ULL,
		0x7F0A474F0DE2C901ULL,
		0xC9A3D70D0EAB495DULL,
		0xE84ECA84822D6CBCULL,
		0x8E57608C356B99FBULL,
		0xA7C323897D4AD057ULL,
		0xD822963A1EC33FEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 330\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 330 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -330;
	} else {
		printf("Test Case 330 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x3BFB756AA18D1C36ULL,
		0x3C2AC62ADA557B5DULL,
		0x95CE70749E6CA174ULL,
		0xA7C0CFFC0E5496E3ULL,
		0x8BA67EF0600B746AULL,
		0x537407DE1C9AD997ULL,
		0x5BB8B3D0BA1C84F9ULL,
		0x18A78F7E2BF6BBAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 331\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 331 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -331;
	} else {
		printf("Test Case 331 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1A7F3DD9139F3C74ULL,
		0x67EE1EB7B606D6D5ULL,
		0x03266167880B75E8ULL,
		0x50B5E197F7F0A798ULL,
		0x82D9E246DA6C0E67ULL,
		0xEFC9D82479CACFCCULL,
		0xDF6C5C9C9F0C7744ULL,
		0x50E39432514B20DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 332\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 332 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -332;
	} else {
		printf("Test Case 332 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x5D5A479E68F6ED05ULL,
		0xBB3C4C03309BC51DULL,
		0x1D17C56AD931F54CULL,
		0xFEA70C32834A21F7ULL,
		0x029EF082CA1316A4ULL,
		0x84BEAC66C0FB7865ULL,
		0xFBAEFA72B104D595ULL,
		0x05033F95A6BD4F79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 333\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 333 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -333;
	} else {
		printf("Test Case 333 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x494C6A937DB0721FULL,
		0x1FA4C2A4BFB2797FULL,
		0xF6990C47DE5993F0ULL,
		0xCA362D2875FA2F14ULL,
		0xDCEAA88DBFE8C512ULL,
		0x9C49D178A56E96A7ULL,
		0xF86536F8E5787B35ULL,
		0x146A340C11BC8868ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 334\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 334 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -334;
	} else {
		printf("Test Case 334 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3CF17CA12DE7CC70ULL,
		0x5894D10F4E2E092BULL,
		0x87EA5EA30549E4ABULL,
		0xAEDD4C7C50AFF152ULL,
		0xAA89619926905591ULL,
		0x1B9EDA60C866B3DBULL,
		0xBC96EA44C3DBB473ULL,
		0x35D6D544D03753DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 335\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 335 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -335;
	} else {
		printf("Test Case 335 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6C641DE20A9625BEULL,
		0x2B37879AB53DDBCDULL,
		0xB33DC0E32A35AA77ULL,
		0x725811E6700E1B87ULL,
		0xE041DFDD57DF377CULL,
		0x8F4BEA07AC79447DULL,
		0x1A64B82033285A58ULL,
		0x9FAA8722AB33B321ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 336\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 336 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -336;
	} else {
		printf("Test Case 336 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4CB382E320D7CE93ULL,
		0x9E8064C9AD7C8D9AULL,
		0x61FE08985C893C47ULL,
		0x99E3E4A7BAB424F6ULL,
		0x9AB57AA867D0C4B4ULL,
		0x0BE40551AB4C464EULL,
		0x1251FE4B1026AEBEULL,
		0x8BBBC83E7D221F1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 337\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 337 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -337;
	} else {
		printf("Test Case 337 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0F4ABBB9A25BA5C7ULL,
		0x56E9FF3354D56D4FULL,
		0xAC18608C0C0C56BAULL,
		0xC03DABCE141FB3A2ULL,
		0x0B5B1DBFE73E131EULL,
		0x8271D21DDBD1DB31ULL,
		0x02DB2C98C7042B32ULL,
		0x6B8A054FC8718262ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 338\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 338 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -338;
	} else {
		printf("Test Case 338 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0D18D5AEAA7F174ULL,
		0x7C3D6453E31B4069ULL,
		0x0A364DAA412B942EULL,
		0xBBD1919B0D9C9827ULL,
		0xC73C7C702FCF67B2ULL,
		0x138D33F906A172A0ULL,
		0x8AF5565D8441EB84ULL,
		0xFBC024AC9F75E1F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 339\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 339 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -339;
	} else {
		printf("Test Case 339 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5E9C72D2A093AF22ULL,
		0x590D432103E9110FULL,
		0x52D15FD8B059D1F0ULL,
		0x8426702500C5174BULL,
		0x31AABACD385B11BAULL,
		0xB08866267D573641ULL,
		0xCEFE8EE559009C3AULL,
		0x66A4C8AF366E13C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 340\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 340 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -340;
	} else {
		printf("Test Case 340 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF0AF569F843B49AEULL,
		0xE8852EFD7A376C2FULL,
		0xBD6CD46F7FF9EBE7ULL,
		0xDD9B9C8A56D873A7ULL,
		0xBB83DA2CFF5EFE0FULL,
		0x6036DE05D63CC0DAULL,
		0x8FCBF31B4BBC351DULL,
		0x35B3965A51BA7143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 341\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 341 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -341;
	} else {
		printf("Test Case 341 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEB6A43CDD84D388BULL,
		0xEC5AE4DB5D005156ULL,
		0x3965369301C035A4ULL,
		0x994F03CACE7A0820ULL,
		0xF83E371D42EEE907ULL,
		0x5DF028966F54CFE5ULL,
		0x2B42F847FB5553BBULL,
		0xD3A39804B70F4946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 342\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 342 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -342;
	} else {
		printf("Test Case 342 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9A8FE16126914203ULL,
		0x0C815B9480DD544BULL,
		0xF3CACCA2164F5719ULL,
		0x4536539A01D6B8FCULL,
		0xCC1567BD74648352ULL,
		0x155A62ADEA39D322ULL,
		0x9F998D8BEC942934ULL,
		0x7B708BAF88CC3E81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 343\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 343 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -343;
	} else {
		printf("Test Case 343 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3AD32CBDCC9C044FULL,
		0x2E4A8A530ECABF3CULL,
		0x3A6C5C9F5493E313ULL,
		0xDBFDB9542463A4C2ULL,
		0xC308973DE75C2929ULL,
		0x555DD41026F6095FULL,
		0x2A5F70686C662311ULL,
		0x736684C32E5C298BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 344\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 344 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -344;
	} else {
		printf("Test Case 344 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFC23CB467A7536FDULL,
		0x38A95DFB270768B6ULL,
		0x52406EBDE231F5BDULL,
		0x8ACF678A1DD50B38ULL,
		0x048C5AF256A6D409ULL,
		0x1FA9E7EEB0B70013ULL,
		0x7A35D8433F3DDE02ULL,
		0x46FF406B6088A7D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 345\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 345 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -345;
	} else {
		printf("Test Case 345 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xE6F518C9B6568694ULL,
		0x5F0671606E5C3F0BULL,
		0x4C81CFE057F32FB1ULL,
		0x79AFF3B4DE606A7AULL,
		0xC89C358DB240ECEDULL,
		0xB9218AA3C3F4EE08ULL,
		0x7EA30176C7FDAC30ULL,
		0x03C5B50475280335ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 346\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 346 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -346;
	} else {
		printf("Test Case 346 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x057FFED8124474A0ULL,
		0xF89AA6CFB44EE1A0ULL,
		0x2DA50215D221DC91ULL,
		0x29809A20A6926B05ULL,
		0x5C387F12AD97E5A2ULL,
		0x88F1873B3D99B0A7ULL,
		0x9099F9F2FC6E7621ULL,
		0x271BC390CE2695E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 347\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 347 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -347;
	} else {
		printf("Test Case 347 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x324BE7022F65EAA2ULL,
		0x7086D55EE1AA0A51ULL,
		0x63E1F6454A41969DULL,
		0x47B46F9775F9AA71ULL,
		0xFC5C9A4D65DB6B8BULL,
		0x8374FCD1346150CDULL,
		0xBA5F947F28320B83ULL,
		0x772EB73A3E58A3D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 348\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 348 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -348;
	} else {
		printf("Test Case 348 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x55C75E563D45D978ULL,
		0xFDD42328F20F1324ULL,
		0xD164BA1437F5D490ULL,
		0x878D4FEE410B295EULL,
		0x116A684F98006AF4ULL,
		0xCAB94D7A5DBC846BULL,
		0x81A490D4F4E3D97DULL,
		0x9CF22A888A42DEE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 349\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 349 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -349;
	} else {
		printf("Test Case 349 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCB4FC8BC51FDB03CULL,
		0x3DCC8ED3F32C3698ULL,
		0xED8BC9D1F235F4DFULL,
		0x2381BABA42ED9DD5ULL,
		0xE744BC02A5C33A7EULL,
		0x2F89FBB962BDFCDCULL,
		0x306C4A04A9214815ULL,
		0x2FBE1AEE2E2C3C43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 350\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 350 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -350;
	} else {
		printf("Test Case 350 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x69B8AEA5E7DA7095ULL,
		0xD781052F8A437A02ULL,
		0x09ED5E12F3BE46F9ULL,
		0x71AF70ABDA233109ULL,
		0x4E5B443DC6AD239AULL,
		0xDC250069E1A187FDULL,
		0xEE7DFC3839A89617ULL,
		0x0CF073FE4644A206ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 351\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 351 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -351;
	} else {
		printf("Test Case 351 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBACC4B5A6B662556ULL,
		0xCA546D504B47ACE8ULL,
		0xE5EDB111BCC38C08ULL,
		0x99A25A1D5518E791ULL,
		0x1FE5B6E6989321BBULL,
		0x6AC134EAC016914CULL,
		0x9E8681C46DEEEDB6ULL,
		0x5AA6FF8E3BADBB50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 352\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 352 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -352;
	} else {
		printf("Test Case 352 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD61E068B819DBEF6ULL,
		0x0E27FC6BF335B5FAULL,
		0x826163A7A80C492BULL,
		0x065291E64ACE9631ULL,
		0xE9497287B1A480B3ULL,
		0x0ACB2B02B0E01ECAULL,
		0x4745A67B51D00D07ULL,
		0xD2139B7C4F08CCADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 353\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 353 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -353;
	} else {
		printf("Test Case 353 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x603D983F85464774ULL,
		0xE9B9EB50B3C52BE4ULL,
		0x105243373ADA7B77ULL,
		0x1E5E06B9F2BF09E7ULL,
		0x0C36A41448CC084FULL,
		0x07DEBA9486D4AF2EULL,
		0x66ED20CD51AC1E11ULL,
		0x6AF1AEEC6CA8E963ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 354\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 354 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -354;
	} else {
		printf("Test Case 354 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2C1255D7BC2049FAULL,
		0x9B0FE640BBE73D94ULL,
		0xA5FF497ECE4351B2ULL,
		0x0DD9C35B6A67A69CULL,
		0x34F83F5E3B1E3FACULL,
		0x95BF35623DD962A9ULL,
		0x97C18693AF76435FULL,
		0xE3B2436D1C892E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 355\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 355 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -355;
	} else {
		printf("Test Case 355 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x917E38DC19E38626ULL,
		0x84A7AF5FA051142CULL,
		0xD8DCB417FFB329BFULL,
		0xB52D373BF5E697EFULL,
		0x517F824DE79B8C5EULL,
		0x9F3F5B63E2ECACF7ULL,
		0x99FF09463A8C72F3ULL,
		0x7720EDA42D704CE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 356\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 356 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -356;
	} else {
		printf("Test Case 356 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3EDDEE5E26D2A7B6ULL,
		0x58D5E76F280708FAULL,
		0xC3F0B61121B9936BULL,
		0x6F1F17272A350D80ULL,
		0xBED5A0E625A5F0B9ULL,
		0xCF86D0BABDF52505ULL,
		0x2DDF0A3750BB62B1ULL,
		0x75914075E713EEE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 357\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 357 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -357;
	} else {
		printf("Test Case 357 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBA5B2489DFFE91A8ULL,
		0xE5E74D0BA1EC8C07ULL,
		0x47B36F9CE31981D4ULL,
		0x08FD2C2FEBA488ADULL,
		0x0782C0AD3B15D3C7ULL,
		0x95F6B2CF86937D9BULL,
		0x667CABE749977075ULL,
		0xB9F334CB26F811DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 358\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 358 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -358;
	} else {
		printf("Test Case 358 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3E98CABBA7297EC0ULL,
		0x72FB97F18FFC1815ULL,
		0x118ED8C7201C5982ULL,
		0xBC7B8AE0E13C7515ULL,
		0xD8A6D8D4DCF7915EULL,
		0x35EEE6886F92898CULL,
		0x67E02AF9FBA4F9BDULL,
		0x8CAED49CE2CC744DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 359\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 359 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -359;
	} else {
		printf("Test Case 359 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xF35DE194AB111A48ULL,
		0xAEDC5BF3DF7E9586ULL,
		0x74DE7846EA968156ULL,
		0x123B1187F3C15633ULL,
		0x232442D975137037ULL,
		0x4BAB5B43140548BEULL,
		0x32A4E0D7CA7E09F2ULL,
		0x026D1743066EB0A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 360\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 360 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -360;
	} else {
		printf("Test Case 360 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xABB6EFB4AD4C3809ULL,
		0x032AD7F292E12552ULL,
		0xCCBAC544129211AFULL,
		0x13B681D49D98A457ULL,
		0x4CA8CF5F173C7DBFULL,
		0x98E0D978A7F816FCULL,
		0xDDEF1B7F5A421691ULL,
		0xC086BA21557928F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 361\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 361 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -361;
	} else {
		printf("Test Case 361 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9F393E8743A9CF0BULL,
		0x881C2A5B2AD3F80BULL,
		0xF6CB4399643053FAULL,
		0x19F3592A69055A35ULL,
		0x4BEF4BD525F703F4ULL,
		0x70F2B04BFFA3C476ULL,
		0x18BD1FA938A1F119ULL,
		0xAA0378AD76764D0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 362\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 362 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -362;
	} else {
		printf("Test Case 362 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0F9188A07D29FB5CULL,
		0xF00C16A258268098ULL,
		0x16A6DBF2341173BAULL,
		0xD95BC79E5559CED1ULL,
		0xB18EB2D9EA885552ULL,
		0xA11C6FC481F8F65DULL,
		0xAC8D5BA3AD83A8F1ULL,
		0x51577E241CB41BB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 363\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 363 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -363;
	} else {
		printf("Test Case 363 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0317955B6D549A09ULL,
		0x46230426D1487F35ULL,
		0xFAB4E07325646B3CULL,
		0x4822491514FED527ULL,
		0x6FD3AF741E9CDD90ULL,
		0x85D6B4E99BDDA9E0ULL,
		0x9852D70A1F2F9F7EULL,
		0x6B0C7D65D7D9F201ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 364\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 364 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -364;
	} else {
		printf("Test Case 364 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x01C8EAE788CB2505ULL,
		0x96291EC965B4D5DAULL,
		0x58C677DB54D6483AULL,
		0x0EC0ACFBDDBCFBFBULL,
		0x6995CF9615DCB44AULL,
		0xC3F4BF1C7A37B001ULL,
		0x622169ACB13A6E37ULL,
		0x243BE2FD96CEB257ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 365\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 365 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -365;
	} else {
		printf("Test Case 365 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF7C6A217EF4BCE6CULL,
		0x988E143B1D3BD415ULL,
		0xF89BC6C10A8AE889ULL,
		0x7F088DA344D920B4ULL,
		0x83831522717487DEULL,
		0xEAF0100AE91705F5ULL,
		0x9E8D690764534877ULL,
		0xB4B8E21951A5D6F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 366\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 366 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -366;
	} else {
		printf("Test Case 366 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x205E4BFEE9CE90F6ULL,
		0xDB8863050E236318ULL,
		0x0E5DD693BF9F9F91ULL,
		0x07E592315692C7CAULL,
		0xD27EB5CFB26FF7C7ULL,
		0xD67B0CE57BDE1986ULL,
		0x572791E96A1E0B3BULL,
		0x412DBD5A3789B4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 367\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 367 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -367;
	} else {
		printf("Test Case 367 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x769D867AE810B565ULL,
		0x0FB5A0572987392BULL,
		0x80A5078ACAC7B2B0ULL,
		0x5B9299B00AE32915ULL,
		0x0A10D155AC6D9343ULL,
		0x76809E2A170355D8ULL,
		0xA4C67ED834B0C5E4ULL,
		0xE4B2A7138650CAABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 368\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 368 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -368;
	} else {
		printf("Test Case 368 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x1DA7D040DA29FABCULL,
		0x88E0C8FF49844871ULL,
		0xC9DA4CE92DB3ADF0ULL,
		0x5912FFBDB3E8B2C2ULL,
		0x88C5896D3492C5E7ULL,
		0x588FF4C32C7E0EFEULL,
		0x5CF0064581107E11ULL,
		0x023A122F714A50C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 369\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 369 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -369;
	} else {
		printf("Test Case 369 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF21E16798B0C8C23ULL,
		0x240306A0B28AAEFAULL,
		0xE281C6EA7E504854ULL,
		0x65BB7440A4E10001ULL,
		0x44A20DEF48819A4CULL,
		0x076529972FC778C0ULL,
		0x386C433797C6ACFCULL,
		0xD73A045EFD93F2A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 370\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 370 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -370;
	} else {
		printf("Test Case 370 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x785BA4402003EB1AULL,
		0xB3A084D680C157B3ULL,
		0x4AD4447C6B387739ULL,
		0xB32F43F9645CAB59ULL,
		0x63151A9718905DB1ULL,
		0x6B52CA8768B692A6ULL,
		0x26674CAC09B71C14ULL,
		0xB4EBB9708C88D5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 371\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 371 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -371;
	} else {
		printf("Test Case 371 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x09B85D149AD23F90ULL,
		0x8356270294B1AD12ULL,
		0x50D0D99A18AE11AAULL,
		0x0C902026A25881E9ULL,
		0xF980C98063CAE299ULL,
		0x8790F50C651801B2ULL,
		0xEE3F3412FAC199F1ULL,
		0x820108E9BC47E7C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 372\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 372 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -372;
	} else {
		printf("Test Case 372 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFDDD089AEC675048ULL,
		0xA6F3604CF097E03DULL,
		0xD856D903B7F42850ULL,
		0x517DDDE7D9DC2EE3ULL,
		0xAC8B91CFDE34E932ULL,
		0xA30B9754CBB0A1EEULL,
		0x653FECE4EEBE4962ULL,
		0x8DF767EDFB815D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 373\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 373 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -373;
	} else {
		printf("Test Case 373 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x97614C767A3A0448ULL,
		0xE4367274129CD805ULL,
		0x7F12E628ACB168CAULL,
		0x2ED9B31F31554A7DULL,
		0x3A2A5428D7DC99DBULL,
		0xA8E85102E5B896ADULL,
		0x5FA2BDFFB850ABBDULL,
		0x9B7EBFB62971D6E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 374\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 374 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -374;
	} else {
		printf("Test Case 374 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6F27A47D726D3A11ULL,
		0x96950F4B7D01BBF3ULL,
		0xE3C88E93D58CDA65ULL,
		0x8D02728741089DC2ULL,
		0x9471BC1573149D40ULL,
		0xB6538F64AD841FF2ULL,
		0xF07543E04A9C9DCEULL,
		0xD9E0FCAA3A3A44E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 375\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 375 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -375;
	} else {
		printf("Test Case 375 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFA519455847F943CULL,
		0x8CFE102C8E512529ULL,
		0xF8D7FD671EB0DA1FULL,
		0x78E26A6E21AF21D1ULL,
		0xA59C5A1D6992EB0DULL,
		0xCBB4B5B67E392B0CULL,
		0xF17926605298A527ULL,
		0x6EAD833B30A96135ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 376\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 376 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -376;
	} else {
		printf("Test Case 376 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1F4AF7FCB37D84E5ULL,
		0xDF1BB54C1F65A0F0ULL,
		0x8DA067EB3BFFC0FEULL,
		0xADBF81B0528F76EBULL,
		0x89AA5E4F130EF825ULL,
		0xE9FB917EF8E4E3B8ULL,
		0xCC3AF5DBAC282A27ULL,
		0x89D8C40018E5D265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 377\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 377 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -377;
	} else {
		printf("Test Case 377 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5D556B14571B3338ULL,
		0xC5686B3422C15F26ULL,
		0x453B92C034C7D6FCULL,
		0x4E9E22EB552F73DBULL,
		0xA8BE03B3C0CA50BAULL,
		0x7524D27D2FA08FF8ULL,
		0xA8C99A7A3F813910ULL,
		0xEB8F2055E439B4BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 378\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 378 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -378;
	} else {
		printf("Test Case 378 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x049FC623BE86440CULL,
		0x1D335241FCD2AAA3ULL,
		0x210DC68006B3178FULL,
		0x14D76BA5A4A373FDULL,
		0x99983B78DEDA04CFULL,
		0x8FA51E207F0841C2ULL,
		0x0541417CFD04E09FULL,
		0x3E8DD18AC7DF9715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 379\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 379 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -379;
	} else {
		printf("Test Case 379 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x58AAC55654D9FC48ULL,
		0xDF931C16F6DBBC62ULL,
		0x3A53CA87454FBE2FULL,
		0x09A9FCAD86D0BF5AULL,
		0x6675F2BC1844E0D9ULL,
		0x9D4106E35FA3E68DULL,
		0x86DC9098256119E7ULL,
		0x37D42A93295975B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 380\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 380 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -380;
	} else {
		printf("Test Case 380 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6978FE45BA68EC3CULL,
		0xC913F72B7E0EEE12ULL,
		0x7B76DB5B81011A05ULL,
		0xDDF0439D41144667ULL,
		0x9C93461B6C135B40ULL,
		0x689E2E4C37F82C0AULL,
		0x2FE8BF89A19500F7ULL,
		0xA0B200CAE931EC41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 381\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 381 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -381;
	} else {
		printf("Test Case 381 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8965E9370B3FC0C7ULL,
		0xB7DF2B53C4421D5BULL,
		0xE6EE56F5F3531E68ULL,
		0x91180EEB26DB9EA7ULL,
		0x57FCA384DA144233ULL,
		0x21AC4832D8540335ULL,
		0x2984ADE945EF2EDCULL,
		0xF0FEB743354CB8A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 382\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 382 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -382;
	} else {
		printf("Test Case 382 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x33714D6DE43FDFA2ULL,
		0x9412EAA023885334ULL,
		0xC7FC1CCBFF1715A7ULL,
		0x166096FBC05C55C5ULL,
		0xAB6B8C131B1B7666ULL,
		0xD92BE28DD8DD4EADULL,
		0xDDCAF3D40C1D08E4ULL,
		0x6E28C9EF70DAB65BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 383\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 383 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -383;
	} else {
		printf("Test Case 383 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x69934EC2F510C79AULL,
		0xCF3217F4745AF21FULL,
		0x1FECE78C29A2E189ULL,
		0xCC14B95C87E0E084ULL,
		0xCBEA551574664FB2ULL,
		0x7F0E2E09345E913BULL,
		0x141AA0C60F6E18B2ULL,
		0x0AC06B349FBFD24BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 384\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 384 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -384;
	} else {
		printf("Test Case 384 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0280FA29C08C65FCULL,
		0x67F683C837010740ULL,
		0x2C04FFBAD5195170ULL,
		0x7F3D2F46D437EB55ULL,
		0xDBB1F698247DE1CAULL,
		0x9625E13B7CFFBAB8ULL,
		0x5A7DACEB04B3B991ULL,
		0xCB9138C5332A8E6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 385\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 385 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -385;
	} else {
		printf("Test Case 385 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC471AD12D80BCD34ULL,
		0x69ECD313E8B32F1BULL,
		0xC148917C08F251B1ULL,
		0x7C292B61DDB6689AULL,
		0xF309CF541C4C2EFAULL,
		0xBE23BDFE30919C65ULL,
		0x84E372799EC34BBAULL,
		0x4D173879F37DCDD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 386\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 386 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -386;
	} else {
		printf("Test Case 386 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBBD106B1740B561EULL,
		0x18768E0A87A510FFULL,
		0xB3124A9B1032C9FFULL,
		0x2A3B7E546CE0A43CULL,
		0xFED3DC8AE8830652ULL,
		0xBFC4B049D7FC9341ULL,
		0x39312E6708A988FAULL,
		0x743CAC96748D3EC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 387\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 387 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -387;
	} else {
		printf("Test Case 387 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x00FA68D59788C953ULL,
		0xB27476E4149DAF90ULL,
		0xA601F9E51C7FCD9EULL,
		0xE99E62FB38F3D303ULL,
		0xFEAA710004B73EC2ULL,
		0x2D04640FACA2596BULL,
		0x59A12F98A0FD2783ULL,
		0x07DE66BFBDB1EAC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 388\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 388 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -388;
	} else {
		printf("Test Case 388 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CB9CA7F4379AB77ULL,
		0x2B9E098DE088899BULL,
		0xE51C02C391366E60ULL,
		0x0E33F1C44231F7CFULL,
		0xDDA5A15905B9746FULL,
		0x4E16C327F33574AEULL,
		0x70359633C80AADC4ULL,
		0xAE2C2DDA3A8311D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 389\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 389 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -389;
	} else {
		printf("Test Case 389 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD06A23F715E13020ULL,
		0xDDE06F99E5417A25ULL,
		0x53E0D1C58B3ACB32ULL,
		0x4665BC3BF28B89D1ULL,
		0xD6E753C0969DD0A9ULL,
		0xBD79AF49F3F88B18ULL,
		0x8AC1DF7099642A79ULL,
		0x4CC0FCB6DFA4B853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 390\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 390 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -390;
	} else {
		printf("Test Case 390 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x702B570022B8AD6DULL,
		0xEA2FDA64F5BCDB5DULL,
		0xF7B4F66F74D631AEULL,
		0xC05B3818004D81E3ULL,
		0x68A38DCDBA2FD747ULL,
		0x4BF75174CA911BD6ULL,
		0x997E6DC37FC7DCEFULL,
		0x80773F717A43A8C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 391\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 391 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -391;
	} else {
		printf("Test Case 391 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x45086C454FBC8DBCULL,
		0x3B0D51A96E097A85ULL,
		0x807E15483920BE56ULL,
		0xFB4387F06632C212ULL,
		0x4B2351A1A8A8188EULL,
		0x2DEBCEC2DAD22A69ULL,
		0xF647AFF6A744B318ULL,
		0xB6A3010AECBB5FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 392\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 392 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -392;
	} else {
		printf("Test Case 392 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4ECE78CB9FF35BACULL,
		0xE9CCEE376E2EA422ULL,
		0x210D57706E7E97CAULL,
		0xBFD229E91C42CE43ULL,
		0xA48F307BF33D1089ULL,
		0x43D5EF78DB5DA87FULL,
		0xA2EBEA97DEA1EB8DULL,
		0xDDE73217546633B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 393\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 393 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -393;
	} else {
		printf("Test Case 393 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x26BD5FBBE42997C6ULL,
		0xC3B7B54B70DA229EULL,
		0x63CCB32C81DD634BULL,
		0xC4872B615C5EF5B3ULL,
		0xA84357D1CCB82344ULL,
		0xA9820D20FD70BD94ULL,
		0x34B11C20DFE575A9ULL,
		0x8CE233613DBD8615ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 394\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 394 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -394;
	} else {
		printf("Test Case 394 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA377C5258A899D0CULL,
		0xF3F294FA03FF286BULL,
		0xB4BD793CEAA942E8ULL,
		0xB1C775A1251C8859ULL,
		0x16D4DDF8FEBAE0E8ULL,
		0xD9D4895099CCC5C4ULL,
		0xABE2B0DF156D4AF1ULL,
		0x2B1675D6023F55D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 395\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 395 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -395;
	} else {
		printf("Test Case 395 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x61D653C53E01C60EULL,
		0xBED8417C5233450EULL,
		0xCBD62931D90B7253ULL,
		0xC5879B351CE2BFECULL,
		0x212F0666796D1735ULL,
		0x39B4C4547AA0E421ULL,
		0x25A36B52400CA391ULL,
		0x7FE546B5EA62B009ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 396\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 396 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -396;
	} else {
		printf("Test Case 396 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8D000CC45AE9C4B4ULL,
		0xC4429AFD3F4EF75FULL,
		0x157316A87DA928AAULL,
		0x6E784AB448624EB4ULL,
		0xD1DAD27B8703C85BULL,
		0xE44CFCBB3B4FBAE9ULL,
		0x94A24880F6E60B05ULL,
		0x6ED9FB50C63D65D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 397\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 397 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -397;
	} else {
		printf("Test Case 397 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6EC901E3893C346EULL,
		0x402783551739B685ULL,
		0x470D59AEA7D73A01ULL,
		0x5021141836D286F3ULL,
		0xB981BE2848B74D2DULL,
		0xB68949A3203DAB6FULL,
		0x64C84BA842020EAFULL,
		0xBF4858B4D48432F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 398\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 398 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -398;
	} else {
		printf("Test Case 398 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4B4A9E5BF49C13AULL,
		0x39968FCAE220AD67ULL,
		0x9B9389C55F63A3A9ULL,
		0x9E5689DA71ECB9C3ULL,
		0x45D5F17B151F05BDULL,
		0x0C465A7BC4C53865ULL,
		0x79FA7B2EAD0355C2ULL,
		0xD2CE046AFD270417ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 399\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 399 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -399;
	} else {
		printf("Test Case 399 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x91225E9D4B956B34ULL,
		0xCC05773B7BB83353ULL,
		0x7EDCF211B5D4D2CEULL,
		0x6DEDBD877E1C2D7AULL,
		0xB7002D36BA3BDCDAULL,
		0x25F500D4976B3E11ULL,
		0x4EC8A0EF47757549ULL,
		0x6E921557E45D3B28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 400\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 400 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -400;
	} else {
		printf("Test Case 400 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8356F009236DA77EULL,
		0xCB74613A3E89E0F9ULL,
		0x6A3A96A2B0E946E3ULL,
		0x8763692FBD585D6AULL,
		0xBBFE09B471369F05ULL,
		0x0BFDAD55792AD422ULL,
		0x07AC5E9502FE0EC2ULL,
		0x2E4076CBC1D3FAD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 401\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 401 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -401;
	} else {
		printf("Test Case 401 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x491A7EA9ED455A91ULL,
		0xC7E74F97AE875261ULL,
		0xCF62356CD6470697ULL,
		0x0E1582FC6F51C949ULL,
		0xBA67B077AB10997CULL,
		0xA0F2925B1A603D05ULL,
		0x4900BEC51B5B0575ULL,
		0xD2E5FBE27BBE2D90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 402\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 402 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -402;
	} else {
		printf("Test Case 402 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC6C17D21D668766CULL,
		0x96C2966BABA17BBEULL,
		0xD6D43D4968A4AD97ULL,
		0xCE1739737F085466ULL,
		0x013F900E1C65C6DDULL,
		0x203E695DE845E797ULL,
		0x981B051702EE7ECDULL,
		0x7ABA6F33686E45A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 403\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 403 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -403;
	} else {
		printf("Test Case 403 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB6918C0FA9CED047ULL,
		0x26D6A6E3406AFB2AULL,
		0x8B9822D94EE94C22ULL,
		0x79E1C25A546DBFD6ULL,
		0x960B66B7887E511BULL,
		0xAB1B17FD4D95A177ULL,
		0xD70EB0D79BEEB110ULL,
		0x930CBFBCB225D0EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 404\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 404 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -404;
	} else {
		printf("Test Case 404 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0x9042E38E23661623ULL,
		0x7F1FE7D1CE03C10AULL,
		0xBBA0309BF52A46BAULL,
		0x6E2E3A11E1047C97ULL,
		0x4E7061B4FA1ACA2CULL,
		0x20CE218E46CBF42EULL,
		0x5BD82F85A3C63146ULL,
		0x01AB977626CC4061ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 405\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 405 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -405;
	} else {
		printf("Test Case 405 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC969C5088F7EC4BEULL,
		0xD59E6E8F07CA6DADULL,
		0xDCB9269E198805AEULL,
		0x8BA02A5892EFC235ULL,
		0xE0419C762A7AFE28ULL,
		0x938DA6D01A378A99ULL,
		0x6F20BFD9A318A1BFULL,
		0x3C7EAA26E5434E20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 406\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 406 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -406;
	} else {
		printf("Test Case 406 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5EB8BA434C91CCA4ULL,
		0xAB20B6D8B7BA6958ULL,
		0xC1FC5340F1F48C14ULL,
		0x2B664EA0113517EAULL,
		0x065764CA8819409DULL,
		0xA56F51798B55D0C4ULL,
		0x4A8D411D70C3A395ULL,
		0xDE5DD560B373B18EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 407\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 407 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -407;
	} else {
		printf("Test Case 407 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9E25FD6062078C31ULL,
		0x97FAA8354CC472FCULL,
		0x3D0872F6D8AF5AB0ULL,
		0xE8D9D8E2F13F441CULL,
		0x9D5E4A0AD0891F53ULL,
		0x913F2E4F93DF228EULL,
		0xAEED7F70B92F2776ULL,
		0xCA711FBCFA3718DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 408\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 408 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -408;
	} else {
		printf("Test Case 408 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2954D603DE490E61ULL,
		0xCF81D7AEA951D5DDULL,
		0xD70E30C27EDAC8A2ULL,
		0xFE5D4FAAC363B280ULL,
		0x5D73439AF398A21FULL,
		0xFE751054E736E5BAULL,
		0xF041BDCD2BF9BD25ULL,
		0xBE90D50376620B3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 409\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 409 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -409;
	} else {
		printf("Test Case 409 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x02B87BBB80287286ULL,
		0x167D7263803ED3CAULL,
		0x4AEBDED6A4138CD9ULL,
		0xCEEBCA68A30E6859ULL,
		0x07EC28E335108329ULL,
		0x3220B69ABCC2D98DULL,
		0x36B989AC5391D513ULL,
		0xB8E6D839C4B6F4F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 410\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 410 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -410;
	} else {
		printf("Test Case 410 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDEC2A1F727B6CDA3ULL,
		0x2316914BEB3CE0E1ULL,
		0xA2822C1A69B4EFF7ULL,
		0xF4319A70EE4AC17EULL,
		0xA3D14522332CC986ULL,
		0xCE5379EF9E27F19EULL,
		0xBFFA6BEC29F5FBB7ULL,
		0xDCCC152E675E700BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 411\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 411 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -411;
	} else {
		printf("Test Case 411 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x11576F4C36FA77E9ULL,
		0x8A70AA62BE91C2F3ULL,
		0x437F5F97AC15035FULL,
		0xF5059963A500E789ULL,
		0xF16ABE1CB9547747ULL,
		0xFF5148F27E73A5C7ULL,
		0xB5C9738AE1CE1A2EULL,
		0xE2E41A75E3D6DABCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 412\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 412 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -412;
	} else {
		printf("Test Case 412 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB8877E2AB8C7067ULL,
		0xFDEFDCA934DD23ADULL,
		0x820DCB317BBE8BD1ULL,
		0xA9A6C10EA0F07D87ULL,
		0x0AE57569C56C9BABULL,
		0x54A8CA0DE234E75EULL,
		0xF8EC207AA5F3B9B9ULL,
		0x9A45EBD6C4D489E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 413\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 413 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -413;
	} else {
		printf("Test Case 413 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5BE3F33F34FEDAB5ULL,
		0xA5BFB3F48EFFBF91ULL,
		0xA82E2176B2F63518ULL,
		0xBD5FD16EA47D1406ULL,
		0xF1B21018F841AA3BULL,
		0xB64FE03332584712ULL,
		0x12FD0302BC0DCD4BULL,
		0x7AB2C869ACD4A63CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 414\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 414 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -414;
	} else {
		printf("Test Case 414 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CCF7E5BF2EA4AC7ULL,
		0xB1FC748AD7394674ULL,
		0xD5A8226CAA5E9A2BULL,
		0xCF1F8CA3CD479A54ULL,
		0x64AB049E48A0FB39ULL,
		0xA47AB2D6365AA745ULL,
		0x5D390E69530DB317ULL,
		0x842EF7EBEAB57D4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 415\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 415 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -415;
	} else {
		printf("Test Case 415 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF0594D653967F5F9ULL,
		0x888751E8EC8A72F5ULL,
		0xD150ECB0CFBA7D80ULL,
		0xDD0343B53A686512ULL,
		0xE539C553103415EBULL,
		0xA28A2785814234A9ULL,
		0xA0B039D614EFEDFFULL,
		0x9DB45F785CF416A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 416\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 416 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -416;
	} else {
		printf("Test Case 416 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9EB3DA981F3FF063ULL,
		0xB798D2B63A0AF56EULL,
		0x72050FD66D1222DBULL,
		0xD36993201104FE3CULL,
		0x2AFC0713FF3C46FDULL,
		0xEB0E89367E25EAACULL,
		0x2D0F7C9CFEECB297ULL,
		0x4C81C489C10EF1CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 417\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 417 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -417;
	} else {
		printf("Test Case 417 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0C5D86ED69E59BEAULL,
		0x94D8A99A3D3D605DULL,
		0xA51BAF15D2D2B7F7ULL,
		0x14183F62C884DB76ULL,
		0xC064609D1B849898ULL,
		0xDBB35F87F786FA2EULL,
		0xEBA2630BA9251523ULL,
		0x57FD2B2BA777D3B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 418\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 418 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -418;
	} else {
		printf("Test Case 418 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x25D540F8C2E68113ULL,
		0xB66EB9DFCD33414AULL,
		0xBBA77FDD0B8703B6ULL,
		0x6D0823D6800FE3FFULL,
		0xC4EB2157DC2F61E1ULL,
		0x9158802AF67D1555ULL,
		0xDBDBC0D1376F4EA4ULL,
		0xEAB36BC876F2AB7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 419\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 419 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -419;
	} else {
		printf("Test Case 419 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x725769CFA608463CULL,
		0x0CE5483A6454C037ULL,
		0xF61872488513D555ULL,
		0x7318AE2891C988E3ULL,
		0xAF2EA0BF15A21CCEULL,
		0x20CE4C4C43A8EFE6ULL,
		0xC319A3DDA3C9EA6DULL,
		0xB03F4472D42F9ACBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 420\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 420 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -420;
	} else {
		printf("Test Case 420 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6D279F9580E9381CULL,
		0xB8854DFF622017E3ULL,
		0x526BFFE44E14D84FULL,
		0xAD0459BA85187409ULL,
		0x7A888ADCFE7E3B5DULL,
		0x0405B5899D23A214ULL,
		0xCE2012E9101287D6ULL,
		0x8A4D6720E6BF5933ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 421\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 421 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -421;
	} else {
		printf("Test Case 421 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x8DD8E64F1D9E6D08ULL,
		0xE1D9F43E37DFE1D2ULL,
		0x9D8600C543D49186ULL,
		0x251D20C560BAA494ULL,
		0x3CA03AFF55A27EB1ULL,
		0x107A271708951B52ULL,
		0x4596AE23277A2F50ULL,
		0x03E8412802958F9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0200000000000000ULL
	}};
	printf("Test Case 422\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 422 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -422;
	} else {
		printf("Test Case 422 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1427E1D4A0522A45ULL,
		0xD395F5EF646C2A27ULL,
		0x7D0B083C65C788DCULL,
		0x2E8E286BA6B5BC8FULL,
		0x0AE7C7F73D9DB518ULL,
		0x3122320C0FB5CEFCULL,
		0x39F79491DB7195B3ULL,
		0x65C2D1847CA9B068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 423\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 423 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -423;
	} else {
		printf("Test Case 423 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFCD08CD0818409F1ULL,
		0xF4F9D029A14367E4ULL,
		0x0D04DEE19AE62B31ULL,
		0x66325D7BF1CBD38AULL,
		0x8C2725D93B063F97ULL,
		0x9359AEEC3A22ECCAULL,
		0x0F5049703EFDE69DULL,
		0xF8F49A9894F2327EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 424\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 424 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -424;
	} else {
		printf("Test Case 424 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xACA5DCEE06E24A3DULL,
		0xAEE9523BA52AE3FEULL,
		0xD587483DFD98657FULL,
		0x06B0B88264CDF701ULL,
		0x02A5D76C0BD44F4DULL,
		0xB4975EED65C56AB6ULL,
		0xB57E96040F28B7FCULL,
		0xD9F8F2733BC0495CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 425\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 425 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -425;
	} else {
		printf("Test Case 425 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0DC1B7A70D9E375EULL,
		0xE9AAAF4D3C9799BAULL,
		0xF7C2CE25A58491DEULL,
		0x250576EBA216FBDFULL,
		0x44ABA13C2F7C2DC1ULL,
		0xA01E807D376E5F6CULL,
		0xB5545F3D5C3DF8D5ULL,
		0x1B838BECBB4B4578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 426\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 426 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -426;
	} else {
		printf("Test Case 426 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8940CDCB25467B1CULL,
		0x7329A34ECE47D568ULL,
		0x70D464B92A3E4FB4ULL,
		0x72999AE68E8FC93FULL,
		0x9AFEAFAC3DB2EB0BULL,
		0x08BA974930E85433ULL,
		0x1FB4722B510B836AULL,
		0x2A450FC04B487B18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 427\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 427 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -427;
	} else {
		printf("Test Case 427 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCD949F2E43968C4CULL,
		0x6BE6C125E34AACA0ULL,
		0x2118C240955EBC52ULL,
		0xF2BD2A83F5164EFAULL,
		0x47ADB00341D8DC13ULL,
		0x219FA22F210363E1ULL,
		0x818F981BF6500C36ULL,
		0xB966D7F412D22B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 428\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 428 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -428;
	} else {
		printf("Test Case 428 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x76794C6D6BFE9ABDULL,
		0x51F86BFD0D78E1ABULL,
		0xF01F3C8D101A52B0ULL,
		0x19690DE14203236DULL,
		0x52E29FCE7E5F87EDULL,
		0xD210D38501D65ADAULL,
		0x28D68BBBEC567D08ULL,
		0x7019B9F301CE58B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 429\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 429 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -429;
	} else {
		printf("Test Case 429 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0F173BBE6D613233ULL,
		0x0CEAEA1731E8332DULL,
		0xC3B8C5C12BC17EC2ULL,
		0x3326CF41BE61D9D6ULL,
		0x04F977C619804C36ULL,
		0x37BD6D4F76DF5D8FULL,
		0x2C9FF03766B67037ULL,
		0x7D4F8C7E1F32DE5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 430\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 430 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -430;
	} else {
		printf("Test Case 430 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEF2E3E54BB7F6066ULL,
		0xCECA999105FF5B16ULL,
		0xE9D4C9D629599809ULL,
		0x1DE0DBFCB39B4726ULL,
		0x30C2ED63928B3B48ULL,
		0x279C2DF1F21815A0ULL,
		0xB5478F598C2EDE54ULL,
		0x74833A246FA516CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 431\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 431 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -431;
	} else {
		printf("Test Case 431 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB7042E952DF6151EULL,
		0xFCF2188C8BC95B30ULL,
		0x266DA3A9EC957D86ULL,
		0x9398F54FD8A49CCBULL,
		0x18A7DD63A645A227ULL,
		0xE5FF6054CEE9B758ULL,
		0x9705D95A54B08DFEULL,
		0x8D22FA44F11E5B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 432\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 432 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -432;
	} else {
		printf("Test Case 432 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2B3F12BD2FE1FC11ULL,
		0x9A8AAEDFFB687E14ULL,
		0xBE9505F1757C54FDULL,
		0x26931846E430E521ULL,
		0xF7A78F719C3C989BULL,
		0xC65E071C1D497C66ULL,
		0x79527BEA3DB2D687ULL,
		0xCC70C6340EBD9BBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 433\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 433 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -433;
	} else {
		printf("Test Case 433 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4125C28DC17999CCULL,
		0xBC9139724AA1164FULL,
		0xD6BFE98245DA3FACULL,
		0x7D2A00311237422FULL,
		0x98ED63F80CCEC4D2ULL,
		0x10E907809D5E7622ULL,
		0x86A5D40291BB1E80ULL,
		0x988261F8CD8B2C54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 434\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 434 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -434;
	} else {
		printf("Test Case 434 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2549BB9ABDCB20F8ULL,
		0x027F4BB843AEAA3AULL,
		0xD751869C18E02B4FULL,
		0x8BE93407267E7F22ULL,
		0x8CC5DE33C76F74F3ULL,
		0x1FBBEB2CE0F0039BULL,
		0xAF9CEFB3F18D1580ULL,
		0xC2808EBC10E44D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 435\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 435 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -435;
	} else {
		printf("Test Case 435 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9A0CCE10B5937AC7ULL,
		0x29ED5EBDCAEF7BBEULL,
		0x3DD2314EA9D41BB6ULL,
		0xD41CD1308F225ADCULL,
		0x1F66B8B73ACA7B50ULL,
		0x2464549EE33B1B98ULL,
		0xF5969B3C185B6D15ULL,
		0x5E6BC70D3757E72FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 436\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 436 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -436;
	} else {
		printf("Test Case 436 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x12EEF7AC137BD7B9ULL,
		0x5C0CE1A80F56DEA9ULL,
		0x7861CC0E6EAA6201ULL,
		0x8D998802F9817B62ULL,
		0x978B39706AEBD5E0ULL,
		0x1C479BB991554094ULL,
		0xDADBAC0F6BE7D27AULL,
		0x6E48A2C0764894ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 437\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 437 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -437;
	} else {
		printf("Test Case 437 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xB4F09149EB220D09ULL,
		0x3889C1CA4BC0D313ULL,
		0x77A96C825EA31B9CULL,
		0xB402493C50B64A94ULL,
		0x69AE24395900EF2EULL,
		0x266DA70C8DC313B2ULL,
		0x9BE9D9DE2AD9BF87ULL,
		0x059ED5A4460542DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 438\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 438 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -438;
	} else {
		printf("Test Case 438 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAD9EB2F2FCE188FFULL,
		0xA75E514F0AA20890ULL,
		0xCA01FC0A91171998ULL,
		0x3630BBBFDE02A07FULL,
		0x479A22F16CE58ED7ULL,
		0xF74BE72037607862ULL,
		0x81BEFF7752F4EF96ULL,
		0xF2951601E0AF8513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 439\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 439 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -439;
	} else {
		printf("Test Case 439 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x54EAD1FB2C50ED21ULL,
		0x41DC85623FA46E9EULL,
		0x51B163A486E00F30ULL,
		0x75BFB47433E42065ULL,
		0xF8AE450C1CED978BULL,
		0x8F03EAE9F336297BULL,
		0x045CBF3344BD064FULL,
		0x1FBF28D569E72D27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 440\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 440 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -440;
	} else {
		printf("Test Case 440 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x8EA284E2ABB5A27BULL,
		0x0F337CCB39A325D3ULL,
		0x1265DB27EA44FB50ULL,
		0x3E3DAA216288CE93ULL,
		0xEF9889F49EA37C9AULL,
		0xAA68D2A5898C1599ULL,
		0x577DFCE059E21D20ULL,
		0x045ACA45B031FF4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 441\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 441 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -441;
	} else {
		printf("Test Case 441 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x26CD9D522BEADD34ULL,
		0xF306437EFA77E3A8ULL,
		0xFDE5E7D9155E452BULL,
		0x2665017ED01A5721ULL,
		0x0DE02ACD12A8E385ULL,
		0x0470EFC2137E76DAULL,
		0xDE05CAB519A38701ULL,
		0xEA007B38B77FFA19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 442\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 442 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -442;
	} else {
		printf("Test Case 442 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9D59314F2187280CULL,
		0x8433BFCB9CEADCBCULL,
		0xA4450FC28E7F8AFAULL,
		0xC32BCBB7EC72A20EULL,
		0x6DA5F50DF70024D9ULL,
		0x23FF56F9A432D0EAULL,
		0xC8A7AF7558C09ACCULL,
		0x888C828AB2E9FBC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 443\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 443 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -443;
	} else {
		printf("Test Case 443 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x939070AAD73AB20FULL,
		0xF25A54056BFE93C8ULL,
		0xB498D0D319990DE4ULL,
		0x239BFB48BD96674CULL,
		0xA48948A2930735B3ULL,
		0xAE8420EC48E6882FULL,
		0x6740DCC866D4DA7DULL,
		0x80A94240D0C5DA1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 444\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 444 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -444;
	} else {
		printf("Test Case 444 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE687369614C08440ULL,
		0xF615D693BC2AE9D3ULL,
		0x52499C3C0FD937F8ULL,
		0x20A9CDAE1A2484F2ULL,
		0x42B06D2F7502F019ULL,
		0x2D312C5A69CDFE67ULL,
		0x18B21DFBF7F17FAEULL,
		0x0D6C71C4471F0B0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 445\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 445 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -445;
	} else {
		printf("Test Case 445 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC802E5B6D48F4DD4ULL,
		0x01347E5A9EA29FEDULL,
		0x7632A45D39B75166ULL,
		0xA5EDDA5565C520BDULL,
		0x502A63A0078B6CBFULL,
		0x73AF01CF4FF576C5ULL,
		0x6ABE0464A31BE29AULL,
		0x4CB0B8EF631B781FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 446\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 446 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -446;
	} else {
		printf("Test Case 446 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD9D2E58EAF9AF700ULL,
		0xF4DFAD1A6C1DD42EULL,
		0x1139CC695C9C5C8FULL,
		0x3E2EAFD17EEB53ADULL,
		0x37436E81AB2A9639ULL,
		0xA73C7F855219552DULL,
		0xE3DEC4EB023EDDFBULL,
		0xF7F8242C9C6CCF00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 447\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 447 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -447;
	} else {
		printf("Test Case 447 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE00F1F97658F0776ULL,
		0x263E5BDE3AC9183DULL,
		0x8E23270A77A578A4ULL,
		0xDE879F0E8FB2A0E4ULL,
		0x3F4B1A8B66EF5E75ULL,
		0xC4E9ACBF2732D113ULL,
		0xE2DE4B90F55F3873ULL,
		0xAE19CC67BC6D8D7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 448\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 448 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -448;
	} else {
		printf("Test Case 448 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEC0D0C97F8FE935EULL,
		0x18478E35639999C0ULL,
		0xEC5A504348875FDFULL,
		0x4C5B4017E8532C13ULL,
		0x1D1DD2AD2DA9E8AEULL,
		0xC2F2C8AFE108A27FULL,
		0x293E064295F91AFDULL,
		0xBAA774EDB6E76F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 449\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 449 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -449;
	} else {
		printf("Test Case 449 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCC9ECBD7DE048936ULL,
		0x9792B94364D08A6FULL,
		0x95D6FD4FA4263A0EULL,
		0xF4F4CA5176D8C7CEULL,
		0x2B4B684421C22068ULL,
		0x5C78EA99056CA9D8ULL,
		0xDFAC801A7AD0521AULL,
		0x3E7EB93ED21F5D4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 450\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 450 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -450;
	} else {
		printf("Test Case 450 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDF785E4FAC2C89D7ULL,
		0xB8A8A8A9ED9B4747ULL,
		0x6F5B64C7D8C33283ULL,
		0x165E1435E9E61643ULL,
		0x28D17392A0AA7FD6ULL,
		0x0A91E990E0FFB401ULL,
		0xA0160DA0EBD66052ULL,
		0x3A0ACA432904B68FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 451\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 451 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -451;
	} else {
		printf("Test Case 451 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5BCFF949450FEB7AULL,
		0xB2181C58A57B1565ULL,
		0x525B66211BB823C2ULL,
		0xC49C81225AB1D537ULL,
		0xB76D9D0247FFAF7FULL,
		0xFBE7CBFCA9354822ULL,
		0x2FE672907755C9AEULL,
		0x446EAF6F39B3E2D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 452\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 452 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -452;
	} else {
		printf("Test Case 452 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1699916E3856875BULL,
		0x0139F21B3E18C781ULL,
		0x1D1522F8D216D5EEULL,
		0x3C4FD01B0EC07D3DULL,
		0x0A9A04D289C03289ULL,
		0x60DB6CFC230AE568ULL,
		0x2EAF8D9C16562D55ULL,
		0x2A04F7D4808380F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 453\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 453 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -453;
	} else {
		printf("Test Case 453 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x9CC09A1C644332BCULL,
		0xF5E2AE137254070BULL,
		0x9B2327341A77885FULL,
		0x999E1827BA67E877ULL,
		0x6D0F7676925BB084ULL,
		0x7EE9FCA9358F4CD5ULL,
		0x179B1E683569932EULL,
		0x1E1B507F3C034010ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 454\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 454 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -454;
	} else {
		printf("Test Case 454 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8CCAB00E583C6C52ULL,
		0x6A2479E1BD4CE9CDULL,
		0x202AA33C859E0616ULL,
		0xE1B85D95A70FF1FEULL,
		0x971230803EDE0B47ULL,
		0x3CC044294EA3D855ULL,
		0xBA4489A87E230CAEULL,
		0x86636D5F7CBDFE5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 455\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 455 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -455;
	} else {
		printf("Test Case 455 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0FB7D4589D04A8ADULL,
		0x9B1B7D4E923F113DULL,
		0x25DA943DC80D8FC0ULL,
		0x6809FF2EF9E6EEBBULL,
		0xA8BE0F93B7374FF2ULL,
		0xDCF5DF84A26724C4ULL,
		0xD16966DBFD92F8FEULL,
		0xB082FC0983286D80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 456\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 456 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -456;
	} else {
		printf("Test Case 456 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEF28CA4C32774FD4ULL,
		0x34161C095EE0EC1FULL,
		0x4ECFE95E79B72AD4ULL,
		0x8C8BF93BF7A37254ULL,
		0xFB6895EF17562A44ULL,
		0xF84F3576DC300004ULL,
		0xC8FDDA678F196CDAULL,
		0x556BA9F334A92C0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 457\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 457 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -457;
	} else {
		printf("Test Case 457 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8AA14D552F767307ULL,
		0x83B3870F708532E3ULL,
		0xBBEBEE7A7DDEAEA3ULL,
		0x87F96CC01BE95723ULL,
		0xBB451754C97C7EDCULL,
		0x2675C490C6855878ULL,
		0x8BC9270E838593B2ULL,
		0xDFB7AE7A2344F22EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 458\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 458 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -458;
	} else {
		printf("Test Case 458 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC69DFB980428FF76ULL,
		0xB072A66D180E7461ULL,
		0x3DC01BA173E045A8ULL,
		0x70FB4D636657473DULL,
		0x3D5C66E355EE5026ULL,
		0xCF2CEF54FA03E4FBULL,
		0x31404FA43AD70B32ULL,
		0x24CECEF262A1B6C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 459\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 459 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -459;
	} else {
		printf("Test Case 459 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5C5572AA4E2B2A7AULL,
		0x5ECF7A2149DC71CEULL,
		0x5FF0219743C06F79ULL,
		0xC9705FB651CA4FD8ULL,
		0xC0F19E5EC21BDEE8ULL,
		0x0FC98E8FC360ECFBULL,
		0x0E9826992BBDC0FCULL,
		0xB81FE8ACFF6A19AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 460\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 460 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -460;
	} else {
		printf("Test Case 460 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCAC85870CB7622CAULL,
		0x7304FC5EB266717EULL,
		0x009EBDD3D63F49EEULL,
		0x2E6CF4D6D8235264ULL,
		0xD0FE89537F0498CDULL,
		0xB36EA2EF8D8BF2FCULL,
		0x3625E77F49F4AA46ULL,
		0xC883DA3C1AA4048AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 461\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 461 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -461;
	} else {
		printf("Test Case 461 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8C843FE6B5001E6ULL,
		0x897268962A4AB345ULL,
		0x08FB96A03747FC7AULL,
		0xAC14AEB7FD56D9A9ULL,
		0xBE462E51193E64A3ULL,
		0x3826E1B0BB0A5D06ULL,
		0x40939A93D0B4004BULL,
		0x8BAB5706111015F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 462\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 462 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -462;
	} else {
		printf("Test Case 462 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE3F4850E7CA74CFCULL,
		0xEEA025440795A006ULL,
		0x9365FB4A4A8523E5ULL,
		0xF0C13CE563A3AF77ULL,
		0xE5BA4EC80B620BACULL,
		0xDAA5697C9391BE78ULL,
		0x6F260F9CB3012031ULL,
		0x233353CD4B1E648FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 463\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 463 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -463;
	} else {
		printf("Test Case 463 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA7FD232E183DA021ULL,
		0xF6C68A4A10E1A2FCULL,
		0xDCC05FF2A955EC42ULL,
		0x2A7D860D423E4C76ULL,
		0x0DDCE4653F956D7DULL,
		0xAA3B550DF280D761ULL,
		0xABA5C8BC7C9D8195ULL,
		0xCA1C9D3C33A5B228ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 464\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 464 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -464;
	} else {
		printf("Test Case 464 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5899B160639EB5F4ULL,
		0xDB3E10C552CD5408ULL,
		0x84646015EA93AAD6ULL,
		0xE9A7FD1C07405006ULL,
		0xDD3BEAA647E3B362ULL,
		0x6FFACF6F7F28939CULL,
		0x3F278BEBCCFCBEE4ULL,
		0xFBFC6C3EDD6C8EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 465\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 465 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -465;
	} else {
		printf("Test Case 465 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x60249EB21AE01010ULL,
		0x1C4B663FFA8544A2ULL,
		0x2BB3E69946193633ULL,
		0x6917A1D3857CC2A1ULL,
		0xBC503582D54DB2E4ULL,
		0x08DA3F2290A77216ULL,
		0xC464C25AE54917A1ULL,
		0x79835946D5D13699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 466\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 466 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -466;
	} else {
		printf("Test Case 466 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6E6D74D688563D99ULL,
		0xFCDD4EF272856F72ULL,
		0x6A6EA6836FF93EFCULL,
		0x014E6B03BA6E5ED8ULL,
		0x0F6C558F344C5513ULL,
		0x1A98660E11BDCB0AULL,
		0x83C99AD8756C0E5AULL,
		0xC6DE9C9F41F35120ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 467\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 467 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -467;
	} else {
		printf("Test Case 467 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAEB5320E1378A399ULL,
		0x1234FCB3FF8ABDB6ULL,
		0xE2F4E395C8A8FA8AULL,
		0x3CB651529B387CB8ULL,
		0xEB77D8A40BBD1B28ULL,
		0x26F59BE17629E543ULL,
		0x531D9CD959B55A1FULL,
		0x8B14858D30E86093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 468\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 468 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -468;
	} else {
		printf("Test Case 468 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA93FDA7D53C6AF82ULL,
		0xFD1726C88E5ABCF0ULL,
		0xDB9ACF96E8E06F1AULL,
		0xAC9EE9B4A9A89D8FULL,
		0x2463A870B3720096ULL,
		0x22635C25C9D91A94ULL,
		0xDA3300B0C57448D8ULL,
		0xF42A853070DEF7F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 469\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 469 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -469;
	} else {
		printf("Test Case 469 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x4F57B29DF93EDE79ULL,
		0x16D576B64663F5C7ULL,
		0xA858DA44FC9A0CCBULL,
		0x3FBA45583C77CE9EULL,
		0x573E4D579B5FBFF5ULL,
		0x06C768E1F28ACE05ULL,
		0xCD2125CED42214F9ULL,
		0x0D24266B4A3528B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0800000000000000ULL
	}};
	printf("Test Case 470\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 470 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -470;
	} else {
		printf("Test Case 470 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x8D39772CA5E62F52ULL,
		0x834DC80BE2479760ULL,
		0x64E88F6C66783181ULL,
		0xF05575BE9ACA172AULL,
		0xD88F836E43F1827DULL,
		0x24585E6EA721E2CDULL,
		0xE3A58C62432B943BULL,
		0x176E3C3A76F2EE16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 471\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 471 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -471;
	} else {
		printf("Test Case 471 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x527C245D2F33A664ULL,
		0x9F3DC60D9699E071ULL,
		0x56BE7C3B6D7B21C0ULL,
		0x4DD7986B129D867CULL,
		0xBC5A8E556633F109ULL,
		0xC1E89D85D6A1B65AULL,
		0xBD6A5BC23E096958ULL,
		0x74F0CB6F13E22E28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 472\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 472 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -472;
	} else {
		printf("Test Case 472 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD8755751DAC53E66ULL,
		0xDCA43FF189BA2552ULL,
		0x2C6A27E0FE6932F3ULL,
		0xF2888B0BE231C180ULL,
		0x457D1A0D34513EADULL,
		0x0BC8E3581FFBBBFEULL,
		0xC796FCCC5256CF34ULL,
		0xF857099E12565AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 473\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 473 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -473;
	} else {
		printf("Test Case 473 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xEF6F09D222FCA22FULL,
		0x8D9BA4A47BADC030ULL,
		0xBCC1AFDE3E4A36C0ULL,
		0x3E784FCA288924C7ULL,
		0xC8D13D8DB3E8A490ULL,
		0x3020FB1E4567BA52ULL,
		0x2C41BA240E0ADACAULL,
		0x15842C6318310436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 474\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 474 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -474;
	} else {
		printf("Test Case 474 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8201167F35578DAAULL,
		0x466B9CE5F1806128ULL,
		0xB6F7DC99CEE74AE6ULL,
		0x79BA207EB8F04431ULL,
		0x0973A21B7ECEA470ULL,
		0x26748E990A2592C7ULL,
		0x3D79C27452161BCCULL,
		0xEEA813E2B4119BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 475\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 475 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -475;
	} else {
		printf("Test Case 475 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x72B82D33D4BFC392ULL,
		0xCC68897428DD91BEULL,
		0xA6DA7260EA1A6A88ULL,
		0xAAC46837D4022631ULL,
		0xDE5BA60394C01B67ULL,
		0x781798685D3AA1E1ULL,
		0xB241564B93A5E435ULL,
		0x578D6A25F864D989ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 476\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 476 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -476;
	} else {
		printf("Test Case 476 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x703FE0C1B3431054ULL,
		0xECEE36BD3FE5E5E1ULL,
		0xD6EF620D6B30478BULL,
		0x68E1DB026D343ABFULL,
		0xE3B227925FE3168BULL,
		0x2232B7202FB0D9B2ULL,
		0x76418E2A4775D0E9ULL,
		0x11AF57F095B20018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 477\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 477 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -477;
	} else {
		printf("Test Case 477 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB45E870AB5F9E5E8ULL,
		0x5F8EAF2AD1ADA26FULL,
		0x442DA1F082BFEDBBULL,
		0xB77E58BF193D1324ULL,
		0x62EA121EAB47EB11ULL,
		0x0512A3C0F289B480ULL,
		0x55E6B96D842A38DDULL,
		0x6698D94E8942E181ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 478\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 478 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -478;
	} else {
		printf("Test Case 478 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA3A50E1A61DF5D4BULL,
		0x96436A8ED9C7B600ULL,
		0x7A9FB81B69F6A396ULL,
		0xE1F14C560C179542ULL,
		0xF7B9DE2AC2F025E3ULL,
		0x8ABD538598846D80ULL,
		0x41898752C13EBBB5ULL,
		0x8B714ECC3574D798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 479\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 479 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -479;
	} else {
		printf("Test Case 479 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x87CC945C9D96A062ULL,
		0x2845F95083A6AC6BULL,
		0x6172F04E20C6D99CULL,
		0xC00923E745931E57ULL,
		0x8B51731E921B957AULL,
		0x4732C7D7CAD30DB4ULL,
		0x4C48090546164705ULL,
		0xC97D06CB198EFF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 480\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 480 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -480;
	} else {
		printf("Test Case 480 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x34D2584A629DEC9DULL,
		0x32FBFB459560C528ULL,
		0xDCDEC9FEBA0A50D6ULL,
		0x2553E348A18CC415ULL,
		0x3A586697C1B1D5EEULL,
		0x2DB23ED1EFAEC71DULL,
		0x37CB58F460C628B6ULL,
		0x99A949547023E535ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 481\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 481 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -481;
	} else {
		printf("Test Case 481 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x88DAAA605E7102FAULL,
		0x5A63C964E59B9FA4ULL,
		0x3C5D854A85646A1AULL,
		0x533EB4A3C70E4903ULL,
		0xA8E2753D7C8AFF71ULL,
		0x955D92A72D9AFB9AULL,
		0x7CBF84909C1C8B99ULL,
		0x8CA07CFA3AB3C4E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 482\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 482 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -482;
	} else {
		printf("Test Case 482 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0D7793E6C58C82DAULL,
		0x2870542EEFCFAC32ULL,
		0x031B93F42CF30DFDULL,
		0xCAAFB3B0BD8473F2ULL,
		0x9934D9235D61EBA1ULL,
		0x781823A8D2CF82C6ULL,
		0xEAC8ECC78A607035ULL,
		0x49AFA21F7367E1D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 483\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 483 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -483;
	} else {
		printf("Test Case 483 PASSED\n");
	}
	printf("---\n\n");
	la = 498;
	k1 = (curve25519_key_t){.key64 = {
		0x275F953489AFFE0CULL,
		0xDD0499B90FC0DE88ULL,
		0x3D9A438D98BFBFF9ULL,
		0xF4B50C2CDE1F120FULL,
		0xBB33CD0C5CED4C21ULL,
		0x9464DCDB07679D64ULL,
		0xCCFF7C7D981FF3FDULL,
		0x00055502609398B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0004000000000000ULL
	}};
	printf("Test Case 484\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 484 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -484;
	} else {
		printf("Test Case 484 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC2D767ECB172E9C8ULL,
		0x8EF7EAD355F12A95ULL,
		0x8D09B41C7D3196CFULL,
		0x513AFFBFC155BDD3ULL,
		0x2FBB11A39D82372AULL,
		0x745CAAF151964F15ULL,
		0xD3185BEF8AA55D08ULL,
		0x1F2DD4C98DDDA467ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 485\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 485 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -485;
	} else {
		printf("Test Case 485 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB5DE51097088BDD4ULL,
		0x2057E8697BB0C65BULL,
		0x56BC86FACF83CEF1ULL,
		0x53B7B983C0C6955EULL,
		0xDAE95C746B9BB69AULL,
		0xE10436370619B13DULL,
		0x2B660CAF860AFBCFULL,
		0xCA51FE04EBFD3A20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 486\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 486 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -486;
	} else {
		printf("Test Case 486 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x71706942CA47658AULL,
		0xEB812498C6F42FCFULL,
		0xEBCB3C4AB1033A84ULL,
		0xB7FFF2F1D2BB34A8ULL,
		0xC7E86410CC53E102ULL,
		0x45E83C18F1FF0454ULL,
		0xAE7A8BE79FD37CF5ULL,
		0xE00C181B38DC442DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 487\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 487 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -487;
	} else {
		printf("Test Case 487 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0x43F3C7D5743AFBA4ULL,
		0xAB585B39E2D7C22CULL,
		0x995D524F4252B73EULL,
		0x700870FB0B364CCFULL,
		0x9C3A69B5A298EF74ULL,
		0x507E4374E878F7CAULL,
		0xB47BF2D95BD53E0AULL,
		0x01D05EEE0D7F9D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0100000000000000ULL
	}};
	printf("Test Case 488\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 488 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -488;
	} else {
		printf("Test Case 488 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x17253A9ECA88C3EEULL,
		0xFA020375B111979CULL,
		0x06DA2DC20B1454A7ULL,
		0x00806973E6BF432FULL,
		0xF00C028F7FB77A02ULL,
		0x6B527B892EDD0AA4ULL,
		0xFE079E2253A9B315ULL,
		0x2E82B5CE0C5C024AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 489\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 489 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -489;
	} else {
		printf("Test Case 489 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDD5617F3EFF3865EULL,
		0x46A5BCC460BC73E6ULL,
		0x05E8806E14043A1DULL,
		0xED75E8E4A0B7F212ULL,
		0x339AD448B14E779FULL,
		0x75D807B2282C255EULL,
		0x1EEBDEF231F9C679ULL,
		0x28841BA1EB8ACEAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 490\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 490 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -490;
	} else {
		printf("Test Case 490 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x489092209EFF1370ULL,
		0x139663F7A36BAFBAULL,
		0xF1E9736F7B7883C2ULL,
		0x7EC268FEB90E8FCEULL,
		0x11707810F5CA73A1ULL,
		0x6E25CC077EBB4556ULL,
		0x0161FC512F5C8514ULL,
		0x26B5DDBE90A2D9BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 491\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 491 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -491;
	} else {
		printf("Test Case 491 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD9DD56C0DE828B37ULL,
		0x548D0089798154D8ULL,
		0x08FEAA3DC2F1453FULL,
		0x33E4009824131E49ULL,
		0xE07A33204BEDBC3AULL,
		0x5A49267BD6FBCA3BULL,
		0xDACB8FB188D71303ULL,
		0x622F28C3E03F9161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 492\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 492 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -492;
	} else {
		printf("Test Case 492 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6F88653567ADA269ULL,
		0x5EA9703EE199C9FBULL,
		0xDA356C0BED163501ULL,
		0x48A0B00320999D51ULL,
		0x8FA2ADBDF69F40C1ULL,
		0x8563E63D36E9ECD9ULL,
		0x4B846F81088F0DA0ULL,
		0x3A278D1D28048C97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 493\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 493 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -493;
	} else {
		printf("Test Case 493 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3B9792EF8CDE65D0ULL,
		0x025A3D200C7306B8ULL,
		0x05864CBD42A96857ULL,
		0xB415C2D0FBEDA387ULL,
		0x70C27EF40472B2ACULL,
		0x0DC3729F06F086DCULL,
		0xFD3758FEAA4F4485ULL,
		0x778775971DF066C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	printf("Test Case 494\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 494 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -494;
	} else {
		printf("Test Case 494 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x53FACEDA280EB68EULL,
		0x0C4EAC41E452C044ULL,
		0x365BB507E05A8644ULL,
		0x83CB17303FCE439EULL,
		0x51B79E3C8CA37776ULL,
		0x222B3F0C5637078DULL,
		0x2AFF5525BC4B3B5AULL,
		0x1575E43E5EC4B711ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x1000000000000000ULL
	}};
	printf("Test Case 495\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 495 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -495;
	} else {
		printf("Test Case 495 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2600C4AE9681BCACULL,
		0x380E8D79A1230EF0ULL,
		0xBAED42A73C2E636BULL,
		0x206910D18E803510ULL,
		0x421E33C3844946DCULL,
		0x3586DAF5E915B392ULL,
		0x2540D53789AA9D43ULL,
		0x20D6790FF56A5CBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 496\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 496 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -496;
	} else {
		printf("Test Case 496 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD28B590B6347BC99ULL,
		0x98FEB86C7FB9CB0DULL,
		0xE79887C2060A5179ULL,
		0x9A3F06CFCDDB865BULL,
		0x836F49AD74925394ULL,
		0x4348940BC621E21CULL,
		0xD03AE2C473E51C69ULL,
		0x26D4EC6F19936788ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 497\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 497 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -497;
	} else {
		printf("Test Case 497 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE8B8E6979EE13912ULL,
		0x5949B29D36BF11EAULL,
		0x57DE9A920F0C5441ULL,
		0x5ACDD88BCEFC40A9ULL,
		0xBDF8DB0B2784C999ULL,
		0x9EF06AECAAEBA57DULL,
		0xCA82B4605FB6A8D7ULL,
		0xCAB407AF43040FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x8000000000000000ULL
	}};
	printf("Test Case 498\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 498 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -498;
	} else {
		printf("Test Case 498 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x84D60976603F7D1BULL,
		0xAAA890BA291B5845ULL,
		0x3169A3AFF8774AB1ULL,
		0xF2588EEBA6BA7BFCULL,
		0x5F1809D83A1B5669ULL,
		0x183AD78D527691DBULL,
		0xC639B18D393DBE14ULL,
		0x3ECB5DD8688B4651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x2000000000000000ULL
	}};
	printf("Test Case 499\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 499 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -499;
	} else {
		printf("Test Case 499 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xAC15DB269B819961ULL,
		0x891505C368FABCB3ULL,
		0x8038538F45064EC5ULL,
		0x5428EA9D68DD21E4ULL,
		0x1B51FBBD8968B6B9ULL,
		0xEE88324A1CA7E05DULL,
		0x328C4080C5B49358ULL,
		0x04E49A6D25652368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0400000000000000ULL
	}};
	printf("Test Case 500\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\nk2:\n", la);
	curve25519_key_printf(&k2, COMPLETE);
	l2 = curve25519_key_log2(&k1, &r);
	res = curve25519_key_cmp(&r, &k2);
	if (res || l2 != la) {
		printf("Test Case 500 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -500;
	} else {
		printf("Test Case 500 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5D171EB173BE8A36ULL,
		0x57A327AFA89D261BULL,
		0x2CD25B38F6D8A767ULL,
		0x03AACB11F648D8FAULL,
		0x9508B8EFDD58410EULL,
		0xE140E9F53CED3EE0ULL,
		0xB195A45C4CF15B04ULL,
		0x8C3D84A4DD0B0C9FULL
	}};
	printf("Test Case 501\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 501 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -501;
	} else {
		printf("Test Case 501 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xCC5EF13CB9CE8C33ULL,
		0x767932964F6705B7ULL,
		0xAEC34F263A1772A5ULL,
		0xBA64D089E78A086EULL,
		0x12E9A2F6BBFEDDFDULL,
		0x1CA18F8B0FF240E6ULL,
		0x1D6FE1AB1CABA3B2ULL,
		0x1FAAF582766D8730ULL
	}};
	printf("Test Case 502\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 502 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -502;
	} else {
		printf("Test Case 502 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x411E6C582BAB4405ULL,
		0xDD4700D622E88454ULL,
		0xA32F746696B8CB51ULL,
		0x60650E7E11FD0E0AULL,
		0x8072AA7513D7CAC1ULL,
		0x95AFA35D02F043A7ULL,
		0xDB922D9E4C6C3CB4ULL,
		0xCA98A710CB8D9DEAULL
	}};
	printf("Test Case 503\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 503 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -503;
	} else {
		printf("Test Case 503 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4DD96BFFB42A0E8AULL,
		0x90564D0ECDDD9E9CULL,
		0x5B79207CC5EAA513ULL,
		0x7C29D5DB7144FA8FULL,
		0xE8D366E945F7069DULL,
		0x3A7E477EB68B455AULL,
		0x67DC369FABE938C5ULL,
		0x79B9F73D2B89FC4FULL
	}};
	printf("Test Case 504\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 504 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -504;
	} else {
		printf("Test Case 504 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4C827AACFABDA87AULL,
		0x03DEEAA20B28CA9CULL,
		0x17988EF94CEE5845ULL,
		0x880CE44D5BCAC9ABULL,
		0xD90FC458D021869FULL,
		0x0000C56A85280D8EULL,
		0x41ED477C102A7127ULL,
		0x325B39DAE4350490ULL
	}};
	printf("Test Case 505\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 505 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -505;
	} else {
		printf("Test Case 505 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0C94139A2FC3E456ULL,
		0x29A9B1B5137DEC27ULL,
		0x21764A04734C2668ULL,
		0x9CCD7EB0F0BC482DULL,
		0x14E68C867EC25CD1ULL,
		0x404BD7134D17D239ULL,
		0x6300C7A23FF4D156ULL,
		0x371A1E93C48C1F5EULL
	}};
	printf("Test Case 506\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 506 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -506;
	} else {
		printf("Test Case 506 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5357E991836C8880ULL,
		0x06FBF66CCADDA629ULL,
		0x0FC5179EBFC874B1ULL,
		0x2E3C0DA1DB3D43A4ULL,
		0x6500B55AEB22AD32ULL,
		0xBC8C3DB5BD688416ULL,
		0xF6AFE2DC1DD49DE6ULL,
		0xA905D1F2A4C9EDF3ULL
	}};
	printf("Test Case 507\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 507 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -507;
	} else {
		printf("Test Case 507 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x10CA9497C6EFB842ULL,
		0xA269D9258D90B83FULL,
		0x6AA61DBF9D734EA7ULL,
		0x8BDA5CAE91C97C4DULL,
		0x60E4FCFD5A800681ULL,
		0xDCF3F90E4C068E83ULL,
		0x4D44B0165256E04FULL,
		0x892D31C601A7F452ULL
	}};
	printf("Test Case 508\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 508 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -508;
	} else {
		printf("Test Case 508 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3D2CA91C50AB2674ULL,
		0x21EAF441D3AD85DCULL,
		0xB126A051BF354C09ULL,
		0x9B171C8694748294ULL,
		0x88521EEA1E62B745ULL,
		0x121E1C61E236EFE7ULL,
		0xF87B9DC3DFC9C229ULL,
		0xFC6000858FF94E69ULL
	}};
	printf("Test Case 509\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 509 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -509;
	} else {
		printf("Test Case 509 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCF6118C0F63BD0A5ULL,
		0x03757D573F42FB96ULL,
		0x87FA7B8AB48E6BEFULL,
		0x2549797B775672BAULL,
		0xE83BA87CCC8C2190ULL,
		0x3B58B72021C6B24FULL,
		0xABACB2696984E3A0ULL,
		0x64A118D5189B9502ULL
	}};
	printf("Test Case 510\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 510 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -510;
	} else {
		printf("Test Case 510 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x127BD251C90EC6C5ULL,
		0xA192E1AA729738B7ULL,
		0xAEB32AE21573393FULL,
		0x421F6037C9FA2C22ULL,
		0xE040E50D0F459D94ULL,
		0x9065380DDC841C5EULL,
		0x72F93B0B827E57A5ULL,
		0x54E08403B154F765ULL
	}};
	printf("Test Case 511\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 511 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -511;
	} else {
		printf("Test Case 511 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFACB11C0A28ECA86ULL,
		0x67582CC153B0C15AULL,
		0xC30B444802EC23B6ULL,
		0x849F76701B0DB198ULL,
		0x58ABBB3C092E5C07ULL,
		0x7E35FA65A261FEF5ULL,
		0x601EB45D2D99F1C7ULL,
		0x3C49142936A44EB5ULL
	}};
	printf("Test Case 512\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 512 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -512;
	} else {
		printf("Test Case 512 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8B13130BE5AD06EFULL,
		0x0CD42E08083E5125ULL,
		0xD6E33CC015E7D4CDULL,
		0x39E9266303165AB6ULL,
		0xC76C0385F52F5922ULL,
		0xFF338ECED235B8FBULL,
		0x1B2A0E110D8A5DAFULL,
		0xD5CC8DDEC02D60C0ULL
	}};
	printf("Test Case 513\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 513 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -513;
	} else {
		printf("Test Case 513 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x14CEF2AD105402A9ULL,
		0xE7A29A4F99961A39ULL,
		0x06166607A440BDE8ULL,
		0x1EA3550D00D1E9F3ULL,
		0x27AEEB9FD478A77CULL,
		0x09F1E17B08A42A75ULL,
		0xAE65FF5FE19F6B1BULL,
		0x63764CF6A149F0D7ULL
	}};
	printf("Test Case 514\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 514 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -514;
	} else {
		printf("Test Case 514 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1401A2B570FD0D92ULL,
		0x97629A86B0B3F3CFULL,
		0xDE978B084F029716ULL,
		0x537071AF13A0366CULL,
		0x471CA6385BE51E36ULL,
		0x60186E790F87E725ULL,
		0xFFDB19E5585E2217ULL,
		0xE4741B2E2AED157DULL
	}};
	printf("Test Case 515\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 515 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -515;
	} else {
		printf("Test Case 515 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x49C7D8A0084145CEULL,
		0x731DE1E4A62E3C2AULL,
		0xF21693DB96C421C1ULL,
		0x29328A1599EA7026ULL,
		0xA927676A0F4AE032ULL,
		0x43E69B28D7E6FD3FULL,
		0xA1A624C98A9521B4ULL,
		0x2987BA7BF682580EULL
	}};
	printf("Test Case 516\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 516 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -516;
	} else {
		printf("Test Case 516 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1B92564DE0687BEDULL,
		0xA4D411199B784DDBULL,
		0x7AB9B57C334CB471ULL,
		0xBE9351BB9BFFA681ULL,
		0x5744067CED769EEBULL,
		0xD0BA767884E29254ULL,
		0x065AA26C702EC568ULL,
		0x64810C58D5743E56ULL
	}};
	printf("Test Case 517\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 517 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -517;
	} else {
		printf("Test Case 517 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3ADA5DC79F2CB308ULL,
		0x61133FF1A7665E60ULL,
		0xFEB0BDEDD09C67B9ULL,
		0x19CFED7597692B1DULL,
		0xE1AB666DF8335D05ULL,
		0xDABE1832872F1B0FULL,
		0x76220952283BD14BULL,
		0xBA44CBA434D8F6DFULL
	}};
	printf("Test Case 518\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 518 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -518;
	} else {
		printf("Test Case 518 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFA88AECE74E4F40FULL,
		0x20D86A3C4ABB721DULL,
		0x4C373002F7C524F4ULL,
		0x4EE92873DDFB0D99ULL,
		0xC1213091ED58682CULL,
		0xCA155E1BC0EE6CF1ULL,
		0x4FCFDBE492EB2B23ULL,
		0x79109DF42B8B70C2ULL
	}};
	printf("Test Case 519\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 519 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -519;
	} else {
		printf("Test Case 519 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x142E81E74ECEE6C2ULL,
		0x9BC6363424654E21ULL,
		0xAB537CDE37697241ULL,
		0x054B7CE131BF47BEULL,
		0xC3A407100DCF8023ULL,
		0xFFD7B05E31B10271ULL,
		0x0FA1534A914593A4ULL,
		0x5612CD558C57CB42ULL
	}};
	printf("Test Case 520\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 520 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -520;
	} else {
		printf("Test Case 520 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x1A0E1E567A829069ULL,
		0x53033CB3DE33636EULL,
		0xA9F0B2822AD9D2D5ULL,
		0xAFF6E11EEBCD8417ULL,
		0x32E2E9E402A88F4EULL,
		0xFC73DB29858680B7ULL,
		0x021C8BA6D00FCD4FULL,
		0x07168ECA57B25C13ULL
	}};
	printf("Test Case 521\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 521 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -521;
	} else {
		printf("Test Case 521 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC439BB268847ECB2ULL,
		0x26A1C6387A6BC6B0ULL,
		0xEDB35FF731AB19D6ULL,
		0x21D583B21D5587EEULL,
		0xE91B8403ADD0DF1CULL,
		0xF416D87BC9AD3B64ULL,
		0xDE0F148599A594D7ULL,
		0x8C6A0033F9813568ULL
	}};
	printf("Test Case 522\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 522 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -522;
	} else {
		printf("Test Case 522 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6871DC9BD02941FCULL,
		0x622B93BF72B1645DULL,
		0xFC85A99BD18479CAULL,
		0xF215B64CCA37E33FULL,
		0x9448418536A8D51BULL,
		0xC03EC3E659F0F517ULL,
		0x7A35F96580F7EBE2ULL,
		0x31FDFE6E5FCB101CULL
	}};
	printf("Test Case 523\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 523 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -523;
	} else {
		printf("Test Case 523 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4523BB6B31947054ULL,
		0x4776ADBE50E09692ULL,
		0xC524B705A6889C95ULL,
		0x718F420A76E99CC1ULL,
		0x5F9CDC7918B4E03FULL,
		0x5F7B27B47C364D57ULL,
		0x6C93F3DBBDBDE2C9ULL,
		0x590A17B1C1B6209AULL
	}};
	printf("Test Case 524\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 524 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -524;
	} else {
		printf("Test Case 524 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDC8310D67094A718ULL,
		0x53697A94CAA80B20ULL,
		0xE0053764EC87044DULL,
		0x98860435553D86FFULL,
		0x13B2CE2D2F3B5B2EULL,
		0x94E3E71BC4458E53ULL,
		0x5F887C7B16A11347ULL,
		0x4799A99118DC0D22ULL
	}};
	printf("Test Case 525\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 525 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -525;
	} else {
		printf("Test Case 525 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8C68EB939D8BAA91ULL,
		0x9E29AA84D1B1E322ULL,
		0xFC246B3C0C92830AULL,
		0x9EAF3D641D549C45ULL,
		0x02BFD6689B97001AULL,
		0xDBD2703117291CACULL,
		0xBB51D9341C22C662ULL,
		0xA0D35C09063FF06BULL
	}};
	printf("Test Case 526\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 526 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -526;
	} else {
		printf("Test Case 526 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x5E51AD84A447069FULL,
		0x2F540F04E4039645ULL,
		0x23E0A91AB73E7745ULL,
		0xD278270A0871D054ULL,
		0xB4B2B1FC2497FE89ULL,
		0x99A2CBBE3F1674A9ULL,
		0xB7AA86AB6482955DULL,
		0x19F77116D5225ACEULL
	}};
	printf("Test Case 527\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 527 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -527;
	} else {
		printf("Test Case 527 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8BBD309F0E7DE89ULL,
		0x4C86262C25FD2721ULL,
		0xE2639984002CFCAFULL,
		0xFD624097D4ACD6E5ULL,
		0xA6EB24342323510CULL,
		0x4EE90FE7C887256AULL,
		0xF69F6015636D62BEULL,
		0x8123102CA4CC59CAULL
	}};
	printf("Test Case 528\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 528 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -528;
	} else {
		printf("Test Case 528 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x48B27A448F37CED8ULL,
		0xAD67B533E317C318ULL,
		0xF30723FD58476167ULL,
		0x9499285F6D53D4DFULL,
		0x63A148860199F91CULL,
		0x3AE517FC1A308AD4ULL,
		0xD57C4FB420DB036DULL,
		0xE95F50B9B9FDE589ULL
	}};
	printf("Test Case 529\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 529 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -529;
	} else {
		printf("Test Case 529 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x796F4F645FBA70FFULL,
		0xC3D27CA4166350A2ULL,
		0xC428352DEAABE7F8ULL,
		0xF1DF0BAE953A6703ULL,
		0xEE19FCA6F8B5BE55ULL,
		0x56AEA1EA42F6CFEAULL,
		0x7270CF119D2A6164ULL,
		0x028C8D70BF4FBF82ULL
	}};
	printf("Test Case 530\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 530 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -530;
	} else {
		printf("Test Case 530 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8A6CCE69E8AA5E58ULL,
		0x01F76CC24B2695CFULL,
		0xD87F72B5810F246BULL,
		0x14B07AAE59ABC57FULL,
		0xCD110DB8384BEDDFULL,
		0x2C4FAEF7EA0811E0ULL,
		0x6B89F1F0F94444F4ULL,
		0xBFAA4BC8A125E23BULL
	}};
	printf("Test Case 531\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 531 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -531;
	} else {
		printf("Test Case 531 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4AADA42E0C765F05ULL,
		0x9FB37044596700A2ULL,
		0x25C81CF911ABDBD8ULL,
		0x27976801B0A4A700ULL,
		0x28758CABF6DECD9CULL,
		0x74096C43B1D75D81ULL,
		0x3AE787FF4EE4FE47ULL,
		0x4D3227F3CAAF6DB5ULL
	}};
	printf("Test Case 532\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 532 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -532;
	} else {
		printf("Test Case 532 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9450352F52941BB3ULL,
		0xEF18A6872C094825ULL,
		0xCE62C09557E4D67BULL,
		0x5B603A05A65A3C7FULL,
		0x5E34E39360F73B50ULL,
		0xB4A8CCDB876E2E6CULL,
		0xB33A2CD8D246CB51ULL,
		0xE1F0BDAA9F963789ULL
	}};
	printf("Test Case 533\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 533 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -533;
	} else {
		printf("Test Case 533 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xB81C7C8FE1819465ULL,
		0x6905A4994FD9936FULL,
		0xCC9EBE2000855CC5ULL,
		0xACE5EB0D3ADBF512ULL,
		0x5D2CD59A493EB52DULL,
		0xB0F5E000D6386737ULL,
		0xD5C3433D9BAA0F17ULL,
		0x02B9EF949205235BULL
	}};
	printf("Test Case 534\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 534 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -534;
	} else {
		printf("Test Case 534 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7FED9DB91445AFEDULL,
		0x8A905714A0F9EDD2ULL,
		0x75D8BB858E678842ULL,
		0x1F9C1DE30F5DB701ULL,
		0x9F9FDD612F7ED383ULL,
		0x28C7B201EA272BE9ULL,
		0x8B9ACAC2D3B6530BULL,
		0x8F93CDC5B85B6B77ULL
	}};
	printf("Test Case 535\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 535 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -535;
	} else {
		printf("Test Case 535 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6236A3C37974BEA1ULL,
		0xC6B6CBB3EB001B6FULL,
		0xA7374231C24139E3ULL,
		0x4A4C0C77283645BDULL,
		0xE4DFE00F0ED38E14ULL,
		0x131E54E7F3EA3458ULL,
		0x185213A432593C7FULL,
		0x2838CA2CD530D65FULL
	}};
	printf("Test Case 536\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 536 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -536;
	} else {
		printf("Test Case 536 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xEA4D8EF9D0D2A067ULL,
		0x4C50F8EA5D102283ULL,
		0x840DF0B081BA0D52ULL,
		0x5A7A27094C737335ULL,
		0xF4817AB1A654F855ULL,
		0x080A1CE7967BDDFFULL,
		0x19288274970EE77DULL,
		0x09753E08CA249B61ULL
	}};
	printf("Test Case 537\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 537 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -537;
	} else {
		printf("Test Case 537 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x65114222521B02C6ULL,
		0xD106DB2651106A14ULL,
		0x5D61A85B3A982E3FULL,
		0xCBE1E7312B67D2C4ULL,
		0xDCAC703AD6786C14ULL,
		0xFCC9E084D94A403AULL,
		0x15B5C5CE4067EE0FULL,
		0x71E89B15F55169C2ULL
	}};
	printf("Test Case 538\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 538 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -538;
	} else {
		printf("Test Case 538 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x84DDB68FD966DB3EULL,
		0xB4BCD8D09A6E0062ULL,
		0x9CA8D789F4A7635FULL,
		0x98E49EADACB5AA21ULL,
		0xAED316BE7710411CULL,
		0x3A43F76317F85B1EULL,
		0x7076CF4E1EB6C3BDULL,
		0xB1F265BF6ABEC026ULL
	}};
	printf("Test Case 539\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 539 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -539;
	} else {
		printf("Test Case 539 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB10A790049BC800CULL,
		0x69E9CEA11006C1DCULL,
		0x353225FF67072D07ULL,
		0x1FB57DA60FBD6295ULL,
		0xDFD9B5827E349967ULL,
		0xB9F9A09DA489C736ULL,
		0xF19C38E61F43394BULL,
		0x29F25F7F258CD4B3ULL
	}};
	printf("Test Case 540\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 540 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -540;
	} else {
		printf("Test Case 540 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC3DA86EC1D96B950ULL,
		0x9B416A07A5ED8AC2ULL,
		0x90E827F013DD292CULL,
		0x7DAEA9A93A58714FULL,
		0x92CB46BE0322B645ULL,
		0xC9C1E6D935FD0733ULL,
		0xC3628E21ED8968CAULL,
		0x8333C74F85C7AD93ULL
	}};
	printf("Test Case 541\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 541 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -541;
	} else {
		printf("Test Case 541 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF692F89C4CEAA3B4ULL,
		0x877B7C98662261A9ULL,
		0x498B510F40089B7AULL,
		0x0D7015E225ED8E85ULL,
		0x3690AB27C27F39BEULL,
		0x287E0DCC7458AC42ULL,
		0x867B81115B739F26ULL,
		0x395FD0BB2167E616ULL
	}};
	printf("Test Case 542\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 542 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -542;
	} else {
		printf("Test Case 542 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6360E614CC41D2A6ULL,
		0xB67AB2FF98599376ULL,
		0x89F89F4C6B76C164ULL,
		0x170C814560FAA235ULL,
		0x34B04ADB1FD9A3E4ULL,
		0x01385DEBF5144C8CULL,
		0xC0ED4E75214D1789ULL,
		0xC680E4D1775784F9ULL
	}};
	printf("Test Case 543\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 543 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -543;
	} else {
		printf("Test Case 543 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5B8979F6DB9619C8ULL,
		0x52120BAA9688DA6FULL,
		0x2FB7907212D475C5ULL,
		0x5EFE16669DA5199EULL,
		0xC495540AC8DC3E94ULL,
		0xB1BE2A880AA70F45ULL,
		0xF35CED47AFAE2688ULL,
		0x4B971FD1809D8A89ULL
	}};
	printf("Test Case 544\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 544 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -544;
	} else {
		printf("Test Case 544 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB60BBBCA25FFE85ULL,
		0x5C6262F71A80D615ULL,
		0xAA20970F145BFC88ULL,
		0x90EE79E33BEB8E44ULL,
		0x03956E4EF7CB7047ULL,
		0x76EB99E2523DE8CDULL,
		0xCB5933CA3F74D359ULL,
		0x971BEAC727C805B5ULL
	}};
	printf("Test Case 545\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 545 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -545;
	} else {
		printf("Test Case 545 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x4216353820994C96ULL,
		0x0447D5210E1BE8CDULL,
		0xBC262ECED11E3135ULL,
		0x657924D848E44F06ULL,
		0x5833998367B98BA1ULL,
		0xBC7A96BC503B8C68ULL,
		0xC33C66526BCD0E3EULL,
		0x061D74C5F0422901ULL
	}};
	printf("Test Case 546\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 546 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -546;
	} else {
		printf("Test Case 546 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0195E758E9C3EBAULL,
		0xECDBDC1D9FCC731AULL,
		0x5A35013C86CE7783ULL,
		0x00233693686BAC77ULL,
		0xF28B070AEB118AABULL,
		0xDD185AC674E7DA7DULL,
		0x67C615D289EFF606ULL,
		0xFDD64C1A001F2970ULL
	}};
	printf("Test Case 547\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 547 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -547;
	} else {
		printf("Test Case 547 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x61A26816564EA627ULL,
		0x65ADA0C5037C029DULL,
		0x577453891DBEC2A2ULL,
		0x34A6C9AA225C1BAEULL,
		0xF730F55DB4D75684ULL,
		0xEF19E7C07F11EA03ULL,
		0x6CB3BA9EBE0BBCB4ULL,
		0x1C5DB0BFA2E2BE0BULL
	}};
	printf("Test Case 548\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 548 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -548;
	} else {
		printf("Test Case 548 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x75C2A4404C75B4DCULL,
		0x7A34735EC2F6D48BULL,
		0x06065F53F58F8F1BULL,
		0xBD458113D73CD02BULL,
		0x0051E45D8D215002ULL,
		0xC339117BD9F8D848ULL,
		0x80CBB1C05E1381C3ULL,
		0x806FC977E7B25C62ULL
	}};
	printf("Test Case 549\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 549 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -549;
	} else {
		printf("Test Case 549 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4ADCC15F25E1CEB2ULL,
		0xDC88E466B799D6A0ULL,
		0x51722FDDD8A65C40ULL,
		0xE1471A09108ABF2DULL,
		0xA7230E0749A7A712ULL,
		0x1DA7289D52798170ULL,
		0x8D760A678D19F1ADULL,
		0x4020ADFA4A1266F9ULL
	}};
	printf("Test Case 550\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 550 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -550;
	} else {
		printf("Test Case 550 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA43A180FD2F9EA37ULL,
		0xEBBDDE7AA1C9971BULL,
		0xC8757DFEFCB7C4CBULL,
		0xA621EFDB0B4DE20FULL,
		0xD46A8745BB28B93BULL,
		0x4115E1DCF9F75057ULL,
		0xFB34A2227BF7CE88ULL,
		0xD9EB0A069CEF0DCAULL
	}};
	printf("Test Case 551\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 551 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -551;
	} else {
		printf("Test Case 551 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x3CE3C7C5AF4866CBULL,
		0x6B658943C89FA0E5ULL,
		0x0E5D6C3E36EE8E61ULL,
		0xAA1055202F7381BEULL,
		0x3485DBCE920D4266ULL,
		0xA6999B43DA987B6EULL,
		0xB12CE28637488F27ULL,
		0x0870D2545D2C9DEBULL
	}};
	printf("Test Case 552\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 552 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -552;
	} else {
		printf("Test Case 552 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC28ABA53A117F6A9ULL,
		0x04529A0FF8F8A142ULL,
		0x6B5D990D94A13498ULL,
		0x3E6CD5157F5C4A3AULL,
		0xD177613618C29AA9ULL,
		0x3B4AA6B4307D24C8ULL,
		0x9247977366A8FF43ULL,
		0x3E7EDF508F38D8E8ULL
	}};
	printf("Test Case 553\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 553 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -553;
	} else {
		printf("Test Case 553 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA5AA919B02734D55ULL,
		0xCA7F025E8EA46045ULL,
		0xF970168A79554948ULL,
		0x4396B184241D93A5ULL,
		0xF3684B8BE2F11630ULL,
		0xB10C65E0C46398E5ULL,
		0xE71BFCF878E82B87ULL,
		0x640EF1F7D297879FULL
	}};
	printf("Test Case 554\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 554 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -554;
	} else {
		printf("Test Case 554 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x813BBF0E4BE1E751ULL,
		0xF16F491F6E16D8D7ULL,
		0xD8127EDA63A17994ULL,
		0x24F82D15BEF3C24EULL,
		0x77FFE28CB6B1E037ULL,
		0x5BEB90F672D3BBDEULL,
		0x9FC2A3A2D4AA7976ULL,
		0xDD5FCD8D55EE1D5FULL
	}};
	printf("Test Case 555\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 555 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -555;
	} else {
		printf("Test Case 555 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x5DE71A108F13BD29ULL,
		0x218919740C52F181ULL,
		0x4FA7633E7E987BF7ULL,
		0x9F6693FA80FDE7B6ULL,
		0xA8AA782BBC97F997ULL,
		0x40820D703DF82D6BULL,
		0x952F241356699E64ULL,
		0x09ADD130B53AFC21ULL
	}};
	printf("Test Case 556\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 556 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -556;
	} else {
		printf("Test Case 556 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72FF5025B792D893ULL,
		0xF8FD468FF1733C2AULL,
		0x5C8634E26E974140ULL,
		0x1478DA2A90660F7BULL,
		0xB3D63A9C68EE29CAULL,
		0x72672469DD6B749BULL,
		0x996272256CCAB761ULL,
		0xB3480A13F53F7F30ULL
	}};
	printf("Test Case 557\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 557 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -557;
	} else {
		printf("Test Case 557 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1CF62288B68002D8ULL,
		0x28F81D98272B3877ULL,
		0xFF9E4499EBDC70EDULL,
		0xF3B3EDE8954CF7D9ULL,
		0x1EAFF2F014030AB3ULL,
		0x6507D66EB493BF32ULL,
		0xBE6F422EDD0246EDULL,
		0x296D01C047B5EF9BULL
	}};
	printf("Test Case 558\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 558 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -558;
	} else {
		printf("Test Case 558 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x882CB270DF45487EULL,
		0xC79D1CF83342CD8FULL,
		0x5076E049B38EDF4BULL,
		0x5187AD1E27318E3AULL,
		0x252C2BBBB9D6D44EULL,
		0x26F317FA4CCFC1FEULL,
		0xE86ED2FB7ABA259DULL,
		0x202856E3AEEB0283ULL
	}};
	printf("Test Case 559\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 559 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -559;
	} else {
		printf("Test Case 559 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3EAE4454A26EE5E4ULL,
		0x44005408BB444929ULL,
		0x4371C8AC662E9880ULL,
		0x6D5920D64966BBD8ULL,
		0x876D8CC6787DED3FULL,
		0xC092DA8497EDC727ULL,
		0x69822E70F9079C1EULL,
		0x393CF513DA0AA967ULL
	}};
	printf("Test Case 560\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 560 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -560;
	} else {
		printf("Test Case 560 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCF8DC2675F9D5927ULL,
		0x9D6B08D0764BEB18ULL,
		0x2BB547D09D3CF7B1ULL,
		0xEB89DBAF14727614ULL,
		0xAFEE78D1AF03D213ULL,
		0x8709B03B8ADD3B13ULL,
		0x92BAF3277645F63AULL,
		0x7B01D88F62BD0CFBULL
	}};
	printf("Test Case 561\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 561 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -561;
	} else {
		printf("Test Case 561 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x40EE4C3DBD3814A7ULL,
		0x276901326F7CC06AULL,
		0xFF346C9F732B5E20ULL,
		0x39637EC43B32B70FULL,
		0x29CC103FBBBA8A78ULL,
		0x8F7BE840B629C8BDULL,
		0x390D01F316BD9383ULL,
		0x78CF9F5DFCCB3E7CULL
	}};
	printf("Test Case 562\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 562 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -562;
	} else {
		printf("Test Case 562 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x89CADD14C5D06D17ULL,
		0x0DDB46A511830070ULL,
		0x02FE58F45F71FCCAULL,
		0x66A1DC595979ECF9ULL,
		0x35FBD537488F4CBEULL,
		0xB3B4D0F43FAFF455ULL,
		0xA2CED33E8858FAA9ULL,
		0xC96694C0515869DAULL
	}};
	printf("Test Case 563\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 563 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -563;
	} else {
		printf("Test Case 563 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3A9C176CA0E882FAULL,
		0x0CB6D7182F884429ULL,
		0x128C8F7450C5392BULL,
		0x7B0431919F4EE09DULL,
		0x80C2141EEFAEA003ULL,
		0x9B9E012B69DEF1FEULL,
		0x109724489A46A59BULL,
		0x46858C3A7F1CD1C8ULL
	}};
	printf("Test Case 564\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 564 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -564;
	} else {
		printf("Test Case 564 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x59BBD8349D586A68ULL,
		0x9759B2C813C0EB4CULL,
		0x9F45913073BAFFFCULL,
		0xE1994D3FC7969C9EULL,
		0x9505C5E780FB957EULL,
		0x4AC9BD762DEE2A43ULL,
		0xE7FE036EF9C20FDFULL,
		0x7AB0EDD7DAF95079ULL
	}};
	printf("Test Case 565\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 565 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -565;
	} else {
		printf("Test Case 565 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4B5D9EC4493A57A9ULL,
		0xF13D7C937BF2E1E1ULL,
		0x3D08B1ED8F43C35CULL,
		0x72B3D8E96464E649ULL,
		0x7BF425600D9216A5ULL,
		0x2CFB16A5050E7D8CULL,
		0x5DEA0CF10CEAF035ULL,
		0xD2B76B008AA25338ULL
	}};
	printf("Test Case 566\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 566 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -566;
	} else {
		printf("Test Case 566 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1E9D0FA8DA9A6D38ULL,
		0xAB02A37E7A3D6048ULL,
		0x8A7868CCB289E694ULL,
		0x2A9BC6F4C818C73AULL,
		0xCF584817E44C88C7ULL,
		0x91E8E9D83D98BBCFULL,
		0x88B0FB8E0AD69587ULL,
		0x5B9C63C43F522680ULL
	}};
	printf("Test Case 567\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 567 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -567;
	} else {
		printf("Test Case 567 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE5B3BFAD9E136D1BULL,
		0x7312627F71271B33ULL,
		0xC8DFD6DE0539AE68ULL,
		0xF3701EB52E25C1B4ULL,
		0x99BC3BA891F9BD1FULL,
		0xF0D5369DDA60BF52ULL,
		0x984DC2DC8EAC714FULL,
		0x1526B2756AD70AA8ULL
	}};
	printf("Test Case 568\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 568 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -568;
	} else {
		printf("Test Case 568 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC0E5B057FB613EB9ULL,
		0x3BD5943CCA79E842ULL,
		0x859527181DE166A2ULL,
		0x57D7A8B515BB6ACFULL,
		0x09F820AE9F26C487ULL,
		0x6DF5FC7130809722ULL,
		0x36C056B2C749336EULL,
		0xF6235F6D9C7C6673ULL
	}};
	printf("Test Case 569\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 569 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -569;
	} else {
		printf("Test Case 569 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x15940F427625066BULL,
		0xCB14263C005B4153ULL,
		0xECB5903B21308FF0ULL,
		0xABBB3B50C0BB7E79ULL,
		0xAA2C757A3B18DC6FULL,
		0x5806F4A168D005E5ULL,
		0xCB833C059E8F11E2ULL,
		0x11C4A583C7871620ULL
	}};
	printf("Test Case 570\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 570 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -570;
	} else {
		printf("Test Case 570 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6DF288E72970D106ULL,
		0x9E89518C194BC394ULL,
		0x8A1B0F243BE4DD2FULL,
		0x5B101CF4F2085889ULL,
		0xBF20C15009E1CF60ULL,
		0x4444FCD6E0E3FAA5ULL,
		0x357C71D8164686DBULL,
		0x5D582C478B130DABULL
	}};
	printf("Test Case 571\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 571 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -571;
	} else {
		printf("Test Case 571 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA9ED751E801650A5ULL,
		0x2C322535E9FE225EULL,
		0x6531AF0C906E1968ULL,
		0xAD3E89A387673551ULL,
		0xF01CA4964CF117CDULL,
		0x313DD9558FFBDE42ULL,
		0x37D98ED6C3FFC02FULL,
		0xE0F1BED37BA2E6ACULL
	}};
	printf("Test Case 572\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 572 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -572;
	} else {
		printf("Test Case 572 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5FCAF8C15CD6A68DULL,
		0xD72CDD16C8F9D2C9ULL,
		0x6B3B9A0A0898B51EULL,
		0xF2F9C427EE452EDDULL,
		0x891980AC33FC8D83ULL,
		0xB83348C0F6459AF9ULL,
		0xC526C1A0CC449B87ULL,
		0x4F1815C2E34E48C1ULL
	}};
	printf("Test Case 573\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 573 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -573;
	} else {
		printf("Test Case 573 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x8396922AB26FC093ULL,
		0x829B6CF4B5DBF00EULL,
		0x7BBF96FC7C99CE29ULL,
		0xBA26D6ACF55AA115ULL,
		0x15FD7C4EC07D34ACULL,
		0x8CD04F2EE39CD37FULL,
		0xE34800FEA5842C27ULL,
		0x05A8CE4B58F123CCULL
	}};
	printf("Test Case 574\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 574 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -574;
	} else {
		printf("Test Case 574 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x90E3E2CA01EDED05ULL,
		0x7D7C7CAF390758DBULL,
		0x46F6ACEF39B93714ULL,
		0x83508BB3C8E9FE8BULL,
		0x96E2AF28F864D3B8ULL,
		0x8B988E48B19EED3AULL,
		0x24BED08BC57304AEULL,
		0x46D884F4C36DC9B3ULL
	}};
	printf("Test Case 575\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 575 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -575;
	} else {
		printf("Test Case 575 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7E5C40E00F63C3ADULL,
		0xEDFD8E4117F11E85ULL,
		0x86CD625227BCF1F0ULL,
		0xDF096DC85E2E9721ULL,
		0xC9329AB66740AD0AULL,
		0x886F1F1B1C52B4F3ULL,
		0x2029C1C966354C5EULL,
		0xB73020C06549ACEFULL
	}};
	printf("Test Case 576\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 576 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -576;
	} else {
		printf("Test Case 576 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBCAD1DD4C493DD8ULL,
		0x05B84901E2AFB7B6ULL,
		0x7F0807D5A69FBCC9ULL,
		0x7AB86CB4A9A40057ULL,
		0x8CD32FEE2733C306ULL,
		0xA0438C06D315A626ULL,
		0x5562612D78712EC4ULL,
		0xB89F2CA2B239EAE0ULL
	}};
	printf("Test Case 577\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 577 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -577;
	} else {
		printf("Test Case 577 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x6454BEEC40BC4C7EULL,
		0xBEF3E28EB36DAD7DULL,
		0x99F3E8317A9077FEULL,
		0x67632EAE324474A7ULL,
		0x310F0934BF2F7A19ULL,
		0x7749E03211FB8B17ULL,
		0xA3847B2555153C02ULL,
		0x0B77256F3E9D5C4AULL
	}};
	printf("Test Case 578\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 578 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -578;
	} else {
		printf("Test Case 578 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9982DFC134CA577EULL,
		0x03B5337957B2A393ULL,
		0xE2423B11205B0B9CULL,
		0xEC6776B74FC1090BULL,
		0x367287A4501BAB94ULL,
		0x47B43F203027A6E1ULL,
		0x91261F993EEBED1CULL,
		0x79B65D9838F8EBBBULL
	}};
	printf("Test Case 579\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 579 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -579;
	} else {
		printf("Test Case 579 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x58943837A368988FULL,
		0x21BA8FA4AC676BC9ULL,
		0x50E8808B6859E760ULL,
		0xD1538EDE60A5E65DULL,
		0xE1915312056BDABAULL,
		0xE6E938E679DCED6FULL,
		0xB7A87A9DDCCB4F93ULL,
		0x674E931BC1B29EF6ULL
	}};
	printf("Test Case 580\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 580 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -580;
	} else {
		printf("Test Case 580 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA0314DCCD31701D2ULL,
		0x6A2F8DE0F8D99EB8ULL,
		0x4296D01DF94E3BE3ULL,
		0x59B3E5C3AEC784D0ULL,
		0xFE8E127CC9782B8DULL,
		0x5FBCCB0FADDF6545ULL,
		0x165FA290BD335043ULL,
		0x90BB2E47EC53F589ULL
	}};
	printf("Test Case 581\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 581 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -581;
	} else {
		printf("Test Case 581 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7FC9615F959C67EAULL,
		0xDC3E5C0C058C96F9ULL,
		0x2737A63B182992D2ULL,
		0xAC2E87ED1552CD65ULL,
		0x3697AF3CFEF2A56EULL,
		0x90B693682A489A20ULL,
		0x14680946BC999C46ULL,
		0xCCFC1F0D172ECCD2ULL
	}};
	printf("Test Case 582\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 582 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -582;
	} else {
		printf("Test Case 582 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3B17E537F609FE8EULL,
		0xEF888A72A67B0DFCULL,
		0x2C53863ADC66EA31ULL,
		0xFDED503082993B8AULL,
		0x2F5B9B81670111A3ULL,
		0x6423843792E98349ULL,
		0xED955CB0C75A1FCEULL,
		0xEB0502BDD22ECD54ULL
	}};
	printf("Test Case 583\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 583 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -583;
	} else {
		printf("Test Case 583 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD72911BCA05B6CA6ULL,
		0xFC5868F2D774E146ULL,
		0xDA7B9A040150C039ULL,
		0x696A767C06529AC8ULL,
		0x0748746D1C92C6EEULL,
		0x48365AAFF3F52E26ULL,
		0x1EF0FAC700124F32ULL,
		0xF67050CCA4214C68ULL
	}};
	printf("Test Case 584\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 584 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -584;
	} else {
		printf("Test Case 584 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB6688F3E922D75F0ULL,
		0x2A338FEFEECCA910ULL,
		0xA4E97AEA0A00C038ULL,
		0xFBD6C08D7BD942D2ULL,
		0x6F697F2BA85654F9ULL,
		0x0EB980D95068FF32ULL,
		0xE85696405883D6B6ULL,
		0xF617D501321A0B60ULL
	}};
	printf("Test Case 585\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 585 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -585;
	} else {
		printf("Test Case 585 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x205AC00429A32C5FULL,
		0xFC7ABDEF06DDA1F3ULL,
		0x0A72F8CBB7DBB50BULL,
		0x5A001F4D71C7ADC5ULL,
		0xAA3259EF22CE4B27ULL,
		0x80ABF3A52898FE0AULL,
		0xED232F8FEFB258E5ULL,
		0x0545C55B6B1F8FAAULL
	}};
	printf("Test Case 586\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 586 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -586;
	} else {
		printf("Test Case 586 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5BC32A5C50D5B2AAULL,
		0xB898AC38297439E5ULL,
		0x2DC38E5B41F21C2CULL,
		0xA8456CB18CAFA977ULL,
		0x379CB3882D223ECDULL,
		0xCC143662AE99E9F5ULL,
		0x9B6F1363F903F5BAULL,
		0xF5E1C3071C0DD21BULL
	}};
	printf("Test Case 587\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 587 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -587;
	} else {
		printf("Test Case 587 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3557D7954069F06BULL,
		0x480C3B37EAE38BDCULL,
		0xC1D333B74C7BBA38ULL,
		0x09513A7E085B89E5ULL,
		0x92D1C26CBEB765DAULL,
		0x5B123DDDE5971CDAULL,
		0x43337D5AFD44F219ULL,
		0x4A3C84ACE95CFBFBULL
	}};
	printf("Test Case 588\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 588 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -588;
	} else {
		printf("Test Case 588 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8CD16FAE382627D1ULL,
		0xFA34DE87D3DDC374ULL,
		0x59B97CB353F08F8EULL,
		0xC5017B0E21C43BE4ULL,
		0x0E847C6760866754ULL,
		0xF5B021787D345ED0ULL,
		0x39851D0B299FD8EAULL,
		0xB815F4F31CD689E2ULL
	}};
	printf("Test Case 589\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 589 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -589;
	} else {
		printf("Test Case 589 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB24BD1C24A47D04ULL,
		0x51FB5078BA1B4CCEULL,
		0x025ADE81E4149943ULL,
		0x462CFE2C1A1EB119ULL,
		0x2907357EFB0D11CDULL,
		0x951E44E7D397D263ULL,
		0x90831EFF93740ED9ULL,
		0xEB08F894741DA339ULL
	}};
	printf("Test Case 590\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 590 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -590;
	} else {
		printf("Test Case 590 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2249918766C7294CULL,
		0x3BE2155F66DEB9F6ULL,
		0xAAF47811C1DE30CCULL,
		0x2EA834F6B99330D9ULL,
		0xEECA47682D13E1E4ULL,
		0xC80D71BA7BF5ACD5ULL,
		0xE991C5D725C9A6C7ULL,
		0xA579CFF051DC1D0CULL
	}};
	printf("Test Case 591\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 591 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -591;
	} else {
		printf("Test Case 591 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF262E848913EDC4BULL,
		0xC24F5D53B0DFD2B6ULL,
		0x886D0542BDA63DFDULL,
		0x727F3FC94E114738ULL,
		0xEA15C31899803A58ULL,
		0xC9630CBEEB25400CULL,
		0xD78B5BD119FCA279ULL,
		0xAC9EF4C40E305282ULL
	}};
	printf("Test Case 592\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 592 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -592;
	} else {
		printf("Test Case 592 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA979F40CDE40F125ULL,
		0x2C6D9F99D1774E86ULL,
		0x57E64657DCDA3A35ULL,
		0x278F6966FB51F0F9ULL,
		0x4D778018FDF27315ULL,
		0xBBDD13B22E04FF77ULL,
		0x33883317320A29A5ULL,
		0x9894A35E733C7B78ULL
	}};
	printf("Test Case 593\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 593 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -593;
	} else {
		printf("Test Case 593 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x700FCCAF02867198ULL,
		0xA7A574025A076B9FULL,
		0xF84721F13E7A3063ULL,
		0xEFC0B1C2EA9687BAULL,
		0x54BBB526716EDEDAULL,
		0x093E3FC81190A9A1ULL,
		0x07A8FFE0CA03DA16ULL,
		0x3D5E7489A51F34BFULL
	}};
	printf("Test Case 594\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 594 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -594;
	} else {
		printf("Test Case 594 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x61911FBD1C567BDFULL,
		0x46C8F784D5CF72B0ULL,
		0xF028EA49461FD9ECULL,
		0x1A5E11B7B864CBA3ULL,
		0x682681223CDC1386ULL,
		0x328C7846EEE347F6ULL,
		0x763497815895EF56ULL,
		0x2A88A79FDB91A220ULL
	}};
	printf("Test Case 595\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 595 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -595;
	} else {
		printf("Test Case 595 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x72B09AC30051F097ULL,
		0x90F307CA4A745DE5ULL,
		0xBF7DF574E0620794ULL,
		0x776519F0B73D6456ULL,
		0x3BC8E22AA24CB411ULL,
		0x23F6258F693CC398ULL,
		0xB085F525F1AB898DULL,
		0x394823C771A57D45ULL
	}};
	printf("Test Case 596\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 596 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -596;
	} else {
		printf("Test Case 596 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF91622C2492994C5ULL,
		0x46B9F32FFEF171DDULL,
		0xFC9D52800F905D60ULL,
		0x1D16C43D64E0012AULL,
		0xDC3DE0A86B77CCD7ULL,
		0x203171F9788DFF3FULL,
		0x99DBB6774ED37879ULL,
		0x5583CD6F15FB594CULL
	}};
	printf("Test Case 597\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 597 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -597;
	} else {
		printf("Test Case 597 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x206AE4AA5B60D0B9ULL,
		0x69839A4D659CD254ULL,
		0xC62E8E228038BE1BULL,
		0x6CC25FC9B364DA42ULL,
		0x863397BF21465CFAULL,
		0x0C11B39721D0FAF1ULL,
		0x6081276E5962FADEULL,
		0x8055A1156887B0FEULL
	}};
	printf("Test Case 598\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 598 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -598;
	} else {
		printf("Test Case 598 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCDAF19F710C7543CULL,
		0x7955BA222168078EULL,
		0x62F59E9E1CEE55A7ULL,
		0xE3999E878F3A8E24ULL,
		0x242A9140A0F71D6AULL,
		0x6CB754671415A62DULL,
		0xBC7907CD53246E30ULL,
		0x7D6F48AD5B876871ULL
	}};
	printf("Test Case 599\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 599 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -599;
	} else {
		printf("Test Case 599 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD4FFE91C1C06E7DFULL,
		0x15EFA3FA2CCFC1BBULL,
		0x1DE30BF1808723EDULL,
		0x3F13EA594400C75EULL,
		0xE805BB2EC5C27F7BULL,
		0xA2BED62EE480A451ULL,
		0x96CB4EB406F7595AULL,
		0x3D9BFC929ADDF296ULL
	}};
	printf("Test Case 600\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 600 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -600;
	} else {
		printf("Test Case 600 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6CBEAED8098F3927ULL,
		0xDA37DCAE605CB520ULL,
		0xBDB8C5BED90577C4ULL,
		0xBA65804BFD842031ULL,
		0xD741F59EA42EB006ULL,
		0xE455CE86E5A02ACEULL,
		0x51A2D2559D2C72FCULL,
		0xEC36334F760D549AULL
	}};
	printf("Test Case 601\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 601 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -601;
	} else {
		printf("Test Case 601 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x164856823C791C95ULL,
		0x40A64053356FD044ULL,
		0x5D0C52B4C77522B1ULL,
		0x1114D2241340935CULL,
		0xBA43353CE91330AAULL,
		0x2ECC205B4DAD710DULL,
		0x0B87ADD13A2DD4D5ULL,
		0x10BD794E8BBA8BB2ULL
	}};
	printf("Test Case 602\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 602 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -602;
	} else {
		printf("Test Case 602 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2A7D695F1988E298ULL,
		0xEF02C01525550D65ULL,
		0x0C1413E8074F882BULL,
		0x5BB5B86B5F276122ULL,
		0xEEB13DBD3E8EA3A0ULL,
		0xE3D293CD44E0ECD9ULL,
		0x91D9232CFEC13C49ULL,
		0x4164A9CB19234518ULL
	}};
	printf("Test Case 603\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 603 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -603;
	} else {
		printf("Test Case 603 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x53A655A9F7310842ULL,
		0x65855845FE4BBE22ULL,
		0x3826463C2B119768ULL,
		0x2A56F53A2CAC5488ULL,
		0x4CF22D777D0ECDCEULL,
		0x509ABF767ACC82BFULL,
		0xD205A5ED10562222ULL,
		0x5B1847F1E5B588F9ULL
	}};
	printf("Test Case 604\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 604 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -604;
	} else {
		printf("Test Case 604 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9FDC564E5FC41AAEULL,
		0xBCE7CE82E524BB38ULL,
		0xB4D2A6DD9C113DCFULL,
		0xB9BF7474E48D24AFULL,
		0x8478C54DBA2924A8ULL,
		0x0687F3461E3BF2DFULL,
		0xEC97008C20DD39E8ULL,
		0xEE6BDC607E7A6FF8ULL
	}};
	printf("Test Case 605\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 605 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -605;
	} else {
		printf("Test Case 605 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x56266718A58C7317ULL,
		0x219ACDB04027DFF8ULL,
		0xA9EEE3647E08FAFBULL,
		0x2C9D3459F0637638ULL,
		0x8FD5255D1AF34C45ULL,
		0xD598FB0E7556E51BULL,
		0x07033AAFCF07CE0DULL,
		0x6A95CB656572A0A2ULL
	}};
	printf("Test Case 606\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 606 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -606;
	} else {
		printf("Test Case 606 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1E6F89A8FDD28267ULL,
		0x0B288F25E176016AULL,
		0xD34286552311E9EBULL,
		0x158369DAC2CD8D45ULL,
		0xC0A41F28DDCCEEB7ULL,
		0x4B129B96E6402108ULL,
		0x8BFA7B46AD9F8ECCULL,
		0xD5A2A83F5BEB3D21ULL
	}};
	printf("Test Case 607\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 607 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -607;
	} else {
		printf("Test Case 607 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB6984736730C2FC8ULL,
		0x3B12BB904A744AC2ULL,
		0x87FF7638C44F8A88ULL,
		0xC1102F9E7AECCDF0ULL,
		0x2B2B6F9DB88F14ABULL,
		0x11F76AA20B9CEF1AULL,
		0x09200372AC89E62BULL,
		0x496B0FBDF09EA992ULL
	}};
	printf("Test Case 608\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 608 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -608;
	} else {
		printf("Test Case 608 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8FB3EFF68F39F117ULL,
		0xC344B78C42F87D5CULL,
		0x285DDF3F073B4355ULL,
		0x988B8F5D1877D03DULL,
		0x2122B65A379F7D55ULL,
		0x0C9461BD034A9BEBULL,
		0x3880B1CEECD3EB64ULL,
		0x2053C84A5F324F50ULL
	}};
	printf("Test Case 609\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 609 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -609;
	} else {
		printf("Test Case 609 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x69FD1DD81B9654ADULL,
		0x20EEE4D3FA95210FULL,
		0xD6AFBD5FCA474AAFULL,
		0x06A49CA982E2DF1FULL,
		0x6A4E624DAEEBA25DULL,
		0x2B10522A251C2A4DULL,
		0x0A6E353B390DDD18ULL,
		0x829F5059C8D3B3C7ULL
	}};
	printf("Test Case 610\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 610 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -610;
	} else {
		printf("Test Case 610 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6D5F8B6230EFD684ULL,
		0x8B57136A67C70F38ULL,
		0x7BFAFADB0DAED4CCULL,
		0x5B5B0323BE207036ULL,
		0xA10576C46802EAE6ULL,
		0x19041C23B3F44188ULL,
		0x6870436BC96EB925ULL,
		0xCA2C6D9AE5974F6EULL
	}};
	printf("Test Case 611\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 611 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -611;
	} else {
		printf("Test Case 611 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x594D7293A74777C0ULL,
		0xB200FD7DC19D5C0FULL,
		0x5220D15475F9D5E5ULL,
		0x597440BFCEE94B9BULL,
		0x04F1A95A696D994EULL,
		0x37A4FDC00FE5102FULL,
		0xA53C320A2430DF0BULL,
		0xCBEF2879E99C88F6ULL
	}};
	printf("Test Case 612\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 612 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -612;
	} else {
		printf("Test Case 612 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5AD40ED6B3835B09ULL,
		0x6575155EA251CE74ULL,
		0xBCA08B54B48EE776ULL,
		0x412B1906B8EDDF1EULL,
		0x13F2B8DAFA92BD16ULL,
		0xDB7450A92FAF9F07ULL,
		0x9E5162444B859FBDULL,
		0x30A5DDEF9F496748ULL
	}};
	printf("Test Case 613\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 613 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -613;
	} else {
		printf("Test Case 613 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF9771A49ACC4DC1BULL,
		0x9A03D32A74FD0731ULL,
		0x9BA506794362C6D2ULL,
		0x06A73CF5DDAB68D1ULL,
		0xDEF52144AB93926CULL,
		0xC58F9911A28CB2E9ULL,
		0x26043044DCD9B3CBULL,
		0xCDE3B6E5032D3122ULL
	}};
	printf("Test Case 614\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 614 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -614;
	} else {
		printf("Test Case 614 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x95ACD5FFFB35D2F9ULL,
		0x013E62C4CD9782C7ULL,
		0xE50C29E868778313ULL,
		0xEFF114949F7EB530ULL,
		0x69F3D0564DFF9152ULL,
		0xBE4048B486D851E4ULL,
		0x049E50561290A582ULL,
		0xC3ED17E0E1595D0AULL
	}};
	printf("Test Case 615\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 615 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -615;
	} else {
		printf("Test Case 615 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x66EDF26C9833232FULL,
		0x41D790C936A1181DULL,
		0x526504502A9B707DULL,
		0xD826F080E2AE555CULL,
		0xA3826EDDEB0C1890ULL,
		0x901F8285254FDDF0ULL,
		0xCDC8ABA3567F0949ULL,
		0xC47DF129652AB2A0ULL
	}};
	printf("Test Case 616\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 616 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -616;
	} else {
		printf("Test Case 616 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB3552CDA673E6C0AULL,
		0x2C015A9EEE3AECF6ULL,
		0x3620382310B064C3ULL,
		0x49A390B014E9ED9DULL,
		0xD5FF292905D13BABULL,
		0xF0577575E98CC75CULL,
		0x319701326ECD9009ULL,
		0xE83F05D04F9D4787ULL
	}};
	printf("Test Case 617\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 617 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -617;
	} else {
		printf("Test Case 617 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x8F98D3008E15C506ULL,
		0x00E4D4F2C714A1D4ULL,
		0x57CD05FEFCB0EAA5ULL,
		0x7CCA39D71ECA5C88ULL,
		0xE72D8B1C73B11DC5ULL,
		0xFABA34F02630254CULL,
		0xA636534AF4DF6A94ULL,
		0x17D74EA805FCD695ULL
	}};
	printf("Test Case 618\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 618 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -618;
	} else {
		printf("Test Case 618 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x68223FF4CA966509ULL,
		0x4A9FBCC3CE8284BBULL,
		0x79D6AB77CD3BD1A6ULL,
		0xDBB96C9CE003F137ULL,
		0x48C0E7798BDA946DULL,
		0x0BF6BCCF095158A8ULL,
		0x243C8F939976413CULL,
		0xDE1C2C5AC42D63C1ULL
	}};
	printf("Test Case 619\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 619 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -619;
	} else {
		printf("Test Case 619 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8D47A2F0A638058EULL,
		0xFE9F0B0B8B1BA300ULL,
		0x1B61B390CD7ED8DBULL,
		0x35DAB02664926CE5ULL,
		0xE05AD9AF5DD9480FULL,
		0xBAA9BA144D417A5EULL,
		0x95E03F38FF038B2BULL,
		0x47F8CC34555F664BULL
	}};
	printf("Test Case 620\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 620 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -620;
	} else {
		printf("Test Case 620 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2B774927E6DCB4CEULL,
		0x9445B327FA48BA13ULL,
		0xD4E6911F392B2A02ULL,
		0xAB2967458DECC167ULL,
		0x17B5DCC2D2855328ULL,
		0xA1A0701C40F6832CULL,
		0x98793E4A9297188AULL,
		0xA1A22D45F72AAE01ULL
	}};
	printf("Test Case 621\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 621 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -621;
	} else {
		printf("Test Case 621 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x66816D83F2BFEC6EULL,
		0x788D0BBCE2E54C6FULL,
		0x97A46C69525AF111ULL,
		0x389D094D1839A176ULL,
		0xEF4BB2E94AA7B885ULL,
		0x47A4386D55F6A9F8ULL,
		0x3FC31E6B7AD49D48ULL,
		0xEE0878D3D9E50CD1ULL
	}};
	printf("Test Case 622\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 622 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -622;
	} else {
		printf("Test Case 622 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x35E72308A0F1A6BDULL,
		0x44B89A814D6E5C4EULL,
		0xB9765B1190CFCFADULL,
		0x1E25803E3A2AB644ULL,
		0x177E9B1B2C1B7C78ULL,
		0x3CD6C0D53E7AAA30ULL,
		0xE7424859B2AB458CULL,
		0xA31EF9A310BA041EULL
	}};
	printf("Test Case 623\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 623 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -623;
	} else {
		printf("Test Case 623 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x558BD9262BA5CD55ULL,
		0x610DD21E252DA62DULL,
		0x406AA8A241ADCA24ULL,
		0xB5508655DEB3B878ULL,
		0x82E4E28A49B0E1E9ULL,
		0x7EF886DBD11AC074ULL,
		0xBE77A3AD724DD26EULL,
		0x1B9EBE2E9C98AA8AULL
	}};
	printf("Test Case 624\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 624 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -624;
	} else {
		printf("Test Case 624 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x220B9D1ADBB561C4ULL,
		0xA7852260C8B9CAA1ULL,
		0x74B1BE3F571E1850ULL,
		0xED6CA83664EBA86AULL,
		0xF55511FDE4BC4932ULL,
		0xDCCC43587ADFA345ULL,
		0x52551F5F497DD779ULL,
		0x51D69CCD254124FEULL
	}};
	printf("Test Case 625\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 625 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -625;
	} else {
		printf("Test Case 625 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xDF113413B3B51785ULL,
		0xD8307A35530D0F5DULL,
		0x30FA65313C54C180ULL,
		0x99C1B569310256EDULL,
		0xBF5657548E95808EULL,
		0xBD223520EAB0C274ULL,
		0xF7DF80ADA1F276C6ULL,
		0x02281AF5F5ACDAF4ULL
	}};
	printf("Test Case 626\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 626 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -626;
	} else {
		printf("Test Case 626 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD6D3D3DEDF8A248EULL,
		0xA855C0EFBB79B88FULL,
		0x09BA7DB72C4A1719ULL,
		0x731A4E68799F86F1ULL,
		0x36CB2388A6C44AA1ULL,
		0x290ABF54063C790FULL,
		0xAB08B7F85984790CULL,
		0xA428C4BA478DC10FULL
	}};
	printf("Test Case 627\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 627 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -627;
	} else {
		printf("Test Case 627 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x31682288F0C02E64ULL,
		0x7E52F98791CF8530ULL,
		0x37AD9E26EB036BB3ULL,
		0x85AEB59BDE47A3D5ULL,
		0x41042A747A847052ULL,
		0xBFCD7F7DC7E7D2E6ULL,
		0x6620D169EE77FC51ULL,
		0x281D48E553CA6C7BULL
	}};
	printf("Test Case 628\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 628 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -628;
	} else {
		printf("Test Case 628 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4DB883A38B0EDEE5ULL,
		0x4856BF82D958C501ULL,
		0x44D24B906DF97468ULL,
		0x44258B4934EC84EAULL,
		0x45E3841D5E50F560ULL,
		0x1846903EB2498E63ULL,
		0x4F2E644FCBC2A53CULL,
		0x1DC1F621D7B92661ULL
	}};
	printf("Test Case 629\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 629 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -629;
	} else {
		printf("Test Case 629 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC586345DDC121AF6ULL,
		0xC4A7EDDE3FF76CF5ULL,
		0x4650537627B6E26CULL,
		0xF3989B6D0A1B1DDDULL,
		0xF9E357D20979CD33ULL,
		0xD2EF8C72DA141D90ULL,
		0xC8684B8D868301CDULL,
		0xFCC48BAC9FEA5BAFULL
	}};
	printf("Test Case 630\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 630 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -630;
	} else {
		printf("Test Case 630 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x25DF5D9D6C7DDDA6ULL,
		0xD6CFB975ED6FE8C4ULL,
		0xB488A84D077FE63CULL,
		0x64E1AE821A644665ULL,
		0xDDD7A6B990AA7D46ULL,
		0xECD187211276F5FFULL,
		0x9DC5B34925FC8EF0ULL,
		0x6B6F2A32765DB68FULL
	}};
	printf("Test Case 631\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 631 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -631;
	} else {
		printf("Test Case 631 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB2D0D179AA55DC6BULL,
		0x29355FC67F59CAC8ULL,
		0xC600BA8E108AB493ULL,
		0x365413219C9242EDULL,
		0x3012C58C4AC7BA5EULL,
		0xB8FA810D2BA016A6ULL,
		0xF0D36EEFB1590972ULL,
		0x7587CB57E413D86EULL
	}};
	printf("Test Case 632\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 632 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -632;
	} else {
		printf("Test Case 632 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEFB7C24166277751ULL,
		0xB1043953D7E05DD9ULL,
		0xD63EB9DB822C27CEULL,
		0xD88B6083A819CDFBULL,
		0x27571209DC2B520CULL,
		0x211C6F179D52F76CULL,
		0x6668B19AADF974FBULL,
		0x7E28A347D821151CULL
	}};
	printf("Test Case 633\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 633 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -633;
	} else {
		printf("Test Case 633 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2BAD7E49AFD07AC4ULL,
		0xD8D5C6C0C99A8269ULL,
		0x2F6D9440D3A43BE0ULL,
		0x5736FC51FEAF9DDEULL,
		0x1138DE288A80B2BDULL,
		0x47FDCEFFAFADB589ULL,
		0x440F562660FC68C9ULL,
		0x1BE49FDA05DAAE16ULL
	}};
	printf("Test Case 634\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 634 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -634;
	} else {
		printf("Test Case 634 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x597B1EFE995693ABULL,
		0xC6C917446B7C2B6EULL,
		0xFA7F8FDBE39B9E89ULL,
		0xD2C0AB70BDEF1319ULL,
		0xA9BA2410679B2AE5ULL,
		0x1891E29E0E1C0431ULL,
		0xC63D5B084353B130ULL,
		0xE542C7F8D0233FF6ULL
	}};
	printf("Test Case 635\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 635 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -635;
	} else {
		printf("Test Case 635 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7DCFC681C886F0BFULL,
		0x725CC2140CEEF716ULL,
		0x85DB5D298A237CF1ULL,
		0x1F8EDCA8CEBA1B8DULL,
		0xDC4225E6DEEBDC29ULL,
		0x9D7569D7312D3FD2ULL,
		0x1ED519A933166DBEULL,
		0x5944CEDC7B8EFAA0ULL
	}};
	printf("Test Case 636\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 636 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -636;
	} else {
		printf("Test Case 636 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x994515A0CAE7AC33ULL,
		0xA7D2CD3F63EF67B5ULL,
		0xF217D95417EDE957ULL,
		0x2E0317C2D1FA54A4ULL,
		0x4A4407148A04755DULL,
		0x27F6FC0900615B26ULL,
		0xE3698892FBE2BB52ULL,
		0xFC41DF70B34BB6FBULL
	}};
	printf("Test Case 637\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 637 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -637;
	} else {
		printf("Test Case 637 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD3A6937ADC22F6CFULL,
		0x7777D62F8AC91C2DULL,
		0x9262A58B77893A77ULL,
		0xA00B1D26AE66DFFDULL,
		0xFE9929E620023954ULL,
		0x5D8310900046897CULL,
		0x34776267DDB675F7ULL,
		0xC41C6F5CB9A26176ULL
	}};
	printf("Test Case 638\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 638 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -638;
	} else {
		printf("Test Case 638 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE7EAA45B287595B5ULL,
		0x59D864F0E07E869FULL,
		0xB7C4ABD12C58188AULL,
		0x8BAAFDF1D39188EBULL,
		0xB99DADCF5C5DC81AULL,
		0x7B34DB63CA3E0BABULL,
		0x7499628455EBCDD1ULL,
		0x93A6F8245C1332DCULL
	}};
	printf("Test Case 639\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 639 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -639;
	} else {
		printf("Test Case 639 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD18FF7DF95CF2982ULL,
		0x7E06C56B662F4CE2ULL,
		0x7B5E8BA8C4CB738DULL,
		0x4FF0F0AF39CB74EBULL,
		0x4934FDFAE8B477CCULL,
		0xE576FD6DA828D353ULL,
		0x24B8313AB8BDCDB9ULL,
		0x20394AF8B964F5D9ULL
	}};
	printf("Test Case 640\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 640 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -640;
	} else {
		printf("Test Case 640 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB6639401A4702C87ULL,
		0x3EA6193AB8A700EBULL,
		0x15C0B9E79328BD9BULL,
		0x4630B17087604D1BULL,
		0xCE1803A30AB74CEBULL,
		0x5E32597A3BD9E4E5ULL,
		0x5DD9BB11653979A5ULL,
		0x6C9BEFFFD3564733ULL
	}};
	printf("Test Case 641\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 641 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -641;
	} else {
		printf("Test Case 641 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7EB4941009165E9FULL,
		0x22667778C8A92279ULL,
		0x3EAC0D5DEB430534ULL,
		0x7AB6391F8BD33224ULL,
		0x0D25B1BDFC76DED1ULL,
		0x525F7291766E65FEULL,
		0x31E21ACF0A333ADDULL,
		0x9409CCC04DBEAEE1ULL
	}};
	printf("Test Case 642\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 642 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -642;
	} else {
		printf("Test Case 642 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0E73D7CD7663A5D9ULL,
		0x2A955155ADCE8003ULL,
		0x93E365F7012499DEULL,
		0x17E702E920A693A9ULL,
		0x9CA1E1FF8EE683B1ULL,
		0xCFAEEFC477595377ULL,
		0xC311FAB640C014E3ULL,
		0xA1E01992FF1839FBULL
	}};
	printf("Test Case 643\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 643 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -643;
	} else {
		printf("Test Case 643 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1280BF1E026BD6CBULL,
		0x36EF68A541F9887BULL,
		0x3C8283EE316D14D3ULL,
		0x4177A3044BBE47D5ULL,
		0x4D3557B78400250BULL,
		0x05EDD67035024A78ULL,
		0x9D67F8B6CC955A52ULL,
		0xF6C5F8AF12163331ULL
	}};
	printf("Test Case 644\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 644 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -644;
	} else {
		printf("Test Case 644 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x29F018D8EAC77E2EULL,
		0xDECA2ABEFA5B4829ULL,
		0x12CC7A3CEE58BB7AULL,
		0x16B05B735F518C64ULL,
		0x273C2494B15A026DULL,
		0x94A2F3A26C8806E5ULL,
		0xB8872B757A8D6B18ULL,
		0x9C7C4F908C0CD2BFULL
	}};
	printf("Test Case 645\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 645 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -645;
	} else {
		printf("Test Case 645 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC2A63FA3FA93940CULL,
		0x3E2BB56A2C2FF19CULL,
		0x04F7A211AF6F5B5DULL,
		0x38F876242F1AC490ULL,
		0xD51BAD8A0A40FE5EULL,
		0x20C03ACA82A4FB7DULL,
		0x22B3D5CFFBD662E8ULL,
		0xDE10BEAC3BDC9AAFULL
	}};
	printf("Test Case 646\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 646 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -646;
	} else {
		printf("Test Case 646 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x32F1217062B15B3FULL,
		0xEBC6CD2408A3DBB4ULL,
		0x46FE60FB6B2ECC0DULL,
		0x03D9BAF769FA7401ULL,
		0xF45F241D4DF18D0AULL,
		0x7C45FCD30787F5EFULL,
		0x5098C384028B5763ULL,
		0x6171BAF5AE429BF3ULL
	}};
	printf("Test Case 647\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 647 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -647;
	} else {
		printf("Test Case 647 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x32A0B4844DD08CB0ULL,
		0xEDB9CFD3E5BFB34CULL,
		0x3E8689F7232C0BB4ULL,
		0x7F18515FF6676413ULL,
		0x752B4BAA8885337AULL,
		0xCACA8BCEE5C710E8ULL,
		0x049B960A7D2BE35BULL,
		0x37A7443BA2B6D74BULL
	}};
	printf("Test Case 648\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 648 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -648;
	} else {
		printf("Test Case 648 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x49EA5A4FAF0F73BCULL,
		0x37A20989A08E2A3DULL,
		0x57D61257ACBBDAF4ULL,
		0x192D3D17192EFB74ULL,
		0x85294C2DA220456AULL,
		0xFBE645DECB2BB8FDULL,
		0x3C2E41CD473D6C61ULL,
		0x0EF342C767ACADE7ULL
	}};
	printf("Test Case 649\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 649 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -649;
	} else {
		printf("Test Case 649 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xD7F7706EA527A694ULL,
		0x2D88EBEFF49BC3D8ULL,
		0xF5998B1448939084ULL,
		0x447CDBDC89CBFE02ULL,
		0xCDD885E62DF50C69ULL,
		0xC1B3C3C0A5D132C7ULL,
		0xE7B944FBF9AAA8AEULL,
		0x1AAC39D1CE6D36D9ULL
	}};
	printf("Test Case 650\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 650 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -650;
	} else {
		printf("Test Case 650 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x74C5820FA553B528ULL,
		0xA04D56142B59E7E5ULL,
		0x310E3214E1CFC925ULL,
		0xD26E7CFD1608F2B8ULL,
		0xBF7DB36E270421A3ULL,
		0x30E2C46E53668D86ULL,
		0x2BAB0CDCF0C95555ULL,
		0x479B77F8FC64B265ULL
	}};
	printf("Test Case 651\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 651 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -651;
	} else {
		printf("Test Case 651 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF0636D41E8CE6BC3ULL,
		0xDEC2A61DA436BAE5ULL,
		0x7D9EB02AC8DBDA9BULL,
		0x848BFEA787FEEAE2ULL,
		0x5DBFC534C670E71CULL,
		0x147872ADF63BF3D9ULL,
		0xDA8E3B03CF9DF34FULL,
		0x993B8288140F4ED9ULL
	}};
	printf("Test Case 652\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 652 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -652;
	} else {
		printf("Test Case 652 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x129FC73E29DE274EULL,
		0x34A32C4C9A423FD7ULL,
		0x14CA8DE68F93DF44ULL,
		0x2703E61885934D05ULL,
		0xF12A08A92C05CF54ULL,
		0xC7ABE4909114E6AEULL,
		0x7988E7F2262312CBULL,
		0x0ED1F54C44DF865EULL
	}};
	printf("Test Case 653\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 653 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -653;
	} else {
		printf("Test Case 653 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3D9F4FA70FDDF456ULL,
		0x9217A5731DC9EA3AULL,
		0x1DCED7E4B161EF71ULL,
		0xB28D864A7BFC0BA1ULL,
		0x426493E0CD5D4BBDULL,
		0x8F957717405E5C9FULL,
		0x4306DB7F48687C1CULL,
		0x28EBD6B4BCDC1C4AULL
	}};
	printf("Test Case 654\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 654 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -654;
	} else {
		printf("Test Case 654 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1019181C279191DBULL,
		0x095C7B284447BEB9ULL,
		0x119894D6EBE6CE0DULL,
		0x99654FA85225611EULL,
		0x7C80443BAF134C44ULL,
		0x91E0049CAF78ADAAULL,
		0xB99EE901A7F241F1ULL,
		0x371F068E05EE775FULL
	}};
	printf("Test Case 655\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 655 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -655;
	} else {
		printf("Test Case 655 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x5DF75327502A19AAULL,
		0x823F55E22161E487ULL,
		0x1F86EA211CC4DE99ULL,
		0x29C4BD3A23B45729ULL,
		0xC27A3311CA9CABFAULL,
		0x96D9B86EEC0FE001ULL,
		0x0EB0C9F9FF397E51ULL,
		0x0461CAC86F3062ACULL
	}};
	printf("Test Case 656\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 656 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -656;
	} else {
		printf("Test Case 656 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x559F11E88EF0A1B1ULL,
		0xEF23A90DF0BC7A01ULL,
		0xC275FAF035847076ULL,
		0x6573BD566AC69E3AULL,
		0x668CA443F730B068ULL,
		0x3DEE992B5CEAD5CCULL,
		0xCBE76F2DF3D603C8ULL,
		0xFBB5ADA1D55DECDFULL
	}};
	printf("Test Case 657\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 657 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -657;
	} else {
		printf("Test Case 657 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8B3ACEF7BC2A5FCFULL,
		0x1BE1CC947A9B3437ULL,
		0x041F1059AF1C5F31ULL,
		0x41DB823A38F20FD2ULL,
		0x6FA60BE4BBCAA8D8ULL,
		0xEB3B7535DE6AD75AULL,
		0xA5EB22EEB1A9DB97ULL,
		0x6A14B0BBAF537138ULL
	}};
	printf("Test Case 658\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 658 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -658;
	} else {
		printf("Test Case 658 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x17D5566BC6DBB380ULL,
		0x0C6C860F2DACA86AULL,
		0xEEA227B7EDF77634ULL,
		0xD62DB3D2B3813B44ULL,
		0x95A24BDF27E29EA2ULL,
		0x1F1BEB4860267440ULL,
		0x922D108B32C63CCAULL,
		0xC842A81E318B11C4ULL
	}};
	printf("Test Case 659\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 659 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -659;
	} else {
		printf("Test Case 659 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x49B7749895D0FD5DULL,
		0xA18600ED7BA465B4ULL,
		0x187B5DCEC9ABB3BAULL,
		0xEA1DB985375B8578ULL,
		0xFADDDC293A4E28E8ULL,
		0x0AD849AF4DA08F01ULL,
		0xC4F9F3CF0628006CULL,
		0x8F1187F969179620ULL
	}};
	printf("Test Case 660\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 660 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -660;
	} else {
		printf("Test Case 660 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9BC33D43F32CA630ULL,
		0x8FD2862DD43B7329ULL,
		0xE3936EC499014F4CULL,
		0x7F41C0491BC82A12ULL,
		0xCD82021DF93A321EULL,
		0xA2097F035C38D8CDULL,
		0xDCD0A32770C51C7FULL,
		0xD7F9A53F0DD26017ULL
	}};
	printf("Test Case 661\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 661 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -661;
	} else {
		printf("Test Case 661 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD6E51259A46A8089ULL,
		0xC6E7EB7B09F97989ULL,
		0x6871FDD8361D0B44ULL,
		0x84F4C47D13E67E5FULL,
		0xC48353FDC33D1DB2ULL,
		0x929C1DA6A166AC79ULL,
		0x2B1E2F4687ADDAC6ULL,
		0x726BBB1C20FC80F1ULL
	}};
	printf("Test Case 662\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 662 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -662;
	} else {
		printf("Test Case 662 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2ADCAE2B0B7AB799ULL,
		0x56BA9136DE06AE3DULL,
		0xB4409DE41FDEEAD7ULL,
		0x627AD1C6AAA7CE41ULL,
		0x295781F397C86F89ULL,
		0x041196D8A7F5F21AULL,
		0xB57C88BE0EB4A4D2ULL,
		0xE070532F1934E407ULL
	}};
	printf("Test Case 663\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 663 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -663;
	} else {
		printf("Test Case 663 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7134808F20283D49ULL,
		0x44D008AB578C4451ULL,
		0xCAD595AA3D4C2AC0ULL,
		0x1E574D32A50FF938ULL,
		0xEAE591F9FA96E3CAULL,
		0xD2AD4DE5E85AF220ULL,
		0x23953948B71FBB7BULL,
		0xFBEDB8C2D6517B2DULL
	}};
	printf("Test Case 664\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 664 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -664;
	} else {
		printf("Test Case 664 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD094D928B65C84A9ULL,
		0xED66C52FA6BA1C88ULL,
		0xC9FC2E13B8E43109ULL,
		0xF262A1D2DD99E4ADULL,
		0xE35E8781741F1F50ULL,
		0xDF8CC915FAE2B6A3ULL,
		0x41EDBF2B777C0B43ULL,
		0x748524F03DA1F7C1ULL
	}};
	printf("Test Case 665\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 665 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -665;
	} else {
		printf("Test Case 665 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBEC5CEF7DA527A3ULL,
		0x50AEBE57FC6045B2ULL,
		0x8E2659AA6897F599ULL,
		0x8E326BE09E3963BDULL,
		0x48C2C56DBC3D1BDFULL,
		0x9DB9BF183EEBCF34ULL,
		0x6163D230D6C230BFULL,
		0xD16F3D90E9625733ULL
	}};
	printf("Test Case 666\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 666 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -666;
	} else {
		printf("Test Case 666 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEF10D07FF9DBC576ULL,
		0x9C0C0B0A2CFEF830ULL,
		0x105713397148476DULL,
		0x0838005ED17FB60AULL,
		0x0885FA0FFA57861BULL,
		0x67B74F5E68847C3EULL,
		0xA04BD6FDF7B7A077ULL,
		0xC3C8896B605281D6ULL
	}};
	printf("Test Case 667\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 667 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -667;
	} else {
		printf("Test Case 667 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCA1EA985C6559123ULL,
		0x507E11B58035C5FEULL,
		0x6BB1E70CF0CAADE9ULL,
		0x8A44ADC204B088B3ULL,
		0x5E4B1ABDC38E5386ULL,
		0x832D62C76A5FD2A9ULL,
		0x1EEB8335F6C53143ULL,
		0x539F1098A551F14EULL
	}};
	printf("Test Case 668\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 668 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -668;
	} else {
		printf("Test Case 668 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x35281AFAC540B570ULL,
		0xE64F41653AF8F4C2ULL,
		0xEB9C6E22ED513EBFULL,
		0x39E6B1324BD8788CULL,
		0x513811132D1492E9ULL,
		0xD1542FEAB19889B3ULL,
		0x5D954F32E3CB1AE2ULL,
		0xB94F7C0B5918BCE5ULL
	}};
	printf("Test Case 669\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 669 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -669;
	} else {
		printf("Test Case 669 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFB1331A6F19969F5ULL,
		0x58DA65EEA83C03ECULL,
		0x347EFCBE94558F71ULL,
		0xD09D4D701B1BC4F6ULL,
		0xB1E086C41BFC52D9ULL,
		0x44B45F3EF804A749ULL,
		0x6A07500FA42B39D0ULL,
		0x785699751F59CF73ULL
	}};
	printf("Test Case 670\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 670 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -670;
	} else {
		printf("Test Case 670 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4976117BA5C3CC83ULL,
		0x1E31D199B6830C75ULL,
		0x9B45025BE86BEFDBULL,
		0xD32484698CA946FCULL,
		0x4FCA5D973AFEC016ULL,
		0x290A893DBC6F6501ULL,
		0x9D134D877986CB65ULL,
		0x436BAC8B90D854FDULL
	}};
	printf("Test Case 671\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 671 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -671;
	} else {
		printf("Test Case 671 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCB38225F51B7DC6FULL,
		0xECB2EC424273CDD9ULL,
		0x4D82974F16156FDFULL,
		0x7BD0990171147539ULL,
		0x0F78B365049C3DDEULL,
		0xD80D5EABA441DCF4ULL,
		0x1877325783B064E1ULL,
		0xBACA689EBEBBFA3AULL
	}};
	printf("Test Case 672\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 672 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -672;
	} else {
		printf("Test Case 672 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7CF0E95E01C24C7CULL,
		0x8E1BC6746BFC80B2ULL,
		0x6BD180C62325D05AULL,
		0x531DE189CC78A7C4ULL,
		0x50AA017683D29D11ULL,
		0xC2F1A21D91E90DA3ULL,
		0x53697723F8BB4F02ULL,
		0xDCB8202A180C1B95ULL
	}};
	printf("Test Case 673\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 673 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -673;
	} else {
		printf("Test Case 673 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x178E999481BD6D76ULL,
		0x1F73E04B69532EA1ULL,
		0x3399F10A7BB624F3ULL,
		0x6C29B6D25D63D57DULL,
		0x3DBF3CD378FE8A19ULL,
		0xB976A1D4D186BCF7ULL,
		0x1D4E63456D2F981FULL,
		0xDE39A7EE9E6CEE9FULL
	}};
	printf("Test Case 674\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 674 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -674;
	} else {
		printf("Test Case 674 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA5C1F643FC47B8D0ULL,
		0x6CB312ABA265E325ULL,
		0xBAB4545BA17E6D4AULL,
		0x8BA2FAEDBDFF97C3ULL,
		0x7D7AEE32C347520AULL,
		0x2AEA9FDE1A068B94ULL,
		0x48884A4917E7BE8AULL,
		0x68F320FE1DB83DE9ULL
	}};
	printf("Test Case 675\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 675 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -675;
	} else {
		printf("Test Case 675 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x59F69B3949C99690ULL,
		0xCC00908CEB5F1DFAULL,
		0xF0E843204C729254ULL,
		0x61A5950DA0BBB904ULL,
		0xB581B7D950E56D36ULL,
		0x191C016FE082DA9AULL,
		0x50E6A0049A885912ULL,
		0x8565EB57501B107EULL
	}};
	printf("Test Case 676\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 676 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -676;
	} else {
		printf("Test Case 676 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xEFF729BCFD090DCAULL,
		0xC89351E9CB81D956ULL,
		0x3613224311198493ULL,
		0x2F52AB5EEC3E6C05ULL,
		0x2FA807BDC7041A15ULL,
		0xC560ABA7CE98D04FULL,
		0xB764417852BA7435ULL,
		0x010BD5A0F951B265ULL
	}};
	printf("Test Case 677\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 677 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -677;
	} else {
		printf("Test Case 677 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9F066F822503AA31ULL,
		0xD1396DC314F576CDULL,
		0xF037927887692341ULL,
		0x88DE5C2BF3E32E2AULL,
		0xD40465A11894DDA7ULL,
		0x02B939543F139B7DULL,
		0x4B78E94D7BCB62E3ULL,
		0xF35E30532E7AD8BFULL
	}};
	printf("Test Case 678\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 678 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -678;
	} else {
		printf("Test Case 678 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE551705093404CEAULL,
		0x3953DEBCC92CE187ULL,
		0x24E9851091CEFE01ULL,
		0xD81382CD68F2E123ULL,
		0xBBA3F5CF7FAEECD5ULL,
		0x3B934DB17BFA38E5ULL,
		0x6AC54A2380925331ULL,
		0x78B79BF5BF62989CULL
	}};
	printf("Test Case 679\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 679 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -679;
	} else {
		printf("Test Case 679 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3500520872522B48ULL,
		0xDF0737E3FA3208D4ULL,
		0xEEAA67A1B843078FULL,
		0x8F80AFB69C343546ULL,
		0xB0246CBA59A48851ULL,
		0x8FD1BF91ECCC69A4ULL,
		0xE2A9B857C9CADF95ULL,
		0xDBAF2909AC605D42ULL
	}};
	printf("Test Case 680\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 680 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -680;
	} else {
		printf("Test Case 680 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x79F51AB695A932D5ULL,
		0x5756DD6E74E67342ULL,
		0x61A3570F11A40660ULL,
		0x7BF24425E23CBE96ULL,
		0x925476FB7B4738CEULL,
		0xBED03F529459408CULL,
		0xF38865BA680631FDULL,
		0x61ABBCD94AF1C06EULL
	}};
	printf("Test Case 681\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 681 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -681;
	} else {
		printf("Test Case 681 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC01BA07C6FD63B72ULL,
		0x88175EF138A46648ULL,
		0x66FCD18C262653CCULL,
		0x118610F7569E02CCULL,
		0x6E263D062FB400A6ULL,
		0x971D8542FE78F71AULL,
		0x2C51383D5C2236D7ULL,
		0x395CDDCDB6A50FD0ULL
	}};
	printf("Test Case 682\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 682 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -682;
	} else {
		printf("Test Case 682 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAE01CB916DFCAFAFULL,
		0x265BF4BB9EA20191ULL,
		0xABF3B69DB3BA4CB9ULL,
		0x949ED7403648D888ULL,
		0x60C51DD7BBFD318EULL,
		0xBF117F139B7012D2ULL,
		0x7DB1192AE6508AFEULL,
		0x3EC25F66B6D4444CULL
	}};
	printf("Test Case 683\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 683 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -683;
	} else {
		printf("Test Case 683 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x875FE8A2C9544A50ULL,
		0x8FAC0F0EE6A92474ULL,
		0x9A1D7BF56B0E2B26ULL,
		0x6CB15FDC616A8464ULL,
		0xAAAB62F002B69361ULL,
		0x0AC6A08A679BFE3DULL,
		0xAC9872F9022E7D9DULL,
		0xC7F8DC70D1F14FE8ULL
	}};
	printf("Test Case 684\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 684 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -684;
	} else {
		printf("Test Case 684 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF90EDB241009DCC0ULL,
		0x2B9D76D734D16F24ULL,
		0x666EDF2C8F3B6D37ULL,
		0x859F6E080813EC9CULL,
		0xE5FC4443A95BF3BAULL,
		0xBC0D3FAD8438B453ULL,
		0x413AD131A371F0C8ULL,
		0xEEA20BA51EB75D0FULL
	}};
	printf("Test Case 685\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 685 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -685;
	} else {
		printf("Test Case 685 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF006C5049AC77EDDULL,
		0xD77E7277F98279D2ULL,
		0x0ED60146B74981A8ULL,
		0x2B82B201CEFBCCD9ULL,
		0x6C2689F2826768B3ULL,
		0xE961FD0134BA0BBAULL,
		0xE390ADF13FE3695BULL,
		0x30DCA3915D2273BDULL
	}};
	printf("Test Case 686\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 686 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -686;
	} else {
		printf("Test Case 686 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x08963A60B39B98F3ULL,
		0xC49ED41D85039072ULL,
		0x9DBAA42F2856AADCULL,
		0xB1A4DDDE0B3E1178ULL,
		0x1535411BE173E457ULL,
		0xA6E94E17C6DFC547ULL,
		0xA47906B4F14EAB99ULL,
		0x72FBFC6DB7CC6F3BULL
	}};
	printf("Test Case 687\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 687 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -687;
	} else {
		printf("Test Case 687 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4C860A38CE8C8C49ULL,
		0x8EB33791B76ED5E6ULL,
		0x982B01A0DB95C1C3ULL,
		0x49C4661E4A75E8EDULL,
		0xBF01053E004E328CULL,
		0xF40B7E73078E2D21ULL,
		0x2E71D80CE94B1F0DULL,
		0x7AACDA18D3CB6706ULL
	}};
	printf("Test Case 688\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 688 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -688;
	} else {
		printf("Test Case 688 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x64E612C23BD659A3ULL,
		0xF40186D807ECE09DULL,
		0xEB3603491F691F50ULL,
		0x7E1E495150D76813ULL,
		0x8C795ABB124C012DULL,
		0x9D9CEA9738659383ULL,
		0xB8E7A444F1A116CEULL,
		0x9BE94EB7F86D3D0BULL
	}};
	printf("Test Case 689\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 689 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -689;
	} else {
		printf("Test Case 689 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDDE542EE458DCB17ULL,
		0xE04CC493CE0942CAULL,
		0xD92F267B87A68646ULL,
		0x672D417B29E49446ULL,
		0x8E685E96EB5087D6ULL,
		0x77557CE0362BF145ULL,
		0xA79FD0E3A6913D86ULL,
		0x57433E986704A866ULL
	}};
	printf("Test Case 690\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 690 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -690;
	} else {
		printf("Test Case 690 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4007F0C4855B4987ULL,
		0xC1F7FFE3B1123295ULL,
		0x93461AE072832807ULL,
		0x6429D29F95D23D72ULL,
		0x8ACCA7523CBF284CULL,
		0x9A5D105E27850B3BULL,
		0x297138D8F2555E12ULL,
		0xC354FFDBA5B38539ULL
	}};
	printf("Test Case 691\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 691 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -691;
	} else {
		printf("Test Case 691 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF1341856DAB7FF80ULL,
		0xAB485FF33DD31324ULL,
		0x41B6EDED6263F4F8ULL,
		0x34D90D8E2036D26CULL,
		0xB5394629DA429A54ULL,
		0x645F3FF412F7CC9CULL,
		0x23CC2FBE83CE689BULL,
		0xF9A224A016D5FB33ULL
	}};
	printf("Test Case 692\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 692 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -692;
	} else {
		printf("Test Case 692 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x86AC542E2080B69AULL,
		0xECD0DADAF9175AF3ULL,
		0xF40864A802FCF179ULL,
		0x5E9D9C690F80CB75ULL,
		0xE5E81168F9EF8FADULL,
		0x14C9C08F2E2AFCF3ULL,
		0xD58177853FE7DC81ULL,
		0x952DB78141B249B7ULL
	}};
	printf("Test Case 693\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 693 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -693;
	} else {
		printf("Test Case 693 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4C4CCECA1E1808D0ULL,
		0x502C64AD63C9091CULL,
		0x7E55D6C6D347DA88ULL,
		0xF9F5116BA383C07AULL,
		0xAF32B2F4A0AC3D6DULL,
		0x784940250541A474ULL,
		0xDB3D830315127FC4ULL,
		0xD065B72EFFCC5672ULL
	}};
	printf("Test Case 694\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 694 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -694;
	} else {
		printf("Test Case 694 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAE8FBE563811ED1DULL,
		0x505ED23516A60CF4ULL,
		0xCB17025CD6BC3784ULL,
		0x1FDD3C10B5C4CEAFULL,
		0xDA5EC8C61DE8DD53ULL,
		0x25AECA7BE41F0C7BULL,
		0xEC44EF728E2B218EULL,
		0x7A47552B7D794B19ULL
	}};
	printf("Test Case 695\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 695 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -695;
	} else {
		printf("Test Case 695 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x62F6E0F84FAEC934ULL,
		0x4D5B689AC8B34EBDULL,
		0x7798E24B50958D60ULL,
		0xEAAD4F3C5DD16C4CULL,
		0x6226531927A8E729ULL,
		0x97578909AA42B467ULL,
		0x1B4397D98DE50B55ULL,
		0x028E085E80E6181AULL
	}};
	printf("Test Case 696\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 696 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -696;
	} else {
		printf("Test Case 696 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6CD17D0CF76254ADULL,
		0x058067023E972009ULL,
		0xE922650686CB1C8CULL,
		0x8120DEC3A588D920ULL,
		0x4FFD8685E42E5965ULL,
		0x86349842B56AF149ULL,
		0xAEED5E8AA9181A23ULL,
		0xE94790E979E3C379ULL
	}};
	printf("Test Case 697\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 697 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -697;
	} else {
		printf("Test Case 697 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x75AD901B4236DA84ULL,
		0x2CB27084F34EBEC6ULL,
		0xB5CF0736B4D1CF8EULL,
		0x7F8CE46252191A46ULL,
		0x00F39A66A3A49A49ULL,
		0x0901B5716DFF8848ULL,
		0x88AD22A3AEBDF9F5ULL,
		0xF273D0973C04E1BDULL
	}};
	printf("Test Case 698\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 698 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -698;
	} else {
		printf("Test Case 698 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9D2C143149F6E598ULL,
		0x32DFB5D48A88FA6AULL,
		0x51304EC2F40AD4C4ULL,
		0x40C87136F9FBC34FULL,
		0xA6F9B152034D12ABULL,
		0x28A97FFC9E62FC72ULL,
		0x3A0864AD27035C8DULL,
		0xFD3E63AF882F18B2ULL
	}};
	printf("Test Case 699\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 699 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -699;
	} else {
		printf("Test Case 699 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5EFC12876B3D1AA9ULL,
		0xD4C34D93F450DEFCULL,
		0x4FCBAF7911575E40ULL,
		0x3CC5642AD8C8DA16ULL,
		0xB12A3145B5159F01ULL,
		0xD8DB3AF21AB655CCULL,
		0xD49B7AC3D632C9BEULL,
		0xC01046AEB40AE732ULL
	}};
	printf("Test Case 700\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 700 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -700;
	} else {
		printf("Test Case 700 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE8A9BEE4ABD25411ULL,
		0xF3F51B49B7FA8AF0ULL,
		0xAA845A0948AFA88CULL,
		0xAADF61809D433583ULL,
		0xB2BAA040F84E197CULL,
		0xDD8E7FBE50F0994BULL,
		0xA76D7D85FF1A2910ULL,
		0xC0028CA9B10DF9ADULL
	}};
	printf("Test Case 701\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 701 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -701;
	} else {
		printf("Test Case 701 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6F5878C0790A46A6ULL,
		0x29D18B0E76A54E7FULL,
		0x9E2AC08AD0BB484DULL,
		0xE0A003BAD738115FULL,
		0x65DC573454C44B81ULL,
		0x19F6CFD48C4E3CDBULL,
		0x1B6C4BBCFE20CA8FULL,
		0xA790B39317EACA9BULL
	}};
	printf("Test Case 702\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 702 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -702;
	} else {
		printf("Test Case 702 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE3FEFA1B88B18F5DULL,
		0x328BD8B4B8A3A394ULL,
		0x3718ED14FFF9824AULL,
		0x1BC9090F2DD91C3DULL,
		0x230D1D7E6E6EA7BFULL,
		0xE7C90F5B98844899ULL,
		0x077B3758E5929157ULL,
		0xD5E006C1B2560E39ULL
	}};
	printf("Test Case 703\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 703 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -703;
	} else {
		printf("Test Case 703 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC1F1607FA986B7DAULL,
		0xABF1B3106BA5101FULL,
		0xCD9DFB0AE2105A25ULL,
		0x0AEBC4B7639FFA42ULL,
		0xBCFC0484DE672D82ULL,
		0x56D386F8CCA42962ULL,
		0xDE7EEA0D1EB0F908ULL,
		0x8F319B0BC7A64D3DULL
	}};
	printf("Test Case 704\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 704 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -704;
	} else {
		printf("Test Case 704 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBBC95FC94FE303BFULL,
		0x1897F42A822496B6ULL,
		0x52D551F45FD6E2E1ULL,
		0x053E4EC9A2E20F59ULL,
		0x1966DF981A8A267DULL,
		0x22074CA51D0DC824ULL,
		0xCF61AA3E30C774E4ULL,
		0x230AD7C51D00E5ACULL
	}};
	printf("Test Case 705\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 705 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -705;
	} else {
		printf("Test Case 705 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB2582DB0C30DDDCULL,
		0xF8C3620B0648F8D8ULL,
		0x4CD9FB0CB7011E04ULL,
		0x2E0CCF6DA35848DFULL,
		0xF0AE25CC6618C4D8ULL,
		0x104F029AC0F6971CULL,
		0x379B2CEF77CF9023ULL,
		0xE9B18FDFABBD1480ULL
	}};
	printf("Test Case 706\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 706 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -706;
	} else {
		printf("Test Case 706 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB79B7D5998B6D928ULL,
		0x09BE75B1F1654CC4ULL,
		0xB3979C15D67EC6EAULL,
		0x6C2D7776691B1D88ULL,
		0xBD580E5C116967EEULL,
		0x3464D37F4D1A388EULL,
		0x3CF410C953C32A2CULL,
		0x75F0515DC94C9D58ULL
	}};
	printf("Test Case 707\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 707 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -707;
	} else {
		printf("Test Case 707 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x58F12FD985B6D119ULL,
		0x3D4F0F798C72E564ULL,
		0x8473194FB0B3CAD7ULL,
		0x34D6C6BA85BAABE4ULL,
		0x8F4ACCE2814B4BA6ULL,
		0x335A59D132306385ULL,
		0x8E180E7A19BF06BCULL,
		0x8FAAB76354E5236BULL
	}};
	printf("Test Case 708\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 708 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -708;
	} else {
		printf("Test Case 708 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x612FE8B2B7E1924CULL,
		0xE410162F0BACCC30ULL,
		0x0997E620F1B74C41ULL,
		0xE68CCD528E572CDCULL,
		0x587B3C2DA16FB5D5ULL,
		0x6A9EA92AEFC103DEULL,
		0xBAA8F6C46AB6603BULL,
		0x16817CD49CBA2AC7ULL
	}};
	printf("Test Case 709\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 709 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -709;
	} else {
		printf("Test Case 709 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9495B4C801A94953ULL,
		0xBD9C9A515FE54740ULL,
		0x101D6AB4672C534BULL,
		0xD878C04F434ECE06ULL,
		0x8230FA39A3691C4CULL,
		0xACD2EE752F4A9773ULL,
		0x0DC1606B13C23F88ULL,
		0xCB5B2B32DBCBA50FULL
	}};
	printf("Test Case 710\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 710 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -710;
	} else {
		printf("Test Case 710 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x30E37EB0E8F3A73DULL,
		0xD1A129F9CD2E0981ULL,
		0x099D913C377ED579ULL,
		0xAB34C0866EF2B62DULL,
		0x83A15358994DF8C9ULL,
		0x8E6895FBA4044BDEULL,
		0x36258B19AB91E072ULL,
		0x2D621C3B60575E85ULL
	}};
	printf("Test Case 711\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 711 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -711;
	} else {
		printf("Test Case 711 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xEBB94EC0AA7AE957ULL,
		0x296DFD92B611DC0CULL,
		0x1E26FB71932B6823ULL,
		0xD4BBD026B545FDDEULL,
		0x3ECBC1DE361F786CULL,
		0xA4686A2C2463E6C0ULL,
		0x138EFC9F24E4AB96ULL,
		0x1F65174F475CEC64ULL
	}};
	printf("Test Case 712\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 712 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -712;
	} else {
		printf("Test Case 712 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x749FA1E8CF9D4094ULL,
		0x477D2BFC7D88902BULL,
		0xA298383C66E3AD34ULL,
		0xE50B465EB4D536BAULL,
		0x87E7BD03C9CD496AULL,
		0x587790CF7DF179FCULL,
		0xF76FC3B39F145DEBULL,
		0x8E373029C9959783ULL
	}};
	printf("Test Case 713\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 713 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -713;
	} else {
		printf("Test Case 713 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x128D638D31193079ULL,
		0x9E0F602F401B5CACULL,
		0x19A7C19641C115B3ULL,
		0x98970CD406B9344FULL,
		0xB374E333E8587262ULL,
		0x368FCBD7E9869781ULL,
		0x779E874C8B2C2B31ULL,
		0x7A8E186091CF501FULL
	}};
	printf("Test Case 714\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 714 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -714;
	} else {
		printf("Test Case 714 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB9341EAB44CB4975ULL,
		0x8ADC99BFA596BA40ULL,
		0x444F36083E8BF061ULL,
		0x3109BEEB139369ABULL,
		0xDA51ACD318D562C8ULL,
		0xD82442BE46591135ULL,
		0x37791E950474FAADULL,
		0x223972551A47AACBULL
	}};
	printf("Test Case 715\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 715 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -715;
	} else {
		printf("Test Case 715 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB98263D5CF0EDEFDULL,
		0xE983B7AEC5F26D73ULL,
		0x746225CBBF255FB5ULL,
		0xC1062CC873A8ED55ULL,
		0x556C187E00A9D4C1ULL,
		0x706D76264C577838ULL,
		0x9F4F070A245C7944ULL,
		0xB282A116C924BCD8ULL
	}};
	printf("Test Case 716\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 716 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -716;
	} else {
		printf("Test Case 716 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2EB4013408255B8FULL,
		0xB4F6D08891A886D2ULL,
		0x89A6123C1B522E4AULL,
		0xD5F9858BF973D044ULL,
		0xA5D4F822A6AD1C60ULL,
		0x2692FA81AEEBC43AULL,
		0xA919452EF9E712CDULL,
		0x606C88B52242CC32ULL
	}};
	printf("Test Case 717\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 717 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -717;
	} else {
		printf("Test Case 717 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xC056DF16D4C0E634ULL,
		0x699FF66510C1E7FDULL,
		0xC9A4F59903EF9E6DULL,
		0x25325FF2947076D4ULL,
		0xC3B6E58525AF4555ULL,
		0x5C3C84975330D362ULL,
		0x5F2BD26A5CF2B04EULL,
		0x022C90C1AA83DA49ULL
	}};
	printf("Test Case 718\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 718 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -718;
	} else {
		printf("Test Case 718 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x7F3B6C36C4734663ULL,
		0x392DCF03A37A1888ULL,
		0x78F944AD1C5E78E9ULL,
		0x4EBD70EE6EAF6F46ULL,
		0xB966F07A4BBB7B36ULL,
		0x8BB42D01657A74E3ULL,
		0x30FE39BC733F1830ULL,
		0x0F76BD17F52A8E1FULL
	}};
	printf("Test Case 719\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 719 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -719;
	} else {
		printf("Test Case 719 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDC2A0B528164FE53ULL,
		0xFA6514441D77B0C7ULL,
		0x8DFD6830103F6E6EULL,
		0x907FA114D9845376ULL,
		0x1410B340F7353009ULL,
		0x63ACAD4B3D15FA58ULL,
		0x3DCA75BAC9E3867AULL,
		0x775A54CC7A5EC687ULL
	}};
	printf("Test Case 720\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 720 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -720;
	} else {
		printf("Test Case 720 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE5ED0B649A72D328ULL,
		0x152EE62C2B153C0CULL,
		0x8A6DF43AB81CE328ULL,
		0x2CFE8D2F6A1797D9ULL,
		0xFFBBA82B9865846EULL,
		0x0C9525BE3CAAB255ULL,
		0x68CB49CFD668E544ULL,
		0xE229683E5E86C48AULL
	}};
	printf("Test Case 721\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 721 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -721;
	} else {
		printf("Test Case 721 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB11E69594B470C24ULL,
		0xB6390D58B6E12306ULL,
		0x4AB52F916E2D0157ULL,
		0x2FCCCBB9DE7EA20FULL,
		0xE9D47E31DB60F5F8ULL,
		0xF99C81EF27237FECULL,
		0x986C21AEF9D343E7ULL,
		0x4D81DBB8F0D674D9ULL
	}};
	printf("Test Case 722\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 722 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -722;
	} else {
		printf("Test Case 722 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDDC6FA4CDD87562EULL,
		0x75CFE375A2C06642ULL,
		0xABF6A7B9AAE8FD33ULL,
		0xF4EAA0B9A0FB4C24ULL,
		0x184EAE77FA83BF01ULL,
		0x64302AC0FF13B6E8ULL,
		0xC489048F1AD780E0ULL,
		0x6BF0BC8B4DBE62ECULL
	}};
	printf("Test Case 723\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 723 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -723;
	} else {
		printf("Test Case 723 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3259613E89592402ULL,
		0x321D2BCBA1C63654ULL,
		0x516297AD0EE02987ULL,
		0xF79D37D806986AE7ULL,
		0xD0F8004C4FFC0ED2ULL,
		0xB7EEF067EA90B86BULL,
		0x24F3104C67D70B76ULL,
		0x973AAB80AE8D02EDULL
	}};
	printf("Test Case 724\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 724 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -724;
	} else {
		printf("Test Case 724 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x797117B10B617C01ULL,
		0xA1317FF054444721ULL,
		0x7727743980F39A44ULL,
		0x759769566B759635ULL,
		0x1E855933E542FFB6ULL,
		0xA6D399F630A8718DULL,
		0x4E285E6FE8C3B303ULL,
		0x027EE00A00C25D4BULL
	}};
	printf("Test Case 725\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 725 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -725;
	} else {
		printf("Test Case 725 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8C3AF18774FDB6CDULL,
		0xC44667B531D1250AULL,
		0x066BB409F54BADD5ULL,
		0x5BEF419E9AEAE468ULL,
		0x03A6161E4BE159ABULL,
		0x266847148069EACDULL,
		0xE5A5C7D53A12EAF4ULL,
		0x34F888E477566F03ULL
	}};
	printf("Test Case 726\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 726 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -726;
	} else {
		printf("Test Case 726 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6BDB63529053B4A4ULL,
		0x1B26C7A9A13E4ACEULL,
		0x9E8C49D2BFEDBD28ULL,
		0x96B658E767D62021ULL,
		0x61E02516A967923CULL,
		0x08BD9E59DF1D406AULL,
		0xA8B1985624D31806ULL,
		0x55BDC4236275F0D6ULL
	}};
	printf("Test Case 727\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 727 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -727;
	} else {
		printf("Test Case 727 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x118D5DFF68FABD6BULL,
		0x444054A3C0218A40ULL,
		0xA0A3D3119DAD3D87ULL,
		0xAE92413814728912ULL,
		0x454A5BB7A0A01A45ULL,
		0x0BFBF6597C572F1CULL,
		0x1A23BBA94C27F1D0ULL,
		0x8B4A0E5BC3EFA6A0ULL
	}};
	printf("Test Case 728\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 728 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -728;
	} else {
		printf("Test Case 728 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x47D38D3CDE868748ULL,
		0x39D14C24283D87C5ULL,
		0x5C8C3390142FB1F5ULL,
		0x3049EDD039643509ULL,
		0xB2C27B11EB606245ULL,
		0x0BD5E49927AE6698ULL,
		0x0C9A1296CBBAC062ULL,
		0xD7676E41830F91D0ULL
	}};
	printf("Test Case 729\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 729 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -729;
	} else {
		printf("Test Case 729 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA1F74A4652EBE6D3ULL,
		0xAEAE55060F922E39ULL,
		0xDCD866BA94208EACULL,
		0x7A3550C9C01FC80AULL,
		0x04899039E293CF8EULL,
		0xDA6587B832974E41ULL,
		0x9939AE098BED979CULL,
		0xFEA4C22CB4BC6115ULL
	}};
	printf("Test Case 730\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 730 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -730;
	} else {
		printf("Test Case 730 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8A433629D31EF79AULL,
		0xFEAE881DCD26EC2FULL,
		0x1D11F08C24E51D60ULL,
		0x897FB8EAEDA66A80ULL,
		0x0C35F40C2671F5BAULL,
		0xEAD8334958A1F825ULL,
		0xC15DD45D462BA23BULL,
		0x73F14395C4F9FF7FULL
	}};
	printf("Test Case 731\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 731 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -731;
	} else {
		printf("Test Case 731 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x29BB845E477E0535ULL,
		0xE0FFE258A545B088ULL,
		0xAE897C2C9C308C5AULL,
		0x1CC534CC398A5607ULL,
		0xC85EB36AA616FEFCULL,
		0xAA7F0654A6D405DCULL,
		0x618072AA234F6589ULL,
		0x042E211BF06D832FULL
	}};
	printf("Test Case 732\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 732 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -732;
	} else {
		printf("Test Case 732 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF01E3D99C21BCF8AULL,
		0x90E945601BC45221ULL,
		0xBC7DCF8414E033E0ULL,
		0x61413C8D7B900DA7ULL,
		0xACB1111AB359A390ULL,
		0x8A98563E89491681ULL,
		0xE0A62114DE7E9713ULL,
		0xEA8C7ED956F3B60BULL
	}};
	printf("Test Case 733\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 733 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -733;
	} else {
		printf("Test Case 733 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x55EED7C05A3CB4B6ULL,
		0xD0FD16A9DC3E371DULL,
		0xB5D89E83A10D8817ULL,
		0xE67EC3E393E0CA16ULL,
		0x4B0EB06AD8E3E356ULL,
		0x72A1916E3714AD46ULL,
		0x0BE86C04EF52DF61ULL,
		0xDF7C2E3B95FE8CCBULL
	}};
	printf("Test Case 734\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 734 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -734;
	} else {
		printf("Test Case 734 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED268C18708DFEC0ULL,
		0x1C034F569FCB7747ULL,
		0x2BE3CDAD8AA5F369ULL,
		0x120D7B448B053EADULL,
		0x70F1C3DB99D8B11FULL,
		0x05943E049E5597A2ULL,
		0x1A9C5A4085A21E69ULL,
		0xB6C161DD6CE2F1D4ULL
	}};
	printf("Test Case 735\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 735 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -735;
	} else {
		printf("Test Case 735 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3E7622606D2822E2ULL,
		0x34EDC0D176B166A9ULL,
		0xF0555A0AC5C3DF00ULL,
		0x08E33153C66CBB81ULL,
		0x3DB2057CABB054A4ULL,
		0xB36A1BC1A5023164ULL,
		0x82EF0D16D7A6A775ULL,
		0x8D621B8FBE36BC10ULL
	}};
	printf("Test Case 736\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 736 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -736;
	} else {
		printf("Test Case 736 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5CCC3B95B20B64C6ULL,
		0x9EAB9B38B37AB1D2ULL,
		0xD0FECDAD2F25B7DFULL,
		0xDCBD44BF1C8411EEULL,
		0xA3F1E8BD33695833ULL,
		0x77A961E6A0C1D722ULL,
		0xEC1EE875F4B7E044ULL,
		0x312A7DE46F7C2B9FULL
	}};
	printf("Test Case 737\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 737 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -737;
	} else {
		printf("Test Case 737 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x80F80DD9EA5B4A06ULL,
		0x949F2610BEFAF8F1ULL,
		0x4A0A4B36D8A25747ULL,
		0x6DD5713F42FF9338ULL,
		0x8BFC8982B29A8F6CULL,
		0xD96B25D83B3B1ED3ULL,
		0xCDBEF5F5D1B71CC8ULL,
		0x5F089CF283DBEB1AULL
	}};
	printf("Test Case 738\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 738 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -738;
	} else {
		printf("Test Case 738 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA3AD08518716A360ULL,
		0xFDDA1CAC64A923F5ULL,
		0x31132166D65EE2FFULL,
		0x5D58650C2A8A591AULL,
		0xA539211F8B69246DULL,
		0xAF324AFA6CDE0D2FULL,
		0x038CC11523E47D90ULL,
		0xEC999427B12C5A95ULL
	}};
	printf("Test Case 739\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 739 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -739;
	} else {
		printf("Test Case 739 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x9E41BDA59FBA4CA5ULL,
		0xB4FE871796B93BE1ULL,
		0x490373DEEFCF2C67ULL,
		0x39BDF49F897969E8ULL,
		0x317220BC07EDCB9FULL,
		0x940685F0C6008282ULL,
		0x08398EE760DA6427ULL,
		0x0D3CF24DE474F4CEULL
	}};
	printf("Test Case 740\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 740 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -740;
	} else {
		printf("Test Case 740 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9BF65D0944C34ECEULL,
		0xEBCC2CB2E7EBF554ULL,
		0xD68641289E766DB9ULL,
		0xF9367A8F1208BCABULL,
		0xB2DCBFCE9CBF8BF6ULL,
		0xD28942CD69D74BABULL,
		0x83D59DE13E82B8F4ULL,
		0xC5B58AA7500AF88FULL
	}};
	printf("Test Case 741\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 741 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -741;
	} else {
		printf("Test Case 741 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCEBB703B00C7EA39ULL,
		0x0086C1E71A053846ULL,
		0x6F9D5ACA70D2D408ULL,
		0xB43160F2E38BA7EFULL,
		0xD116A31741082CE5ULL,
		0x1B9F4C532CC927F3ULL,
		0xAFCD23AC4E0EE3A5ULL,
		0xD1B501E0F4B8495CULL
	}};
	printf("Test Case 742\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 742 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -742;
	} else {
		printf("Test Case 742 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xEE421530389B3BC6ULL,
		0x61B691940C364F3BULL,
		0xD06341C0BC3E6EB1ULL,
		0x945DED6D3B0D8ED5ULL,
		0x146403AC6D9C66C9ULL,
		0x693314831E16ABA8ULL,
		0x04D2652DD1ACBCCAULL,
		0x369A46C9A191D6E2ULL
	}};
	printf("Test Case 743\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 743 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -743;
	} else {
		printf("Test Case 743 PASSED\n");
	}
	printf("---\n\n");
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0xB2F73E38F83AFBE3ULL,
		0xAE2233223B5A58C0ULL,
		0x06DCB293A19D98BCULL,
		0x0888AC294ADA2A58ULL,
		0xB2FA4AC06AF97792ULL,
		0xEA4F649338AFEB7DULL,
		0x4181CFBBF4F5CC1CULL,
		0x00FBEE31BE0B90E0ULL
	}};
	printf("Test Case 744\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 744 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -744;
	} else {
		printf("Test Case 744 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x53EA74E5BDC779BFULL,
		0x0430FFFA7E9CB5B6ULL,
		0x138ACBC0A251C4B0ULL,
		0x1309FEFD9F761ED5ULL,
		0xB26546A0A5325EFEULL,
		0x4B9789627D6FD3A3ULL,
		0xCA247A73C2F7E231ULL,
		0xB4D38047604C87F5ULL
	}};
	printf("Test Case 745\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 745 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -745;
	} else {
		printf("Test Case 745 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9EE981BC1B6D474EULL,
		0xC9EC226B2B54CE9AULL,
		0x90A69ADE997B995FULL,
		0x6AA96D26C5EE6062ULL,
		0xA9B517EC75FACFBCULL,
		0x35D7A52B4E8C56EDULL,
		0xC397FE80428C366DULL,
		0x722114E8A912DD96ULL
	}};
	printf("Test Case 746\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 746 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -746;
	} else {
		printf("Test Case 746 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x017F151EA8D3854CULL,
		0xDB96265470DE61FBULL,
		0xCFC302E5D9664A67ULL,
		0xD9751D36BF596A8BULL,
		0x5E8A53251466DE1AULL,
		0x26621277182D6995ULL,
		0x8CE04D0B598A47AAULL,
		0x9406E21E18C538ADULL
	}};
	printf("Test Case 747\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 747 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -747;
	} else {
		printf("Test Case 747 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0EC3D6854ADE82AULL,
		0x3A761DB276DE2698ULL,
		0xDC1015BB3A13DA14ULL,
		0xEEFEE1E5E2AF7C05ULL,
		0xBC435469F8ACE14EULL,
		0x2557C4F06FB0F916ULL,
		0xFB7C15A1F2B63EFAULL,
		0x99800A09F069852FULL
	}};
	printf("Test Case 748\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 748 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -748;
	} else {
		printf("Test Case 748 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD6A7ED48F9ABC122ULL,
		0x8531C6EFE8D734CAULL,
		0xA4FB03A1D5C1ECF1ULL,
		0x516C7A50B2132BBAULL,
		0x5F2A4DB6D77347DAULL,
		0xA2BFFE7A2CC46616ULL,
		0xE4AAC8EA5D5D1DFDULL,
		0x7CFE5BB73515129FULL
	}};
	printf("Test Case 749\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 749 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -749;
	} else {
		printf("Test Case 749 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9F87E0E89945E3F2ULL,
		0x5EC3BE8295A876C6ULL,
		0xAA46431CEE5B7E4FULL,
		0xA0BCD8DBF01DB408ULL,
		0x521BBA33E13E5EC1ULL,
		0xF93780CE5DE74762ULL,
		0xC285AFCDCF2B0BDBULL,
		0x479C6796D90B7228ULL
	}};
	printf("Test Case 750\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 750 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -750;
	} else {
		printf("Test Case 750 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB0A1F2382C629522ULL,
		0xCDB31055935362EEULL,
		0xC1169187D0595ACCULL,
		0x96DA7B95CB463CC7ULL,
		0x86A461C38328276EULL,
		0x15CDDC44D64BFF50ULL,
		0xFF31F2C7C5164573ULL,
		0x9CAAEA73796ECF9CULL
	}};
	printf("Test Case 751\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 751 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -751;
	} else {
		printf("Test Case 751 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBF822844FD05F6DDULL,
		0xD2B3BF7A36511CA2ULL,
		0x03FB1BB6BC57FB76ULL,
		0x69DD779DA2120474ULL,
		0xA02738CE78B8602EULL,
		0x1AD444A14A3A8F2DULL,
		0xD2375AAA73F950B7ULL,
		0xC564AA23D15E124EULL
	}};
	printf("Test Case 752\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 752 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -752;
	} else {
		printf("Test Case 752 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA33C6DF678A122A5ULL,
		0xF509B88FCE31A723ULL,
		0x51DDEC1847A38F6DULL,
		0x6D65F50B9FA05843ULL,
		0x2CDB767E697DFC43ULL,
		0x318972A85DA29B08ULL,
		0x1C37676A73AB8467ULL,
		0xB2DD11744D9D61F0ULL
	}};
	printf("Test Case 753\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 753 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -753;
	} else {
		printf("Test Case 753 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x38C18D7534F83872ULL,
		0x9BBA37CD14D5B7B0ULL,
		0xABB3F3C484BA4C56ULL,
		0x0D076EA2F77A46E2ULL,
		0x94AA3344C1CF7847ULL,
		0xC1463EA45EDADADDULL,
		0x5CC5669E939EF162ULL,
		0x8635B3CAB9F3F269ULL
	}};
	printf("Test Case 754\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 754 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -754;
	} else {
		printf("Test Case 754 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBAD939EB4FD821CCULL,
		0x4944E891C526772CULL,
		0xB76AD46B24217A55ULL,
		0x1172BCCD2272C590ULL,
		0xA53F98F972BCD2BDULL,
		0xC9D59245F49034F1ULL,
		0x25DCCEE80340C2CCULL,
		0x9CFB5D29BE1F72B3ULL
	}};
	printf("Test Case 755\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 755 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -755;
	} else {
		printf("Test Case 755 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF9557ACDFD36561CULL,
		0x390600CF21518004ULL,
		0x680AD7C9716AA7ECULL,
		0x13EC06E254E8C48FULL,
		0xB5EBF0FED01A6840ULL,
		0x0FD35140E14EB036ULL,
		0xAF204DD88B1F8F68ULL,
		0x78C813DFEDF8101DULL
	}};
	printf("Test Case 756\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 756 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -756;
	} else {
		printf("Test Case 756 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB3562D48199BCC31ULL,
		0xC52C3B2901171600ULL,
		0x79260B9BD903D251ULL,
		0x87A91E820A5D58F8ULL,
		0x0B435DD84900552CULL,
		0xCD9694BB36C03D4FULL,
		0x0ECF4FAA25EE5057ULL,
		0x10504ACAA44D7F79ULL
	}};
	printf("Test Case 757\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 757 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -757;
	} else {
		printf("Test Case 757 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDC761179E47C4DB3ULL,
		0xB9657C82503CEFC4ULL,
		0x4EBCE68F99F59D71ULL,
		0xE0E6480EC0EB3C39ULL,
		0xC2D073C4A41208B8ULL,
		0x0D83F1F3F669ED67ULL,
		0x9E103B7179F2F74AULL,
		0x37359369D0B9D082ULL
	}};
	printf("Test Case 758\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 758 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -758;
	} else {
		printf("Test Case 758 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD86C3634D785355FULL,
		0x655AC2E87EE67198ULL,
		0xD7841DF200C06101ULL,
		0x25F012BA3EFF530CULL,
		0x034E735C1BAB83EAULL,
		0x61B46017A3503572ULL,
		0x02F6A44DC6B583B9ULL,
		0xF54BF80414E4FEB3ULL
	}};
	printf("Test Case 759\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 759 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -759;
	} else {
		printf("Test Case 759 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x67EE0D39628FEC96ULL,
		0x3200424231327C05ULL,
		0xCB6FB07336509DCBULL,
		0x403443F774A89F7BULL,
		0x7F446DB7D7FA11ABULL,
		0x458B9E4FB68FCDA2ULL,
		0xABB8BBBC1EF21BCAULL,
		0x6988AE96BA79D6D3ULL
	}};
	printf("Test Case 760\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 760 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -760;
	} else {
		printf("Test Case 760 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8882AA642FC5A29BULL,
		0x84F2362AC3DF4835ULL,
		0xFC756C1971B50FFBULL,
		0xEC71BBFBBC9F9A7AULL,
		0xB051DB5B4CAFC455ULL,
		0x157924541CA11387ULL,
		0x817287FD8F06FC95ULL,
		0xFD1F7AA10EACC828ULL
	}};
	printf("Test Case 761\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 761 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -761;
	} else {
		printf("Test Case 761 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xEA54CAB9BD3B9FEAULL,
		0xCA56315962122118ULL,
		0xD5E06D93CDB4219CULL,
		0x75DA417665C9045CULL,
		0xC11A2C3780944FA8ULL,
		0xAE720293D54052A5ULL,
		0xA49FB3DCE52691A6ULL,
		0x1088451680DA8368ULL
	}};
	printf("Test Case 762\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 762 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -762;
	} else {
		printf("Test Case 762 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCA8E788D20ED28D8ULL,
		0x581B04D82287E66EULL,
		0x5C995C392C041A13ULL,
		0xFFB354F2B9A86116ULL,
		0xDE1A601FE254C1FAULL,
		0x59EF38B5C383806CULL,
		0xA25655DCB2D5A671ULL,
		0x48D3B3B21D56526EULL
	}};
	printf("Test Case 763\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 763 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -763;
	} else {
		printf("Test Case 763 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA6B4C626763131FAULL,
		0x0B9A0679B5D47A6AULL,
		0x559F6DF6C4B23EDDULL,
		0x023B1FA4C15BDAF4ULL,
		0x3DAD253EA16ACA1EULL,
		0x9E3E3C115FAAFAF6ULL,
		0xCDD7E45A66AB1DE4ULL,
		0x6D9C5F46DB0A2802ULL
	}};
	printf("Test Case 764\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 764 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -764;
	} else {
		printf("Test Case 764 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x75AC903E4100E628ULL,
		0xAC99A9D6B4165926ULL,
		0x82EA3369E3C7ADA1ULL,
		0xA07842E4CFC5C23AULL,
		0x1225FA349B2891B3ULL,
		0x0E956A39E91AB7EBULL,
		0x3805C828BB79BCEAULL,
		0x0FA39386A6E5C6E3ULL
	}};
	printf("Test Case 765\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 765 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -765;
	} else {
		printf("Test Case 765 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE249D8558FE8EE6AULL,
		0xD720F4B4AE89DE4BULL,
		0x5F9ABA73A6CA256EULL,
		0x06C0E5E8D0AD0491ULL,
		0x67ADC78D43484CADULL,
		0x628277F09B7B4DC6ULL,
		0x04FD8D30F71BE8BCULL,
		0xB739476D883BD9BCULL
	}};
	printf("Test Case 766\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 766 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -766;
	} else {
		printf("Test Case 766 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x0DF33D0879D6B99CULL,
		0xAD4CA3A8E9AF1A41ULL,
		0x54EBC61209CBD697ULL,
		0x287561A768EF8FB8ULL,
		0x7B13D92B2AC3CEEDULL,
		0x89FA214EC8D6FABDULL,
		0xA2A95B278878E986ULL,
		0x0C68DBA3FE86576FULL
	}};
	printf("Test Case 767\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 767 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -767;
	} else {
		printf("Test Case 767 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE2D1FC460FD348BEULL,
		0x54A512D35AB64B0FULL,
		0x3869F537CDE3AEA4ULL,
		0xE13D7C39F5DEAC35ULL,
		0x126334DDB8F541CCULL,
		0x9704E0FA744B4F8EULL,
		0x8E3E87E498C481CEULL,
		0xBD433BA161CC0A03ULL
	}};
	printf("Test Case 768\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 768 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -768;
	} else {
		printf("Test Case 768 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x32024672C0F2DC4EULL,
		0xFEDB315E24467809ULL,
		0xBC82B403619C46FCULL,
		0xAC98EB6E56D28C1FULL,
		0x4E0793B62CC58B84ULL,
		0x80334D6DC178381FULL,
		0x8307D6C062D05CE1ULL,
		0x68F51986E603737BULL
	}};
	printf("Test Case 769\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 769 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -769;
	} else {
		printf("Test Case 769 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9AE898F459CE82B9ULL,
		0x3358DBEB24EE903EULL,
		0xFB32C628AA4230A5ULL,
		0xAF2967EF3D36C1D9ULL,
		0x249B0ED56BAF99A9ULL,
		0x8B8BEB3C4CEF481DULL,
		0xB687A7EDE1AAC222ULL,
		0x625887CCE4BE6926ULL
	}};
	printf("Test Case 770\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 770 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -770;
	} else {
		printf("Test Case 770 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9254975A02CC78F2ULL,
		0x0A7B1DABB8C32267ULL,
		0x065902A1FFEC2168ULL,
		0xCA3B142A93F43F68ULL,
		0xB0BA8D7C23BC20C3ULL,
		0xF9799B1F117CBD92ULL,
		0x72D9BED37FE14515ULL,
		0xC2CF02504205A357ULL
	}};
	printf("Test Case 771\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 771 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -771;
	} else {
		printf("Test Case 771 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF08B7420B8A2D237ULL,
		0x6B38410EC3E74F43ULL,
		0x393359AF208B0F82ULL,
		0x3B3A23E130770CA1ULL,
		0xFCBC68CC2D34BBBFULL,
		0x41B440975011AF36ULL,
		0x8B42BB7F951407EBULL,
		0x644758322299C488ULL
	}};
	printf("Test Case 772\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 772 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -772;
	} else {
		printf("Test Case 772 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3B6AEEFF9CA48308ULL,
		0x062EC41FD6361FE2ULL,
		0x1FCAF26D981AF7DAULL,
		0x3FD708BAD3DA8F76ULL,
		0xFC3D333DEA834BA7ULL,
		0xCE081CD1A1FB84DBULL,
		0x3DAFFE5E6A4AB6ABULL,
		0xFFA3644D9AA6FE68ULL
	}};
	printf("Test Case 773\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 773 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -773;
	} else {
		printf("Test Case 773 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x352B8693EB4E6482ULL,
		0x3642B40C1E0AA636ULL,
		0x432C22FD1CB28504ULL,
		0xC58C92C821E27DD0ULL,
		0x64FF6EB5CE44070AULL,
		0xFEB16439A2EC1CB1ULL,
		0x28E2730606E69125ULL,
		0x565C7D352E7FCE8DULL
	}};
	printf("Test Case 774\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 774 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -774;
	} else {
		printf("Test Case 774 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFE221B07D524EFA5ULL,
		0x089A4074302BF3C2ULL,
		0x718F252CBEED3130ULL,
		0xC8E0DBC37153EA37ULL,
		0x11026146DFBDB0AAULL,
		0x0D766D244E18EC2CULL,
		0xB33F34EE98850EF8ULL,
		0xB30793FE12272C28ULL
	}};
	printf("Test Case 775\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 775 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -775;
	} else {
		printf("Test Case 775 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x63BADCEB59F05B47ULL,
		0xDC5189722D9CB448ULL,
		0x76313EB7C27A0DB2ULL,
		0x31AF79E775BB1623ULL,
		0xDCD7911208308A87ULL,
		0x876DD8A228823C6FULL,
		0xCD6189C40AE12BF0ULL,
		0xCAA7060E2799A4F7ULL
	}};
	printf("Test Case 776\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 776 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -776;
	} else {
		printf("Test Case 776 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB64694A8C580E4A8ULL,
		0x85E29DA5878D59C5ULL,
		0x1EAEBC2E0E24087DULL,
		0xB806CB3F2BA3BD93ULL,
		0x99371136D4C78399ULL,
		0x2AB3BB9837FE8FA0ULL,
		0xC07AC92D429ED5BAULL,
		0x22D7CA632FDAF9E9ULL
	}};
	printf("Test Case 777\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 777 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -777;
	} else {
		printf("Test Case 777 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x43FA1823D36B2007ULL,
		0x0931C8C793CAE019ULL,
		0x3FAAC8606F60FF0BULL,
		0xFDFC6B5CD8FDCA44ULL,
		0x5F2F272C4E15DB7CULL,
		0x90988496A97F486EULL,
		0xBBC6184BA9B1C80BULL,
		0x1FB446C64740BD8EULL
	}};
	printf("Test Case 778\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 778 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -778;
	} else {
		printf("Test Case 778 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1805A6266B57F8E9ULL,
		0x515A0CF4EE4122A5ULL,
		0xBD524665C457BC46ULL,
		0xE80A5360B4496E9AULL,
		0x46ADF961637EF035ULL,
		0x5A546EED3FF7293FULL,
		0x2176B7D974ACE8EBULL,
		0xDD60A25A71734DC1ULL
	}};
	printf("Test Case 779\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 779 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -779;
	} else {
		printf("Test Case 779 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7F44EA1579CE4DE9ULL,
		0x4248F1106355B3DBULL,
		0x29B78BD043B2CA2FULL,
		0x478C0A5A18C400E5ULL,
		0x9CA3CAFDBEC8B7DBULL,
		0x78AC4CFE065AB270ULL,
		0xC772F88BDA607374ULL,
		0x3ACA2ECC3302CEF5ULL
	}};
	printf("Test Case 780\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 780 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -780;
	} else {
		printf("Test Case 780 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE9C59A2983154840ULL,
		0x4508DFB52424A780ULL,
		0xFCD1B1D8B4A30FC3ULL,
		0x8CBB3511DF3B644AULL,
		0xB9A93DC95584D960ULL,
		0xD6358043A31DCB27ULL,
		0x62DEF686CB359184ULL,
		0x1C1AFB279F01FF76ULL
	}};
	printf("Test Case 781\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 781 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -781;
	} else {
		printf("Test Case 781 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD6D5A3A9E0ADA1BFULL,
		0xCDB6E0317FA20AA4ULL,
		0x465589BCFB4C34CDULL,
		0xD446FF9A55F5EA3AULL,
		0xF56ED34FC9E91204ULL,
		0x3EBEF907F7D83A6EULL,
		0x6FC897AD1F8E21EAULL,
		0x49488E1B708A856EULL
	}};
	printf("Test Case 782\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 782 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -782;
	} else {
		printf("Test Case 782 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC42BD8B8EA73C3BCULL,
		0x86780141BEA01F8CULL,
		0x79479FF7B4DAA21FULL,
		0xFCF39E3174ED6416ULL,
		0xBF70115C5CB577F8ULL,
		0x7B970E801D256801ULL,
		0x83087AFB7C0EF150ULL,
		0xA6D2F706B43243E3ULL
	}};
	printf("Test Case 783\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 783 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -783;
	} else {
		printf("Test Case 783 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x11733FEF2737EA03ULL,
		0x83D54B2D29AA4B2AULL,
		0x50DFD1B698486204ULL,
		0x68A0820D22BB0F4CULL,
		0xE290F905D5918195ULL,
		0xD8557D11C6B624C2ULL,
		0xE805821DCCEF2C35ULL,
		0x23BEC2641E83B14EULL
	}};
	printf("Test Case 784\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 784 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -784;
	} else {
		printf("Test Case 784 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x79751DB3D905BBC7ULL,
		0x8D54319DAB3D6CD4ULL,
		0x3CB84FB5B65709A8ULL,
		0x1DD1400668910A9EULL,
		0x4EE37B0A563E1D71ULL,
		0x6E14C407C737D6C6ULL,
		0xDBAE5506CFD24CD4ULL,
		0x5B2EC79AF5F4D145ULL
	}};
	printf("Test Case 785\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 785 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -785;
	} else {
		printf("Test Case 785 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x715E352E0FFE5B7AULL,
		0x5FC6D871FCA809D1ULL,
		0x7146B4052BFFBF37ULL,
		0x76CDC21BCE4F506FULL,
		0x5106C6B214877141ULL,
		0x12CE39ECC4E84822ULL,
		0xEFD3EFC18915BB36ULL,
		0x4360ACB643CD930FULL
	}};
	printf("Test Case 786\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 786 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -786;
	} else {
		printf("Test Case 786 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x18BA6B1E4260FF5EULL,
		0xFBB681CD8DAD021FULL,
		0x191F72B68C07DFBBULL,
		0xDA6FF1B53EAFB392ULL,
		0x9FD904C25DFAF654ULL,
		0xA69AB903DBEF9E26ULL,
		0x9E6FEFADF6CC79BEULL,
		0xDCBAE1FA00DA0111ULL
	}};
	printf("Test Case 787\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 787 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -787;
	} else {
		printf("Test Case 787 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x232A4AB4E4F9E972ULL,
		0xB6B4DF7C576BF56EULL,
		0x22C6671A2FB910B8ULL,
		0x0345EF332F2170D8ULL,
		0xE354C7670EB9D4EFULL,
		0x1B0F4AC4DF466A50ULL,
		0x4518DE214CBDB90CULL,
		0x4383FF24926E7D4AULL
	}};
	printf("Test Case 788\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 788 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -788;
	} else {
		printf("Test Case 788 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x39155EC8691635F6ULL,
		0xE122C14104D3F18FULL,
		0x8B5638DA12BA55A7ULL,
		0xFE04E6842756DBB4ULL,
		0x9B6C5C75BD921978ULL,
		0xF7BE02E21026E73AULL,
		0x3F4D4ACC23F42E04ULL,
		0x98524D50C5238D00ULL
	}};
	printf("Test Case 789\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 789 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -789;
	} else {
		printf("Test Case 789 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x60CD4A4680C60651ULL,
		0x1F251C56C6D5A61FULL,
		0x5AF8AB1A4C7E2232ULL,
		0xCD40B1E7EE695764ULL,
		0xBFC32415EF3B2040ULL,
		0xF16E834B25B128F2ULL,
		0x9373FEF9972505ABULL,
		0xD7649D5FF596D6F0ULL
	}};
	printf("Test Case 790\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 790 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -790;
	} else {
		printf("Test Case 790 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF06B81591E8E02A4ULL,
		0xD64B32AB1C2183C4ULL,
		0x033A52908B314651ULL,
		0x51FDF5C2BAF1895DULL,
		0x43E374DB11542673ULL,
		0x59AEE3EE0CE61744ULL,
		0x43C5A5E2EAEF9313ULL,
		0x9E7AA8CC336FACD2ULL
	}};
	printf("Test Case 791\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 791 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -791;
	} else {
		printf("Test Case 791 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD98B07EA197764FBULL,
		0x59A619FF275A58A6ULL,
		0x0EF7650A12E81CD9ULL,
		0xA97CEDCBBDFD065DULL,
		0x071976C4495D3B79ULL,
		0x1DDCD7C1215AD390ULL,
		0x00C4DE8BFC625345ULL,
		0x785B629EE99C54F6ULL
	}};
	printf("Test Case 792\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 792 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -792;
	} else {
		printf("Test Case 792 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x38B4AF381F9781BDULL,
		0xE50B648B8A2ED6B8ULL,
		0x7D6B76F187F9F004ULL,
		0xE2271CC08FB40037ULL,
		0xCD59BBE27CCE64B5ULL,
		0x0F28C0A2040E725BULL,
		0x18363ECC6A21D61CULL,
		0x309B3932A8A07FFAULL
	}};
	printf("Test Case 793\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 793 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -793;
	} else {
		printf("Test Case 793 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x36FE9319C70F70A9ULL,
		0x604C522E5157197EULL,
		0x16D7893D196FC307ULL,
		0x90054802C37F8955ULL,
		0x23348AFAF862DFB7ULL,
		0x02CA299CC4D523DDULL,
		0xD75DB0E2008F1EB0ULL,
		0x16750099C7812EB7ULL
	}};
	printf("Test Case 794\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 794 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -794;
	} else {
		printf("Test Case 794 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3C841D3C69FC5564ULL,
		0x68E897ADB7BA2B57ULL,
		0x04D25F6E0D8D4057ULL,
		0xFFE2F7F998E2CD83ULL,
		0x49B0E9D3A930FE2BULL,
		0x9357A28A59FF841AULL,
		0x1E2C5C53F42519A2ULL,
		0xDE1F44258672CBE4ULL
	}};
	printf("Test Case 795\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 795 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -795;
	} else {
		printf("Test Case 795 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAE849C3C634F6625ULL,
		0x2C1F91928C5917CFULL,
		0xCF5067262D253675ULL,
		0xE4D5499D12F7C51CULL,
		0xB3670368E56E4EF6ULL,
		0xBC8D6ACBFEC7061CULL,
		0xD131552889109B55ULL,
		0x339939B9966E1495ULL
	}};
	printf("Test Case 796\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 796 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -796;
	} else {
		printf("Test Case 796 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x835141F428ED591FULL,
		0x19AA63CCB711D969ULL,
		0x37984E4A9845FD33ULL,
		0x25F92EC0F9C60B75ULL,
		0xE853634E4EA43AFEULL,
		0x49BB4BA076E6413DULL,
		0x82EF41EC95C0DD83ULL,
		0xFD2EA98EF016CA32ULL
	}};
	printf("Test Case 797\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 797 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -797;
	} else {
		printf("Test Case 797 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xFB5C9A213B6F7D35ULL,
		0x0B5BBDC05E2F1C2FULL,
		0xE223DB51B0EF2741ULL,
		0x373DCB59C0C1F2C2ULL,
		0x6CFFAEC7531E7C08ULL,
		0xFBEE5600F1B351BDULL,
		0x4919CF25627FB746ULL,
		0x1E921AB9B4920442ULL
	}};
	printf("Test Case 798\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 798 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -798;
	} else {
		printf("Test Case 798 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6B057102160A877FULL,
		0x9B58D6BF37D4D09FULL,
		0x27CAEFC85852FCAEULL,
		0xC93F31183DBD9D93ULL,
		0x96E93009FCDC8A56ULL,
		0x02881BE79BA7CF4DULL,
		0x60BFE70BF15B48CDULL,
		0x2F5AF8C3F45250A5ULL
	}};
	printf("Test Case 799\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 799 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -799;
	} else {
		printf("Test Case 799 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3E6EBA0B2CD3E8B2ULL,
		0x38C66FB617054FD2ULL,
		0xFECD73EF52E2000AULL,
		0xB5552EA25D20D432ULL,
		0x957EC5340A0720B2ULL,
		0xD12CAFC8F9AEE48FULL,
		0x9B73AF8CC5A82D40ULL,
		0x7786A0897F372CA8ULL
	}};
	printf("Test Case 800\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 800 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -800;
	} else {
		printf("Test Case 800 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xCA7BC8AC6C5F6B7DULL,
		0x7F96E51BCEFAFF36ULL,
		0xCD02D5236A304309ULL,
		0x5FE9488F84C1B010ULL,
		0x9AAD216174045B88ULL,
		0xC23D495B8F1244E4ULL,
		0x14F87C85AEC70C71ULL,
		0x1D451EA41CC3FA0FULL
	}};
	printf("Test Case 801\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 801 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -801;
	} else {
		printf("Test Case 801 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xAED5197C946414F1ULL,
		0xD3BFA8AA55D5AA07ULL,
		0xCF377C8EF929BC7BULL,
		0xC56FFA338D25F4DEULL,
		0x6BEE4DE4AA772ABAULL,
		0xE55FCF3D52DE88FBULL,
		0xF7292616AF624FC7ULL,
		0x0875F6CC53B7E9A9ULL
	}};
	printf("Test Case 802\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 802 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -802;
	} else {
		printf("Test Case 802 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8C13DAE818F0D48ULL,
		0xC87E935D53A3FCA3ULL,
		0x4723E9EB67F32430ULL,
		0xBE21CBEAB86AC54FULL,
		0xCAA3060E1197BE00ULL,
		0xC10E95F806E4B0F3ULL,
		0xA411F5571D6EFFA2ULL,
		0xD244715CAEEFCBAFULL
	}};
	printf("Test Case 803\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 803 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -803;
	} else {
		printf("Test Case 803 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3C7774CD2DAC7D9EULL,
		0xF21E51062A9549D0ULL,
		0xADF8C1B8B1C3F665ULL,
		0x9E49E40AA3E8EFD1ULL,
		0xD4F8831F2262926BULL,
		0x5C3D1DD2A1257B30ULL,
		0x51B596DECF7E2627ULL,
		0x5F40E0337F567172ULL
	}};
	printf("Test Case 804\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 804 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -804;
	} else {
		printf("Test Case 804 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xC1C279510A91EC6BULL,
		0xBBCBCDD2C5C9A44AULL,
		0xD294D1FD58BE6DAFULL,
		0xD845943A2880BE7CULL,
		0xDBDA609B100875A6ULL,
		0xD72DA1D069BD4D33ULL,
		0xE535BC69EC796DB3ULL,
		0x0A1375D171DF812AULL
	}};
	printf("Test Case 805\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 805 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -805;
	} else {
		printf("Test Case 805 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8F781B42D2B30385ULL,
		0x3D944BB8879AF609ULL,
		0xC8723C24EED17EE1ULL,
		0x4824DD04CE65301BULL,
		0xB28B948D1CAFDBABULL,
		0x83F0DD57E5926621ULL,
		0x9BFAF8DF7F749059ULL,
		0x9359BDAE4BF6A257ULL
	}};
	printf("Test Case 806\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 806 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -806;
	} else {
		printf("Test Case 806 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x642D31CB6DE81B39ULL,
		0x2B6EE22414E25384ULL,
		0xB7B614B6743CFD85ULL,
		0x6BB520AFCEC8D1C0ULL,
		0xA23C871BE6C3F979ULL,
		0xAE7E8B6F2356F788ULL,
		0xD77B86F7F4210A00ULL,
		0x4FA6B5C4A1BAA877ULL
	}};
	printf("Test Case 807\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 807 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -807;
	} else {
		printf("Test Case 807 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE880C6370CD1220CULL,
		0x8A209D2679DB415FULL,
		0x1EFC0E81894599A6ULL,
		0x7097C12A2D303155ULL,
		0x424E48300EBEB7B5ULL,
		0x030FF606E39E9A14ULL,
		0x01BD7E7347889DDCULL,
		0x24B86D58AC431A6AULL
	}};
	printf("Test Case 808\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 808 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -808;
	} else {
		printf("Test Case 808 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5FDAF02A4E4AD800ULL,
		0x51D5AE7DAEF42867ULL,
		0x2BA64E1A8496764AULL,
		0x53BAC6FBAA7F285AULL,
		0x9C4E28BB6C739A7FULL,
		0xB3C040FA16E85CD4ULL,
		0x41BF5F0761CFE2A3ULL,
		0xCFD6CE779C15BA77ULL
	}};
	printf("Test Case 809\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 809 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -809;
	} else {
		printf("Test Case 809 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xFB5BB20CCFD0B542ULL,
		0x5AD763CA50225039ULL,
		0xE18C44309BFD7D39ULL,
		0x8B6FD7B8AF24DE47ULL,
		0xBB42E2D777E14D23ULL,
		0xC2A5F3322E59D9DEULL,
		0x100F448CDA3AF14DULL,
		0x09A6E0B7609D0937ULL
	}};
	printf("Test Case 810\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 810 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -810;
	} else {
		printf("Test Case 810 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF6E40AA3843131A0ULL,
		0xB687401CEB2F5274ULL,
		0xEF976216B730BFDDULL,
		0x2714635768EC00CAULL,
		0x40376159E2BE0832ULL,
		0x60C8DCFBF1D8DA7CULL,
		0x4D4E750949314E01ULL,
		0xEE356C679C58B689ULL
	}};
	printf("Test Case 811\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 811 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -811;
	} else {
		printf("Test Case 811 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x18DEDCF753F32CF9ULL,
		0xE67882D7212B4C0CULL,
		0xE4C7DA1C71F352CCULL,
		0xC5F8360E6869576BULL,
		0x19BF1B8FE4EC8532ULL,
		0x021AC75C756FB8A4ULL,
		0x08E5C681B51AD82DULL,
		0x23C9690ADF1B6EE6ULL
	}};
	printf("Test Case 812\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 812 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -812;
	} else {
		printf("Test Case 812 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFB9DFF12559D8CE1ULL,
		0x9FF3EC1553BBE574ULL,
		0x5E85981F43D66FADULL,
		0xC98B131C81DEC90BULL,
		0x8A147FB52D5D3628ULL,
		0x7F3AC7E12DCF35E7ULL,
		0x93FBBE1AAC474FBDULL,
		0x56CA355F4B5BC00BULL
	}};
	printf("Test Case 813\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 813 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -813;
	} else {
		printf("Test Case 813 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCCCDD166424FFC30ULL,
		0x76CF71B0F7CBFB4EULL,
		0x6B449333237A5029ULL,
		0x289A793F2CE04282ULL,
		0x1466D1360E953CFAULL,
		0xEFF44CAB08F7DFFFULL,
		0x5080879DCA7376A7ULL,
		0xB789AEDCA7500008ULL
	}};
	printf("Test Case 814\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 814 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -814;
	} else {
		printf("Test Case 814 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0682049206981EFDULL,
		0x77E13A0448CD69E8ULL,
		0x9ABC1EC1A6A0FB8EULL,
		0x80FDE8763577F92CULL,
		0xADCE45FD38981296ULL,
		0xC17EB27207E60B39ULL,
		0xB1E8F992CA951868ULL,
		0xD990DE09BA87C4E6ULL
	}};
	printf("Test Case 815\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 815 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -815;
	} else {
		printf("Test Case 815 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBFC9B217CEF2AF92ULL,
		0xAF4162C29F3B7515ULL,
		0x1D67CA1FE396C3E7ULL,
		0xDBDA47937749BE88ULL,
		0x4A27B1F15FEF6A8CULL,
		0x0102D2E03A935056ULL,
		0xCEDEF33418AA9425ULL,
		0x37ED23832FF1297DULL
	}};
	printf("Test Case 816\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 816 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -816;
	} else {
		printf("Test Case 816 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x79154CFD1E730D6EULL,
		0x1AF49876F228F897ULL,
		0x002CFFF4AA43EB02ULL,
		0x77700D6571C0BFE3ULL,
		0x67516FD9FB554745ULL,
		0x6DB1BCB316E648CAULL,
		0xB72BDF2F1DB40416ULL,
		0x5AEFC715820B1825ULL
	}};
	printf("Test Case 817\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 817 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -817;
	} else {
		printf("Test Case 817 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1447D196DDF5C7B4ULL,
		0x8FEE322EC78485B4ULL,
		0x0391825531C7FA30ULL,
		0x6B215961C95EE6AEULL,
		0x39E36AB249EC3C58ULL,
		0x47AB54B0347DEEBBULL,
		0x16BE6E11904F79B9ULL,
		0x457549E83E7ADA0BULL
	}};
	printf("Test Case 818\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 818 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -818;
	} else {
		printf("Test Case 818 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3797F7459916AF14ULL,
		0xDA0570A6C42CD6A9ULL,
		0xC29E93F5E594FDDAULL,
		0x2377D260D3BC431AULL,
		0x897CB67085C5B2CAULL,
		0x82190AD42B2E94CAULL,
		0x1A0EC8CCAD13B90BULL,
		0x5B5F2031A3126429ULL
	}};
	printf("Test Case 819\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 819 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -819;
	} else {
		printf("Test Case 819 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x44500E0479648A18ULL,
		0x5B02A85C9957FEF2ULL,
		0xB631E7E8019413C6ULL,
		0x143106190483366BULL,
		0xC4746E26E6CEF69AULL,
		0x6392B0C96BF8ABDDULL,
		0xAD55B5CBF3DD0AC9ULL,
		0xFD351903965F8E6CULL
	}};
	printf("Test Case 820\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 820 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -820;
	} else {
		printf("Test Case 820 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5BAEFDE7DA2AF3ECULL,
		0x0501018CCD37969BULL,
		0xE6EC342D68AA03F7ULL,
		0x3D1AB73A9497A85FULL,
		0x9410A0BA01B64B3CULL,
		0x9903008440FDAC60ULL,
		0xCD2704FBB73024FEULL,
		0xECA2B8B0E87731C0ULL
	}};
	printf("Test Case 821\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 821 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -821;
	} else {
		printf("Test Case 821 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xF6EBACB15AA03DD8ULL,
		0xD891ED81B3605A13ULL,
		0x52314B3AF7FA68BAULL,
		0x642207D5CDE03D10ULL,
		0x6C2F13FFF0E1DF0FULL,
		0x2057FFE63A52B7A0ULL,
		0xC5E36875D3C46D0EULL,
		0x0A4DDB837D3F7F1AULL
	}};
	printf("Test Case 822\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 822 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -822;
	} else {
		printf("Test Case 822 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0206415BA2E287BDULL,
		0xBCAC167B28EB7AE9ULL,
		0xB9C60393FAB2AEB9ULL,
		0x38529F43A0B6F777ULL,
		0x1B62A223FCFE535CULL,
		0xBFCF6097DB8B0075ULL,
		0xF6EF536BDFF43412ULL,
		0x791643D65B52CA12ULL
	}};
	printf("Test Case 823\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 823 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -823;
	} else {
		printf("Test Case 823 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2758C620937493C2ULL,
		0xCC6E0AF3C744F537ULL,
		0xC98107C5E473914BULL,
		0x6B1D78FE06FC5EB0ULL,
		0x8EC89030658428A2ULL,
		0xB99A092DDE27CDABULL,
		0xDD959F313624A938ULL,
		0x497EF89E2A0100BAULL
	}};
	printf("Test Case 824\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 824 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -824;
	} else {
		printf("Test Case 824 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCBA5244425A1F452ULL,
		0x3156B61D6C582B41ULL,
		0x7AA5BAE89CE8510AULL,
		0xE8EB0A1B407C2F3FULL,
		0x20866A5C4CC83F78ULL,
		0x8C4AA3F6A733FD78ULL,
		0xFA23647C717BAA50ULL,
		0x27DD8690D513B63AULL
	}};
	printf("Test Case 825\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 825 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -825;
	} else {
		printf("Test Case 825 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x398B52478412E88FULL,
		0x1E36ED5581D3B547ULL,
		0xB7CA9BE811ED7883ULL,
		0x4869B1F65521D15FULL,
		0xC411BD5B6FB9F110ULL,
		0x1983B92F0034466FULL,
		0x41D3DCD8D07FC064ULL,
		0xB4C8F43658555AECULL
	}};
	printf("Test Case 826\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 826 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -826;
	} else {
		printf("Test Case 826 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x2A238EF2C2ADC8ACULL,
		0xD791A100B98F22B3ULL,
		0x47AACCB15504ABA1ULL,
		0x8635107C568C8472ULL,
		0x5CCF90CFABFE6351ULL,
		0x4779D170D2C7920CULL,
		0x5A4650AD91F3673FULL,
		0x1AB5EC513B785013ULL
	}};
	printf("Test Case 827\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 827 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -827;
	} else {
		printf("Test Case 827 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2C71F8150D4030B2ULL,
		0xC405402FD8F90A17ULL,
		0xA9C0BDBCE42222D3ULL,
		0xB0366AF43FE66E38ULL,
		0x67889848C30678BDULL,
		0xA1DCCD5D3ED6026AULL,
		0xD253F23BEF8D2883ULL,
		0x27079383C2462365ULL
	}};
	printf("Test Case 828\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 828 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -828;
	} else {
		printf("Test Case 828 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA06AA293EDE33CBFULL,
		0x1E3E690273E38280ULL,
		0x170120AD7E7AF837ULL,
		0x61CE26126F9BA5C8ULL,
		0x264DDDE46AFEFE63ULL,
		0xF04AA813C6ECE27AULL,
		0xED2DD448DB4B4947ULL,
		0x5C9C8BE05C0035A7ULL
	}};
	printf("Test Case 829\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 829 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -829;
	} else {
		printf("Test Case 829 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x5719D9AE02B8AE6EULL,
		0x00572B35052106F9ULL,
		0x1ED40B972581A82AULL,
		0xCAE20460C7351008ULL,
		0xABA7BECDB25E7B00ULL,
		0xB9953A8F5A9C5C40ULL,
		0x7D94B1D356B1089DULL,
		0x0BF80822F7D9FC7FULL
	}};
	printf("Test Case 830\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 830 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -830;
	} else {
		printf("Test Case 830 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE5FB8E7A13CC541ULL,
		0x76C2F6FAA9C96641ULL,
		0x94943D29DD040E2BULL,
		0x77AE016E7B4786D0ULL,
		0xE23152353BF80A00ULL,
		0xBD7480EAECDB6E54ULL,
		0x1481AE124EE2F321ULL,
		0xD8DBE261B3A9C038ULL
	}};
	printf("Test Case 831\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 831 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -831;
	} else {
		printf("Test Case 831 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA06F932CFAD32CD2ULL,
		0x27456D65FE4FC5D0ULL,
		0xCCB5375C96080D10ULL,
		0x89DC5D3CC0F256C4ULL,
		0x79C5A72458B5A88FULL,
		0xBFFBC297D1854E7CULL,
		0x36DE65335DCDAAD0ULL,
		0x8B10875BF56BA78AULL
	}};
	printf("Test Case 832\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 832 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -832;
	} else {
		printf("Test Case 832 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDF94D96CF18DE447ULL,
		0x8383CB5648CB9790ULL,
		0x72DE921903F9C953ULL,
		0x1CE32FD90A4DD275ULL,
		0xFDE6F9F868E600F9ULL,
		0x2DFBC605DAD1B11EULL,
		0xE5B15D0611EF3F8EULL,
		0xC63C35C4C2BD0C36ULL
	}};
	printf("Test Case 833\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 833 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -833;
	} else {
		printf("Test Case 833 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2F6B482B7ACE29FBULL,
		0xCCBF4BF44A642774ULL,
		0x2DF0EAC64EEF3706ULL,
		0xB7FAB8E7DBC61964ULL,
		0x37CDCACA82210FBAULL,
		0x02B455110367F523ULL,
		0x2C7FD300644C1FC4ULL,
		0x6C0A7A8E99EA8A4FULL
	}};
	printf("Test Case 834\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 834 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -834;
	} else {
		printf("Test Case 834 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE9C0CAEE421A9096ULL,
		0x5928D5FB472A2AC7ULL,
		0x4D4BCB5D266AF46FULL,
		0x1E3BB98C6B438A48ULL,
		0x0257587953F1C2F2ULL,
		0x2C00789931EBBBBBULL,
		0x099C32764A917EA8ULL,
		0xFAC00259DD052BA3ULL
	}};
	printf("Test Case 835\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 835 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -835;
	} else {
		printf("Test Case 835 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7AEEE6709C003D6BULL,
		0x72F092DDB6012002ULL,
		0x8E95DBA576911130ULL,
		0xF6FF0990A5100CBEULL,
		0x5EAFC3C8CECE9428ULL,
		0xED5FB8D9281CC9BDULL,
		0x6323226E8C95EEBAULL,
		0x789A87AE83498D03ULL
	}};
	printf("Test Case 836\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 836 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -836;
	} else {
		printf("Test Case 836 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE293B4233F103932ULL,
		0x015B766E70075F1AULL,
		0x50C7B91B508BF054ULL,
		0xAA594A6DDCE81DE8ULL,
		0x0546E9EAAF2DA0D5ULL,
		0x6C4FF4DC1653BC7EULL,
		0x1C96A9C8848413ABULL,
		0x4F7C4C0ED41911ACULL
	}};
	printf("Test Case 837\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 837 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -837;
	} else {
		printf("Test Case 837 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2DCAE1819D8079D8ULL,
		0xDD040CCAB79A3001ULL,
		0xBF10CA1541DE7555ULL,
		0x692D90EC7FB30726ULL,
		0xE1ACFAB61C0E21F6ULL,
		0xF842641707421F0BULL,
		0xD9B0B6D6BEBBFFF7ULL,
		0x588422D3049A3AA7ULL
	}};
	printf("Test Case 838\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 838 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -838;
	} else {
		printf("Test Case 838 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB3C5A7026D368DD1ULL,
		0x8E2CF868D67B7B15ULL,
		0x3BB403877DD4BAF6ULL,
		0x6AA004083C06BC3BULL,
		0x322867D8B4F2C188ULL,
		0x52C1EB264EA8FBC3ULL,
		0x87AEC0E45699E773ULL,
		0x7F1BDC34A8BC7936ULL
	}};
	printf("Test Case 839\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 839 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -839;
	} else {
		printf("Test Case 839 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9E7B37ED92E08FD5ULL,
		0x68A66B699FD9E86EULL,
		0x0904C2ABB37DEE42ULL,
		0xAFD774092252E5FFULL,
		0xA83895897E7B8FA8ULL,
		0xDD6A3E440F5069D2ULL,
		0x1A2506FDF213C0C6ULL,
		0xBE75BB12B90640B4ULL
	}};
	printf("Test Case 840\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 840 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -840;
	} else {
		printf("Test Case 840 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC4D1FEF42A069A40ULL,
		0x0292C0B295A4030FULL,
		0x9E488549F1726F47ULL,
		0xD3E623CA58943F75ULL,
		0x6640D76750988732ULL,
		0xF38A628308FD0532ULL,
		0x3338D0981964794BULL,
		0xB8E6932F68C0E1FFULL
	}};
	printf("Test Case 841\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 841 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -841;
	} else {
		printf("Test Case 841 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x464B8BBA2F53A3A7ULL,
		0xA29521E837FD326BULL,
		0x5FFCFE7556023258ULL,
		0xAC5AD4BF8D6DB8C4ULL,
		0x706BA0B76AF7EBEBULL,
		0x1C272F49AA757279ULL,
		0x1E8B2A3EACE6707AULL,
		0xF86E0B41CE587053ULL
	}};
	printf("Test Case 842\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 842 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -842;
	} else {
		printf("Test Case 842 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x149E1F608251FA9AULL,
		0x4A3208480E2D3A00ULL,
		0x437F85F2DB4A2DF1ULL,
		0x2485BF31A01EC346ULL,
		0xFF9A817DA3457EECULL,
		0xA1F5BA5D6C68601CULL,
		0xA3B4C5BF1BD31F1AULL,
		0xE4C7754A15256730ULL
	}};
	printf("Test Case 843\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 843 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -843;
	} else {
		printf("Test Case 843 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x35577C27D4D943ACULL,
		0xC245C3919356D4CBULL,
		0x504C5C8C4867F8DDULL,
		0x3D3B2A9F320DDE76ULL,
		0xCDF6EC167CB8017AULL,
		0x69CC3ABB599F1B3BULL,
		0x67533D94FE1C2031ULL,
		0x6CE72095328603E8ULL
	}};
	printf("Test Case 844\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 844 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -844;
	} else {
		printf("Test Case 844 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9BC5D54F8A886013ULL,
		0x785924F25B0F2B31ULL,
		0x2F8BA6909EE0AFD4ULL,
		0x93D1D3DE27FBE472ULL,
		0xF605FB62432AFD11ULL,
		0x5ECEE0C60E042911ULL,
		0xC5F814C9D2F1CC1CULL,
		0x2246D8E94CF62C36ULL
	}};
	printf("Test Case 845\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 845 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -845;
	} else {
		printf("Test Case 845 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6E7DF11334AD0279ULL,
		0x701A8BEC1AB3BB44ULL,
		0xE5C87BC19E62F4C2ULL,
		0x426E1D642A4A36CEULL,
		0x4A69ABC525B43FD6ULL,
		0x8DA5464F997F356CULL,
		0xFE7BF4866DC013F1ULL,
		0xDC36837B2C0E4975ULL
	}};
	printf("Test Case 846\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 846 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -846;
	} else {
		printf("Test Case 846 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x51939C295FF924B1ULL,
		0x53604CC736539E5CULL,
		0x1245B87FA7AD8E7DULL,
		0xCE4AA4B24C2377F9ULL,
		0x6846874E050BAB7DULL,
		0x77DA99E058F5D4FEULL,
		0xC1A3A6B658B0BFEAULL,
		0xBD93C09169FAF8BEULL
	}};
	printf("Test Case 847\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 847 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -847;
	} else {
		printf("Test Case 847 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7FB35618FBD15C70ULL,
		0x7EDBAFC0B1F4F532ULL,
		0x6E656B1FB74C509BULL,
		0x8626BD45CD58D28EULL,
		0xBEE1751AFCFA6419ULL,
		0x9EDF14A4E2489B0EULL,
		0x1D9CB5ED9417C8C1ULL,
		0x83F948F2650A87F6ULL
	}};
	printf("Test Case 848\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 848 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -848;
	} else {
		printf("Test Case 848 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5FE060DC2793F65FULL,
		0x8910AB7E67ACBF18ULL,
		0x006EF5180F40F9A7ULL,
		0x3A799A8FFF7F7E1FULL,
		0x4BC8AE07AF9E6162ULL,
		0x943CC020D9352D42ULL,
		0x22A173E108A1FB43ULL,
		0x672701DA9081C61FULL
	}};
	printf("Test Case 849\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 849 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -849;
	} else {
		printf("Test Case 849 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDDF24748B03D965AULL,
		0xFD339D2636A31F96ULL,
		0x8A593E2C994CFBE8ULL,
		0xD96B27C0AF1CB46FULL,
		0xA813A9329F13326EULL,
		0xB45D15EAE714AA87ULL,
		0x3FEA1406C6431717ULL,
		0xC468948E4CBA969CULL
	}};
	printf("Test Case 850\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 850 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -850;
	} else {
		printf("Test Case 850 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x490D0C310959B0D9ULL,
		0xACD843D1050B6067ULL,
		0x15A249C2BA513AC5ULL,
		0x45505E2F2334F404ULL,
		0xBA0D5E2762AA4370ULL,
		0x78D74217FC079DDEULL,
		0xF4D3B507953003ABULL,
		0x5A11894D8A870192ULL
	}};
	printf("Test Case 851\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 851 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -851;
	} else {
		printf("Test Case 851 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6C97768B0A4511C6ULL,
		0x5DF522697E17FDE0ULL,
		0xD4C20169B7DF6D5BULL,
		0x9CB8743A9A04D035ULL,
		0x1D7C7096329B5EA6ULL,
		0x908C99808053EF64ULL,
		0x03E53745D955D5B3ULL,
		0x43463E19EC11BD7CULL
	}};
	printf("Test Case 852\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 852 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -852;
	} else {
		printf("Test Case 852 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x68FAEFE13EFB4B6EULL,
		0xE5749E7A57BE6295ULL,
		0x4EF2C02396A24763ULL,
		0x9FC9681EDF7A64B8ULL,
		0xBC28D718F16E72E6ULL,
		0x500776680290A566ULL,
		0x85A07DA6E9655595ULL,
		0x3F8386586E606811ULL
	}};
	printf("Test Case 853\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 853 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -853;
	} else {
		printf("Test Case 853 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBAC94DF602BB71CULL,
		0x91C9EF8CA1D60579ULL,
		0xC6C638512EF1CB31ULL,
		0x3A07EE4499655634ULL,
		0x978428A37E971CC1ULL,
		0xB085ED78DBD9015CULL,
		0xC6F09F590FCCAE80ULL,
		0x81899BB727894D8AULL
	}};
	printf("Test Case 854\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 854 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -854;
	} else {
		printf("Test Case 854 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF967ED01AECABC74ULL,
		0x9BA85E630A837626ULL,
		0xA5F35F7E22917047ULL,
		0x44DD541ECDFEB29BULL,
		0xCA3B8827DBFF1998ULL,
		0xE3AB1670E970B976ULL,
		0x2DB24828E8604127ULL,
		0xE53C2AEDFF72EA81ULL
	}};
	printf("Test Case 855\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 855 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -855;
	} else {
		printf("Test Case 855 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7A6E7753F701B183ULL,
		0x08B62E17BAD6CC06ULL,
		0xDBC6C925D99D5B39ULL,
		0x2D11211DE496E13DULL,
		0xD04720BEE3554B19ULL,
		0xB6EE74D9ADC752F7ULL,
		0x8A0C3ABDAD6777C6ULL,
		0x6E937D8AC39999F1ULL
	}};
	printf("Test Case 856\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 856 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -856;
	} else {
		printf("Test Case 856 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD230CD6A79EE0D2DULL,
		0xD91A2728EEA38611ULL,
		0x8881B8DEC55AE609ULL,
		0xD979C7E5D892C574ULL,
		0x072972590A6E1553ULL,
		0x62175DA4BE846F9CULL,
		0xFB5FBF121B2AE00EULL,
		0xFDEE167D51702766ULL
	}};
	printf("Test Case 857\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 857 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -857;
	} else {
		printf("Test Case 857 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x64ECB55AB0FD143DULL,
		0xE64E2096E0132BE5ULL,
		0x5BBD804B75F46926ULL,
		0x965E9F0700611306ULL,
		0xE728847F468B3AEAULL,
		0x9B5F152D43EE61CAULL,
		0xFC3AD82DDF1ABE4AULL,
		0x199E63B1079283DFULL
	}};
	printf("Test Case 858\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 858 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -858;
	} else {
		printf("Test Case 858 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2AFEE065B47D42D7ULL,
		0xBF222C681DF1469EULL,
		0xC00933DC2179D29BULL,
		0xB6B27F5D2EC300D7ULL,
		0xA877F7C010683F7CULL,
		0x181EA80A6CA39154ULL,
		0x26EDAA161F6FFEBEULL,
		0x8315E35624157CD7ULL
	}};
	printf("Test Case 859\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 859 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -859;
	} else {
		printf("Test Case 859 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x632F55E2E90BFE3AULL,
		0x80C0A3854760A58FULL,
		0x8781D37C03EB5C74ULL,
		0x643F9BBDD4AF36B6ULL,
		0xA7DC2B0D600AA0A7ULL,
		0x65FDB29460C162E4ULL,
		0x86E3E225E999A129ULL,
		0x5B0982B2B6F7B81EULL
	}};
	printf("Test Case 860\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 860 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -860;
	} else {
		printf("Test Case 860 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x98519A8EF4FE5E62ULL,
		0xB202B124AFF2EE51ULL,
		0xCEA1BF549BE46CEFULL,
		0x37B83623474186A8ULL,
		0xAAAD5FC07EED1A2FULL,
		0x539ECFE75322F198ULL,
		0x8D78B1BE96A3A078ULL,
		0xCAE578F494C209AEULL
	}};
	printf("Test Case 861\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 861 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -861;
	} else {
		printf("Test Case 861 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x15EC9E5B10DB13CCULL,
		0xF8AAE4AD7B546CC1ULL,
		0x26CE3E98FB3DCC03ULL,
		0x736EBA2B1E0F8A9EULL,
		0xBA7051CF188FED51ULL,
		0x03F6D6A4F5525F2AULL,
		0x2EBD2299ABAF2668ULL,
		0x25D0DAFF383D825CULL
	}};
	printf("Test Case 862\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 862 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -862;
	} else {
		printf("Test Case 862 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x99E9E33D4BE86F42ULL,
		0xB8C2E529B8EBF78BULL,
		0x3B06333C0709A574ULL,
		0x4EEAA1EC980DE72CULL,
		0x72017D98EB5AF694ULL,
		0xA9803EFDFBFB1CC3ULL,
		0xF6E47A6259BABEF8ULL,
		0x5E90899B2611898BULL
	}};
	printf("Test Case 863\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 863 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -863;
	} else {
		printf("Test Case 863 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x74F0D2E8D75ACC89ULL,
		0x88CA7A36AC267E3EULL,
		0xE8977F8B5B0751DCULL,
		0x696AC14457DE07CDULL,
		0x44979C9E7408D88FULL,
		0xC0D02A5093DF4C1FULL,
		0xE47036611AA515E5ULL,
		0x9A0FF148A5577A92ULL
	}};
	printf("Test Case 864\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 864 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -864;
	} else {
		printf("Test Case 864 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3AA72D42F4ACA185ULL,
		0x2A16EF3FC8FDD6C7ULL,
		0x8761527F37939952ULL,
		0x8FCAFF5C2DF5CB6CULL,
		0xFC7EF86779D5A130ULL,
		0x4E798EB9EB6ADBC6ULL,
		0x09131AA7F6F85705ULL,
		0xE805C12587885042ULL
	}};
	printf("Test Case 865\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 865 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -865;
	} else {
		printf("Test Case 865 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCEF6A2E6682E4C85ULL,
		0xB4DD5910535FAD25ULL,
		0xEE55C558F5A44AAAULL,
		0xE954E2E7A9C3DBDCULL,
		0x0575FCBE14308FABULL,
		0x92A2A7C9AA45B052ULL,
		0x45DCE0218A5DAE09ULL,
		0xBF85AD7698D953EBULL
	}};
	printf("Test Case 866\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 866 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -866;
	} else {
		printf("Test Case 866 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE0E0DD5D7EF5B1C5ULL,
		0x0A9BCA129915F99AULL,
		0x8762E34B1303CBF9ULL,
		0x9029AAB6F5D3A56FULL,
		0xAFFE2BB632F9223DULL,
		0x29A89567DDC897C2ULL,
		0xC80EE33B384FC9DFULL,
		0xC9E25ADEF7F1577DULL
	}};
	printf("Test Case 867\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 867 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -867;
	} else {
		printf("Test Case 867 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCD3F93FA131F1D0DULL,
		0x581157CFC1B85A99ULL,
		0x6667374BADAAAFE1ULL,
		0x4F0B942109233B8FULL,
		0xFD94A3E11885D83AULL,
		0x288DF3CD12928E21ULL,
		0x6BB035D55B788CDDULL,
		0x5D8ADD717C1754B6ULL
	}};
	printf("Test Case 868\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 868 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -868;
	} else {
		printf("Test Case 868 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD535BEBD0BD1876CULL,
		0x996A31B93F28698FULL,
		0x5830A328E04FE5DAULL,
		0xB2D4EF143B6D593EULL,
		0x565C7D89F1898972ULL,
		0xD7B1F8537EF83D2BULL,
		0x9F1BD121A8AEEA59ULL,
		0x7D12863550F7DF80ULL
	}};
	printf("Test Case 869\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 869 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -869;
	} else {
		printf("Test Case 869 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD64FBF5EDFA63C5CULL,
		0x025E1DA8BAAF182CULL,
		0x2F58D06C0DB0B2EBULL,
		0x0F1C51669D55D124ULL,
		0x02BCFFCFDC7FA49EULL,
		0x2527DBC05BEC26B9ULL,
		0xF155873A0DF65B82ULL,
		0xB65034F1146E8392ULL
	}};
	printf("Test Case 870\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 870 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -870;
	} else {
		printf("Test Case 870 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x06CBB00D58536B38ULL,
		0xAB94097AA414D071ULL,
		0xDF7E851A83E1B22FULL,
		0x71523CDAC229BBC8ULL,
		0x695F7149BEC3C9EDULL,
		0xCAC2B36998B18C2AULL,
		0xB5384152787AAD86ULL,
		0x4F40C54F9CD2751AULL
	}};
	printf("Test Case 871\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 871 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -871;
	} else {
		printf("Test Case 871 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x55CD8C1827102A4CULL,
		0xC11AA5D211E0B525ULL,
		0xFE7CFD8DE6C72E4EULL,
		0x35A2911A2F959ED0ULL,
		0x4E51ABDF8A49027FULL,
		0x6AD3F14650D2E190ULL,
		0x83011EB442A807AAULL,
		0xE86A2D7B488EC675ULL
	}};
	printf("Test Case 872\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 872 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -872;
	} else {
		printf("Test Case 872 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7C160BC16BACD539ULL,
		0x63303D5342A80898ULL,
		0x5ABD05C7414AE6D5ULL,
		0xF3B0E879576B38B6ULL,
		0x99BCAB75FDCBB370ULL,
		0x91B4DCE9AF5AEBB0ULL,
		0x457635320730C097ULL,
		0x3ACEB3DEFB25144BULL
	}};
	printf("Test Case 873\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 873 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -873;
	} else {
		printf("Test Case 873 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEB1333D0CB40CCB2ULL,
		0xCFA1D42A8995CC6EULL,
		0x375D55CCFBFE6B58ULL,
		0x53FD77BFF8A0B755ULL,
		0x164D58E7A1969AC6ULL,
		0x27C6D31B5F0BE8FCULL,
		0xD231F8A95291FF5FULL,
		0xAFC3854A1CB7AAF2ULL
	}};
	printf("Test Case 874\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 874 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -874;
	} else {
		printf("Test Case 874 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x988D55C1AE4684A9ULL,
		0x5889D63587DC1FBEULL,
		0xF691433DBBB6BB3EULL,
		0xEED0B3E6D7A41B9AULL,
		0x8F946C898489AA66ULL,
		0xE16F4B8927CE9279ULL,
		0x73887B1A06C7C009ULL,
		0xA1C15E129F41D014ULL
	}};
	printf("Test Case 875\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 875 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -875;
	} else {
		printf("Test Case 875 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA49A15BC576D95F1ULL,
		0xEA6BC2DB3D4B274AULL,
		0xAAC9AC06066D04AEULL,
		0x7753BA5EC46D9268ULL,
		0x8F6BDFFBFDBB70D8ULL,
		0xFE223876B6922D73ULL,
		0xB8B923CCD92FD267ULL,
		0x2741060F1E7EAA6EULL
	}};
	printf("Test Case 876\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 876 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -876;
	} else {
		printf("Test Case 876 PASSED\n");
	}
	printf("---\n\n");
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xA68C278AEF867B6EULL,
		0xFC40EDF0CAA7696EULL,
		0xD9C85326A47DCAF0ULL,
		0x9AAB8C26E288EA61ULL,
		0x1742DF52C7CD7820ULL,
		0x553CD028CB975939ULL,
		0xBE8B8556F112E4C8ULL,
		0x012313D9EC29DC27ULL
	}};
	printf("Test Case 877\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 877 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -877;
	} else {
		printf("Test Case 877 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDFDE107D0340DE32ULL,
		0xBA67108E09437C17ULL,
		0x58C1561AF8FF7A97ULL,
		0x6266D197ACA0547CULL,
		0xA0A87664FE4ACE5CULL,
		0x5D593EF143DA84EAULL,
		0x4B12E2A947365878ULL,
		0xDF71DD2F6F0E4997ULL
	}};
	printf("Test Case 878\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 878 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -878;
	} else {
		printf("Test Case 878 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x60221D4AF7998662ULL,
		0x0390AD0D19CCB918ULL,
		0xC1A90FAE8EF28DEBULL,
		0x26D48DD1F8C5DC3CULL,
		0x6306EC5314A1BDC5ULL,
		0x69B99EC3D5B0A8CDULL,
		0x89C93C1DF861645AULL,
		0xB87B1C852D95888CULL
	}};
	printf("Test Case 879\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 879 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -879;
	} else {
		printf("Test Case 879 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCE1B48956CEE4171ULL,
		0xF15327977BB98041ULL,
		0xA38C04F0BE092E3DULL,
		0x7FCD64BA2AFA19C0ULL,
		0xDBA425834022947EULL,
		0xB0DCDD990B1BCD04ULL,
		0x2C7EBDFB79094D43ULL,
		0x769DAC89323694E7ULL
	}};
	printf("Test Case 880\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 880 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -880;
	} else {
		printf("Test Case 880 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD3876EBF705B2854ULL,
		0x5CD70BE8C3D44784ULL,
		0x3CE458E98ECB07DBULL,
		0x7912A91F622CE7ABULL,
		0x025DD8B731DC19F2ULL,
		0x74D7BB9EE42FE6DEULL,
		0x7E421ACB9804D586ULL,
		0x7B14358E9DCC231AULL
	}};
	printf("Test Case 881\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 881 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -881;
	} else {
		printf("Test Case 881 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB71A4E0BCE9ADE7DULL,
		0xB3F7852F37485916ULL,
		0x671576D29A3125EFULL,
		0x7E051D54C777AF1EULL,
		0x964C605779FBBE68ULL,
		0x0708FFE7F446AEABULL,
		0xB693FF1420A763CDULL,
		0xEA783F50E9BF8C35ULL
	}};
	printf("Test Case 882\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 882 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -882;
	} else {
		printf("Test Case 882 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x47DEF2822850145DULL,
		0xC5F6A5CE6D0FBD99ULL,
		0x2B3B98B1686CB064ULL,
		0x6F8B0948B75BFC9DULL,
		0x00B2512EADBE5C77ULL,
		0x3AF0D9F78002C3C5ULL,
		0x8A2177F90BEA3D8DULL,
		0x2BDEE79D72EEF09BULL
	}};
	printf("Test Case 883\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 883 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -883;
	} else {
		printf("Test Case 883 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC98E1BA7E8BC5897ULL,
		0x8AFD743C3892E66EULL,
		0x69466E59DCFBE283ULL,
		0x726C5A7898595D75ULL,
		0x4069D7235F0237CBULL,
		0x9292B63C45D6452EULL,
		0xFCD2A57AF4B2481EULL,
		0x45794FC1C02F43F7ULL
	}};
	printf("Test Case 884\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 884 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -884;
	} else {
		printf("Test Case 884 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA9A50A1467FFA39FULL,
		0x8409B44A4F1AEC9FULL,
		0xE7B6CBB79CCC6E5CULL,
		0x0F57869FA54451F1ULL,
		0x3F4A61C976A2D34BULL,
		0x8D09C11F4CD1C8A9ULL,
		0x956BB3E772DCD625ULL,
		0x62D7434A2334CEAFULL
	}};
	printf("Test Case 885\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 885 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -885;
	} else {
		printf("Test Case 885 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE863D1D2D542AC2AULL,
		0x37044D4BDC283D13ULL,
		0x734D03B6232BA31FULL,
		0xEABDD58FAA0069CDULL,
		0xA42898D7C9371E79ULL,
		0x574A105CE43537BDULL,
		0xF2AF886F0DCA909FULL,
		0x23618F9A2B1A9EC7ULL
	}};
	printf("Test Case 886\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 886 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -886;
	} else {
		printf("Test Case 886 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x01881C1A1577E2D3ULL,
		0x1518A430BD7D28CCULL,
		0x5508099C104D8914ULL,
		0xE26B5F077FB84517ULL,
		0x0F521A766A30597CULL,
		0x174B0E32C30B191EULL,
		0x0848A02E71BD3DF9ULL,
		0x04B0A623DA537B16ULL
	}};
	printf("Test Case 887\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 887 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -887;
	} else {
		printf("Test Case 887 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9BB743D63C008CB4ULL,
		0x31106794E4B75914ULL,
		0x89821C8B82CC33E6ULL,
		0xD01590E984A128A2ULL,
		0x336169E2D3BE2FCEULL,
		0xD5A403BFDF159A9BULL,
		0x74B1EB84B11FBCD7ULL,
		0xCCB830BF508B6601ULL
	}};
	printf("Test Case 888\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 888 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -888;
	} else {
		printf("Test Case 888 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC02319480CC22F46ULL,
		0x53BE99CA52BA73A1ULL,
		0xA348314F27400DA6ULL,
		0xBF588D19D3C018AAULL,
		0x0F4E34818275D21FULL,
		0x51D6D8FB71D11518ULL,
		0xCDD853EC8649CB49ULL,
		0x35B5C11BAF4E6FCBULL
	}};
	printf("Test Case 889\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 889 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -889;
	} else {
		printf("Test Case 889 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5BD2EDAB61D7397DULL,
		0x12513AD622D65364ULL,
		0xD554A620A8A91865ULL,
		0x1DDE5B2FDE1A41F3ULL,
		0xE8A35DF40279C231ULL,
		0xE14A7D574BE213E3ULL,
		0x649231E39A6BE72BULL,
		0xA150301357BF58FCULL
	}};
	printf("Test Case 890\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 890 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -890;
	} else {
		printf("Test Case 890 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4C43A3DA2119DAF3ULL,
		0x60C8D1EB8A292796ULL,
		0xB237F459D979161BULL,
		0xADA061870009BE68ULL,
		0x8F174ABEDDD1ECCDULL,
		0x5C2ED6ABD6385C5AULL,
		0x34B3B9CCBC85037DULL,
		0x72C352544BB225A6ULL
	}};
	printf("Test Case 891\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 891 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -891;
	} else {
		printf("Test Case 891 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x77229DD8C7BC617DULL,
		0x0DE1FC3F48E83BF8ULL,
		0x36B8D693F7E5E335ULL,
		0x17FF6B49F7370865ULL,
		0x272F81B7E33CD525ULL,
		0x0544E33066728CAFULL,
		0x71452480E81B7BAFULL,
		0x245307E3760E9CF8ULL
	}};
	printf("Test Case 892\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 892 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -892;
	} else {
		printf("Test Case 892 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC66E3449A47C5C21ULL,
		0x0B6F8D10D34D9316ULL,
		0xD1770A4093648822ULL,
		0x1A307069DB027A0BULL,
		0xBA513FCC1CBEBB83ULL,
		0xDFA67034BA25EB48ULL,
		0xDF6C104E87759B7DULL,
		0x83DD40D660EDC175ULL
	}};
	printf("Test Case 893\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 893 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -893;
	} else {
		printf("Test Case 893 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDCAAFA49A7515F5EULL,
		0x42433B22870AFA14ULL,
		0x34DFAA6A28AD1FF0ULL,
		0x5DB22DE93335DDDAULL,
		0xD3BDFBCD268C25EDULL,
		0x64CA1852D6E6FD3DULL,
		0x1D07D76DB1E44FB1ULL,
		0x4BFBB71E4FAD565DULL
	}};
	printf("Test Case 894\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 894 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -894;
	} else {
		printf("Test Case 894 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8C1613BF9C740054ULL,
		0x975527F1C19F4E9DULL,
		0xDAB6FC99347488E0ULL,
		0x8D48CFDD0C49BEA3ULL,
		0xF4BBCA046AB91BA0ULL,
		0xF29082AE08BFC145ULL,
		0xAC9C45B9B88322D6ULL,
		0x61A1628D1C471B2DULL
	}};
	printf("Test Case 895\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 895 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -895;
	} else {
		printf("Test Case 895 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAE8C681F72111CACULL,
		0x43DAE3423C507568ULL,
		0xAFB5528129059973ULL,
		0x73BE64685C80DFA6ULL,
		0x76AF5B7F8AF5B0A3ULL,
		0x8870152146190CCAULL,
		0x592D05A5BAFD2F90ULL,
		0x6093EF410334ABEBULL
	}};
	printf("Test Case 896\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 896 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -896;
	} else {
		printf("Test Case 896 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x25166EAFEE48521BULL,
		0xD2E6241D93539991ULL,
		0x66E5A625078ED58DULL,
		0x97349F5F7AD02606ULL,
		0xFF28BA591B375261ULL,
		0x74A84FF402D0F763ULL,
		0x38A8557BF8D8A12CULL,
		0x5C693AC029454F38ULL
	}};
	printf("Test Case 897\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 897 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -897;
	} else {
		printf("Test Case 897 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x027634CC340FCCD6ULL,
		0x211396DEFC686EE9ULL,
		0x2EB7CADDEE683378ULL,
		0x278C986D9B18457DULL,
		0x1C38711A84EAEE9CULL,
		0x0C817390F1D00CD1ULL,
		0x08274D72C589BB84ULL,
		0x9F83ACEE34443A80ULL
	}};
	printf("Test Case 898\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 898 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -898;
	} else {
		printf("Test Case 898 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x37EA11ED3CCF5BA9ULL,
		0x8C76C3F31B8381ACULL,
		0x55E82EAD19F72F07ULL,
		0x09DDCB43DF559A0DULL,
		0xFA9C1B247E24D02EULL,
		0xEA1D480318E30E47ULL,
		0x0CFD8FFA71390392ULL,
		0x682E9477A8A11E4DULL
	}};
	printf("Test Case 899\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 899 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -899;
	} else {
		printf("Test Case 899 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFDCB07CFAF8A92DBULL,
		0x9EEF9E4A4A4D6EBEULL,
		0x3E3B4762172C157FULL,
		0xB9606247A264F1FCULL,
		0x312D69AEEEC433E8ULL,
		0x86656E0C095F15BEULL,
		0xDA3CDEB9EC84FB8CULL,
		0x6C5B7F8681A464C8ULL
	}};
	printf("Test Case 900\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 900 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -900;
	} else {
		printf("Test Case 900 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE532440E8A7393C8ULL,
		0x927FDE3EA4781796ULL,
		0xD7C591ACE83F5522ULL,
		0x5463E46FEB33F4C2ULL,
		0xBA538D9BD3E1B606ULL,
		0x179A15DE2B34323CULL,
		0x136BDFEF88D437C5ULL,
		0x92F882BD8C6CD4B7ULL
	}};
	printf("Test Case 901\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 901 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -901;
	} else {
		printf("Test Case 901 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x37B8E0F42AD53BEAULL,
		0x5F4EBEF504E072B2ULL,
		0xA24714B60F0CF00FULL,
		0x7C937AD03A1FFCB5ULL,
		0x22C9BD660B9EC880ULL,
		0xA6BC4345D1F89F9CULL,
		0x73FB852E88F8E560ULL,
		0xC6CA7D047C9B4B2FULL
	}};
	printf("Test Case 902\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 902 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -902;
	} else {
		printf("Test Case 902 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0BC2E2C18B5913DDULL,
		0xED5304A5894E0CC0ULL,
		0x970E9218A8161D5BULL,
		0x3A5D296701F4A557ULL,
		0x711269234E5A555FULL,
		0xA526036D063BB773ULL,
		0xA2140C83BFF6B718ULL,
		0xAB4CA7DFB4015AABULL
	}};
	printf("Test Case 903\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 903 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -903;
	} else {
		printf("Test Case 903 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x19348C29A26B8135ULL,
		0x9654360F76ED1AD9ULL,
		0x33009359DE84E9A4ULL,
		0x18EF4FDFFDE093A4ULL,
		0xF88DA8913F407650ULL,
		0xA77BD2EC33062283ULL,
		0x5C9193A6CB5714F1ULL,
		0xD4022B3FD7E41127ULL
	}};
	printf("Test Case 904\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 904 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -904;
	} else {
		printf("Test Case 904 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE05100373F151B6FULL,
		0xF8B387B8B477A689ULL,
		0xE749AD18EC7A65F2ULL,
		0xBAB59732F8BB6267ULL,
		0xDB61551344D76FD0ULL,
		0xA73FC4F034D6AB63ULL,
		0x53F647CEB41BBC1FULL,
		0x92D9C3D650A91101ULL
	}};
	printf("Test Case 905\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 905 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -905;
	} else {
		printf("Test Case 905 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD4F06D1022EAB7A8ULL,
		0x7E93C4EAF009BBBCULL,
		0x5C60035E98D016E4ULL,
		0xA5F3603153E201E1ULL,
		0x93C76D013FDFE4AEULL,
		0x41926F68271049B4ULL,
		0x84B0011FB79C8107ULL,
		0x9C6E9AD7C0C91AC9ULL
	}};
	printf("Test Case 906\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 906 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -906;
	} else {
		printf("Test Case 906 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B3266454857F7DEULL,
		0xE1690FE16523E79AULL,
		0x1EA8B8058934513FULL,
		0x4E4074A6D02A20F0ULL,
		0xFD5FE2D7F9A66F36ULL,
		0x5EE7139DAD35D8DFULL,
		0x9A47DF00A3974261ULL,
		0xA581350C20850E35ULL
	}};
	printf("Test Case 907\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 907 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -907;
	} else {
		printf("Test Case 907 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x17EF0B9E89E0BC15ULL,
		0xEAECF2951B17E09CULL,
		0xDF12CBE99C9BF9D7ULL,
		0xFE4DB4C012AED3C0ULL,
		0xBEFB3FEA56AE8379ULL,
		0xAD2F7BBC6CAA5FF9ULL,
		0x8B0A42D89AE90B2BULL,
		0xD00FCA18F5F50CE5ULL
	}};
	printf("Test Case 908\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 908 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -908;
	} else {
		printf("Test Case 908 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4B13CDF1BDA32B62ULL,
		0x20E53673C59C2291ULL,
		0x0819BB84D16BD0F4ULL,
		0x055CD86317EB26CEULL,
		0x0E6063C1174D3D1EULL,
		0x77BD2D5E194303DBULL,
		0xBA977B8287FDA7EBULL,
		0x7C39E46E2A3C143EULL
	}};
	printf("Test Case 909\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 909 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -909;
	} else {
		printf("Test Case 909 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x02EDE874FCA311E0ULL,
		0xC13B39844E063D6BULL,
		0x48B12838BE2DF15CULL,
		0x35C9582E328ACED1ULL,
		0x232CC187B2C5A5D2ULL,
		0x1D54A88783CC9991ULL,
		0xF73ED55D8EB3833FULL,
		0xAAD28F16C41ABDFDULL
	}};
	printf("Test Case 910\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 910 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -910;
	} else {
		printf("Test Case 910 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBAF9A876F22E4E59ULL,
		0x495178AB0C1C0EE1ULL,
		0x9933E99A21C3DF5AULL,
		0xBD1CA7567D4E8807ULL,
		0xAA3801EE2D208D78ULL,
		0x5A6309B42D0CEDE1ULL,
		0xF96AB6268730F32CULL,
		0xA140A4237A053FAFULL
	}};
	printf("Test Case 911\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 911 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -911;
	} else {
		printf("Test Case 911 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x73C08C496385AD9BULL,
		0x72E472A6D69C4F72ULL,
		0xA356B690C128D5AFULL,
		0xC767FFBA9CD6D6A5ULL,
		0xFED3F0F57D980952ULL,
		0x82812E22A155E499ULL,
		0x50309168E85A67F5ULL,
		0xE15BD501D8CAB43DULL
	}};
	printf("Test Case 912\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 912 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -912;
	} else {
		printf("Test Case 912 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xADECCB2F60BE4397ULL,
		0xC856D0D5268CD485ULL,
		0x8BE49C4B119545F6ULL,
		0xD0FC4CD4BC0FFB04ULL,
		0x76B0D722B2D9E4DBULL,
		0x09ADB1B8B96B67D2ULL,
		0x5BE048E100AFEAFAULL,
		0x9BB422AD8FB57FFDULL
	}};
	printf("Test Case 913\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 913 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -913;
	} else {
		printf("Test Case 913 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x04C2CF78D944AEACULL,
		0x0F9DA4F72E90955AULL,
		0x25C15EA4302A5AF2ULL,
		0x44D4406A72E1F5E0ULL,
		0x6ACE3BDA7875FD0EULL,
		0xDD2BB3CF3A3B8FF8ULL,
		0xF0FEA134D152CB04ULL,
		0xEDC5E600E842037DULL
	}};
	printf("Test Case 914\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 914 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -914;
	} else {
		printf("Test Case 914 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4387C44CD28FE658ULL,
		0x3A585018A653542DULL,
		0xF53AAEBF36439E88ULL,
		0x3105A937040648E5ULL,
		0x6E97C000E14D9F17ULL,
		0x27C77019EC186147ULL,
		0x868D13EA1F755AA3ULL,
		0x3FE63B8EAA55E882ULL
	}};
	printf("Test Case 915\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 915 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -915;
	} else {
		printf("Test Case 915 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB953F092053FF52EULL,
		0x322540A8F4D0CA47ULL,
		0xF9FC3454C1DE6F8EULL,
		0x949C26C28C887E42ULL,
		0xB8731CC004B3A583ULL,
		0x31948B4495FB8EB0ULL,
		0x205AEC6BEE1B6628ULL,
		0x6A8D5F455689B2C0ULL
	}};
	printf("Test Case 916\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 916 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -916;
	} else {
		printf("Test Case 916 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x416E1FF8F6ECD72EULL,
		0xA38693BE3DB12C58ULL,
		0x10969555DE65AA74ULL,
		0x22F23685399B1490ULL,
		0x8D2B1C27219E5452ULL,
		0x77E1E7E2B99AD485ULL,
		0xEE21B15F7FA5FEB1ULL,
		0xF9291A6D5FC0D46DULL
	}};
	printf("Test Case 917\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 917 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -917;
	} else {
		printf("Test Case 917 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB502A8D7FAC54896ULL,
		0x0C721D1166114F75ULL,
		0xC6AEE68F4CD377B2ULL,
		0xBA40E0EAE080A5C1ULL,
		0x9CAD582E75D8096FULL,
		0x0822C6297D3A9DBCULL,
		0x1BCCB1051CADF227ULL,
		0x74F206BDCA35817BULL
	}};
	printf("Test Case 918\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 918 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -918;
	} else {
		printf("Test Case 918 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC2EC07BB00525DDFULL,
		0x1774DC680341C3CEULL,
		0xE6503376BDC1259AULL,
		0x0486007698C8870BULL,
		0x52FCDF9762D3DD4BULL,
		0xF2CC5EDF1C92AFECULL,
		0x9EB800040AC70308ULL,
		0x2269C66BB61051ACULL
	}};
	printf("Test Case 919\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 919 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -919;
	} else {
		printf("Test Case 919 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x524756425D752988ULL,
		0xB01739633515710BULL,
		0x41B2750B33A60B2DULL,
		0x1B80A8FBDD711636ULL,
		0x35F577879F74D78BULL,
		0xD884E57B6FC75C60ULL,
		0xF1EE467F57322A51ULL,
		0xCE986822DD422D39ULL
	}};
	printf("Test Case 920\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 920 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -920;
	} else {
		printf("Test Case 920 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x07443048388C4EB6ULL,
		0x5180DD9319DCCE9BULL,
		0x88520367E6FF977DULL,
		0x57BB665EC54E92C2ULL,
		0x48D52392AEAFC7E6ULL,
		0xCB56AF7892EF15DFULL,
		0xDF0E0BFC5E05DA10ULL,
		0xD732B56584A2566BULL
	}};
	printf("Test Case 921\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 921 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -921;
	} else {
		printf("Test Case 921 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB8491AA25A0DE3E8ULL,
		0x903607D67A219134ULL,
		0x2D52756835182295ULL,
		0xB0D88D4B744EA1A1ULL,
		0x763EEA4669938E48ULL,
		0xDC1B16E6CC5DA321ULL,
		0xDD6F0D983B781D3BULL,
		0x5E0CF2075932688EULL
	}};
	printf("Test Case 922\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 922 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -922;
	} else {
		printf("Test Case 922 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x83D9A0829D7622A5ULL,
		0xDCD441E83A968E76ULL,
		0x546516D78BBF1297ULL,
		0x4DAD1249BA34FE3FULL,
		0x3DC432A8CF09059CULL,
		0x57C05B24E71E58F6ULL,
		0xA7663DE52AEA3644ULL,
		0xE2A87B8E437E8AE1ULL
	}};
	printf("Test Case 923\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 923 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -923;
	} else {
		printf("Test Case 923 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xBB173B9894CF0823ULL,
		0xA1118EB2D3155501ULL,
		0xBE19C07521CA8D10ULL,
		0xB0315823C4EF7F9DULL,
		0xA4F543C02545F5C1ULL,
		0xA57A34BD5CF75346ULL,
		0x8D26E19A5683CFBBULL,
		0x1EFCB711D3C86B1FULL
	}};
	printf("Test Case 924\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 924 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -924;
	} else {
		printf("Test Case 924 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xEA189731895A9AE8ULL,
		0xACA30C19CBAF42C5ULL,
		0xDA82BEE9C7D39487ULL,
		0x774084A9BEA22F8EULL,
		0x9F6A1BD67C22DD70ULL,
		0xBEDB6C79F548D604ULL,
		0x46A648023C611A53ULL,
		0x35424DF7C92C6B0FULL
	}};
	printf("Test Case 925\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 925 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -925;
	} else {
		printf("Test Case 925 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3F403CBECB3F7DC6ULL,
		0xE747FEA10DA18220ULL,
		0x9BE1B8584333BB9AULL,
		0xE68354F4C0F37DE4ULL,
		0x49E402073B9221B9ULL,
		0x46A4279F1BEFE021ULL,
		0x8701FE04DF4571C7ULL,
		0xBCD88B46133FED43ULL
	}};
	printf("Test Case 926\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 926 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -926;
	} else {
		printf("Test Case 926 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCC82F83A5FB0999CULL,
		0x5EC530E39EF58B02ULL,
		0x54AE2C480758337EULL,
		0x5AD032F74CDACFC9ULL,
		0x8E7DA1FE019F9581ULL,
		0x8755D0B915C48638ULL,
		0xB579204E7F77D34EULL,
		0x9301C5AA5BDDE0ACULL
	}};
	printf("Test Case 927\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 927 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -927;
	} else {
		printf("Test Case 927 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x23B6D3F360E457C9ULL,
		0xEC3E6900D6D81E24ULL,
		0x5136881E33498B14ULL,
		0xEE50B4ADEDEF0985ULL,
		0xF40A09EC2F3DC67BULL,
		0xEB0F387D436BD30BULL,
		0x579767D6114631F5ULL,
		0xA7A6D3742511A333ULL
	}};
	printf("Test Case 928\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 928 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -928;
	} else {
		printf("Test Case 928 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC19F70A2C76771F4ULL,
		0xF9159110B7A77F39ULL,
		0x6344B65BD618D5D1ULL,
		0x98B188EA3F216B6AULL,
		0x562B38239C51A742ULL,
		0x6073C689A321CE7CULL,
		0x330994CAF7AA36A5ULL,
		0x8FE49A9D12AB95E8ULL
	}};
	printf("Test Case 929\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 929 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -929;
	} else {
		printf("Test Case 929 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A4C170A6374C271ULL,
		0xFB9A6BE5739C183CULL,
		0xCC29D68568CF1D9FULL,
		0x9920D82D5411B0DBULL,
		0x86BB3D248BB9E0B8ULL,
		0xE769CB12E594E719ULL,
		0x17E2E5134C2D16EEULL,
		0xB036A823EDC9F768ULL
	}};
	printf("Test Case 930\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 930 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -930;
	} else {
		printf("Test Case 930 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAF103D8E196FA62EULL,
		0xEC82DA9AF18122ACULL,
		0x040505A82A1D05FAULL,
		0x8EB9B0360C09F7CFULL,
		0xB85E12B83231918BULL,
		0xF42B89AB63706F95ULL,
		0x56F6066AB1AF9B2EULL,
		0xBF516CDAEC275BA8ULL
	}};
	printf("Test Case 931\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 931 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -931;
	} else {
		printf("Test Case 931 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6FF08F8A64E2E586ULL,
		0xF63901145354A7D7ULL,
		0x39FDBB62BAB1C43CULL,
		0xDD172495C15B0C69ULL,
		0x94820A61DC15E9C4ULL,
		0x00E73439BB2E961FULL,
		0xA43F16DAE4A1C5EEULL,
		0x10656AD0C0CC6C42ULL
	}};
	printf("Test Case 932\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 932 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -932;
	} else {
		printf("Test Case 932 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x667FB202087BAB99ULL,
		0xAE60A87E86BA163FULL,
		0x9121BF546C368AE3ULL,
		0xD753EDD0989936D8ULL,
		0xD9A7075B016370E2ULL,
		0x0A09869934F48193ULL,
		0x26BEBB754CC6390FULL,
		0xF0ED5E6673A9D476ULL
	}};
	printf("Test Case 933\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 933 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -933;
	} else {
		printf("Test Case 933 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD739CA1BF8D8F808ULL,
		0xD5DDC155C055A3BFULL,
		0xDA37D85B5134EBCDULL,
		0x21B3CEAFECE859DBULL,
		0x21D6902A0417D777ULL,
		0x5EC25C1D923D0058ULL,
		0xF663F9172EDC6382ULL,
		0xAD329CC597F087DDULL
	}};
	printf("Test Case 934\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 934 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -934;
	} else {
		printf("Test Case 934 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x017D3A087E1AFC15ULL,
		0x4F62D65453F85BA0ULL,
		0xB2D7A19ADF1A36A0ULL,
		0x097FB55B5E3336B5ULL,
		0xF0D6954B0437635DULL,
		0x878024FA68961F4BULL,
		0x4781E9DE20AD1CB2ULL,
		0xD7138CD1B529E75CULL
	}};
	printf("Test Case 935\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 935 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -935;
	} else {
		printf("Test Case 935 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x40271DE155FAB77DULL,
		0x073B87123BF0AF07ULL,
		0x72A87686DCB36C1BULL,
		0xC6BD486307FA5BECULL,
		0x3BEC492B22827095ULL,
		0xE799A6C7FF7E5704ULL,
		0x72F7567F5564BB78ULL,
		0x08EAA475E8CE2CF7ULL
	}};
	printf("Test Case 936\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 936 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -936;
	} else {
		printf("Test Case 936 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE5E5E6CB0DC817D9ULL,
		0xDDAFDB2B5A5B18DFULL,
		0x9C6EDAD5AD3E1783ULL,
		0xC29EDBC545DC9BA4ULL,
		0xF46A29F340642DDDULL,
		0x709ED68ABB566EE6ULL,
		0xEA87D1510411E7A0ULL,
		0x6669ABA9027D1F05ULL
	}};
	printf("Test Case 937\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 937 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -937;
	} else {
		printf("Test Case 937 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x671E115F55DBFFC8ULL,
		0x2DFAEE53B25A2645ULL,
		0x21361E2C728C41D5ULL,
		0x02147EBD03C80F9EULL,
		0x2ADE28A7BC3792FFULL,
		0x67EE1F8576892486ULL,
		0xF6210FC8E88887FDULL,
		0x2DF8E1B9A05DBA83ULL
	}};
	printf("Test Case 938\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 938 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -938;
	} else {
		printf("Test Case 938 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x837A3D2CBF6C7C16ULL,
		0x2D6643F4710D2C55ULL,
		0x4C21A39D3DAE3FAAULL,
		0xD530751A48CBE385ULL,
		0x6E321D57E72D5A30ULL,
		0xCC71987286455A62ULL,
		0x72AADDEC529C8479ULL,
		0x37624070D05AE191ULL
	}};
	printf("Test Case 939\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 939 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -939;
	} else {
		printf("Test Case 939 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE9B58924BD7ACD9DULL,
		0x06A3907762E7AD0EULL,
		0x965C97118297F4A5ULL,
		0x67964E4CAF9369EFULL,
		0xFDD0A7DD3F31212BULL,
		0x94C47C94ACC24278ULL,
		0x63D0ECF81B614335ULL,
		0xBA7285E511A8419DULL
	}};
	printf("Test Case 940\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 940 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -940;
	} else {
		printf("Test Case 940 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6A27AA405E3C2F0FULL,
		0xC6A862756F94A286ULL,
		0xDA0E6FA53BE5A779ULL,
		0xDA7C58C43AB6334CULL,
		0xBBE30A3FA7D7BF7CULL,
		0xD609430288EC0B8DULL,
		0xC096EC616281F760ULL,
		0xC383043649483DACULL
	}};
	printf("Test Case 941\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 941 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -941;
	} else {
		printf("Test Case 941 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5794F037F83C6F47ULL,
		0x902A25D5C60E1351ULL,
		0x92D5C07B9AFDF28CULL,
		0x71437DFBD224897EULL,
		0xFF77CB1D27E90393ULL,
		0xF84DA69508D74457ULL,
		0xB01B1CC26C493C7FULL,
		0xA8B0829F0D8A065AULL
	}};
	printf("Test Case 942\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 942 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -942;
	} else {
		printf("Test Case 942 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD9B892612FB1F0A4ULL,
		0x7E0E11EC0CF894EEULL,
		0x71D7F88252868AA1ULL,
		0xCC055ADF3756AA3BULL,
		0x18FFB07534C1912AULL,
		0x5CECD836A6F23663ULL,
		0x4AAED3F052AC0E8AULL,
		0x42C76C6288ADDE61ULL
	}};
	printf("Test Case 943\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 943 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -943;
	} else {
		printf("Test Case 943 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9098C0E7A0ECD1ABULL,
		0x357D14CC8E2A2324ULL,
		0x57438F6F34B0F250ULL,
		0xDA17971B21181103ULL,
		0x27083FFFEE76EA7EULL,
		0xCC9788F6B550486EULL,
		0x9607C4E1C8846BF2ULL,
		0xA2BE364334AA811BULL
	}};
	printf("Test Case 944\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 944 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -944;
	} else {
		printf("Test Case 944 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5C0FA00FB989EB9FULL,
		0x113388518B1BCF86ULL,
		0x2DEC7B7B25F6D1DDULL,
		0xEEC360686C67FA0CULL,
		0x879DE9128FD72AEDULL,
		0x3DE5FC0EAE7413CAULL,
		0x457AEFAA4CC5C60EULL,
		0x5FC3D7D9E510774AULL
	}};
	printf("Test Case 945\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 945 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -945;
	} else {
		printf("Test Case 945 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x9F788C961742FD4AULL,
		0x532C8D4C9C1E665DULL,
		0x982276BE64704E34ULL,
		0x403072BA83D3B73CULL,
		0x401A64398947CCC5ULL,
		0x417D5ADC5F7A5A55ULL,
		0xA86914C4E537AE84ULL,
		0x02F55F44E4BB4F51ULL
	}};
	printf("Test Case 946\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 946 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -946;
	} else {
		printf("Test Case 946 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA574670909C4569FULL,
		0xB537A2BB20600B46ULL,
		0xCF9AC24B555DE99CULL,
		0x662A22C493AFC32DULL,
		0xA2300EDBAA4EF9ECULL,
		0x2131AA7ECC315EB3ULL,
		0x263279EEC1F635C2ULL,
		0x13D7AC4E3DE850ACULL
	}};
	printf("Test Case 947\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 947 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -947;
	} else {
		printf("Test Case 947 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x568D7C0D70982C26ULL,
		0x09AC1F8233D5E10DULL,
		0x8BBAB897EA6F790FULL,
		0x1FB1754A374CD86BULL,
		0x7B366B601A03EC3AULL,
		0x2C53CE2583497209ULL,
		0x699AE8E0F3C3B2B5ULL,
		0x4037DF5CAD7B100AULL
	}};
	printf("Test Case 948\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 948 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -948;
	} else {
		printf("Test Case 948 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x27098416A44E083BULL,
		0x55CCD902775D5E3BULL,
		0xEEC6FC5F16B572B9ULL,
		0x829548FBC40CDE68ULL,
		0xE9BF1F6766E57479ULL,
		0x5DAAA1B35B1C57E3ULL,
		0xEEC2B12A8387D956ULL,
		0xE0C9F40B3C313047ULL
	}};
	printf("Test Case 949\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 949 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -949;
	} else {
		printf("Test Case 949 PASSED\n");
	}
	printf("---\n\n");
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xCF5486B051ED1F21ULL,
		0xDE7CE3C063CC0959ULL,
		0x40657A01A779B65DULL,
		0x4E0707AE1983E0F4ULL,
		0x62A3CC223C29FDDFULL,
		0x5785E9ED9F0F9899ULL,
		0xAC359AC15DF60993ULL,
		0x02CA28AE94D815A7ULL
	}};
	printf("Test Case 950\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 950 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -950;
	} else {
		printf("Test Case 950 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7F28F46D368CD634ULL,
		0x0D4D3C4A004861DBULL,
		0xA9B438EC506A6083ULL,
		0xD7F70F2BCA61D460ULL,
		0xF2E2B444F03A8369ULL,
		0x0FB3481996A4690AULL,
		0xC0CA10C6F65B32CDULL,
		0xD5E092005B438A5FULL
	}};
	printf("Test Case 951\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 951 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -951;
	} else {
		printf("Test Case 951 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x19DFEBB787D37A67ULL,
		0x7A6D102C93CAD7A1ULL,
		0xC7232591962D8B83ULL,
		0x9954731C16F6C425ULL,
		0x13481A335E25452FULL,
		0xC269B9097186EF70ULL,
		0xDBDA7093BDB7D378ULL,
		0x4F25FF28273C1D91ULL
	}};
	printf("Test Case 952\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 952 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -952;
	} else {
		printf("Test Case 952 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2942EA3BB8FA6B5AULL,
		0x104295E847126C8BULL,
		0xAE4BBB28E9BFF977ULL,
		0x2EF0AE34E7492C10ULL,
		0xFB33524049D6CA14ULL,
		0xAA3262DF6924991DULL,
		0x7C60D4549928DB9DULL,
		0x730779A2AA22C657ULL
	}};
	printf("Test Case 953\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 953 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -953;
	} else {
		printf("Test Case 953 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x39C5296A17F827AEULL,
		0x2D60B15E00B2960AULL,
		0x4E47FBD42BA4AC18ULL,
		0x7F8F9C087F440135ULL,
		0x809D7F4CFF1BFC9BULL,
		0x9FDCFA2FFB4078C4ULL,
		0xBE8582228019C482ULL,
		0xF0C16EE498E25866ULL
	}};
	printf("Test Case 954\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 954 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -954;
	} else {
		printf("Test Case 954 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8DAC61E51E25F82FULL,
		0x076D4AE7F16A1973ULL,
		0x6855008FB9146610ULL,
		0xA6755B8A31C7071CULL,
		0xE80F76CCC78AC4AAULL,
		0xF6396C509B11B606ULL,
		0xC7C093772C6360A1ULL,
		0x45E08EB2F0B94494ULL
	}};
	printf("Test Case 955\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 955 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -955;
	} else {
		printf("Test Case 955 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFF95CC8184C3B265ULL,
		0x7A0DD87D77B70154ULL,
		0xC734A3E4B07BDD74ULL,
		0x1ABDD1C6A552CE9EULL,
		0xB7A420E636D30F8CULL,
		0xAE0F854686C5B997ULL,
		0xEEBD8C0A6DB7EA4FULL,
		0x9C6292A6321FFA9BULL
	}};
	printf("Test Case 956\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 956 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -956;
	} else {
		printf("Test Case 956 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x70B6AE2D185F31D8ULL,
		0x91314CC7C685621DULL,
		0x7B254AE08956A4C8ULL,
		0xFF768F912B507F06ULL,
		0x6D80143E43822AD5ULL,
		0x06A626356023EECFULL,
		0x4E2A7D67B44CBD22ULL,
		0x6C7F7F1BC537B3C0ULL
	}};
	printf("Test Case 957\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 957 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -957;
	} else {
		printf("Test Case 957 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x14EF8837E84F7581ULL,
		0x0EE992967F6A4293ULL,
		0xB97A122CD25538ECULL,
		0x8293B5AEA674902CULL,
		0xFFCB42D39B0F91E8ULL,
		0x352EC57D59FF4A9EULL,
		0x48DD9450EBBBA2CFULL,
		0xA611FA7DC6BD7144ULL
	}};
	printf("Test Case 958\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 958 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -958;
	} else {
		printf("Test Case 958 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC3ECC6241E4F8613ULL,
		0x677C7B89137CC900ULL,
		0x6C7CEB2330802516ULL,
		0xD1AE54295285EB71ULL,
		0x12AFD77FDEEF130FULL,
		0x62769E42FAF55848ULL,
		0xA6D8F1DCB3F9D809ULL,
		0x91B6D4583F82B055ULL
	}};
	printf("Test Case 959\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 959 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -959;
	} else {
		printf("Test Case 959 PASSED\n");
	}
	printf("---\n\n");
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0xCE62F5A950636329ULL,
		0x5C78DD2CA0CA056BULL,
		0xE9A2BBF32F8DCCD2ULL,
		0x208C986DEACAA3A4ULL,
		0x83BAA3DDAFB67F01ULL,
		0x3ECC96E640187526ULL,
		0x957CF6FC264A4E72ULL,
		0x00CEC0C63D640DCEULL
	}};
	printf("Test Case 960\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 960 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -960;
	} else {
		printf("Test Case 960 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x29B4D6CC3C798798ULL,
		0x18B9C4A0F80224D4ULL,
		0xEC069FCF3D42731AULL,
		0xA43516D05E6EB593ULL,
		0x9A7BD18A541DCF0EULL,
		0x27445F5502080675ULL,
		0xA3424A8E0C6DA8EDULL,
		0xA3F953BD1BA96253ULL
	}};
	printf("Test Case 961\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 961 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -961;
	} else {
		printf("Test Case 961 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3F6F04A4C36448C8ULL,
		0x75C3A94C93177719ULL,
		0x171C79AF90C6BDF8ULL,
		0x0AAECF900E32D674ULL,
		0x85D87D5F7476CDC8ULL,
		0xB116304911E1B1FDULL,
		0x37111F80809787DFULL,
		0xC12A6C872D1EA6E4ULL
	}};
	printf("Test Case 962\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 962 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -962;
	} else {
		printf("Test Case 962 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5F47382EA213F0A5ULL,
		0x32D4E2E5FE7DCB7CULL,
		0x3F5E17A1A5C4DAD5ULL,
		0x668661B4AE0AA16DULL,
		0xA6B3583A298365B0ULL,
		0x5D42B35DBBC2109FULL,
		0xCCCB04A020F0589DULL,
		0x316A517B5885D12FULL
	}};
	printf("Test Case 963\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 963 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -963;
	} else {
		printf("Test Case 963 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC337BE119A16624DULL,
		0x86F8849D209BEE8EULL,
		0xFE5427ACEAA7FBA8ULL,
		0x40D4F28AE57D08B5ULL,
		0x8258E629575B60C8ULL,
		0x99492EE250042540ULL,
		0xBD1D38F6DA955373ULL,
		0xCBEBEBD0E5423986ULL
	}};
	printf("Test Case 964\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 964 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -964;
	} else {
		printf("Test Case 964 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBF208FFD384B2AA0ULL,
		0x4A6D9C6E26424B7DULL,
		0xA0084E6E8D55FAEBULL,
		0x6F3C0DB8F70C3439ULL,
		0x175A24C3ED94E912ULL,
		0xE652F5317BE832B7ULL,
		0x30B8D54B5A610086ULL,
		0x6E3A9AA47D6CCFDFULL
	}};
	printf("Test Case 965\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 965 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -965;
	} else {
		printf("Test Case 965 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD976714DAEE2FF08ULL,
		0x0B4768163351B9CCULL,
		0x6D789BB2915AADE7ULL,
		0x97A4EDDB475D3D81ULL,
		0x602CE8771925EB60ULL,
		0xB7409DFF005021A2ULL,
		0x5E042B7DB8F2F255ULL,
		0x8F7451797C913E82ULL
	}};
	printf("Test Case 966\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 966 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -966;
	} else {
		printf("Test Case 966 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5BB9A6B0C1698B79ULL,
		0x4B0FE5C4976C14B4ULL,
		0x3518D4F6092F98C9ULL,
		0x1C2E4FC9EDCB541FULL,
		0x04F7741EBD20494CULL,
		0xE8C491823315D0DBULL,
		0xBED3441B35AB2176ULL,
		0x3C1A7B87CAE1D7ACULL
	}};
	printf("Test Case 967\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 967 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -967;
	} else {
		printf("Test Case 967 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x46C2B54E571E6FA9ULL,
		0x960697736DB2DCE5ULL,
		0xAFDDF249FFAABA7DULL,
		0x0576A74E706340FDULL,
		0x584603E62367EB41ULL,
		0x6A15ADBFDA295F6BULL,
		0x9AF5F888E3A47ECFULL,
		0x1A377316A80DF269ULL
	}};
	printf("Test Case 968\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 968 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -968;
	} else {
		printf("Test Case 968 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBD4047A301183E00ULL,
		0x8AFB37CEC35BFD0AULL,
		0xEC27990FC4E9C0B3ULL,
		0xE0B584D31ED60AFBULL,
		0xA6A585B3FBFA8AA1ULL,
		0x9CBD09D544C9AA41ULL,
		0x698B682D0AB1F39FULL,
		0x33618A1B28C31079ULL
	}};
	printf("Test Case 969\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 969 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -969;
	} else {
		printf("Test Case 969 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD24AF24EDF008EE2ULL,
		0x7AD2771F64F24FE2ULL,
		0x74A2EAB76BB7639DULL,
		0x0E185DAF74DAA34DULL,
		0xF3EA90D450F89180ULL,
		0x752260DB7A281BF3ULL,
		0x3F6E2FEDCFA5B784ULL,
		0x7B9669516E618013ULL
	}};
	printf("Test Case 970\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 970 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -970;
	} else {
		printf("Test Case 970 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5E4A2DC6B9B71B3AULL,
		0xCA01D407FD003033ULL,
		0x8460143256751853ULL,
		0xD3D99802F8997E0CULL,
		0xE05024AC10FE37F6ULL,
		0x3691F8725A1AE983ULL,
		0x72D42D4333A71C54ULL,
		0xDFB232DE9BA6A651ULL
	}};
	printf("Test Case 971\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 971 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -971;
	} else {
		printf("Test Case 971 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x78CEC336D092CA47ULL,
		0x581ABDAA151E5930ULL,
		0x10C439CE06C7D17AULL,
		0x4D088BE6A6F35592ULL,
		0x41C2135F3E6DE7F0ULL,
		0xE0A3979C7874B893ULL,
		0x242494A644D7D4B0ULL,
		0x2A3D2978895D6E0FULL
	}};
	printf("Test Case 972\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 972 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -972;
	} else {
		printf("Test Case 972 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC2C7D10F3EC9F636ULL,
		0xD8D7A875FD10CB65ULL,
		0x8BAF134DA8301E38ULL,
		0x6977C4D23F759E2AULL,
		0xCAF64AC6DBF76A67ULL,
		0x7919F6E1087C0ECBULL,
		0x6B3D056AC2D0D5AEULL,
		0xA428E8F40B6F9F80ULL
	}};
	printf("Test Case 973\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 973 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -973;
	} else {
		printf("Test Case 973 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBA21E3128AAE8763ULL,
		0x97270BCBC786C212ULL,
		0x1CD803FA5E6DABB4ULL,
		0xBE0A4D9B5BF19305ULL,
		0x3448CF33A426A1ADULL,
		0x69CCC0930008D641ULL,
		0x356C5DB94092B7C1ULL,
		0xD64F03B2BCFA0FA1ULL
	}};
	printf("Test Case 974\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 974 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -974;
	} else {
		printf("Test Case 974 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7F4FC4308ED50EE2ULL,
		0x25E741A4E451DAC6ULL,
		0xFC210C55B6641867ULL,
		0xF78450F11ACC09DBULL,
		0x74279FACC8D4C113ULL,
		0x1E027790B4C3B53DULL,
		0xFBD60260017DB7E3ULL,
		0x337E70F5B4C01953ULL
	}};
	printf("Test Case 975\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 975 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -975;
	} else {
		printf("Test Case 975 PASSED\n");
	}
	printf("---\n\n");
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x16890336DD690314ULL,
		0x44404667650B5168ULL,
		0xFDB73D187A0CCFD2ULL,
		0x2C5828749AE96AFEULL,
		0x1255DDB498169D10ULL,
		0x86E0FE7689E5561DULL,
		0x8D3EA8CE901DF1D6ULL,
		0x0E2AA9E65E5EFE42ULL
	}};
	printf("Test Case 976\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 976 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -976;
	} else {
		printf("Test Case 976 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x39DDB27D51202640ULL,
		0x999558363A7E4984ULL,
		0x039AAAB3FCDBF6F0ULL,
		0x8D01729D92572C90ULL,
		0x04D28B008922FA7FULL,
		0xD11F85F1B5239EABULL,
		0x2CF1D9195BA3EE5EULL,
		0xBDE8D234DCEDF795ULL
	}};
	printf("Test Case 977\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 977 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -977;
	} else {
		printf("Test Case 977 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEB4E60569A1FB625ULL,
		0x516158B0706A6C2DULL,
		0x82BCA6553D2A5C9CULL,
		0x7B4532ED76358D05ULL,
		0x1429D5D952A91B3EULL,
		0x9EDFFA0FD48F5BABULL,
		0x3267C39245F4E6E1ULL,
		0xA867FB278EC5B09CULL
	}};
	printf("Test Case 978\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 978 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -978;
	} else {
		printf("Test Case 978 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x416352DC15686E46ULL,
		0xAAB0E41E717F585AULL,
		0xDEDC21D6FD57E7A3ULL,
		0xFF39BD8A9D16CA24ULL,
		0x41F77D239AE204C0ULL,
		0xE58AC5EAD16D47BEULL,
		0x5D49442417148A9FULL,
		0xA94D000D354A3D42ULL
	}};
	printf("Test Case 979\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 979 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -979;
	} else {
		printf("Test Case 979 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEAD4CE4057230489ULL,
		0xE1958D5C261BF483ULL,
		0x24372FECB83DD945ULL,
		0xBAAEB9579DA89B09ULL,
		0x57CB95B68EF7F5BBULL,
		0x0D6769900E1785BEULL,
		0xBC1CB187204B5205ULL,
		0xFCFC9BF278EBD4B7ULL
	}};
	printf("Test Case 980\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 980 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -980;
	} else {
		printf("Test Case 980 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF0FDED39E815D5D9ULL,
		0xCD7B4EA4FE84182AULL,
		0xB2AECBB68692521DULL,
		0x785EECA876C9C7E9ULL,
		0x5CEF16AE9D233498ULL,
		0xBE1DA3755ECC67FBULL,
		0x12549617F6DC34BFULL,
		0x6EDE4F461B4D20B0ULL
	}};
	printf("Test Case 981\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 981 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -981;
	} else {
		printf("Test Case 981 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2689D35E27E1C4D9ULL,
		0x4660F1BF4ECE59C5ULL,
		0x50C0F9CE55638B54ULL,
		0x75AC527157636645ULL,
		0x0FF505374DDDD425ULL,
		0x882BE4C2F6B44831ULL,
		0xB59A7F6BFB62EA0BULL,
		0x334387779B883B71ULL
	}};
	printf("Test Case 982\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 982 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -982;
	} else {
		printf("Test Case 982 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x847E05EB50A1A83DULL,
		0xD3E8FD4B26E7B42BULL,
		0x3ECCBF8D542EBD67ULL,
		0x309518D4A3BA5D98ULL,
		0x13BDA2F588216319ULL,
		0x0D511A6BC8A7D2B7ULL,
		0x192AD7619A1E222DULL,
		0x796050D5D6592D1AULL
	}};
	printf("Test Case 983\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 983 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -983;
	} else {
		printf("Test Case 983 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x206361B8AF25C300ULL,
		0xA7EE01C0F94F5BDEULL,
		0x796CDD4F373B265BULL,
		0x1FDABE0A8F8A46ECULL,
		0x8D286193C7ECEA17ULL,
		0x10FF06DEF787E7B3ULL,
		0xA664DF2EBA4F158EULL,
		0x6655107C196BB39DULL
	}};
	printf("Test Case 984\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 984 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -984;
	} else {
		printf("Test Case 984 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x9CB2C88A86F0042EULL,
		0xD400B68A9CD488CBULL,
		0x5779A149EA29D04CULL,
		0x76CE177EDCEB182FULL,
		0x65D63F5AC737C671ULL,
		0x18E5AE54A51D2032ULL,
		0x4715BD760C84603FULL,
		0x2B2409830CD5055FULL
	}};
	printf("Test Case 985\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 985 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -985;
	} else {
		printf("Test Case 985 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xCE44324F6A791942ULL,
		0x2B661A1F39FEB136ULL,
		0x81972B38F09AD0B5ULL,
		0xFB0DFA77315B3E94ULL,
		0x520346F8791ED01AULL,
		0x00EC720651FC5142ULL,
		0xE3701170420B331CULL,
		0x309BD1A3E4864E08ULL
	}};
	printf("Test Case 986\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 986 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -986;
	} else {
		printf("Test Case 986 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1B2E15266209587AULL,
		0xBA5B13D86B56BADFULL,
		0xD6BAC7538FA4B32BULL,
		0xEDF7D69421F9D3A4ULL,
		0x5F3AEEDDDA8D7493ULL,
		0x45326EFD1BFA56A9ULL,
		0x6D4EDF2D0865F7E8ULL,
		0xD6E05D7F27AC72A4ULL
	}};
	printf("Test Case 987\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 987 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -987;
	} else {
		printf("Test Case 987 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x08E8479785A68D26ULL,
		0x38E95578FA777052ULL,
		0x50EAE8BCF78BEA0FULL,
		0xA3A2876E3FAD550FULL,
		0x436EFCB00687D7E9ULL,
		0xF5ADD19D875B0CE3ULL,
		0xB8421736BF68597FULL,
		0x152A73826119DDB3ULL
	}};
	printf("Test Case 988\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 988 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -988;
	} else {
		printf("Test Case 988 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B6C5A11E7FF4AEFULL,
		0xFC2B9D5C371C6409ULL,
		0xD882D6F114636FF7ULL,
		0x2A6DD34FF8A2006BULL,
		0x0C3A5202B42F01DAULL,
		0xD14324C8B9EA6925ULL,
		0x0A1453C96ABBE4A4ULL,
		0xC6FB7B40C3E051E6ULL
	}};
	printf("Test Case 989\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 989 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -989;
	} else {
		printf("Test Case 989 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3D438EDE1386D12EULL,
		0x5077CB1634595FB9ULL,
		0x5537921B51731BC8ULL,
		0xE5EACE5815DB2FA3ULL,
		0x295EBDCBB2CE82F1ULL,
		0xE172A56D78A110B9ULL,
		0xA28F93403085F87AULL,
		0xA2021458E3A33DD3ULL
	}};
	printf("Test Case 990\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 990 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -990;
	} else {
		printf("Test Case 990 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x315FE8EB4DCCCB5BULL,
		0xAF8B1BA7F1731CABULL,
		0x078942356947CD7EULL,
		0x6C3787517B373A7AULL,
		0xE9A7FAED4114AD20ULL,
		0x4B5E11AA097BD38AULL,
		0x68F0B67065BE8929ULL,
		0x11D052394E00994FULL
	}};
	printf("Test Case 991\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 991 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -991;
	} else {
		printf("Test Case 991 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC9A7BDA0FBB0A43CULL,
		0x1E7432B35A5DDF25ULL,
		0x6BBE90B9F9BF8037ULL,
		0x6BF4C8122B0974EEULL,
		0xA982AE42F3862D5DULL,
		0x87FDD009319230B1ULL,
		0x39DED619C622D5FDULL,
		0x649B3EDBEE03F900ULL
	}};
	printf("Test Case 992\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 992 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -992;
	} else {
		printf("Test Case 992 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A7DC321D0D10C72ULL,
		0x51BE304B65BC94D2ULL,
		0x7C79B8205C7445B2ULL,
		0xC5E8A82BADBF7CE8ULL,
		0x983C382D25D8C862ULL,
		0x2A782EED354640B0ULL,
		0x5DC34E3A9C60090EULL,
		0xF045251805CF6191ULL
	}};
	printf("Test Case 993\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 993 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -993;
	} else {
		printf("Test Case 993 PASSED\n");
	}
	printf("---\n\n");
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x346F47DF63619E20ULL,
		0xD5A6354289E4E0B9ULL,
		0xBBF4FA4725178134ULL,
		0x2E48D67CFFEA1608ULL,
		0xB0EFBDF0615C5C58ULL,
		0x2478268454408ACAULL,
		0x7A25086FC6FD3431ULL,
		0x5E97F1587B529E31ULL
	}};
	printf("Test Case 994\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 994 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -994;
	} else {
		printf("Test Case 994 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2A019758B6EF1389ULL,
		0xA947B0F1B1288331ULL,
		0x99ED0295E9C05F6BULL,
		0x32E0275440922B63ULL,
		0x61C807BA482F9251ULL,
		0x1600A6418345C105ULL,
		0x1D7E8919D0B0A72BULL,
		0xA0853E471BF9BD53ULL
	}};
	printf("Test Case 995\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 995 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -995;
	} else {
		printf("Test Case 995 PASSED\n");
	}
	printf("---\n\n");
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xA0BD1FDBA1A7E3EBULL,
		0x1F5859B0D4A30015ULL,
		0x6F021FDFF584B080ULL,
		0xFB3D909951ED6833ULL,
		0xE1A3A156B6D8472EULL,
		0x02CFA3B9B6DDC12AULL,
		0xC0A685B392CCD906ULL,
		0x053CC39C8F128347ULL
	}};
	printf("Test Case 996\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 996 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -996;
	} else {
		printf("Test Case 996 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB620BBB64846C79AULL,
		0xDA0AE5A2BD81F018ULL,
		0xDBD39BFE8905040CULL,
		0x09C6CC0171415FE4ULL,
		0xD5FFF639543CA6A8ULL,
		0xBE468AD0826288BBULL,
		0x638140CB6EAA4743ULL,
		0xB2A188C2F54591D2ULL
	}};
	printf("Test Case 997\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 997 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -997;
	} else {
		printf("Test Case 997 PASSED\n");
	}
	printf("---\n\n");
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x66B0320F54167FC8ULL,
		0xA4BD4DB4B11C9328ULL,
		0xF40BD36724F7C0CAULL,
		0x13F9903118E90EA0ULL,
		0x995A382B652993FDULL,
		0xB0D2C52ADEBB0DB4ULL,
		0x6D5606D4143E3363ULL,
		0xF8FAD2FBF91EBCB5ULL
	}};
	printf("Test Case 998\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 998 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -998;
	} else {
		printf("Test Case 998 PASSED\n");
	}
	printf("---\n\n");
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x830F22A145F1A893ULL,
		0x588569224B1772B5ULL,
		0x5A56B0605BA7FD42ULL,
		0x4BCC3E0A0C27D924ULL,
		0x40FF45BA8EC76F36ULL,
		0x2CBAA762A900CC2EULL,
		0x865DF920A2A7FADEULL,
		0x2F7C584BBD882F7CULL
	}};
	printf("Test Case 999\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 999 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -999;
	} else {
		printf("Test Case 999 PASSED\n");
	}
	printf("---\n\n");
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x6D6B255A2D4214BAULL,
		0x320A21FB1EA6116DULL,
		0xB6FE16BB920193F0ULL,
		0x8BB6033AB6C42290ULL,
		0xEA3216F51C8867BCULL,
		0x27E0BA977F86D117ULL,
		0x571CEEE67EE8BC24ULL,
		0x1520EBD70ECD69A6ULL
	}};
	printf("Test Case 1000\n");
	printf("Key: \n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: %lld\n", la);
	l2 = curve25519_key_log2(&k1, NULL);
	if (l2 != la) {
		printf("Test Case 1000 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		return -1000;
	} else {
		printf("Test Case 1000 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}