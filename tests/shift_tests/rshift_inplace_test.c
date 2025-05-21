#include "../tests.h"

int32_t curve25519_key_rshift_inplace_test(void) {
	printf("Key Right Shift Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xD9F880F8A54663E7ULL,
		0x6384D47CCD38B5F0ULL,
		0xFB51ADB4E4B56434ULL,
		0x966B22C8D3132F6EULL,
		0x6044EECA835E9E5CULL,
		0x81C3A276C2DF9EA8ULL,
		0xB28875D1E8F6E133ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xD9F880F8A54663E7ULL,
		0x6384D47CCD38B5F0ULL,
		0xFB51ADB4E4B56434ULL,
		0x966B22C8D3132F6EULL,
		0x6044EECA835E9E5CULL,
		0x81C3A276C2DF9EA8ULL,
		0xB28875D1E8F6E133ULL,
		0x0000000000000000ULL
	}};
	int shift = 0;
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
		0x3A5A3616DFC9D078ULL,
		0xE189A806F4573784ULL,
		0xE5D528F51907FFFFULL,
		0x426099A15028289AULL,
		0xCB83CCF0FB01CC93ULL,
		0xB870FA12384AC33DULL,
		0xAFDB504DAEDD64B1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD15CDE10E968D85BULL,
		0x641FFFFF8626A01BULL,
		0x40A0A26B9754A3D4ULL,
		0xEC07324D09826685ULL,
		0xE12B0CF72E0F33C3ULL,
		0xBB7592C6E1C3E848ULL,
		0x00000002BF6D4136ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x72B548BE2E13DA47ULL,
		0x534FAA1A0F257A4FULL,
		0xC6BCCA66FEAA4A7CULL,
		0x3F0E1381444F2C63ULL,
		0x00421B946D731549ULL,
		0x4FE1C11A5603CEDEULL,
		0x416155610881F378ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE93DCAD522F8B84FULL,
		0x29F14D3EA8683C95ULL,
		0xB18F1AF3299BFAA9ULL,
		0x5524FC384E05113CULL,
		0x3B7801086E51B5CCULL,
		0xCDE13F870469580FULL,
		0x0001058555842207ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xE18EC319DE7C1100ULL,
		0x5C9C4FB2FF25A5AFULL,
		0x8C5816B305F7E992ULL,
		0x0843ABEAE7C4EFA7ULL,
		0x21DEB188D63A7059ULL,
		0x49E3F5DD8A881021ULL,
		0x6F59075063589F9DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A5AFE18EC319DE7ULL,
		0x7E9925C9C4FB2FF2ULL,
		0x4EFA78C5816B305FULL,
		0xA70590843ABEAE7CULL,
		0x8102121DEB188D63ULL,
		0x89F9D49E3F5DD8A8ULL,
		0x000006F590750635ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x9669BC0349EBB239ULL,
		0x37854656DC9A8251ULL,
		0x8400CC20BA480CAFULL,
		0xA186AC2C6F21F548ULL,
		0xF79B1A096106AD88ULL,
		0x35EC32A1B33AEDE4ULL,
		0x54FE03F1B2DBFF30ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82519669BC0349EBULL,
		0x0CAF37854656DC9AULL,
		0xF5488400CC20BA48ULL,
		0xAD88A186AC2C6F21ULL,
		0xEDE4F79B1A096106ULL,
		0xFF3035EC32A1B33AULL,
		0x000054FE03F1B2DBULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xFFF3BFED46764263ULL,
		0xA55870D13E4FC128ULL,
		0x08155E304CC4857BULL,
		0x85C7B9AF1ED9F5C0ULL,
		0xC63448DAFF76C934ULL,
		0xC212C0A9DA0563E3ULL,
		0x6EEF22D30901BF23ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C344F93F04A3FFCULL,
		0x578C1331215EE956ULL,
		0xEE6BC7B67D700205ULL,
		0x1236BFDDB24D2171ULL,
		0xB02A768158F8F18DULL,
		0xC8B4C2406FC8F084ULL,
		0x0000000000001BBBULL,
		0x0000000000000000ULL
	}};
	shift = 50;
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
		0x5915A4A77A6C2F22ULL,
		0x22AD41A41AA61317ULL,
		0x5EA6AE6FB18393AFULL,
		0x2711FBB7F8063E7CULL,
		0xEB6E3ED081B0CE5CULL,
		0xC1C6E5C354BA9DF3ULL,
		0x04BB14FBEEB7AF98ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0D20D53098BAC8AULL,
		0x5737D8C1C9D79156ULL,
		0xFDDBFC031F3E2F53ULL,
		0x1F6840D8672E1388ULL,
		0x72E1AA5D4EF9F5B7ULL,
		0x8A7DF75BD7CC60E3ULL,
		0x000000000000025DULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0xC10A0271DF2050EDULL,
		0x009EAA64F7DA177EULL,
		0x78549004C9317E8BULL,
		0x24F03B76417C4006ULL,
		0x9F8F83935022AC6CULL,
		0x2703D165EF10D37AULL,
		0xE548BBFFDE495FBCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55327BED0BBF6085ULL,
		0x48026498BF45804FULL,
		0x1DBB20BE20033C2AULL,
		0xC1C9A81156361278ULL,
		0xE8B2F78869BD4FC7ULL,
		0x5DFFEF24AFDE1381ULL,
		0x00000000000072A4ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x6E25C1A7F0868147ULL,
		0x2E7894C920EC5E83ULL,
		0x8D8F21AF8CB68EF0ULL,
		0x3CAFEFC77F57A055ULL,
		0xF5AE962D6BEF3D79ULL,
		0xE4204BA48F5A3C47ULL,
		0xCD3B8CE45EA78FB2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0762F41B712E0D3FULL,
		0x65B4778173C4A649ULL,
		0xFABD02AC6C790D7CULL,
		0x5F79EBC9E57F7E3BULL,
		0x7AD1E23FAD74B16BULL,
		0xF53C7D9721025D24ULL,
		0x0000000669DC6722ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x188A615126BB7928ULL,
		0x63DBFE4A8A3B5957ULL,
		0xCBE57566F64DC357ULL,
		0xAF16519090DAF716ULL,
		0xD0107B3896CEB0F9ULL,
		0xA5C5EF2D7CCA314CULL,
		0x53C0E0B07CC5FBE6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5957188A615126BBULL,
		0xC35763DBFE4A8A3BULL,
		0xF716CBE57566F64DULL,
		0xB0F9AF16519090DAULL,
		0x314CD0107B3896CEULL,
		0xFBE6A5C5EF2D7CCAULL,
		0x000053C0E0B07CC5ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0x3339E8B99DC73750ULL,
		0xC1309A09CC7C53A5ULL,
		0x146898717C4D547FULL,
		0xA5243467BC23F7FDULL,
		0x33724B130E6EA6D4ULL,
		0xDABA5F35620D4C6EULL,
		0xD335253790B3D4CBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6673D1733B8E6EULL,
		0xFF8261341398F8A7ULL,
		0xFA28D130E2F89AA8ULL,
		0xA94A4868CF7847EFULL,
		0xDC66E496261CDD4DULL,
		0x97B574BE6AC41A98ULL,
		0x01A66A4A6F2167A9ULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x3F8BA27E4FBF9D82ULL,
		0x677153F84E1CA78AULL,
		0xF4FF60C8F2802C1AULL,
		0x036EFCE691FE5961ULL,
		0x0BB2FDCDDAB0220DULL,
		0xC8E7A27EA129A6B2ULL,
		0x67B18BA89C357D7EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B8A9FC270E53C51ULL,
		0xA7FB0647940160D3ULL,
		0x1B77E7348FF2CB0FULL,
		0x5D97EE6ED5811068ULL,
		0x473D13F5094D3590ULL,
		0x3D8C5D44E1ABEBF6ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
		0xD4F7E9FE68876EDEULL,
		0x29A03AC4C6F7ED0BULL,
		0x06BB0EC46026878EULL,
		0xB1F60C8620EC3368ULL,
		0x76C1FD481DCFAAA3ULL,
		0xA49B9954E953CEE9ULL,
		0xDD38A00770A2F5A6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7ED0BD4F7E9FE68ULL,
		0x26878E29A03AC4C6ULL,
		0xEC336806BB0EC460ULL,
		0xCFAAA3B1F60C8620ULL,
		0x53CEE976C1FD481DULL,
		0xA2F5A6A49B9954E9ULL,
		0x000000DD38A00770ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x68925F82435D479DULL,
		0xD7DF302A87C0C8A1ULL,
		0xBA6804CCDF0D1EBDULL,
		0x711A030A89757771ULL,
		0xA29E0062CD8A48E2ULL,
		0xD3BE1DEFC45BA763ULL,
		0xC13CCFFED4C04382ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF302A87C0C8A16ULL,
		0xA6804CCDF0D1EBDDULL,
		0x11A030A89757771BULL,
		0x29E0062CD8A48E27ULL,
		0x3BE1DEFC45BA763AULL,
		0x13CCFFED4C04382DULL,
		0x000000000000000CULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x10ECE2A23CCE9ACAULL,
		0xF80FB7C5BE9A9FFCULL,
		0x97DB0021D3F9DABAULL,
		0xD8CDE76AFC7C2713ULL,
		0xF9218C5D5EFC3A15ULL,
		0x39843C628C266C6EULL,
		0x0D5B9FBBE94D33EDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D353FF821D9C54ULL,
		0x3A7F3B575F01F6F8ULL,
		0x5F8F84E272FB6004ULL,
		0xABDF8742BB19BCEDULL,
		0x5184CD8DDF24318BULL,
		0x7D29A67DA730878CULL,
		0x0000000001AB73F7ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x988FBA1BAEFB0BE9ULL,
		0x8202EA39C0EFD23CULL,
		0x1FDF01158918DC1EULL,
		0x8656BD623AF7B1FFULL,
		0xF105E667662393DFULL,
		0x761981FF393450A3ULL,
		0x69C2BF8640D687C8ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EFD23C988FBA1BAULL,
		0x918DC1E8202EA39CULL,
		0xAF7B1FF1FDF01158ULL,
		0x62393DF8656BD623ULL,
		0x93450A3F105E6676ULL,
		0x0D687C8761981FF3ULL,
		0x000000069C2BF864ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x29C83ACB22909F4BULL,
		0xE353651CA174171FULL,
		0xD8225890B31A6391ULL,
		0xA7167D7EC098D52DULL,
		0x846DE4F51A4AC504ULL,
		0x071EB6F2CD7777A2ULL,
		0x9E28A5AA93D4C929ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82E3E53907596452ULL,
		0x4C723C6A6CA3942EULL,
		0x1AA5BB044B121663ULL,
		0x58A094E2CFAFD813ULL,
		0xEEF4508DBC9EA349ULL,
		0x992520E3D6DE59AEULL,
		0x000013C514B5527AULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0xE659CA281E6E5A86ULL,
		0x11765D5586EEA84DULL,
		0x58C5552633AC01F9ULL,
		0xBD3B51571FCE72DAULL,
		0x8004269FBEF198DDULL,
		0x84B1E3156BE17B81ULL,
		0x97E8AA56867113B6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA84DE659CA281E6ULL,
		0xC01F911765D5586EULL,
		0xE72DA58C5552633AULL,
		0x198DDBD3B51571FCULL,
		0x17B818004269FBEFULL,
		0x113B684B1E3156BEULL,
		0x0000097E8AA56867ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x726EE8A311FF5618ULL,
		0x23A1875B42099E68ULL,
		0x1D9FBE0499621528ULL,
		0x0CAA33CD76EAACADULL,
		0x1E3C8751BC1699DAULL,
		0xF012D4227293C80FULL,
		0x63826EDC4A9677D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133CD0E4DDD14623ULL,
		0xC42A5047430EB684ULL,
		0xD5595A3B3F7C0932ULL,
		0x2D33B41954679AEDULL,
		0x27901E3C790EA378ULL,
		0x2CEFA1E025A844E5ULL,
		0x000000C704DDB895ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0xE5C8D321455BB309ULL,
		0x760E0C019E5F7E96ULL,
		0xD6B7EDFC40419151ULL,
		0x04306E4EDF071E8EULL,
		0xEAC4FD29E92A43C0ULL,
		0x5062E8D5265FB3FBULL,
		0x0CE892A6912DE678ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4B72E46990A2ADULL,
		0xC8A8BB070600CF2FULL,
		0x8F476B5BF6FE2020ULL,
		0x21E0021837276F83ULL,
		0xD9FDF5627E94F495ULL,
		0xF33C2831746A932FULL,
		0x0000067449534896ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xFE6E2E67F677FDEEULL,
		0x917FFD51BA1DC28EULL,
		0xE652D8E12FD6F02CULL,
		0x96E34313B25D6388ULL,
		0x2D65A06BB152FF85ULL,
		0x1D8391B9395DA40FULL,
		0x0A1AD6F692D29657ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F371733FB3BFEFULL,
		0x648BFFEA8DD0EE14ULL,
		0x473296C7097EB781ULL,
		0x2CB71A189D92EB1CULL,
		0x796B2D035D8A97FCULL,
		0xB8EC1C8DC9CAED20ULL,
		0x0050D6B7B49694B2ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x1B01F23AD9E7E6AFULL,
		0xF1920AB4D7214244ULL,
		0x095AF236941BE86CULL,
		0x228C909B777B3447ULL,
		0xBE778E3484E71B7CULL,
		0x8D0D8CD3A721B7CBULL,
		0x60A4C71F97793F8FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055A6B90A1220D80ULL,
		0x791B4A0DF43678C9ULL,
		0x484DBBBD9A2384ADULL,
		0xC71A42738DBE1146ULL,
		0xC669D390DBE5DF3BULL,
		0x638FCBBC9FC7C686ULL,
		0x0000000000003052ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x45091DED62B383FAULL,
		0xD5F3F684C59B78CDULL,
		0x1C734CA93CD50F70ULL,
		0x860D57DE721671DBULL,
		0x5EEF3CB3FD6842A5ULL,
		0xCFB977D9233794F8ULL,
		0x5AB526D88D14DE28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2848EF6B159C1FDULL,
		0x6AF9FB4262CDBC66ULL,
		0x8E39A6549E6A87B8ULL,
		0xC306ABEF390B38EDULL,
		0x2F779E59FEB42152ULL,
		0x67DCBBEC919BCA7CULL,
		0x2D5A936C468A6F14ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x0A48F9FF1345B110ULL,
		0xDBBE0B10C5D2BF2AULL,
		0x1C96ED42D07E13C0ULL,
		0xA929533119835BE7ULL,
		0x6273EFDE9BBE9E1CULL,
		0xD8022844187243E1ULL,
		0xD66AA17F18841080ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E541491F3FE268BULL,
		0x2781B77C16218BA5ULL,
		0xB7CE392DDA85A0FCULL,
		0x3C395252A6623306ULL,
		0x87C2C4E7DFBD377DULL,
		0x2101B004508830E4ULL,
		0x0001ACD542FE3108ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0x28BDE0AF82C79EF1ULL,
		0xE23BC13039FA2330ULL,
		0x7CF8F69F841361D7ULL,
		0x82AEBE251539DC25ULL,
		0xCB6EEBE99EBCAD07ULL,
		0x7DCEA36072EE1DE7ULL,
		0x4678A5630AA3D565ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1198145EF057C163ULL,
		0xB0EBF11DE0981CFDULL,
		0xEE12BE7C7B4FC209ULL,
		0x5683C1575F128A9CULL,
		0x0EF3E5B775F4CF5EULL,
		0xEAB2BEE751B03977ULL,
		0x0000233C52B18551ULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0xEC7F15DAE8C0DB45ULL,
		0x2B4D15CF74649EFDULL,
		0xF3DA6E651480038EULL,
		0xE3FEE62C681C46C9ULL,
		0x53A81D203DA3EEC6ULL,
		0xF175C0321DA2149EULL,
		0x7FF70B7E6B206568ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD1927BF7B1FC576ULL,
		0x452000E38AD34573ULL,
		0x1A0711B27CF69B99ULL,
		0x0F68FBB1B8FFB98BULL,
		0x8768852794EA0748ULL,
		0x9AC8195A3C5D700CULL,
		0x000000001FFDC2DFULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xA8D31A8113F0CD40ULL,
		0xE8302AE130884014ULL,
		0x164C03AB207AE464ULL,
		0xA6B17AF2CB0EE694ULL,
		0x9FBD4AB03CC46E18ULL,
		0x31699C79DDE73E18ULL,
		0x5DA77E550A7B02F2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54698D4089F866A0ULL,
		0x741815709844200AULL,
		0x0B2601D5903D7232ULL,
		0x5358BD796587734AULL,
		0x4FDEA5581E62370CULL,
		0x18B4CE3CEEF39F0CULL,
		0x2ED3BF2A853D8179ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x2CE19F5E14039418ULL,
		0x9B61D6A5443DA691ULL,
		0x439ACB30DA624001ULL,
		0x8EAE1AD5AF1DCD64ULL,
		0x5E035D71EE324E56ULL,
		0x1D6D71FB53806229ULL,
		0x3511F90E4A5A9E47ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D875A9510F69A44ULL,
		0x0E6B2CC369890006ULL,
		0x3AB86B56BC773591ULL,
		0x780D75C7B8C9395AULL,
		0x75B5C7ED4E0188A5ULL,
		0xD447E439296A791CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x1AA48375C7BD9E32ULL,
		0x72201F15AC99A776ULL,
		0x947EBD4300C3CB6AULL,
		0x6974EBCCD33517F4ULL,
		0x90FBE46D905D79BBULL,
		0xE56732CE7E5CBC14ULL,
		0x15F47B2963B6BD05ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC99A7761AA48375ULL,
		0x00C3CB6A72201F15ULL,
		0xD33517F4947EBD43ULL,
		0x905D79BB6974EBCCULL,
		0x7E5CBC1490FBE46DULL,
		0x63B6BD05E56732CEULL,
		0x0000000015F47B29ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x44330701822BAD98ULL,
		0xFDC0B80D3846AF52ULL,
		0x3D1BBAFEEDC3E7C5ULL,
		0x7536B29435F90A20ULL,
		0x21741AEA70633D5FULL,
		0xD62862F859C3375AULL,
		0xF5C278AA6E9BDEC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E11ABD4910CC1CULL,
		0xFBB70F9F17F702E0ULL,
		0x50D7E42880F46EEBULL,
		0xA9C18CF57DD4DACAULL,
		0xE1670CDD6885D06BULL,
		0xA9BA6F7B0F58A18BULL,
		0x0000000003D709E2ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0xEEF75FDFCCBD1BF1ULL,
		0x2EE83155311BCF01ULL,
		0x9C26F564BB94236CULL,
		0x7E366E58DB54BADAULL,
		0x8891090DC68BCFB4ULL,
		0x1A12FD04ADBB505BULL,
		0x5DBABC05A03755BBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE780F77BAFEFE65ULL,
		0xA11B6177418AA988ULL,
		0xA5D6D4E137AB25DCULL,
		0x5E7DA3F1B372C6DAULL,
		0xDA82DC4488486E34ULL,
		0xBAADD8D097E8256DULL,
		0x000002EDD5E02D01ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0xB13B77C6932B19FEULL,
		0x9EC9C50FA3565BECULL,
		0x057FAEFAF34FDFC9ULL,
		0xC8A757ED6A9E2544ULL,
		0x51ED693B6AFF2152ULL,
		0x793E615CDE596942ULL,
		0x17C7D9181A0DCCB9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3565BECB13B77C6ULL,
		0xF34FDFC99EC9C50FULL,
		0x6A9E2544057FAEFAULL,
		0x6AFF2152C8A757EDULL,
		0xDE59694251ED693BULL,
		0x1A0DCCB9793E615CULL,
		0x0000000017C7D918ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x0B1FD3DEF1E2086AULL,
		0xAF4DA707BFBF3938ULL,
		0xB627BA2DCB8E3B53ULL,
		0x92C5A8EA4B9FC3BBULL,
		0x486C317A2BC48327ULL,
		0x5E58A62CFA6C603BULL,
		0xAE7BA2BB38915F2CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFCE4E02C7F4F7BCULL,
		0xE38ED4EBD369C1EFULL,
		0xE7F0EEED89EE8B72ULL,
		0xF120C9E4B16A3A92ULL,
		0x9B180ED21B0C5E8AULL,
		0x2457CB1796298B3EULL,
		0x0000002B9EE8AECEULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x457A364BFE659A3BULL,
		0xA2D99766E5751C9EULL,
		0x01A98A20E1D64671ULL,
		0xEF8CEF1580C33EAFULL,
		0x6D3E35C31D2F4DC9ULL,
		0x82EFB82BB0089BBBULL,
		0x7A58E3D4B4722B4CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45B32ECDCAEA393CULL,
		0x03531441C3AC8CE3ULL,
		0xDF19DE2B01867D5EULL,
		0xDA7C6B863A5E9B93ULL,
		0x05DF705760113776ULL,
		0xF4B1C7A968E45699ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x35E2B89D1AC18378ULL,
		0x4CE5B22CA780A4E9ULL,
		0x27D9043D3E0F51C1ULL,
		0x8CB8265F66E7F9FCULL,
		0xB0C137BEF3B87D88ULL,
		0xAF1F3474087C5F6DULL,
		0xA05FF882BF1BB10FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4E935E2B89D1AC1ULL,
		0x51C14CE5B22CA780ULL,
		0xF9FC27D9043D3E0FULL,
		0x7D888CB8265F66E7ULL,
		0x5F6DB0C137BEF3B8ULL,
		0xB10FAF1F3474087CULL,
		0x0000A05FF882BF1BULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xB48B69007A0BFE00ULL,
		0xBBD77699BD46562EULL,
		0xC20A8055F7698165ULL,
		0xCF5FD0521D44FD57ULL,
		0xA99996B9303196C0ULL,
		0x7233CDE93E78C6C8ULL,
		0xA8A9427D10C76F58ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB4CDEA32B175A45ULL,
		0x402AFBB4C0B2DDEBULL,
		0xE8290EA27EABE105ULL,
		0xCB5C9818CB6067AFULL,
		0xE6F49F3C636454CCULL,
		0xA13E8863B7AC3919ULL,
		0x0000000000005454ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x1D1DD143E01617F6ULL,
		0xCDA140CA8F23F402ULL,
		0x429A698A7EEB5B2FULL,
		0xD0B3EEF448CFCAC3ULL,
		0x9A80FC19DA0F3812ULL,
		0x3FD2BA61DC723459ULL,
		0xB3F9A2796AEFE7A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043A3BA287C02C2FULL,
		0x5F9B4281951E47E8ULL,
		0x868534D314FDD6B6ULL,
		0x25A167DDE8919F95ULL,
		0xB33501F833B41E70ULL,
		0x4E7FA574C3B8E468ULL,
		0x0167F344F2D5DFCFULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x87B097EB7428D628ULL,
		0x7923E76CBC46CC21ULL,
		0x393D429670478469ULL,
		0x56D5E0107321F750ULL,
		0x76F636B358113379ULL,
		0x68AD888405703483ULL,
		0xBA735F1E7CFD54F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48F9DB2F11B30861ULL,
		0x4F50A59C11E11A5EULL,
		0xB578041CC87DD40EULL,
		0xBD8DACD6044CDE55ULL,
		0x2B6221015C0D20DDULL,
		0x9CD7C79F3F553D5AULL,
		0x000000000000002EULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x2221BB073413FF53ULL,
		0x304E6BAFDD8BDB7DULL,
		0x9B8ACB2E75642324ULL,
		0x36BB2CB07F18BEDEULL,
		0x80F76919F28732FCULL,
		0x12437F0F37B5094DULL,
		0x46E17032B2902B21ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EDBE9110DD839A0ULL,
		0x21192182735D7EECULL,
		0xC5F6F4DC565973ABULL,
		0x3997E1B5D96583F8ULL,
		0xA84A6C07BB48CF94ULL,
		0x815908921BF879BDULL,
		0x000002370B819594ULL,
		0x0000000000000000ULL
	}};
	shift = 21;
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
		0x3CC53C2A9EFBB190ULL,
		0xD9E4B0ABB48A7BF5ULL,
		0x0DF634A73CB0C0A7ULL,
		0xAD4DF3AB812640EFULL,
		0xA4A73D867EEE9D12ULL,
		0x1466EC0F9C0262E8ULL,
		0x4356CE999938774DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF53CC53C2A9EFBB1ULL,
		0xA7D9E4B0ABB48A7BULL,
		0xEF0DF634A73CB0C0ULL,
		0x12AD4DF3AB812640ULL,
		0xE8A4A73D867EEE9DULL,
		0x4D1466EC0F9C0262ULL,
		0x004356CE99993877ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xC5B59B58490D9C38ULL,
		0x21597E99872BC03AULL,
		0x598F99B46B95A4FCULL,
		0x90E18A358B48ACCFULL,
		0xE53CC8C3789AE95BULL,
		0x63A9D36E67C04B6BULL,
		0x9F7C4FC442160EBAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8565FA661CAF00EBULL,
		0x663E66D1AE5693F0ULL,
		0x438628D62D22B33DULL,
		0x94F3230DE26BA56EULL,
		0x8EA74DB99F012DAFULL,
		0x7DF13F1108583AE9ULL,
		0x0000000000000002ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x71410762D3597141ULL,
		0x5A70509C1ADD3816ULL,
		0xF2D119D146161AA4ULL,
		0x675C6DF7B108E148ULL,
		0x42A88BD44CEDA589ULL,
		0x0E5A24A5CBFFC284ULL,
		0x7AAF83BF2B7983A0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B74E059C5041D8BULL,
		0x18586A9169C14270ULL,
		0xC4238523CB446745ULL,
		0x33B696259D71B7DEULL,
		0x2FFF0A110AA22F51ULL,
		0xADE60E8039689297ULL,
		0x00000001EABE0EFCULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x3EC720500C83B2F0ULL,
		0xDF7926AE480C4D48ULL,
		0xE0D40A543D67DA79ULL,
		0xE3560F1CBB76B00CULL,
		0x2B6EA3CF601B5637ULL,
		0x432136C4C2169A3AULL,
		0x6C56250DCC0F7426ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40626A41F6390280ULL,
		0xEB3ED3CEFBC93572ULL,
		0xDBB5806706A052A1ULL,
		0x00DAB1BF1AB078E5ULL,
		0x10B4D1D15B751E7BULL,
		0x607BA1321909B626ULL,
		0x0000000362B1286EULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x0F4DE58110640B27ULL,
		0x51841D50EBEC96B5ULL,
		0x5926D346A8E8D19CULL,
		0xBA1C62AEED8DC249ULL,
		0x789E5818D4BDECB1ULL,
		0xB96912FC444C653BULL,
		0xFDA21261DD01A9E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D50EBEC96B50F4DULL,
		0xD346A8E8D19C5184ULL,
		0x62AEED8DC2495926ULL,
		0x5818D4BDECB1BA1CULL,
		0x12FC444C653B789EULL,
		0x1261DD01A9E3B969ULL,
		0x000000000000FDA2ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0x1E66AC6168D7A4C5ULL,
		0x2E0E6E8DDCDB21EFULL,
		0xED0E44802500C065ULL,
		0x2C82C2030BDC1D66ULL,
		0xB4AA0BF2780720C6ULL,
		0xE1466218C032B604ULL,
		0x924AD14BE8581792ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7736C87BC799AB18ULL,
		0x094030194B839BA3ULL,
		0xC2F70759BB439120ULL,
		0x9E01C8318B20B080ULL,
		0x300CAD812D2A82FCULL,
		0xFA1605E4B8519886ULL,
		0x000000002492B452ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xE060DD5B168C6379ULL,
		0x966EC5D2CF0EAE75ULL,
		0x6628DB74DCB38C3BULL,
		0x8C979D617AEBEC61ULL,
		0x98B889F5B6FEB2A1ULL,
		0xB9BB257784BB9F2DULL,
		0xFE59C147A6692E2BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8BA59E1D5CEBC0CULL,
		0x1B6E9B96718772CDULL,
		0xF3AC2F5D7D8C2CC5ULL,
		0x113EB6DFD6543192ULL,
		0x64AEF09773E5B317ULL,
		0x3828F4CD25C57737ULL,
		0x0000000000001FCBULL,
		0x0000000000000000ULL
	}};
	shift = 51;
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
		0x80706F14C3742FFCULL,
		0xACF99F19C3C08C7FULL,
		0xFE86A2C7BB1D243CULL,
		0xC9FF540AAF248729ULL,
		0x269A66D82E5BFA8DULL,
		0x2E45B5BB9A0A9064ULL,
		0xD3C05858E130678EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59F33E33878118FFULL,
		0xFD0D458F763A4879ULL,
		0x93FEA8155E490E53ULL,
		0x4D34CDB05CB7F51BULL,
		0x5C8B6B77341520C8ULL,
		0xA780B0B1C260CF1CULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0x01D535F9407A7EA4ULL,
		0xAA6EDCC9440F5E56ULL,
		0x0C369C44B3C34F53ULL,
		0x301E218E4C157103ULL,
		0xDE1AEF881BDBA283ULL,
		0xF6545B382BEAEC93ULL,
		0xDDC5BAD36E620C52ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x103D79580754D7E5ULL,
		0xCF0D3D4EA9BB7325ULL,
		0x3055C40C30DA7112ULL,
		0x6F6E8A0CC0788639ULL,
		0xAFABB24F786BBE20ULL,
		0xB988314BD9516CE0ULL,
		0x000000037716EB4DULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xA44F82B94100229EULL,
		0xF0790337D84F4B36ULL,
		0x072295E6B7A072C4ULL,
		0xAFDAAFDBEA4C6A03ULL,
		0x9A71239DD30FC9E1ULL,
		0x45F4A58AC749B3C6ULL,
		0x74D21E8AF7322523ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B5227C15CA0801ULL,
		0x962783C819BEC27AULL,
		0x50183914AF35BD03ULL,
		0x4F0D7ED57EDF5263ULL,
		0x9E34D3891CEE987EULL,
		0x291A2FA52C563A4DULL,
		0x0003A690F457B991ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0xCA11498F7008F723ULL,
		0x3D3D0CAE29B611BCULL,
		0x83DF22C1E67066DEULL,
		0x7103F8B31D40BCA8ULL,
		0x1C57280608774670ULL,
		0xFD01F9183395D442ULL,
		0xECC41D4291B6CD95ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3D0CAE29B611BCCULL,
		0x3DF22C1E67066DE3ULL,
		0x103F8B31D40BCA88ULL,
		0xC572806087746707ULL,
		0xD01F9183395D4421ULL,
		0xCC41D4291B6CD95FULL,
		0x000000000000000EULL,
		0x0000000000000000ULL
	}};
	shift = 60;
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
		0x7B6031517BEC69DEULL,
		0x18653E3A1A531B0EULL,
		0xF0A112019797089DULL,
		0x431A8C7199F5C426ULL,
		0x03603D4910C3EA6BULL,
		0xEAA6CA99260574E6ULL,
		0xAB0CCD9955A3D943ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x434A6361CF6C062AULL,
		0x32F2E113A30CA7C7ULL,
		0x333EB884DE142240ULL,
		0x22187D4D6863518EULL,
		0x24C0AE9CC06C07A9ULL,
		0x2AB47B287D54D953ULL,
		0x00000000156199B3ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x2F4639763BE7F999ULL,
		0x322D2B5C96343F9EULL,
		0x218BE117A034E085ULL,
		0xE8D4CC42111176FAULL,
		0x5A5466380410168DULL,
		0x8448E4E612B6A2E0ULL,
		0x0648F14E7EE27407ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B5C96343F9E2F46ULL,
		0xE117A034E085322DULL,
		0xCC42111176FA218BULL,
		0x66380410168DE8D4ULL,
		0xE4E612B6A2E05A54ULL,
		0xF14E7EE274078448ULL,
		0x0000000000000648ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xD4EACF57A6C954A7ULL,
		0x0CDDF005457CE527ULL,
		0x9FE315BE8A8B268FULL,
		0x465190F92D8FF0A5ULL,
		0xB2B2323ADCBE8721ULL,
		0xF704F3D495698A82ULL,
		0x0C8389F19AD72C2FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x527D4EACF57A6C95ULL,
		0x68F0CDDF005457CEULL,
		0x0A59FE315BE8A8B2ULL,
		0x721465190F92D8FFULL,
		0xA82B2B2323ADCBE8ULL,
		0xC2FF704F3D495698ULL,
		0x0000C8389F19AD72ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0xF4448FF74AEA2588ULL,
		0x50B3787FA82EADA3ULL,
		0x8ABD6D534AE5D4CAULL,
		0xA41FD46848869A68ULL,
		0xC375D5164EF9165CULL,
		0xF4EBD917B3BD86D7ULL,
		0x5A4C35AA654F88F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5B47E8891FEE95DULL,
		0xBA994A166F0FF505ULL,
		0xD34D1157ADAA695CULL,
		0x22CB9483FA8D0910ULL,
		0xB0DAF86EBAA2C9DFULL,
		0xF11EBE9D7B22F677ULL,
		0x00000B4986B54CA9ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x856847C73A26D27AULL,
		0x4F3E8841F8F90766ULL,
		0xA88833DFD1EE2228ULL,
		0x12AFCC108F56430CULL,
		0x797453D12693E87AULL,
		0xDF7DBF331589802CULL,
		0x88C25D7CC95856AEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECD0AD08F8E744DULL,
		0x44509E7D1083F1F2ULL,
		0x8619511067BFA3DCULL,
		0xD0F4255F98211EACULL,
		0x0058F2E8A7A24D27ULL,
		0xAD5DBEFB7E662B13ULL,
		0x00011184BAF992B0ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xB2BF58A9C08F06A3ULL,
		0x7C619A509E49E85DULL,
		0xE9C7259CDBA53404ULL,
		0xBE7D7DBD9323B7F8ULL,
		0x8857FA9203096982ULL,
		0xA5EEE02C08779D63ULL,
		0xA453CA745E29B604ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A176CAFD62A7023ULL,
		0x4D011F1866942792ULL,
		0xEDFE3A71C96736E9ULL,
		0x5A60AF9F5F6F64C8ULL,
		0xE758E215FEA480C2ULL,
		0x6D81297BB80B021DULL,
		0x00002914F29D178AULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0xEE5B6A7E87995B1EULL,
		0xA367F0581F7EB128ULL,
		0x69228D3C99163E51ULL,
		0x39F9B16CA14B8E28ULL,
		0xE627D70C4310ECDAULL,
		0xE0769A8DA36EA3ABULL,
		0x26D60337574B2F72ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67F0581F7EB128EEULL,
		0x228D3C99163E51A3ULL,
		0xF9B16CA14B8E2869ULL,
		0x27D70C4310ECDA39ULL,
		0x769A8DA36EA3ABE6ULL,
		0xD60337574B2F72E0ULL,
		0x0000000000000026ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x2FC201E9A5A8CED1ULL,
		0x1162EBA7FBB0FA75ULL,
		0x150D2C3AC60F9528ULL,
		0xC9C9709E9C7F38C1ULL,
		0x62D4F56B4DD175BCULL,
		0x881CFE8125F5667BULL,
		0xA20CD44A59ED5259ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FBB0FA752FC201EULL,
		0xAC60F95281162EBAULL,
		0xE9C7F38C1150D2C3ULL,
		0xB4DD175BCC9C9709ULL,
		0x125F5667B62D4F56ULL,
		0xA59ED5259881CFE8ULL,
		0x000000000A20CD44ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x9E6FBEF4651679A6ULL,
		0xDBE368A83926E776ULL,
		0xBF0FA9F5C9B2940CULL,
		0x8F8982B0260769E4ULL,
		0x9FD984CC8168E834ULL,
		0x2EAE14CCD85E5C78ULL,
		0xD2DF3BC315439690ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEED3CDF7DE8CA2CFULL,
		0x819B7C6D150724DCULL,
		0x3C97E1F53EB93652ULL,
		0x0691F1305604C0EDULL,
		0x8F13FB3099902D1DULL,
		0xD205D5C2999B0BCBULL,
		0x001A5BE77862A872ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xC24673C9A3B065A3ULL,
		0x2AE5C25CCCE02E00ULL,
		0xF32D06A41B0CA135ULL,
		0x4FD7858438300742ULL,
		0xCEC4C8BB2463D4FEULL,
		0x7CC4B2C10BD52DC5ULL,
		0x0A52576E8CD8B3A7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C24673C9A3B065AULL,
		0x52AE5C25CCCE02E0ULL,
		0x2F32D06A41B0CA13ULL,
		0xE4FD785843830074ULL,
		0x5CEC4C8BB2463D4FULL,
		0x77CC4B2C10BD52DCULL,
		0x00A52576E8CD8B3AULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xF172EB6181319E2CULL,
		0xCCB0EE6ED0A65FADULL,
		0x949A85EF0C5051E8ULL,
		0x82C4F8B73D580011ULL,
		0x5D63CDDD43AFED42ULL,
		0x45872DCA890DC3C1ULL,
		0xF5EFCFF952FBDCF9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFADF172EB6181319ULL,
		0x1E8CCB0EE6ED0A65ULL,
		0x011949A85EF0C505ULL,
		0xD4282C4F8B73D580ULL,
		0x3C15D63CDDD43AFEULL,
		0xCF945872DCA890DCULL,
		0x000F5EFCFF952FBDULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x1573ECF855CB43C2ULL,
		0xDB009AD4FC5C0898ULL,
		0x6C562ECDF1C6D2DFULL,
		0x367C3FE54F7427F5ULL,
		0x2C7CBF8194D71A53ULL,
		0xF5442E6AB028A3A3ULL,
		0x3A3841CA09B4057DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB60135A9F8B81130ULL,
		0xD8AC5D9BE38DA5BFULL,
		0x6CF87FCA9EE84FEAULL,
		0x58F97F0329AE34A6ULL,
		0xEA885CD560514746ULL,
		0x7470839413680AFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xF6720A4A4A27956EULL,
		0xCCCDB28F4A522696ULL,
		0x20523E6EAB803424ULL,
		0xC09D5BF014AD0DBFULL,
		0x9D2F660A7FC9F727ULL,
		0x5E3748C8BCB3DAF7ULL,
		0x34F90F6877264E49ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A529134B7B39052ULL,
		0x755C01A126666D94ULL,
		0x80A5686DF90291F3ULL,
		0x53FE4FB93E04EADFULL,
		0x45E59ED7BCE97B30ULL,
		0x43B932724AF1BA46ULL,
		0x0000000001A7C87BULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x991D71130DB0C94DULL,
		0x6EE8920AEFCAC822ULL,
		0x5CF44BFCB827991EULL,
		0xDA95236904F67E69ULL,
		0x38742DE5B3FA5A7BULL,
		0x5951BBE2DD1DE8E2ULL,
		0x2DAD7DEF73801DBEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD12415DF9590453ULL,
		0x9E897F9704F323CDULL,
		0x52A46D209ECFCD2BULL,
		0x0E85BCB67F4B4F7BULL,
		0x2A377C5BA3BD1C47ULL,
		0xB5AFBDEE7003B7CBULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x45F3F57E0027DBE5ULL,
		0xA974C0221C58A747ULL,
		0x98C6F6269D4D9AF8ULL,
		0x21002F84CFDDD6ADULL,
		0x7F2E7DFC78B648FCULL,
		0xC9A10FED0E5B95A8ULL,
		0x1BDA6CB79385D804ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA74745F3F57E0027ULL,
		0x9AF8A974C0221C58ULL,
		0xD6AD98C6F6269D4DULL,
		0x48FC21002F84CFDDULL,
		0x95A87F2E7DFC78B6ULL,
		0xD804C9A10FED0E5BULL,
		0x00001BDA6CB79385ULL,
		0x0000000000000000ULL
	}};
	shift = 16;
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
		0xD34674F5D8752A3CULL,
		0xE3CE167F2C6C30D6ULL,
		0xC277130CCE6B3A28ULL,
		0x9198D9E484FF5191ULL,
		0x4B8607BB24C94B18ULL,
		0x16453089217B2234ULL,
		0x149095582AE63489ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C30D6D34674F5D8ULL,
		0x6B3A28E3CE167F2CULL,
		0xFF5191C277130CCEULL,
		0xC94B189198D9E484ULL,
		0x7B22344B8607BB24ULL,
		0xE634891645308921ULL,
		0x000000149095582AULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x89D2C5036D9BF245ULL,
		0x7BA531FAA9E55629ULL,
		0x6E4B4CE855FA57D1ULL,
		0x1AE8E4BCE8DBAD66ULL,
		0x54DA72721FAA0803ULL,
		0x07CB5FC5A6E1B6B1ULL,
		0x93C736CC437FC03DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5562989D2C5036DULL,
		0xFA57D17BA531FAA9ULL,
		0xDBAD666E4B4CE855ULL,
		0xAA08031AE8E4BCE8ULL,
		0xE1B6B154DA72721FULL,
		0x7FC03D07CB5FC5A6ULL,
		0x00000093C736CC43ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x1EBEA5E13F4AFBE1ULL,
		0x9307CCFC9B42BF22ULL,
		0x137DE6B4697697EDULL,
		0xA5DCC2BFA475AF02ULL,
		0xA78AAC70D7379AF0ULL,
		0x0A24999C8B7FF633ULL,
		0xB04311746277549CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6857E443D7D4BC27ULL,
		0x2ED2FDB260F99F93ULL,
		0x8EB5E0426FBCD68DULL,
		0xE6F35E14BB9857F4ULL,
		0x6FFEC674F1558E1AULL,
		0x4EEA938144933391ULL,
		0x0000001608622E8CULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x7CE1C201CD98FC87ULL,
		0x7F23D92E8CCCF94AULL,
		0x261DF138015B5C60ULL,
		0xDF58083F61B5C18AULL,
		0x21DF324958EE1333ULL,
		0xD906C171BCB46246ULL,
		0xE2E8553F81C0E85FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CCCF94A7CE1C201ULL,
		0x015B5C607F23D92EULL,
		0x61B5C18A261DF138ULL,
		0x58EE1333DF58083FULL,
		0xBCB4624621DF3249ULL,
		0x81C0E85FD906C171ULL,
		0x00000000E2E8553FULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x387115FD97E08A9DULL,
		0x685C33141DFB5F79ULL,
		0x54392F68876C3ADBULL,
		0x28A31C55EE68FFDBULL,
		0x586340A758866F78ULL,
		0x309A57E21A215DA2ULL,
		0x533B415CB41B1F1DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF270E22BFB2FC11ULL,
		0x5B6D0B866283BF6BULL,
		0xFB6A8725ED10ED87ULL,
		0xEF0514638ABDCD1FULL,
		0xB44B0C6814EB10CDULL,
		0xE3A6134AFC43442BULL,
		0x000A67682B968363ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xC1A073BC1D0CB906ULL,
		0x30681959D98459F2ULL,
		0x0B00E2C07358D674ULL,
		0x0A677F6BF5EDFCB1ULL,
		0x9CA2F829FAF0DE3DULL,
		0xEDF6511E5930B9CDULL,
		0xEC0231A18D05169AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60D032B3B308B3E5ULL,
		0x1601C580E6B1ACE8ULL,
		0x14CEFED7EBDBF962ULL,
		0x3945F053F5E1BC7AULL,
		0xDBECA23CB261739BULL,
		0xD80463431A0A2D35ULL,
		0x0000000000000001ULL,
		0x0000000000000000ULL
	}};
	shift = 63;
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
		0xBF3BF81F711E32F2ULL,
		0xDB21ACEC23E44723ULL,
		0x8AAC8730E35B4C04ULL,
		0x82488DC1E61549ABULL,
		0x875E6CECF70FF78BULL,
		0xDC245F2FBDA49845ULL,
		0x3AE46D50648A1ABBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D67611F22391DF9ULL,
		0x6439871ADA6026D9ULL,
		0x446E0F30AA4D5C55ULL,
		0xF36767B87FBC5C12ULL,
		0x22F97DED24C22C3AULL,
		0x236A832450D5DEE1ULL,
		0x00000000000001D7ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0xAD5F67789312FF66ULL,
		0x8F172C514D1C42A5ULL,
		0xD7F125FEDDABCFD7ULL,
		0xE9102BE34B99E850ULL,
		0xADCC6FBD726CFE1FULL,
		0xE354BB91228A7EE4ULL,
		0xE4BDC9297EBB3937ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8854B5ABECEF1262ULL,
		0x79FAF1E2E58A29A3ULL,
		0x3D0A1AFE24BFDBB5ULL,
		0x9FC3FD22057C6973ULL,
		0x4FDC95B98DF7AE4DULL,
		0x6726FC6A97722451ULL,
		0x00001C97B9252FD7ULL,
		0x0000000000000000ULL
	}};
	shift = 19;
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
		0x83BD509E870C0A9DULL,
		0xC2E8768C24F30820ULL,
		0x8F6654700277D21CULL,
		0x42960655F692D30EULL,
		0x1328CD88E51439C2ULL,
		0xC40095C5E3916A46ULL,
		0xE33C4C8E523BE64FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43B461279841041DULL,
		0x32A38013BE90E617ULL,
		0xB032AFB49698747BULL,
		0x466C4728A1CE1214ULL,
		0x04AE2F1C8B523099ULL,
		0xE2647291DF327E20ULL,
		0x0000000000000719ULL,
		0x0000000000000000ULL
	}};
	shift = 53;
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
		0x537DD657D5163E2DULL,
		0x4D113A0EE229A73FULL,
		0x054A3DB2B16A209CULL,
		0x1AB44891A7906034ULL,
		0xCB04D29AB826D2A6ULL,
		0x6CFB2B0F4801FE12ULL,
		0x7D2DBFCDCED81AAFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A0EE229A73F537DULL,
		0x3DB2B16A209C4D11ULL,
		0x4891A7906034054AULL,
		0xD29AB826D2A61AB4ULL,
		0x2B0F4801FE12CB04ULL,
		0xBFCDCED81AAF6CFBULL,
		0x0000000000007D2DULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xFE83CC9C145E204AULL,
		0x0C620DDF8ED89D35ULL,
		0x494C3016BBFD8C24ULL,
		0xE95E39CBE3218466ULL,
		0x303A4575C09414D6ULL,
		0x3BDF7B8FFA2A0C34ULL,
		0x199787E8F2F08453ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDF8ED89D35FE83CULL,
		0x016BBFD8C240C620ULL,
		0x9CBE3218466494C3ULL,
		0x575C09414D6E95E3ULL,
		0xB8FFA2A0C34303A4ULL,
		0x7E8F2F084533BDF7ULL,
		0x0000000000019978ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x8A1FA66FFB87C658ULL,
		0x4523A6D2B6C35FADULL,
		0x84A51943B06F5FD2ULL,
		0x4DD993B28BC995EEULL,
		0x0DC7547C03276FFFULL,
		0xE7F2DF25ADD7CF4BULL,
		0x4CBE438E7C16900DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56D86BF5B143F4CDULL,
		0x760DEBFA48A474DAULL,
		0x517932BDD094A328ULL,
		0x8064EDFFE9BB3276ULL,
		0xB5BAF9E961B8EA8FULL,
		0xCF82D201BCFE5BE4ULL,
		0x000000000997C871ULL,
		0x0000000000000000ULL
	}};
	shift = 35;
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
		0x7B309F1AE6834B13ULL,
		0x3DEE887F4330E53BULL,
		0x1221B67B6EB1F0F0ULL,
		0x63E14ADEBA3B69A5ULL,
		0x0940AF5E2F378F56ULL,
		0xD3618429FDD241F3ULL,
		0xB66687C2CE5C7BDAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC394EDECC27C6B9AULL,
		0xC7C3C0F7BA21FD0CULL,
		0xEDA6944886D9EDBAULL,
		0xDE3D598F852B7AE8ULL,
		0x4907CC2502BD78BCULL,
		0x71EF6B4D8610A7F7ULL,
		0x000002D99A1F0B39ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xE998EB7DF430D238ULL,
		0xDD44CD00F1315990ULL,
		0x703D08D1964B8D6BULL,
		0x0342D813CF081B18ULL,
		0x0B77FF7C08A90353ULL,
		0x0876ECA1BF7B6F38ULL,
		0x219DDDEF6C7389AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB321D331D6FBE861ULL,
		0x1AD7BA899A01E262ULL,
		0x3630E07A11A32C97ULL,
		0x06A60685B0279E10ULL,
		0xDE7016EFFEF81152ULL,
		0x135E10EDD9437EF6ULL,
		0x0000433BBBDED8E7ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xBF64BCD2CACB9C1FULL,
		0x55376A3F48C9B3EAULL,
		0x004D13B7C4ECD4C7ULL,
		0xF95E00551A3E87A6ULL,
		0x483EC77EA85725C0ULL,
		0x1DF17D5C608EE9CBULL,
		0xE9643C973BBD01AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E919367D57EC979ULL,
		0x6F89D9A98EAA6ED4ULL,
		0xAA347D0F4C009A27ULL,
		0xFD50AE4B81F2BC00ULL,
		0xB8C11DD396907D8EULL,
		0x2E777A035E3BE2FAULL,
		0x0000000001D2C879ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x8FA72A8C648ABB7FULL,
		0x0EE6F106653AFFE1ULL,
		0x624276600C9B6B9EULL,
		0xB5BD0F9C4F4FD82FULL,
		0x18E31B6917A71A06ULL,
		0x6907DA2B1E148433ULL,
		0x5B7999083F6C6EC2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x994EBFF863E9CAA3ULL,
		0x0326DAE783B9BC41ULL,
		0x13D3F60BD8909D98ULL,
		0x45E9C681AD6F43E7ULL,
		0xC785210CC638C6DAULL,
		0x0FDB1BB09A41F68AULL,
		0x0000000016DE6642ULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0xA8E983D460C86062ULL,
		0xF2D4EA75B0DB39A2ULL,
		0x5099792A89E4BF06ULL,
		0x96565396FFD9C37BULL,
		0x6B0E733F7AF08DEFULL,
		0xAC3FD4B14F33D5DBULL,
		0x0A73F2C4581D327FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB61B6734551D307ULL,
		0x5513C97E0DE5A9D4ULL,
		0x2DFFB386F6A132F2ULL,
		0x7EF5E11BDF2CACA7ULL,
		0x629E67ABB6D61CE6ULL,
		0x88B03A64FF587FA9ULL,
		0x000000000014E7E5ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xF74A2AFB6B5EA0B2ULL,
		0x54AE642CDDD794FCULL,
		0x7ABA4E412080D64BULL,
		0x563ACCF36455516AULL,
		0x3871D5996AF65D87ULL,
		0x631D15CE5CC084C8ULL,
		0x6D0B49A4BE736D33ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95CC859BBAF29F9EULL,
		0x5749C824101AC96AULL,
		0xC7599E6C8AAA2D4FULL,
		0x0E3AB32D5ECBB0EAULL,
		0x63A2B9CB98109907ULL,
		0xA1693497CE6DA66CULL,
		0x000000000000000DULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0xC8FE04F2AAE44968ULL,
		0x2ED0F70883FD540CULL,
		0x6D092099B0A316B5ULL,
		0x2E472185952F488FULL,
		0xB891C4EC220AFAF2ULL,
		0x75BD38D7C3D803CAULL,
		0xD870D7B0BF827918ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB43DC220FF55033ULL,
		0xB4248266C28C5AD4ULL,
		0xB91C861654BD223DULL,
		0xE24713B0882BEBC8ULL,
		0xD6F4E35F0F600F2AULL,
		0x61C35EC2FE09E461ULL,
		0x0000000000000003ULL,
		0x0000000000000000ULL
	}};
	shift = 62;
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
		0x3804C319C01EBBFEULL,
		0x40F2DA297446F3B7ULL,
		0x25B5CAC6FAB50C09ULL,
		0xF36F9C3E5D3F49E6ULL,
		0xDFFE11C8DF0C5089ULL,
		0xF772136C79C04CF7ULL,
		0x3D1453028092208AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2379DB9C02618CEULL,
		0xD5A8604A0796D14BULL,
		0xE9FA4F312DAE5637ULL,
		0xF862844F9B7CE1F2ULL,
		0xCE0267BEFFF08E46ULL,
		0x04910457BB909B63ULL,
		0x00000001E8A29814ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0xE8636F13477827C3ULL,
		0x42888E04F7134CC8ULL,
		0x02371727659B0E64ULL,
		0xFF0A06592DEBF9AEULL,
		0x549B6070FF293E05ULL,
		0x87F8AC1D99A4203FULL,
		0xB53684BB4625EE2DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89A6647431B789A3ULL,
		0xCD8732214447027BULL,
		0xF5FCD7011B8B93B2ULL,
		0x949F02FF85032C96ULL,
		0xD2101FAA4DB0387FULL,
		0x12F716C3FC560ECCULL,
		0x0000005A9B425DA3ULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xD2EE3A38E717A27FULL,
		0x6B37B86C0242C419ULL,
		0xA6E098CFB5313D12ULL,
		0x1CB71E6F6D5CC464ULL,
		0x4EDEDF1133449AF5ULL,
		0x171A1CBB3ADAA1AAULL,
		0x5D2CE3F91FE6477CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x242C419D2EE3A38EULL,
		0x5313D126B37B86C0ULL,
		0xD5CC464A6E098CFBULL,
		0x3449AF51CB71E6F6ULL,
		0xADAA1AA4EDEDF113ULL,
		0xFE6477C171A1CBB3ULL,
		0x00000005D2CE3F91ULL,
		0x0000000000000000ULL
	}};
	shift = 28;
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
		0x53E02FFDC26DA30BULL,
		0x1A213BDB3F77E19EULL,
		0x4DA959C73058A58FULL,
		0x07F47F11BDF03870ULL,
		0x2F91E03BD92F3457ULL,
		0xC678D6CCF6CDDCCEULL,
		0xA568364DB439D387ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FBBF0CF29F017FEULL,
		0x982C52C78D109DEDULL,
		0xDEF81C3826D4ACE3ULL,
		0xEC979A2B83FA3F88ULL,
		0x7B66EE6717C8F01DULL,
		0xDA1CE9C3E33C6B66ULL,
		0x0000000052B41B26ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xDA63E553A83EC3A7ULL,
		0x14FCEC8B7D011207ULL,
		0xA294C564AAFE4A26ULL,
		0x85F6B204A6B67DADULL,
		0xE8BA03C5AACC5AFDULL,
		0x444678F21463962BULL,
		0x05784F6118F1DB90ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D011207DA63E55ULL,
		0x4AAFE4A2614FCEC8ULL,
		0x4A6B67DADA294C56ULL,
		0x5AACC5AFD85F6B20ULL,
		0x21463962BE8BA03CULL,
		0x118F1DB90444678FULL,
		0x00000000005784F6ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0x7EC0EA9561EB1145ULL,
		0x7DBAB86728F72E06ULL,
		0x8677398F871F6603ULL,
		0xDF4ADED56874BBF3ULL,
		0x110AC7011F2A3609ULL,
		0x116307A21D963AD5ULL,
		0x0E41B1B1E3C0FE81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86728F72E067EC0ULL,
		0x398F871F66037DBAULL,
		0xDED56874BBF38677ULL,
		0xC7011F2A3609DF4AULL,
		0x07A21D963AD5110AULL,
		0xB1B1E3C0FE811163ULL,
		0x0000000000000E41ULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xA3A9A7B53C266CEEULL,
		0xD21E83408CC3D121ULL,
		0x5C1CA2E5CE6FADC8ULL,
		0xA8AB14CCD5BD4941ULL,
		0x342824C774ABDC78ULL,
		0x225308F5FCEF23B2ULL,
		0x043F91FD508745D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x121A3A9A7B53C266ULL,
		0xDC8D21E83408CC3DULL,
		0x9415C1CA2E5CE6FAULL,
		0xC78A8AB14CCD5BD4ULL,
		0x3B2342824C774ABDULL,
		0x5D7225308F5FCEF2ULL,
		0x000043F91FD50874ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x05CCFA07E4692587ULL,
		0x32AC5482ABAF3CD0ULL,
		0x0478382AC3ACE248ULL,
		0x5D331FB4404E1FDFULL,
		0xDF6C10DB115110ACULL,
		0xDA6108709FC7BDCBULL,
		0x584BC5341FC3EFE1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEBCF3401733E81FULL,
		0x0EB38920CAB1520AULL,
		0x01387F7C11E0E0ABULL,
		0x454442B174CC7ED1ULL,
		0x7F1EF72F7DB0436CULL,
		0x7F0FBF87698421C2ULL,
		0x00000001612F14D0ULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x4F439C170FE5A603ULL,
		0xCEAED49E77883264ULL,
		0x7C326D0BB55208FCULL,
		0x6EE4B414D9C456CBULL,
		0xE7DC4FE24C4631A3ULL,
		0x48A789996718E832ULL,
		0xFB41D1BF5D0058AFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89E87382E1FCB4C0ULL,
		0x99D5DA93CEF1064CULL,
		0x6F864DA176AA411FULL,
		0x6DDC96829B388AD9ULL,
		0x5CFB89FC4988C634ULL,
		0xE914F1332CE31D06ULL,
		0x1F683A37EBA00B15ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0xE79930BB20A12658ULL,
		0x06BB68DA1E7277D0ULL,
		0xF7CFE7E6C37B63EBULL,
		0xF5B64D2156B982FDULL,
		0xA24C77600D400086ULL,
		0x05236387FF387830ULL,
		0x883D2333C5C3636FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB43CE4EFA1CF3261ULL,
		0xCD86F6C7D60D76D1ULL,
		0x42AD7305FBEF9FCFULL,
		0xC01A80010DEB6C9AULL,
		0x0FFE70F0614498EEULL,
		0x678B86C6DE0A46C7ULL,
		0x0000000001107A46ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0x3EF08339882CFAB8ULL,
		0xCD9BDED8FA92053BULL,
		0x4C1DC03CCD86AFD7ULL,
		0x72C090A19735FD1AULL,
		0x8AEFEBE2864E9B56ULL,
		0x78EDE95573DE843EULL,
		0x699496FF2106F9C2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B3EF08339882CFAULL,
		0xD7CD9BDED8FA9205ULL,
		0x1A4C1DC03CCD86AFULL,
		0x5672C090A19735FDULL,
		0x3E8AEFEBE2864E9BULL,
		0xC278EDE95573DE84ULL,
		0x00699496FF2106F9ULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0x6ACE1E1AEE69CB9CULL,
		0x2869469262274112ULL,
		0x81A9EFB425FE52ADULL,
		0xB35C00AE977BC9AEULL,
		0x39D1712726BBEC5FULL,
		0xD507E5EC999593DAULL,
		0xFF8F809211E9E130ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26ACE1E1AEE69CB9ULL,
		0xD286946926227411ULL,
		0xE81A9EFB425FE52AULL,
		0xFB35C00AE977BC9AULL,
		0xA39D1712726BBEC5ULL,
		0x0D507E5EC999593DULL,
		0x0FF8F809211E9E13ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x25F2B3F14BB2B5C4ULL,
		0x29CA7D42D4F1FA11ULL,
		0x0817B44330D95F37ULL,
		0xC15A94BCDD08D634ULL,
		0xEA54C9D71E9129D7ULL,
		0x11E137019131B9E3ULL,
		0xDAD8A3C94397AC3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125F2B3F14BB2B5CULL,
		0x729CA7D42D4F1FA1ULL,
		0x40817B44330D95F3ULL,
		0x7C15A94BCDD08D63ULL,
		0x3EA54C9D71E9129DULL,
		0xB11E137019131B9EULL,
		0x0DAD8A3C94397AC3ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x97B55F9F51B990AEULL,
		0x61DACEDDFFAE5116ULL,
		0x972B6E7C4067C8A5ULL,
		0x902C2B9734A5A93FULL,
		0x635A433341D8025AULL,
		0x8A20B3B4B05B588DULL,
		0xE0F31C6F4473A85CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED676EFFD7288B4BULL,
		0x95B73E2033E452B0ULL,
		0x1615CB9A52D49FCBULL,
		0xAD2199A0EC012D48ULL,
		0x1059DA582DAC46B1ULL,
		0x798E37A239D42E45ULL,
		0x0000000000000070ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x44A0B105926F8D63ULL,
		0x0D68FE7DCB1C1D77ULL,
		0x0BB8C6D6B5A5C940ULL,
		0x8D244EB42985D6FFULL,
		0x4F9B24C1A4308536ULL,
		0x1B786182BAF1E72AULL,
		0x4F38445357F3CB3BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEE8941620B24DF1ULL,
		0x2801AD1FCFB96383ULL,
		0xDFE17718DAD6B4B9ULL,
		0xA6D1A489D68530BAULL,
		0xE549F36498348610ULL,
		0x67636F0C30575E3CULL,
		0x0009E7088A6AFE79ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xD791E4E5042C8814ULL,
		0xC7D93BCC7E658676ULL,
		0x38552A71933162C7ULL,
		0xB3E3093673774F08ULL,
		0xB89E2D5B253D7C81ULL,
		0xF28B6D5C9BF27172ULL,
		0xCBFB50ECB8137A1CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93BCC7E658676D79ULL,
		0x52A71933162C7C7DULL,
		0x3093673774F08385ULL,
		0xE2D5B253D7C81B3EULL,
		0xB6D5C9BF27172B89ULL,
		0xB50ECB8137A1CF28ULL,
		0x0000000000000CBFULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0x4646DFAE48FD5161ULL,
		0x160975B51A2CF985ULL,
		0x99563AB718D488EFULL,
		0xEE9A7061594B504AULL,
		0xAC8EB0E3730F3821ULL,
		0xE8792270F077E386ULL,
		0x8DE4736E2D52C2E2ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A3236FD7247EA8ULL,
		0x778B04BADA8D167CULL,
		0x254CAB1D5B8C6A44ULL,
		0x10F74D3830ACA5A8ULL,
		0xC356475871B9879CULL,
		0x71743C9138783BF1ULL,
		0x0046F239B716A961ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0x1FE47BD92C537ED5ULL,
		0x05B45634FC303801ULL,
		0x98BF2F8C76F1908FULL,
		0x7A093F0948244767ULL,
		0xFAA3A9539A52B619ULL,
		0x6791AFA2B4DBB56FULL,
		0xB3DCCFC1395245DAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5634FC3038011FE4ULL,
		0x2F8C76F1908F05B4ULL,
		0x3F094824476798BFULL,
		0xA9539A52B6197A09ULL,
		0xAFA2B4DBB56FFAA3ULL,
		0xCFC1395245DA6791ULL,
		0x000000000000B3DCULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xD7E80C4A8D406C00ULL,
		0xD9C66884569577A5ULL,
		0xFDCC9B8B34D67008ULL,
		0x3C600FB7A9F0071DULL,
		0xA58F22F87A090AA7ULL,
		0x005A3EBC52D4C754ULL,
		0x151F9A42EC1A86D0ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08AD2AEF4BAFD018ULL,
		0x1669ACE011B38CD1ULL,
		0x6F53E00E3BFB9937ULL,
		0xF0F412154E78C01FULL,
		0x78A5A98EA94B1E45ULL,
		0x85D8350DA000B47DULL,
		0x00000000002A3F34ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xAF6EE083A4102830ULL,
		0x599CD9F5A1D4C556ULL,
		0xED24BB88016FB096ULL,
		0xE935BFE9DD0714EDULL,
		0x92CC807F8D90149FULL,
		0x8F245721E62F7B2CULL,
		0x4FAED9836C711984ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB43A98AAD5EDDC1ULL,
		0x1002DF612CB339B3ULL,
		0xD3BA0E29DBDA4977ULL,
		0xFF1B20293FD26B7FULL,
		0x43CC5EF659259900ULL,
		0x06D8E233091E48AEULL,
		0x00000000009F5DB3ULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xF76C507FAF2D9321ULL,
		0x17B72F71664CA18CULL,
		0x3109BF419AA89944ULL,
		0x636A748A8B3B0D8FULL,
		0x2216BF837297D3A4ULL,
		0xFD9A94C592F92B3AULL,
		0x25AC69A07C1E1FF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2650C67BB6283FD7ULL,
		0x544CA20BDB97B8B3ULL,
		0x9D86C79884DFA0CDULL,
		0x4BE9D231B53A4545ULL,
		0x7C959D110B5FC1B9ULL,
		0x0F0FFAFECD4A62C9ULL,
		0x00000012D634D03EULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0xAE2C56ADA3367D92ULL,
		0x2B3C2C0ACB103E67ULL,
		0xBA0DFBE767EACC9FULL,
		0xC4070FE89DB621DDULL,
		0x5235A77CF19A8DF3ULL,
		0xF5CF583B7B44CC05ULL,
		0xB8FB7660DBAD7552ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x160565881F33D716ULL,
		0xFDF3B3F5664F959EULL,
		0x87F44EDB10EEDD06ULL,
		0xD3BE78CD46F9E203ULL,
		0xAC1DBDA26602A91AULL,
		0xBB306DD6BAA97AE7ULL,
		0x0000000000005C7DULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x1C17D8968A2F922DULL,
		0x53DF6AB84886DEC2ULL,
		0xCC67396183232DE9ULL,
		0xF5ED37141CF067DBULL,
		0x94387A640BA241DDULL,
		0x972031FD75A48831ULL,
		0x1D1F5D8AAE6CDD45ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8705F625A28BE48BULL,
		0x54F7DAAE1221B7B0ULL,
		0xF319CE5860C8CB7AULL,
		0x7D7B4DC5073C19F6ULL,
		0x650E1E9902E89077ULL,
		0x65C80C7F5D69220CULL,
		0x0747D762AB9B3751ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0x01D9A617969DB94BULL,
		0xD6CF75E6F97821DBULL,
		0xA7E454017A335278ULL,
		0xAE1F656E06B74FA7ULL,
		0x0B9BFB0DBE12C805ULL,
		0xA0F8C5B3226305D8ULL,
		0x3BF109322AA50564ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E0876C0766985E5ULL,
		0x8CD49E35B3DD79BEULL,
		0xADD3E9E9F915005EULL,
		0x84B2016B87D95B81ULL,
		0x98C17602E6FEC36FULL,
		0xA94159283E316CC8ULL,
		0x0000000EFC424C8AULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x1C5E3E853F81435CULL,
		0x5FABF858F538B79DULL,
		0x8CC0BD5863576BA6ULL,
		0x79FB91A7CA539E7EULL,
		0x432687D8FC7B8F4DULL,
		0x80B922AC5D4ECB40ULL,
		0x488764EC796BE8F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE163D4E2DE747178ULL,
		0xF5618D5DAE997EAFULL,
		0x469F294E79FA3302ULL,
		0x1F63F1EE3D35E7EEULL,
		0x8AB1753B2D010C9AULL,
		0x93B1E5AFA3C602E4ULL,
		0x000000000001221DULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xF2DCB9C68DF8D585ULL,
		0xEEDF5BD489E47240ULL,
		0x3DD8F3A4238C1B7AULL,
		0x0AF39BA7559A562EULL,
		0x659D3B3ACF0F24A5ULL,
		0x9E012FA0AC68DF3AULL,
		0x68941032256EB95BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22791C903CB72E71ULL,
		0x08E306DEBBB7D6F5ULL,
		0xD566958B8F763CE9ULL,
		0xB3C3C92942BCE6E9ULL,
		0x2B1A37CE99674ECEULL,
		0x895BAE56E7804BE8ULL,
		0x000000001A25040CULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x58C627A983C5D4E0ULL,
		0x64E10F8730094491ULL,
		0x0A53EDD4AB3F6762ULL,
		0x462A501D3334E4E9ULL,
		0x5EE9B34046C94F2EULL,
		0x45AB4110908F3C34ULL,
		0xB8C2E9018217D696ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7087C39804A248ACULL,
		0x29F6EA559FB3B132ULL,
		0x15280E999A727485ULL,
		0x74D9A02364A79723ULL,
		0xD5A08848479E1A2FULL,
		0x617480C10BEB4B22ULL,
		0x000000000000005CULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x4E9C8FA4420DA1ABULL,
		0x13543FB47D324B57ULL,
		0x6955DF19999918D9ULL,
		0x253F871201FBF261ULL,
		0x3B0BF8DDD65C068DULL,
		0xB3B3BCBE6F859AFBULL,
		0xA46DE916280DEBFEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x574E9C8FA4420DA1ULL,
		0xD913543FB47D324BULL,
		0x616955DF19999918ULL,
		0x8D253F871201FBF2ULL,
		0xFB3B0BF8DDD65C06ULL,
		0xFEB3B3BCBE6F859AULL,
		0x00A46DE916280DEBULL,
		0x0000000000000000ULL
	}};
	shift = 8;
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
		0xC2CE4429D38133ACULL,
		0xE343997E960F6E4AULL,
		0x425FB928C76DFF03ULL,
		0x6635349587AC86E0ULL,
		0x6534C109B38C2F54ULL,
		0xB02DDA689BA6022EULL,
		0xA32D5EFBC47DAF5AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB07B72561672214EULL,
		0x3B6FF81F1A1CCBF4ULL,
		0x3D64370212FDC946ULL,
		0x9C617AA331A9A4ACULL,
		0xDD30117329A6084DULL,
		0x23ED7AD5816ED344ULL,
		0x00000005196AF7DEULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x728F693BB4B08988ULL,
		0x6F7B301F7134F828ULL,
		0x7B84A0CEDAE0761DULL,
		0xF6DCDE396930A42EULL,
		0xC892977A630D182DULL,
		0x2F90945C0878DD8FULL,
		0x5106C975DEDEB880ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01F7134F828728F6ULL,
		0x0CEDAE0761D6F7B3ULL,
		0xE396930A42E7B84AULL,
		0x77A630D182DF6DCDULL,
		0x45C0878DD8FC8929ULL,
		0x975DEDEB8802F909ULL,
		0x000000000005106CULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x0F0FD54F02A1335EULL,
		0xC32765342397CE30ULL,
		0xA99BF50A216BD681ULL,
		0x08C6E825BFCAA812ULL,
		0xBF9031816C700947ULL,
		0x70E30B2FF4ED976AULL,
		0x8C3D7D12D5B5EB1AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29A11CBE7180787EULL,
		0xA8510B5EB40E193BULL,
		0x412DFE5540954CDFULL,
		0x8C0B63804A384637ULL,
		0x597FA76CBB55FC81ULL,
		0xE896ADAF58D38718ULL,
		0x00000000000461EBULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0xAEE45493E590D587ULL,
		0xCD812CA580510F33ULL,
		0x45BF479E09FC42B2ULL,
		0xDA0C4AD201E21CE6ULL,
		0xEC46A4B95B643028ULL,
		0x80A802C21E880CFFULL,
		0x113CBC061B9D43D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA21E675DC8A927CBULL,
		0xF885659B02594B00ULL,
		0xC439CC8B7E8F3C13ULL,
		0xC86051B41895A403ULL,
		0x1019FFD88D4972B6ULL,
		0x3A87A3015005843DULL,
		0x0000002279780C37ULL,
		0x0000000000000000ULL
	}};
	shift = 23;
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
		0x99432804CE616537ULL,
		0x8429CF710A856ACAULL,
		0x42928BE8E96D2DBCULL,
		0x76FACC9C229C6B86ULL,
		0x44A3068068A7F1C5ULL,
		0xF4A427C3DB131C62ULL,
		0xF208B68CC46622D7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8539EE2150AD5953ULL,
		0x52517D1D2DA5B790ULL,
		0xDF599384538D70C8ULL,
		0x9460D00D14FE38AEULL,
		0x9484F87B62638C48ULL,
		0x4116D1988CC45AFEULL,
		0x000000000000001EULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x60152F6B7E65A8D7ULL,
		0x0296E8879FF83C43ULL,
		0x013213DFF34B6D55ULL,
		0xAC7F0E007B7D49A6ULL,
		0xB695BD858168856EULL,
		0x4CD8192FF757C1B5ULL,
		0x0ECCADBB50142731ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF10D8054BDADF996ULL,
		0xB5540A5BA21E7FE0ULL,
		0x269804C84F7FCD2DULL,
		0x15BAB1FC3801EDF5ULL,
		0x06D6DA56F61605A2ULL,
		0x9CC5336064BFDD5FULL,
		0x00003B32B6ED4050ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0xA25DD47522481CECULL,
		0x11B65FB9AA553693ULL,
		0xF4A8F7647237AB6CULL,
		0x5164B8DB0D904117ULL,
		0xC4469EF071BFE184ULL,
		0x21F40A6B5ACF0C0FULL,
		0x8551B8105BB21B81ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB49D12EEA3A91240ULL,
		0x5B608DB2FDCD52A9ULL,
		0x08BFA547BB2391BDULL,
		0x0C228B25C6D86C82ULL,
		0x607E2234F7838DFFULL,
		0xDC090FA0535AD678ULL,
		0x00042A8DC082DD90ULL,
		0x0000000000000000ULL
	}};
	shift = 13;
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
		0x199CB772A8C3FBDCULL,
		0x502BBA4D46D5492AULL,
		0xF4349E1A2FDDC6F4ULL,
		0x2286A3DDE9AF7B7FULL,
		0x7575E798EB45ECCAULL,
		0x2A7CCCC3597EE9FDULL,
		0x2C41DFC30620E4D1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x925433396EE55187ULL,
		0x8DE8A057749A8DAAULL,
		0xF6FFE8693C345FBBULL,
		0xD994450D47BBD35EULL,
		0xD3FAEAEBCF31D68BULL,
		0xC9A254F99986B2FDULL,
		0x00005883BF860C41ULL,
		0x0000000000000000ULL
	}};
	shift = 15;
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
		0xE8D751A4D03E9B43ULL,
		0xDD9C00A4B24B0CF2ULL,
		0xDD0D0EE6A845C1D7ULL,
		0xB428AC43A04EC63FULL,
		0x096B354B07C81712ULL,
		0x3E06166CCED81AAFULL,
		0x3E3ADED8B072FD76ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x746BA8D2681F4DA1ULL,
		0xEECE005259258679ULL,
		0xEE8687735422E0EBULL,
		0x5A145621D027631FULL,
		0x84B59AA583E40B89ULL,
		0x1F030B36676C0D57ULL,
		0x1F1D6F6C58397EBBULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x409CFBD177A457EDULL,
		0xBFB2033E5ADF46D0ULL,
		0x1EB7CCB4ADBE4D38ULL,
		0xF8826D13F77DAA09ULL,
		0x150BF3E2417541F6ULL,
		0x47C36A064CC7C24BULL,
		0x8C45B94EB88B860FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x019F2D6FA368204EULL,
		0xE65A56DF269C5FD9ULL,
		0x3689FBBED5048F5BULL,
		0xF9F120BAA0FB7C41ULL,
		0xB5032663E1258A85ULL,
		0xDCA75C45C307A3E1ULL,
		0x0000000000004622ULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x4E0DC43BE3BF8E5EULL,
		0x4AE365BAB9D23A2DULL,
		0x97BDAEB1CF5DDCA4ULL,
		0xF081D3CB95FA8CE6ULL,
		0xC529C3EE07E12B2EULL,
		0xA4A147F7B6B59850ULL,
		0x8C6C6B41EACAACBDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23A2D4E0DC43BE3BULL,
		0xDDCA44AE365BAB9DULL,
		0xA8CE697BDAEB1CF5ULL,
		0x12B2EF081D3CB95FULL,
		0x59850C529C3EE07EULL,
		0xAACBDA4A147F7B6BULL,
		0x000008C6C6B41EACULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xFFFDA6F4AB08903BULL,
		0x6999A05EF51B450DULL,
		0xD38F4982488EB225ULL,
		0x531821E46F950B97ULL,
		0xF03E5DCB9E5DEEE1ULL,
		0x0844227C3B79EE77ULL,
		0xDF09DD6E7AD1B974ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A05EF51B450DFFFULL,
		0xF4982488EB225699ULL,
		0x821E46F950B97D38ULL,
		0xE5DCB9E5DEEE1531ULL,
		0x4227C3B79EE77F03ULL,
		0x9DD6E7AD1B974084ULL,
		0x0000000000000DF0ULL,
		0x0000000000000000ULL
	}};
	shift = 52;
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
		0xDEC02073414F18EDULL,
		0xD43D0156440714BBULL,
		0x03D50D6252FD8873ULL,
		0x62049B13AAD97DFDULL,
		0xAF47AA166B953A46ULL,
		0x33C935F1B1AF4E6FULL,
		0x055649629AB28810ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D0156440714BBDEULL,
		0xD50D6252FD8873D4ULL,
		0x049B13AAD97DFD03ULL,
		0x47AA166B953A4662ULL,
		0xC935F1B1AF4E6FAFULL,
		0x5649629AB2881033ULL,
		0x0000000000000005ULL,
		0x0000000000000000ULL
	}};
	shift = 56;
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
		0x2FE772F85B9E9822ULL,
		0xBC9F494BD5297155ULL,
		0x5C85FE784D0DA283ULL,
		0x9D4126FC6C16733DULL,
		0x7F0BF2B3583F676FULL,
		0x1F4955C583971732ULL,
		0x04F59DEE88C84AB7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2971552FE772F85BULL,
		0x0DA283BC9F494BD5ULL,
		0x16733D5C85FE784DULL,
		0x3F676F9D4126FC6CULL,
		0x9717327F0BF2B358ULL,
		0xC84AB71F4955C583ULL,
		0x00000004F59DEE88ULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x72C81E381BDE04A3ULL,
		0xAA2F66BE0E807378ULL,
		0xFED6849A08116B82ULL,
		0x65DB5AB4910311A8ULL,
		0x11A0EF3DCFF14DEFULL,
		0xCB591776FA41A666ULL,
		0x1B1C22864C6DA8A5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D00E6F0E5903C70ULL,
		0x1022D705545ECD7CULL,
		0x22062351FDAD0934ULL,
		0x9FE29BDECBB6B569ULL,
		0xF4834CCC2341DE7BULL,
		0x98DB514B96B22EEDULL,
		0x000000003638450CULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x28F0B6894EAC14FEULL,
		0x2233309FC2D2EDACULL,
		0x97A64CCF185B9C19ULL,
		0x8D7EFE77A9CB90D1ULL,
		0xB64C720B7F7F4892ULL,
		0x84D3F61BCD7BE2C7ULL,
		0x83493BA4A6C0F869ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BB6B0A3C2DA253ULL,
		0x16E706488CCC27F0ULL,
		0x72E43465E99333C6ULL,
		0xDFD224A35FBF9DEAULL,
		0x5EF8B1ED931C82DFULL,
		0xB03E1A6134FD86F3ULL,
		0x00000020D24EE929ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x255A9FF19D69F822ULL,
		0xB8D1A25EF4C5DEB6ULL,
		0xBEFC1406D2710576ULL,
		0x5554AE2A8A29ED81ULL,
		0x1D46018EDD6CC8A0ULL,
		0x69910097FC5A22CAULL,
		0x5A8F6C3EDDE69ACDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5DEB6255A9FF19DULL,
		0x710576B8D1A25EF4ULL,
		0x29ED81BEFC1406D2ULL,
		0x6CC8A05554AE2A8AULL,
		0x5A22CA1D46018EDDULL,
		0xE69ACD69910097FCULL,
		0x0000005A8F6C3EDDULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0xCBE183FBF360DFD3ULL,
		0x0ECBB8291F7F415CULL,
		0xFB6AC6228DF2D3F9ULL,
		0x5C334980671D7B7FULL,
		0x989703212421AB6AULL,
		0x6E3DAC7ACED702D0ULL,
		0xC6448BFCCEAD0784ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A47DFD05732F86ULL,
		0x188A37CB4FE43B2EULL,
		0x26019C75EDFFEDABULL,
		0x0C849086ADA970CDULL,
		0xB1EB3B5C0B42625CULL,
		0x2FF33AB41E11B8F6ULL,
		0x0000000000031912ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xD393254809C4B46FULL,
		0x3D912DBE1539B663ULL,
		0x2ED78A237EC97B34ULL,
		0xC938FD37CD41AF68ULL,
		0xA950AF0E899F05B6ULL,
		0xEBBDA600EC5C73C6ULL,
		0xE01CC2DA23311B7FULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A9CDB31E9C992A4ULL,
		0xBF64BD9A1EC896DFULL,
		0xE6A0D7B4176BC511ULL,
		0x44CF82DB649C7E9BULL,
		0x762E39E354A85787ULL,
		0x11988DBFF5DED300ULL,
		0x00000000700E616DULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xC7379019DA886532ULL,
		0xECA1E05F3532A123ULL,
		0x08D08D3B13FB650DULL,
		0x5AA3B3DD86295257ULL,
		0xB85E9BD767577EBFULL,
		0x33F42B3948FC6C3EULL,
		0x4A643F34A357F0D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6542478E6F2033BULL,
		0x7F6CA1BD943C0BE6ULL,
		0xC52A4AE11A11A762ULL,
		0xEAEFD7EB54767BB0ULL,
		0x1F8D87D70BD37AECULL,
		0x6AFE1AA67E856729ULL,
		0x000000094C87E694ULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x2EEC850DF5EE8492ULL,
		0xF43B295D5C88D69BULL,
		0xD80139D0B902CDC7ULL,
		0xCD193A0F0B8B8247ULL,
		0x72D7B182CCA0A813ULL,
		0xD06A34977993FBF4ULL,
		0x9086BB2FA40809F7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ECA57572235A6CBULL,
		0x004E742E40B371FDULL,
		0x464E83C2E2E091F6ULL,
		0xB5EC60B3282A04F3ULL,
		0x1A8D25DE64FEFD1CULL,
		0x21AECBE902027DF4ULL,
		0x0000000000000024ULL,
		0x0000000000000000ULL
	}};
	shift = 58;
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
		0x25D262214B17B2ABULL,
		0x18E788EBF9B9E687ULL,
		0x1DAFBD70AA280E5DULL,
		0xBDA1EF9B06D88F6FULL,
		0xE1F10AB30D9B635FULL,
		0x26A535FA76B88B40ULL,
		0xA437E4918ADFE177ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF9B9E68725D2622ULL,
		0x0AA280E5D18E788EULL,
		0xB06D88F6F1DAFBD7ULL,
		0x30D9B635FBDA1EF9ULL,
		0xA76B88B40E1F10ABULL,
		0x18ADFE17726A535FULL,
		0x000000000A437E49ULL,
		0x0000000000000000ULL
	}};
	shift = 36;
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
		0xA12ACF143D6EF94EULL,
		0x0110A6A57D0B8CFCULL,
		0xD52FCB16F9EEB6A7ULL,
		0x7BAEC9C5A5B4AEF9ULL,
		0x55EC96FD0AFF3AFAULL,
		0x58310B28E7878D2DULL,
		0xBECB4854E1155C8BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8CFCA12ACF143D6ULL,
		0xEB6A70110A6A57D0ULL,
		0x4AEF9D52FCB16F9EULL,
		0xF3AFA7BAEC9C5A5BULL,
		0x78D2D55EC96FD0AFULL,
		0x55C8B58310B28E78ULL,
		0x00000BECB4854E11ULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0xF20984DA440F6F7FULL,
		0xF85780130E522AA5ULL,
		0xE1619E5E541CEDFCULL,
		0x0DD42587E14B4AFCULL,
		0x2BDE1CF5C9E41260ULL,
		0x9839D4B8F2508CFDULL,
		0x6A5CB66383D6C5E7ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22AA5F20984DA440ULL,
		0xCEDFCF85780130E5ULL,
		0xB4AFCE1619E5E541ULL,
		0x412600DD42587E14ULL,
		0x08CFD2BDE1CF5C9EULL,
		0x6C5E79839D4B8F25ULL,
		0x000006A5CB66383DULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x3723394E9747812FULL,
		0x2892957673DF8CEEULL,
		0x853BBA366544332BULL,
		0x58AC0C87DFC03438ULL,
		0xAA0B89BA451BD567ULL,
		0x1F3207FF4BC56C1BULL,
		0x4399B2BB84FB57A9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DC8CE53A5D1E04BULL,
		0xCA24A55D9CF7E33BULL,
		0x214EEE8D99510CCAULL,
		0xD62B0321F7F00D0EULL,
		0xEA82E26E9146F559ULL,
		0x47CC81FFD2F15B06ULL,
		0x10E66CAEE13ED5EAULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xF3C790F72EF3EB26ULL,
		0x614C946C21126B0FULL,
		0x20BB295B2F13FA6AULL,
		0x7EFCF40512CF5B42ULL,
		0x7233592D9F92C3A1ULL,
		0xC198A670384876F1ULL,
		0x7C1C6EF0A7F33FABULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21126B0FF3C790F7ULL,
		0x2F13FA6A614C946CULL,
		0x12CF5B4220BB295BULL,
		0x9F92C3A17EFCF405ULL,
		0x384876F17233592DULL,
		0xA7F33FABC198A670ULL,
		0x000000007C1C6EF0ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x0E7A925B3C68C4F9ULL,
		0x2B6A948457368844ULL,
		0x61897240E2486BA4ULL,
		0x3BDDE007686CAF34ULL,
		0x14C6DA1D66B950CBULL,
		0xC178B1AF51857E85ULL,
		0xE07F61DCF83AF206ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D52908AE6D10881ULL,
		0x312E481C490D7485ULL,
		0x7BBC00ED0D95E68CULL,
		0x98DB43ACD72A1967ULL,
		0x2F1635EA30AFD0A2ULL,
		0x0FEC3B9F075E40D8ULL,
		0x000000000000001CULL,
		0x0000000000000000ULL
	}};
	shift = 59;
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
		0x556C70D0E8041F5CULL,
		0xA88AC8998639181DULL,
		0x9AA3E52D02518540ULL,
		0x7AF6093D3EAC4798ULL,
		0x55DACF1B739420A9ULL,
		0x1E6EEC5E917C5C99ULL,
		0xDD312B74D8FE69E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC72303AAAD8E1A1DULL,
		0x4A30A81511591330ULL,
		0xD588F313547CA5A0ULL,
		0x7284152F5EC127A7ULL,
		0x2F8B932ABB59E36EULL,
		0x1FCD3C63CDDD8BD2ULL,
		0x0000001BA6256E9BULL,
		0x0000000000000000ULL
	}};
	shift = 27;
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
		0x7289948DBA409B4BULL,
		0xEC056E6CBA11214CULL,
		0x78BA750450520EA5ULL,
		0xE346EC2EA13C81E8ULL,
		0xA40908F4F5B56E5BULL,
		0x035DCC25289C03DFULL,
		0xF6AA6A43D181B02CULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3944CA46DD204DA5ULL,
		0xF602B7365D0890A6ULL,
		0x3C5D3A8228290752ULL,
		0xF1A37617509E40F4ULL,
		0xD204847A7ADAB72DULL,
		0x01AEE612944E01EFULL,
		0x7B553521E8C0D816ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0x9EACA924BCFE996AULL,
		0x9AC970DDCDA968E5ULL,
		0xF46888E2452E30FDULL,
		0x94C0EC5CE841F6A8ULL,
		0x0204BD855592A6D0ULL,
		0x2EEF72564CA1E9DAULL,
		0x6775CADF07440A8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3967AB2A492F3FAULL,
		0xC3F66B25C37736A5ULL,
		0xDAA3D1A2238914B8ULL,
		0x9B425303B173A107ULL,
		0xA7680812F615564AULL,
		0x2A28BBBDC9593287ULL,
		0x00019DD72B7C1D10ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x2B64983B9144D1C1ULL,
		0xB4D205AB1B5BA1DDULL,
		0x6CD836B334598235ULL,
		0x2484EBB5916E4FC2ULL,
		0x68C0A2F6E848FFF6ULL,
		0x0EB4B6E2D2315135ULL,
		0xA8EA22C2D0B4F9E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6E8774AD9260EE4ULL,
		0x16608D6D34816AC6ULL,
		0x5B93F09B360DACCDULL,
		0x123FFD89213AED64ULL,
		0x8C544D5A3028BDBAULL,
		0x2D3E78C3AD2DB8B4ULL,
		0x0000002A3A88B0B4ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0xF2EB072237A40A17ULL,
		0x9EAF2C7E89B1C869ULL,
		0x350199B076FDCB4DULL,
		0xA81056A0C11AB51EULL,
		0xE275079AE9C01FD2ULL,
		0x13AD7B469E07256FULL,
		0x96EABF7295C9F8EDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A7CBAC1C88DE90ULL,
		0x2D367ABCB1FA26C7ULL,
		0xD478D40666C1DBF7ULL,
		0x7F4AA0415A83046AULL,
		0x95BF89D41E6BA700ULL,
		0xE3B44EB5ED1A781CULL,
		0x00025BAAFDCA5727ULL,
		0x0000000000000000ULL
	}};
	shift = 14;
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
		0x8127A7245C00301AULL,
		0x6A4B9A1286F818B5ULL,
		0xAC68A8AEB2B493F3ULL,
		0x6B0F66089015ABCFULL,
		0x206EDF3C286FD7DBULL,
		0x35AB143DEE1C6EDCULL,
		0x02FCCD8F039E4F3EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16B024F4E48B8006ULL,
		0x7E6D49734250DF03ULL,
		0x79F58D1515D65692ULL,
		0xFB6D61ECC11202B5ULL,
		0xDB840DDBE7850DFAULL,
		0xE7C6B56287BDC38DULL,
		0x00005F99B1E073C9ULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0x9093EEB91553CE76ULL,
		0xA170FA73A766AC97ULL,
		0xC5480B0F78A76EA6ULL,
		0x7D9CF586AADB4B69ULL,
		0x3E65014D383D5780ULL,
		0x0225DCF4B39500B6ULL,
		0x90450E02A50A102AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE9D9AB25E424FBAULL,
		0x3DE29DBA9A85C3E9ULL,
		0x1AAB6D2DA715202CULL,
		0x34E0F55E01F673D6ULL,
		0xD2CE5402D8F99405ULL,
		0x0A942840A8089773ULL,
		0x0000000002411438ULL,
		0x0000000000000000ULL
	}};
	shift = 38;
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
		0x0F7802091C1B4D36ULL,
		0x2DD60382246EEA3EULL,
		0xE9692F9581966137ULL,
		0x52E31836B9AFBC58ULL,
		0x19B189815AC1C94BULL,
		0x79884FEB63F32BF1ULL,
		0x5F878A853C3D46A1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E0891BBA8F83DE0ULL,
		0xBE56065984DCB758ULL,
		0x60DAE6BEF163A5A4ULL,
		0x26056B07252D4B8CULL,
		0x3FAD8FCCAFC466C6ULL,
		0x2A14F0F51A85E621ULL,
		0x0000000000017E1EULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x2A3E46409553BC66ULL,
		0x62D064C4ADCFE785ULL,
		0x5EBA5075067197E5ULL,
		0x17DDC8CE2646423CULL,
		0xF2AB311D7CBCA900ULL,
		0x109D90D370C2E51AULL,
		0x93532A6FBD5BD976ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951F23204AA9DE33ULL,
		0xB168326256E7F3C2ULL,
		0x2F5D283A8338CBF2ULL,
		0x0BEEE4671323211EULL,
		0x7955988EBE5E5480ULL,
		0x084EC869B861728DULL,
		0x49A99537DEADECBBULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xD5B8D25837F47523ULL,
		0x1F14253FD8E2B605ULL,
		0x8883174014C5004DULL,
		0x4C012F193DF4E6ABULL,
		0x006DF95B234303A7ULL,
		0x304819782F0C8947ULL,
		0xBDD8568F71DB0694ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD81756E34960DFDULL,
		0x401347C5094FF638ULL,
		0x39AAE220C5D00531ULL,
		0xC0E9D3004BC64F7DULL,
		0x2251C01B7E56C8D0ULL,
		0xC1A50C12065E0BC3ULL,
		0x00002F7615A3DC76ULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x8094C124269CD082ULL,
		0x4E4A8D5F7BDABA8EULL,
		0xADA75327F6AAEE55ULL,
		0xEA3169BE25940707ULL,
		0xE565158402667356ULL,
		0x250753AC56C30279ULL,
		0x6180EB9300368014ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A025304909A7342ULL,
		0x55392A357DEF6AEAULL,
		0x1EB69D4C9FDAABB9ULL,
		0x5BA8C5A6F896501CULL,
		0xE7959456100999CDULL,
		0x50941D4EB15B0C09ULL,
		0x018603AE4C00DA00ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0xAB8A81C44BC8B5B1ULL,
		0xE58ED6399EC8AD1DULL,
		0x06704527E3B4372BULL,
		0x9CE7944854F155C0ULL,
		0xA7178B0BF29061DEULL,
		0xD0EDB8BFA11B57B1ULL,
		0x380C731234CF8544ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E67B22B476AE2A0ULL,
		0x49F8ED0DCAF963B5ULL,
		0x12153C5570019C11ULL,
		0xC2FCA41877A739E5ULL,
		0x2FE846D5EC69C5E2ULL,
		0xC48D33E151343B6EULL,
		0x00000000000E031CULL,
		0x0000000000000000ULL
	}};
	shift = 42;
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
		0x27D864B6DCE87A1EULL,
		0xEBF41942A9428951ULL,
		0xE472CACF322DD04BULL,
		0xE0DEF360ED4C7A6FULL,
		0xB21C6F0345E24C6AULL,
		0x56A165B2F2A0DD54ULL,
		0x16B73841417001CEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54A144A893EC325BULL,
		0x9916E825F5FA0CA1ULL,
		0x76A63D37F2396567ULL,
		0xA2F12635706F79B0ULL,
		0x79506EAA590E3781ULL,
		0xA0B800E72B50B2D9ULL,
		0x000000000B5B9C20ULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0xD99E8E76C0E1FDB1ULL,
		0xCE9B03BF0506217DULL,
		0x687F145C90CC5CD1ULL,
		0xE387D3BFCBAC5F75ULL,
		0xE7677AA8200704A7ULL,
		0xAFC899F2B2E92A26ULL,
		0x036F6A62CCF7F645ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41885F7667A39DB0ULL,
		0x33173473A6C0EFC1ULL,
		0xEB17DD5A1FC51724ULL,
		0x01C129F8E1F4EFF2ULL,
		0xBA4A89B9D9DEAA08ULL,
		0x3DFD916BF2267CACULL,
		0x00000000DBDA98B3ULL,
		0x0000000000000000ULL
	}};
	shift = 26;
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
		0x7588E058AC3EE6AEULL,
		0xE1802C1519EE40B7ULL,
		0xE66FE76B78CC80DCULL,
		0x354C0F3041851615ULL,
		0x6D3DA376A25EBA26ULL,
		0xAE7B578C4C70E6EBULL,
		0x0321EE7FF65AC45DULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x467B902DDD623816ULL,
		0xDE33203738600B05ULL,
		0x10614585799BF9DAULL,
		0xA897AE898D5303CCULL,
		0x131C39BADB4F68DDULL,
		0xFD96B1176B9ED5E3ULL,
		0x0000000000C87B9FULL,
		0x0000000000000000ULL
	}};
	shift = 34;
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
		0x11635465FBE9C3B9ULL,
		0x5CD52017E2D6107CULL,
		0x12F69426398FA6B2ULL,
		0x081074ADD52B37A9ULL,
		0x7E04909DC51934E6ULL,
		0x1BE11D3CB97CC673ULL,
		0x1DD53C914AC7472BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E08B1AA32FDF4E1ULL,
		0x592E6A900BF16B08ULL,
		0xD4897B4A131CC7D3ULL,
		0x7304083A56EA959BULL,
		0x39BF02484EE28C9AULL,
		0x958DF08E9E5CBE63ULL,
		0x000EEA9E48A563A3ULL,
		0x0000000000000000ULL
	}};
	shift = 9;
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
		0x06A717CF0F8BB8CEULL,
		0x965C1E9020AAD336ULL,
		0xABD16D9459BEA740ULL,
		0x39D3AD43DF78E0C8ULL,
		0x5916952052FEB9FFULL,
		0xB3E0D0615E3B67E5ULL,
		0xC3FC1C355D50DC87ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4082AB4CD81A9CULL,
		0xB65166FA9D025970ULL,
		0xB50F7DE38322AF45ULL,
		0x54814BFAE7FCE74EULL,
		0x418578ED9F95645AULL,
		0x70D57543721ECF83ULL,
		0x0000000000030FF0ULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0x08A691B51307CDADULL,
		0xE687F07BF8F01A0FULL,
		0x0AE1724FDB19E92DULL,
		0xF05F79E71E38D85EULL,
		0x6E7F9636F6BAD03BULL,
		0x2B479BAFE8612C89ULL,
		0x6928BEDE7084F3E3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F01A0F08A691B5ULL,
		0xDB19E92DE687F07BULL,
		0x1E38D85E0AE1724FULL,
		0xF6BAD03BF05F79E7ULL,
		0xE8612C896E7F9636ULL,
		0x7084F3E32B479BAFULL,
		0x000000006928BEDEULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0xD6EE2BF9801F8A3CULL,
		0x2088FE066F762CA5ULL,
		0xBB8F7E56ECB9483AULL,
		0xDD4D4A4B9B55C810ULL,
		0x463C3F16AE2EC984ULL,
		0x45D40E3DFF0A34FCULL,
		0x6AC97B3C2E1D8512ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975BB8AFE6007E28ULL,
		0xE88223F819BDD8B2ULL,
		0x42EE3DF95BB2E520ULL,
		0x137535292E6D5720ULL,
		0xF118F0FC5AB8BB26ULL,
		0x49175038F7FC28D3ULL,
		0x01AB25ECF0B87614ULL,
		0x0000000000000000ULL
	}};
	shift = 6;
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
		0xB7F6772901B361EEULL,
		0xA1DB6871A61377C7ULL,
		0xC0852FF983AEB002ULL,
		0x20B78ED307FA75BEULL,
		0x1DEEEEEE014032E7ULL,
		0xD898188933D7122AULL,
		0x4F359271A261BEC3ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F6FECEE520366C3ULL,
		0x0543B6D0E34C26EFULL,
		0x7D810A5FF3075D60ULL,
		0xCE416F1DA60FF4EBULL,
		0x543BDDDDDC028065ULL,
		0x87B130311267AE24ULL,
		0x009E6B24E344C37DULL,
		0x0000000000000000ULL
	}};
	shift = 7;
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
		0x03B515C4E3076A6EULL,
		0x265A87BD5DD0EB7EULL,
		0xA7CDC8A5F8CBF71DULL,
		0x143326D0AF6A69ECULL,
		0x0D9A8AE75E418599ULL,
		0xD03C5CD6AA4682DBULL,
		0x189364CD36FDDFCAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC076A2B89C60ED4DULL,
		0xA4CB50F7ABBA1D6FULL,
		0x94F9B914BF197EE3ULL,
		0x228664DA15ED4D3DULL,
		0x61B3515CEBC830B3ULL,
		0x5A078B9AD548D05BULL,
		0x03126C99A6DFBBF9ULL,
		0x0000000000000000ULL
	}};
	shift = 3;
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
		0x64E374C2033594E7ULL,
		0x0D4771EA7450D7DDULL,
		0x3295E20D42310E27ULL,
		0x59E9F87A935F4FACULL,
		0xF1214264F0943B9AULL,
		0x54528B77866DBA4CULL,
		0x774FA5E263A55AF5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB271BA61019ACA7ULL,
		0x386A3B8F53A286BEULL,
		0x6194AF106A118871ULL,
		0xD2CF4FC3D49AFA7DULL,
		0x67890A132784A1DCULL,
		0xAAA2945BBC336DD2ULL,
		0x03BA7D2F131D2AD7ULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x08BB7A3B1C31CB5FULL,
		0xBDCA3C3866C0E581ULL,
		0xB7C7498D57EB943CULL,
		0x1589AA8AAACF7902ULL,
		0xA5A3B7524CE1FF93ULL,
		0x9D6901F576AD1173ULL,
		0x57CEE6637F634B27ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70CD81CB021176F4ULL,
		0x1AAFD728797B9478ULL,
		0x15559EF2056F8E93ULL,
		0xA499C3FF262B1355ULL,
		0xEAED5A22E74B476EULL,
		0xC6FEC6964F3AD203ULL,
		0x0000000000AF9DCCULL,
		0x0000000000000000ULL
	}};
	shift = 39;
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
		0xA54C44B8021AB2CAULL,
		0xA67B15825537BA94ULL,
		0xDA5F933868A3A32AULL,
		0xFB539B67F7276A95ULL,
		0xD3BAAB827B0371A9ULL,
		0xE850C3C458DFF3DFULL,
		0x19B8D3694A22A9CDULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x825537BA94A54C44ULL,
		0x3868A3A32AA67B15ULL,
		0x67F7276A95DA5F93ULL,
		0x827B0371A9FB539BULL,
		0xC458DFF3DFD3BAABULL,
		0x694A22A9CDE850C3ULL,
		0x000000000019B8D3ULL,
		0x0000000000000000ULL
	}};
	shift = 40;
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
		0x11F0FE3B3B2E7D2EULL,
		0x118FC1199D73083DULL,
		0x8A7367621143D3D3ULL,
		0x655418458A86D764ULL,
		0xBCEA408C73C9EBF4ULL,
		0xABE98797F6B6DF3EULL,
		0x50C42DB88F768391ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AE6107A23E1FC76ULL,
		0x2287A7A6231F8233ULL,
		0x150DAEC914E6CEC4ULL,
		0xE793D7E8CAA8308BULL,
		0xED6DBE7D79D48118ULL,
		0x1EED072357D30F2FULL,
		0x00000000A1885B71ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0x77C58DF41ED9519BULL,
		0x6C2B1C9F52F1A8CEULL,
		0x9F78E1A06885846CULL,
		0xD545774ECABB8AADULL,
		0xFA203329685A0E14ULL,
		0x52BB55787453A047ULL,
		0x4C76B4DF2C3EE4EAULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA978D4673BE2C6FAULL,
		0x3442C23636158E4FULL,
		0x655DC556CFBC70D0ULL,
		0xB42D070A6AA2BBA7ULL,
		0x3A29D023FD101994ULL,
		0x961F7275295DAABCULL,
		0x00000000263B5A6FULL,
		0x0000000000000000ULL
	}};
	shift = 33;
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
		0x31A4BE58E0509A7BULL,
		0x465D8D8109C86C84ULL,
		0x0FBE1BB1B793643BULL,
		0x1FC61FE908BDE07EULL,
		0x1238FE54B893B0A1ULL,
		0xBB722FFB5C04B99DULL,
		0xDF4FB3A88BFFAEEBULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC86C8431A4BE58E0ULL,
		0x93643B465D8D8109ULL,
		0xBDE07E0FBE1BB1B7ULL,
		0x93B0A11FC61FE908ULL,
		0x04B99D1238FE54B8ULL,
		0xFFAEEBBB722FFB5CULL,
		0x000000DF4FB3A88BULL,
		0x0000000000000000ULL
	}};
	shift = 24;
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
		0x506BA13A29D0A084ULL,
		0xF15B9C64C5331496ULL,
		0x3F89CFA9C1658455ULL,
		0xDF407D34877EEC74ULL,
		0xC206557056CA1DBEULL,
		0x16C935FADF59E045ULL,
		0x7976F6BA335696D5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC525941AE84E8A7ULL,
		0x961157C56E719314ULL,
		0xFBB1D0FE273EA705ULL,
		0x2876FB7D01F4D21DULL,
		0x678117081955C15BULL,
		0x5A5B545B24D7EB7DULL,
		0x000001E5DBDAE8CDULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0xBDE58605197A9759ULL,
		0xC8AB38F0D3F87948ULL,
		0xA5DE6B8B9FF94738ULL,
		0xB8DC9B61976FE0CDULL,
		0xB6AECCD3B9D1F00FULL,
		0xEB7D73FCB917CAE5ULL,
		0x82B344D1D4ED231AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BDE58605197A975ULL,
		0x8C8AB38F0D3F8794ULL,
		0xDA5DE6B8B9FF9473ULL,
		0xFB8DC9B61976FE0CULL,
		0x5B6AECCD3B9D1F00ULL,
		0xAEB7D73FCB917CAEULL,
		0x082B344D1D4ED231ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0xDB93EA57DC1C33DDULL,
		0xFDEC1A4544DB6F6DULL,
		0x4CA78930BCD08713ULL,
		0xC86BBCE40C6E3C1EULL,
		0x13F4D1FF3AE8723EULL,
		0xC65E086E0ABAE99AULL,
		0xA657D392BA4A5AA4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB06915136DBDB76EULL,
		0x9E24C2F3421C4FF7ULL,
		0xAEF39031B8F07932ULL,
		0xD347FCEBA1C8FB21ULL,
		0x7821B82AEBA6684FULL,
		0x5F4E4AE9296A9319ULL,
		0x0000000000000299ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x23093D03FB89F09AULL,
		0x82593F0A738FEF25ULL,
		0xD8CEC4903EDF6355ULL,
		0xA9CFEBE54D78CC9AULL,
		0x7CEBE82AEE5067A4ULL,
		0xAE1BC5BC3511B438ULL,
		0xCC0800E91E44ACA9ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FBC948C24F40FEEULL,
		0x7D8D560964FC29CEULL,
		0xE3326B633B1240FBULL,
		0x419E92A73FAF9535ULL,
		0x46D0E1F3AFA0ABB9ULL,
		0x12B2A6B86F16F0D4ULL,
		0x000003302003A479ULL,
		0x0000000000000000ULL
	}};
	shift = 22;
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
		0x672FB8FEDD046546ULL,
		0x5F1FB6BA623765BCULL,
		0xFC64529FE7B225C6ULL,
		0xBAA4FB81D94DE303ULL,
		0x045952816E9B556FULL,
		0x34E4887E5DE4C6F1ULL,
		0x8217F188C3A888D6ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB5D311BB2DE3397ULL,
		0x294FF3D912E32F8FULL,
		0x7DC0ECA6F181FE32ULL,
		0xA940B74DAAB7DD52ULL,
		0x443F2EF26378822CULL,
		0xF8C461D4446B1A72ULL,
		0x000000000000410BULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0xE7272FCC191F8DA6ULL,
		0x2DC87FCDD8BAE6AAULL,
		0x943798E47EA6B6D1ULL,
		0xC9F89964CFC9B253ULL,
		0xE19894E60B3A71B9ULL,
		0x14FA1A4B12D0B115ULL,
		0xA90C6B0B9B55C495ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7355739397E60C8FULL,
		0x5B6896E43FE6EC5DULL,
		0xD929CA1BCC723F53ULL,
		0x38DCE4FC4CB267E4ULL,
		0x588AF0CC4A73059DULL,
		0xE24A8A7D0D258968ULL,
		0x000054863585CDAAULL,
		0x0000000000000000ULL
	}};
	shift = 17;
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
		0x541C2416037378B0ULL,
		0x0B72B9235126CF90ULL,
		0xFFEF4A86FEC2819EULL,
		0x32959D1B0A661239ULL,
		0x07551155FA700000ULL,
		0xC141E74251E590F9ULL,
		0x4257E70496143B92ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE48D449B3E415070ULL,
		0x2A1BFB0A06782DCAULL,
		0x746C299848E7FFBDULL,
		0x4557E9C00000CA56ULL,
		0x9D09479643E41D54ULL,
		0x9C125850EE4B0507ULL,
		0x000000000001095FULL,
		0x0000000000000000ULL
	}};
	shift = 46;
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
		0xE6BA766407FCA978ULL,
		0xFB101C4DC39D885FULL,
		0x6A8DD446B395173AULL,
		0x2CFC66F08C8952A3ULL,
		0x20F144FD2ADD1D27ULL,
		0xD0889DFAE18AD197ULL,
		0x3B5B629080B4ABB4ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD885FE6BA766407FULL,
		0x5173AFB101C4DC39ULL,
		0x952A36A8DD446B39ULL,
		0xD1D272CFC66F08C8ULL,
		0xAD19720F144FD2ADULL,
		0x4ABB4D0889DFAE18ULL,
		0x000003B5B629080BULL,
		0x0000000000000000ULL
	}};
	shift = 20;
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
		0x4F808E47CB539219ULL,
		0x0C4B78C71C39F4F5ULL,
		0x1B0320459F1424B5ULL,
		0x65DD0E618A779E46ULL,
		0x558F0FFC2631A3D1ULL,
		0x7C2607AFA684E3F7ULL,
		0x0C7ACA75CF80D050ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C39F4F54F808E47ULL,
		0x9F1424B50C4B78C7ULL,
		0x8A779E461B032045ULL,
		0x2631A3D165DD0E61ULL,
		0xA684E3F7558F0FFCULL,
		0xCF80D0507C2607AFULL,
		0x000000000C7ACA75ULL,
		0x0000000000000000ULL
	}};
	shift = 32;
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
		0x4EC297FBAD21A25EULL,
		0x6E29E4B5F2D5E6B3ULL,
		0x95F5E3FE03E75886ULL,
		0x3195279C6217A0AAULL,
		0x89608A30E23A4AF0ULL,
		0xCA2077F00F30C656ULL,
		0x870AF17347BFD9F5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB579ACD3B0A5FEEULL,
		0x0F9D6219B8A792D7ULL,
		0x885E82AA57D78FF8ULL,
		0x88E92BC0C6549E71ULL,
		0x3CC3195A258228C3ULL,
		0x1EFF67D72881DFC0ULL,
		0x000000021C2BC5CDULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0x75088FCC02124310ULL,
		0xADF915A54D73419FULL,
		0xDF913CA0B4053B99ULL,
		0x4733058FAD3D70D7ULL,
		0x27DC029080A031B3ULL,
		0xE204A336FD31A7D2ULL,
		0x745128D29DDD5909ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x35CD067DD4223F30ULL,
		0xD014EE66B7E45695ULL,
		0xB4F5C35F7E44F282ULL,
		0x0280C6CD1CCC163EULL,
		0xF4C69F489F700A42ULL,
		0x7775642788128CDBULL,
		0x00000001D144A34AULL,
		0x0000000000000000ULL
	}};
	shift = 30;
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
		0xA21FE2008BD6AFC5ULL,
		0x13EF0C0EBF558AA1ULL,
		0x062D66A77D289AEEULL,
		0x81BD34E911B7A52BULL,
		0xECF28594F7EBB23EULL,
		0xF907499C3D97B5A5ULL,
		0xC89E7A997B126E0BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86887F88022F5ABULL,
		0xBB84FBC303AFD562ULL,
		0x4AC18B59A9DF4A26ULL,
		0x8FA06F4D3A446DE9ULL,
		0x697B3CA1653DFAECULL,
		0x82FE41D2670F65EDULL,
		0x0032279EA65EC49BULL,
		0x0000000000000000ULL
	}};
	shift = 10;
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
		0x9A017104CA618462ULL,
		0x687D934C71F27B13ULL,
		0x55AF3418EFBF4CEDULL,
		0x3B12B937328EED80ULL,
		0x2C4516B1C7B1904EULL,
		0x95AC675DD6D32BCDULL,
		0x5514FF0794024216ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A017104CA61846ULL,
		0xD687D934C71F27B1ULL,
		0x055AF3418EFBF4CEULL,
		0xE3B12B937328EED8ULL,
		0xD2C4516B1C7B1904ULL,
		0x695AC675DD6D32BCULL,
		0x05514FF079402421ULL,
		0x0000000000000000ULL
	}};
	shift = 4;
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
		0x213CB1546BECDA3AULL,
		0x3E10D3DCAB55C096ULL,
		0xBDD4763D6FC9B4A5ULL,
		0x434E87CA08557BF1ULL,
		0xA603DC34ED099330ULL,
		0x5918259DD24C51F2ULL,
		0x6F42E6E8F86EE240ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56AB812C427962A8ULL,
		0xDF93694A7C21A7B9ULL,
		0x10AAF7E37BA8EC7AULL,
		0xDA132660869D0F94ULL,
		0xA498A3E54C07B869ULL,
		0xF0DDC480B2304B3BULL,
		0x00000000DE85CDD1ULL,
		0x0000000000000000ULL
	}};
	shift = 31;
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
		0xE84B8A5E31BED747ULL,
		0x457F1652D795F148ULL,
		0xF8FB25771CC0A403ULL,
		0x9E64E7470DB2673BULL,
		0xDD2417166F3B726CULL,
		0x57BADA94F5317A61ULL,
		0xC889F6F3987E9227ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAF8A47425C52F18ULL,
		0x605201A2BF8B296BULL,
		0xD9339DFC7D92BB8EULL,
		0x9DB9364F3273A386ULL,
		0x98BD30EE920B8B37ULL,
		0x3F4913ABDD6D4A7AULL,
		0x0000006444FB79CCULL,
		0x0000000000000000ULL
	}};
	shift = 25;
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
		0x94A4EB3DE5D588C8ULL,
		0x727FA0B826C69E78ULL,
		0x5EEF0445B898E5C1ULL,
		0xDF751ED28FA2FEB3ULL,
		0x764790F64975DC3BULL,
		0xF91180101D22029AULL,
		0xA4D52B7FB1365EFCULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3634F3C4A52759EFULL,
		0xC4C72E0B93FD05C1ULL,
		0x7D17F59AF778222DULL,
		0x4BAEE1DEFBA8F694ULL,
		0xE91014D3B23C87B2ULL,
		0x89B2F7E7C88C0080ULL,
		0x0000000526A95BFDULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0xD69E50821150DACCULL,
		0xAD6CCD7C87ECB4FEULL,
		0xE4FAF017B5FD8E85ULL,
		0x8CE1EC922C369024ULL,
		0x889F17D9C0101499ULL,
		0x79E671C2FA00F1F2ULL,
		0x19505583E5EA3A8AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5A79420845436B3ULL,
		0x6B5B335F21FB2D3FULL,
		0x393EBC05ED7F63A1ULL,
		0x63387B248B0DA409ULL,
		0xA227C5F670040526ULL,
		0x9E799C70BE803C7CULL,
		0x06541560F97A8EA2ULL,
		0x0000000000000000ULL
	}};
	shift = 2;
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
		0xFE7A48DFCE51F6EAULL,
		0xBD36A72DBC8699E2ULL,
		0xECC20C1D8281D5B2ULL,
		0xB9674E49A02AFF5BULL,
		0xE8ACE8F8F354FC47ULL,
		0x7A990F37C517E1DAULL,
		0x9348245452DA77DFULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C5FCF491BF9CA3EULL,
		0xB657A6D4E5B790D3ULL,
		0xEB7D984183B0503AULL,
		0x88F72CE9C934055FULL,
		0x3B5D159D1F1E6A9FULL,
		0xFBEF5321E6F8A2FCULL,
		0x001269048A8A5B4EULL,
		0x0000000000000000ULL
	}};
	shift = 11;
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
		0xD2EA3B3E4C7DC67AULL,
		0x6D8C628C577FFA7DULL,
		0x537184EFEDAA5F14ULL,
		0x3426304D2E851034ULL,
		0x20E35F5350D42EF0ULL,
		0x522E062CB0A7E269ULL,
		0xFE0011D6257C1887ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28C577FFA7DD2EA3ULL,
		0x4EFEDAA5F146D8C6ULL,
		0x04D2E85103453718ULL,
		0xF5350D42EF034263ULL,
		0x62CB0A7E26920E35ULL,
		0x1D6257C1887522E0ULL,
		0x00000000000FE001ULL,
		0x0000000000000000ULL
	}};
	shift = 44;
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
		0x1CAD6F280513B982ULL,
		0xFAF1DB7C1B2E6523ULL,
		0x79A5E39D6DB1BCCAULL,
		0x938C0DAD88153A6DULL,
		0x7CDD6A5C6910F787ULL,
		0xDD1610003FE09C0EULL,
		0x075CF53CA05823EEULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F8365CCA46395AULL,
		0xC73ADB637995F5E3ULL,
		0x1B5B102A74DAF34BULL,
		0xD4B8D221EF0F2718ULL,
		0x20007FC1381CF9BAULL,
		0xEA7940B047DDBA2CULL,
		0x0000000000000EB9ULL,
		0x0000000000000000ULL
	}};
	shift = 47;
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
		0x129ECE6322AA56AEULL,
		0x1FAFF3646F51F6E3ULL,
		0x51BDA6BDC58AE58BULL,
		0xFB3E03898243A124ULL,
		0x2443C3C531DFC86EULL,
		0xD92BC4D7E1CDB7C5ULL,
		0x40BD1F25B3798814ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFCD91BD47DB8C4AULL,
		0xF69AF7162B962C7EULL,
		0xF80E26090E849146ULL,
		0x0F0F14C77F21BBECULL,
		0xAF135F8736DF1491ULL,
		0xF47C96CDE6205364ULL,
		0x0000000000000102ULL,
		0x0000000000000000ULL
	}};
	shift = 54;
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
		0x7632A9552A1B49CDULL,
		0x1C4CC3919B2E9106ULL,
		0xA891398AD8831DD2ULL,
		0xEBE50B722759B5F6ULL,
		0x9F9C5948DCBA6740ULL,
		0x4A584D5C68858D0CULL,
		0x614F92106291B5F1ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3919B2E91067632ULL,
		0x398AD8831DD21C4CULL,
		0x0B722759B5F6A891ULL,
		0x5948DCBA6740EBE5ULL,
		0x4D5C68858D0C9F9CULL,
		0x92106291B5F14A58ULL,
		0x000000000000614FULL,
		0x0000000000000000ULL
	}};
	shift = 48;
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
		0xAA9E91DED51A834DULL,
		0x2780A31EEBB8B238ULL,
		0xDBD4D1ED1564CAB6ULL,
		0xBC8C15BF312FC4ECULL,
		0xB007F19F69CF530CULL,
		0x550D131FF6AC5A5BULL,
		0x4EFAA1314FADC371ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x554F48EF6A8D41A6ULL,
		0x13C0518F75DC591CULL,
		0x6DEA68F68AB2655BULL,
		0x5E460ADF9897E276ULL,
		0xD803F8CFB4E7A986ULL,
		0xAA86898FFB562D2DULL,
		0x277D5098A7D6E1B8ULL,
		0x0000000000000000ULL
	}};
	shift = 1;
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
		0xD16C03788D06CF83ULL,
		0x5B057BE3AC409477ULL,
		0xC465E5DB05EB2C72ULL,
		0x1F874CA09C80DC40ULL,
		0x47B61FD3A3BA5BF8ULL,
		0xF9B28BF8B4FE0789ULL,
		0xEBF653425AD78F2AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82BDF1D6204A3BE8ULL,
		0x32F2ED82F596392DULL,
		0xC3A6504E406E2062ULL,
		0xDB0FE9D1DD2DFC0FULL,
		0xD945FC5A7F03C4A3ULL,
		0xFB29A12D6BC7957CULL,
		0x0000000000000075ULL,
		0x0000000000000000ULL
	}};
	shift = 57;
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
		0x0DE7D0E0370B6B8DULL,
		0x2B776797CC1EF9AEULL,
		0x0A90D2570C17AC96ULL,
		0x710E707FE17D28F2ULL,
		0x3CF2AB5E7D4DC129ULL,
		0xA93B90CF558E2D69ULL,
		0x815E330A1CB6DD1EULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE60F7CD706F3E87ULL,
		0xB860BD64B15BBB3CULL,
		0xFF0BE94790548692ULL,
		0xF3EA6E094B887383ULL,
		0x7AAC716B49E7955AULL,
		0x50E5B6E8F549DC86ULL,
		0x00000000040AF198ULL,
		0x0000000000000000ULL
	}};
	shift = 37;
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
		0x093D0B120F442001ULL,
		0x8747FB0E52E66C27ULL,
		0x2EBDC3572D4BF164ULL,
		0xB6A9B7BFE57E3247ULL,
		0x179F2E992263FB5EULL,
		0x4B0DDC42D74C731DULL,
		0xE516F43709EEB392ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B09C24F42C483D1ULL,
		0xFC5921D1FEC394B9ULL,
		0x8C91CBAF70D5CB52ULL,
		0xFED7ADAA6DEFF95FULL,
		0x1CC745E7CBA64898ULL,
		0xACE492C37710B5D3ULL,
		0x00003945BD0DC27BULL,
		0x0000000000000000ULL
	}};
	shift = 18;
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
		0x4ABAFED928B856B5ULL,
		0x16D5EB40E8214BE4ULL,
		0xFB2326C1CF684295ULL,
		0x70FBB9C8F5C97BD4ULL,
		0x2782AC96ED11E6A2ULL,
		0xB10A8DE0DDE76FA9ULL,
		0x302E3EA6948F9F28ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABAFED928B856B5ULL,
		0x16D5EB40E8214BE4ULL,
		0xFB2326C1CF684295ULL,
		0x70FBB9C8F5C97BD4ULL,
		0x2782AC96ED11E6A2ULL,
		0xB10A8DE0DDE76FA9ULL,
		0x302E3EA6948F9F28ULL,
		0x0000000000000000ULL
	}};
	shift = 0;
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
		0x2284D353E0053319ULL,
		0x9C24FE5F2277F63AULL,
		0x4D560453619C4E57ULL,
		0x7709DE2AB4B1E921ULL,
		0x7B8F800FEB9728F0ULL,
		0x0298B6C7B80D692BULL,
		0xBAF0C71186D1E9E5ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD114269A9F002998ULL,
		0xBCE127F2F913BFB1ULL,
		0x0A6AB0229B0CE272ULL,
		0x83B84EF155A58F49ULL,
		0x5BDC7C007F5CB947ULL,
		0x2814C5B63DC06B49ULL,
		0x05D786388C368F4FULL,
		0x0000000000000000ULL
	}};
	shift = 5;
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
		0x44DF2972D4FAAFEFULL,
		0x4D334D56AE25F848ULL,
		0x339EBA0B55A2721BULL,
		0xC33D627E6E30329AULL,
		0xED0511211D2EDE74ULL,
		0x8311BA86D1A1A393ULL,
		0xD5837DC05D4AED71ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x712FC24226F94B96ULL,
		0xAD1390DA699A6AB5ULL,
		0x718194D19CF5D05AULL,
		0xE976F3A619EB13F3ULL,
		0x8D0D1C9F68288908ULL,
		0xEA576B8C188DD436ULL,
		0x00000006AC1BEE02ULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x80FB046BB79EDC44ULL,
		0x9EFCC1D231C8AADFULL,
		0x932F3427C5C79B24ULL,
		0xE4CA0B818A9353AEULL,
		0x0F365045B613BC22ULL,
		0x4963995413A2DED2ULL,
		0xE338279A2B2D3977ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60E918E4556FC07DULL,
		0x9A13E2E3CD924F7EULL,
		0x05C0C549A9D74997ULL,
		0x2822DB09DE117265ULL,
		0xCCAA09D16F69079BULL,
		0x13CD15969CBBA4B1ULL,
		0x000000000000719CULL,
		0x0000000000000000ULL
	}};
	shift = 49;
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
		0x823354578D9110BBULL,
		0x02378C87B91F003AULL,
		0x5D678BA1E4E54B72ULL,
		0x92CC5061305186B0ULL,
		0x28BB3F8DFF88EE0AULL,
		0x11502DDCF04C0220ULL,
		0xBFFE9F8F45A8CF7BULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F801D4119AA2BCULL,
		0x272A5B9011BC643DULL,
		0x828C3582EB3C5D0FULL,
		0xFC47705496628309ULL,
		0x8260110145D9FC6FULL,
		0x2D467BD88A816EE7ULL,
		0x00000005FFF4FC7AULL,
		0x0000000000000000ULL
	}};
	shift = 29;
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
		0x380A52565E33E561ULL,
		0x852B430124C64DA5ULL,
		0xDCFFF74934CE9AECULL,
		0x30452533C3B18A8EULL,
		0xDDD69253EB123367ULL,
		0x99D00E4C75B6D1ACULL,
		0x870620818B7E6979ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x180926326D29C052ULL,
		0xBA49A674D764295AULL,
		0x299E1D8C5476E7FFULL,
		0x929F58919B398229ULL,
		0x7263ADB68D66EEB4ULL,
		0x040C5BF34BCCCE80ULL,
		0x0000000000043831ULL,
		0x0000000000000000ULL
	}};
	shift = 45;
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
		0x82BB66347E506785ULL,
		0x90D1A714CCA03819ULL,
		0xE60576B494826C15ULL,
		0x4D3009B7F6D173C6ULL,
		0x889461AE6E313123ULL,
		0x3B2BCDDDB82A632CULL,
		0x4CB73429E3D85E3AULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81982BB66347E506ULL,
		0xC1590D1A714CCA03ULL,
		0x3C6E60576B494826ULL,
		0x1234D3009B7F6D17ULL,
		0x32C889461AE6E313ULL,
		0xE3A3B2BCDDDB82A6ULL,
		0x0004CB73429E3D85ULL,
		0x0000000000000000ULL
	}};
	shift = 12;
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
		0x2DBFD05C21B55D10ULL,
		0xD250F843E432CC21ULL,
		0x79174E67FF07AC00ULL,
		0xFB03199585D45614ULL,
		0x5F979F35D5B98DFCULL,
		0x18617D8AEAD54209ULL,
		0xE82353573F503D43ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9287C21F21966109ULL,
		0xC8BA733FF83D6006ULL,
		0xD818CCAC2EA2B0A3ULL,
		0xFCBCF9AEADCC6FE7ULL,
		0xC30BEC5756AA104AULL,
		0x411A9AB9FA81EA18ULL,
		0x0000000000000007ULL,
		0x0000000000000000ULL
	}};
	shift = 61;
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
}