#include "tests.h"

int32_t curve25519_key_add_self_test(void) {
	printf("Add Self Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0x7B87172BC3D47C19ULL,
		0x07E8BD5B2919E0F4ULL,
		0x5578A78358776BBCULL,
		0x065A1368B1D95CD2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x7B87172BC3D47C19ULL,
		0x07E8BD5B2919E0F4ULL,
		0x5578A78358776BBCULL,
		0x065A1368B1D95CD2ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0xF70E2E5787A8F832ULL,
		0x0FD17AB65233C1E8ULL,
		0xAAF14F06B0EED778ULL,
		0x0CB426D163B2B9A4ULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	int32_t res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x57DFA30148F4A39FULL,
		0x348158A1F268767AULL,
		0x3C4869A25B843052ULL,
		0x29C5BADB5F1C1081ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57DFA30148F4A39FULL,
		0x348158A1F268767AULL,
		0x3C4869A25B843052ULL,
		0x29C5BADB5F1C1081ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAFBF460291E9473EULL,
		0x6902B143E4D0ECF4ULL,
		0x7890D344B70860A4ULL,
		0x538B75B6BE382102ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2CF27FAC909F2708ULL,
		0xE59E39215CFEA63FULL,
		0x0B000AFC642A5A87ULL,
		0x40507D8937A18127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CF27FAC909F2708ULL,
		0xE59E39215CFEA63FULL,
		0x0B000AFC642A5A87ULL,
		0x40507D8937A18127ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x59E4FF59213E4E23ULL,
		0xCB3C7242B9FD4C7EULL,
		0x160015F8C854B50FULL,
		0x00A0FB126F43024EULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD089F98E921CDAA6ULL,
		0x7D3A77B10BC7686FULL,
		0x27B1942E02A7774CULL,
		0x2B352B1A6279872BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD089F98E921CDAA6ULL,
		0x7D3A77B10BC7686FULL,
		0x27B1942E02A7774CULL,
		0x2B352B1A6279872BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA113F31D2439B54CULL,
		0xFA74EF62178ED0DFULL,
		0x4F63285C054EEE98ULL,
		0x566A5634C4F30E56ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03BDA187CD47DF4FULL,
		0xED3B519874E98485ULL,
		0x6D4DE362E2FE1A75ULL,
		0x597B7B5683C2DE8DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03BDA187CD47DF4FULL,
		0xED3B519874E98485ULL,
		0x6D4DE362E2FE1A75ULL,
		0x597B7B5683C2DE8DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x077B430F9A8FBEB1ULL,
		0xDA76A330E9D3090AULL,
		0xDA9BC6C5C5FC34EBULL,
		0x32F6F6AD0785BD1AULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA12E039B4A876B2CULL,
		0x94A90D1A4B860AF6ULL,
		0xA3C648EF1056600BULL,
		0x397AD58ECB1E47FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA12E039B4A876B2CULL,
		0x94A90D1A4B860AF6ULL,
		0xA3C648EF1056600BULL,
		0x397AD58ECB1E47FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x425C0736950ED658ULL,
		0x29521A34970C15EDULL,
		0x478C91DE20ACC017ULL,
		0x72F5AB1D963C8FFBULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDA6D10B8588B90E8ULL,
		0x28EBFE8838315BC9ULL,
		0xC42583BB8FE07988ULL,
		0x63804F5ABDA5B572ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA6D10B8588B90E8ULL,
		0x28EBFE8838315BC9ULL,
		0xC42583BB8FE07988ULL,
		0x63804F5ABDA5B572ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4DA2170B11721E3ULL,
		0x51D7FD107062B793ULL,
		0x884B07771FC0F310ULL,
		0x47009EB57B4B6AE5ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x146480425A2B6061ULL,
		0x3EF353DE07DADB1EULL,
		0xA586941062C8F734ULL,
		0x514564976B03860BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x146480425A2B6061ULL,
		0x3EF353DE07DADB1EULL,
		0xA586941062C8F734ULL,
		0x514564976B03860BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28C90084B456C0D5ULL,
		0x7DE6A7BC0FB5B63CULL,
		0x4B0D2820C591EE68ULL,
		0x228AC92ED6070C17ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC358ECE18C63C2F0ULL,
		0xDE2E32DBDEFAADC6ULL,
		0xFC5ED38E1DBFBBB2ULL,
		0x78513523577ECF6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC358ECE18C63C2F0ULL,
		0xDE2E32DBDEFAADC6ULL,
		0xFC5ED38E1DBFBBB2ULL,
		0x78513523577ECF6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x86B1D9C318C785F3ULL,
		0xBC5C65B7BDF55B8DULL,
		0xF8BDA71C3B7F7765ULL,
		0x70A26A46AEFD9ED5ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x38E742E793900B00ULL,
		0x148B209912EB8D9EULL,
		0x9AE77DFCE8F6B43CULL,
		0x4CD208A9B47ED773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38E742E793900B00ULL,
		0x148B209912EB8D9EULL,
		0x9AE77DFCE8F6B43CULL,
		0x4CD208A9B47ED773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71CE85CF27201613ULL,
		0x2916413225D71B3CULL,
		0x35CEFBF9D1ED6878ULL,
		0x19A4115368FDAEE7ULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F92D3862FE9E997ULL,
		0x2F8F2AE047834D97ULL,
		0xC7FA0E995CB3684CULL,
		0x49BCFE740490D431ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F92D3862FE9E997ULL,
		0x2F8F2AE047834D97ULL,
		0xC7FA0E995CB3684CULL,
		0x49BCFE740490D431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF25A70C5FD3D341ULL,
		0x5F1E55C08F069B2EULL,
		0x8FF41D32B966D098ULL,
		0x1379FCE80921A863ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75A2258277A0D3F8ULL,
		0x31E9F1F38FBA8927ULL,
		0xBC194D3FC67509C3ULL,
		0x02169F577CF277DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75A2258277A0D3F8ULL,
		0x31E9F1F38FBA8927ULL,
		0xBC194D3FC67509C3ULL,
		0x02169F577CF277DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB444B04EF41A7F0ULL,
		0x63D3E3E71F75124EULL,
		0x78329A7F8CEA1386ULL,
		0x042D3EAEF9E4EFB7ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBDEF8BBCE27DB2AULL,
		0x473C37505C301150ULL,
		0x2CD1FE8B0A2CDFA7ULL,
		0x6D8BD724F28E0035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBDEF8BBCE27DB2AULL,
		0x473C37505C301150ULL,
		0x2CD1FE8B0A2CDFA7ULL,
		0x6D8BD724F28E0035ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7BDF1779C4FB667ULL,
		0x8E786EA0B86022A1ULL,
		0x59A3FD161459BF4EULL,
		0x5B17AE49E51C006AULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84AF90B377F58E0EULL,
		0x89F2249082559DCDULL,
		0xDA19FEFD49BCF60BULL,
		0x5E86D9E5CF02B3F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84AF90B377F58E0EULL,
		0x89F2249082559DCDULL,
		0xDA19FEFD49BCF60BULL,
		0x5E86D9E5CF02B3F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x095F2166EFEB1C2FULL,
		0x13E4492104AB3B9BULL,
		0xB433FDFA9379EC17ULL,
		0x3D0DB3CB9E0567F1ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A047B5D97F40C2CULL,
		0xDC4D2F6EB44BC63EULL,
		0x89BA4EFA5AED565EULL,
		0x076C2A3EF910C3B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A047B5D97F40C2CULL,
		0xDC4D2F6EB44BC63EULL,
		0x89BA4EFA5AED565EULL,
		0x076C2A3EF910C3B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB408F6BB2FE81858ULL,
		0xB89A5EDD68978C7CULL,
		0x13749DF4B5DAACBDULL,
		0x0ED8547DF221876FULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD5555BCE8027BB6ULL,
		0xBC373751F2BF406EULL,
		0xB9EB8316323DB3C6ULL,
		0x7B5A399F3F0A82FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5555BCE8027BB6ULL,
		0xBC373751F2BF406EULL,
		0xB9EB8316323DB3C6ULL,
		0x7B5A399F3F0A82FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AAAAB79D004F77FULL,
		0x786E6EA3E57E80DDULL,
		0x73D7062C647B678DULL,
		0x76B4733E7E1505FDULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x698DD801ED07FD29ULL,
		0xACE79ECB8B741FD0ULL,
		0x89C801665C10F2B4ULL,
		0x63D4E522545A4BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x698DD801ED07FD29ULL,
		0xACE79ECB8B741FD0ULL,
		0x89C801665C10F2B4ULL,
		0x63D4E522545A4BFFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD31BB003DA0FFA65ULL,
		0x59CF3D9716E83FA0ULL,
		0x139002CCB821E569ULL,
		0x47A9CA44A8B497FFULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDCD090E7A37CAA94ULL,
		0x472A11DBA034AEF3ULL,
		0xBA31D29A5E88C515ULL,
		0x2971376DC0598DA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCD090E7A37CAA94ULL,
		0x472A11DBA034AEF3ULL,
		0xBA31D29A5E88C515ULL,
		0x2971376DC0598DA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB9A121CF46F95528ULL,
		0x8E5423B740695DE7ULL,
		0x7463A534BD118A2AULL,
		0x52E26EDB80B31B51ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEABB0361BFDEE45EULL,
		0x3434552CC0B91242ULL,
		0x53FA4190934D846EULL,
		0x52E4753BFA7DCE10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEABB0361BFDEE45EULL,
		0x3434552CC0B91242ULL,
		0x53FA4190934D846EULL,
		0x52E4753BFA7DCE10ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD57606C37FBDC8CFULL,
		0x6868AA5981722485ULL,
		0xA7F48321269B08DCULL,
		0x25C8EA77F4FB9C20ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE017A4F92755E40FULL,
		0xCC3C5865771A7E8AULL,
		0xB84FFE4CF6C08473ULL,
		0x24D925769C29E966ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE017A4F92755E40FULL,
		0xCC3C5865771A7E8AULL,
		0xB84FFE4CF6C08473ULL,
		0x24D925769C29E966ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC02F49F24EABC81EULL,
		0x9878B0CAEE34FD15ULL,
		0x709FFC99ED8108E7ULL,
		0x49B24AED3853D2CDULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4C15D5E18AD4AE38ULL,
		0x4AD1CDA74610B5A6ULL,
		0x85834E04142C59F5ULL,
		0x12F062068C4A7DC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C15D5E18AD4AE38ULL,
		0x4AD1CDA74610B5A6ULL,
		0x85834E04142C59F5ULL,
		0x12F062068C4A7DC2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x982BABC315A95C70ULL,
		0x95A39B4E8C216B4CULL,
		0x0B069C082858B3EAULL,
		0x25E0C40D1894FB85ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2D385D8A5FFB046ULL,
		0x0040DB05E9D85F93ULL,
		0xC5F7A663E1E98C1AULL,
		0x37CB14A177FA3AA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2D385D8A5FFB046ULL,
		0x0040DB05E9D85F93ULL,
		0xC5F7A663E1E98C1AULL,
		0x37CB14A177FA3AA9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45A70BB14BFF608CULL,
		0x0081B60BD3B0BF27ULL,
		0x8BEF4CC7C3D31834ULL,
		0x6F962942EFF47553ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07EB007029700E1AULL,
		0x00242D579F4DFDE6ULL,
		0xC226920B3E6EF4ADULL,
		0x2A2E478E8BBCFB65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07EB007029700E1AULL,
		0x00242D579F4DFDE6ULL,
		0xC226920B3E6EF4ADULL,
		0x2A2E478E8BBCFB65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FD600E052E01C34ULL,
		0x00485AAF3E9BFBCCULL,
		0x844D24167CDDE95AULL,
		0x545C8F1D1779F6CBULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36548A01ACDC8634ULL,
		0x4F342BCE3C1EFA2AULL,
		0xF54090A4D89C815DULL,
		0x71FB3E5534742850ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36548A01ACDC8634ULL,
		0x4F342BCE3C1EFA2AULL,
		0xF54090A4D89C815DULL,
		0x71FB3E5534742850ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CA9140359B90C7BULL,
		0x9E68579C783DF454ULL,
		0xEA812149B13902BAULL,
		0x63F67CAA68E850A1ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x369027313E172593ULL,
		0xB882487DDAC6BCCAULL,
		0x4871C660771838F3ULL,
		0x5BAB138E9D45B5F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x369027313E172593ULL,
		0xB882487DDAC6BCCAULL,
		0x4871C660771838F3ULL,
		0x5BAB138E9D45B5F8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D204E627C2E4B39ULL,
		0x710490FBB58D7994ULL,
		0x90E38CC0EE3071E7ULL,
		0x3756271D3A8B6BF0ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBB578E708AE3B15EULL,
		0x24338348863EE10DULL,
		0x067B7F13E7BECC29ULL,
		0x5457907374AE2A43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB578E708AE3B15EULL,
		0x24338348863EE10DULL,
		0x067B7F13E7BECC29ULL,
		0x5457907374AE2A43ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x76AF1CE115C762CFULL,
		0x486706910C7DC21BULL,
		0x0CF6FE27CF7D9852ULL,
		0x28AF20E6E95C5486ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3C6B11A558B6F1AULL,
		0x0526998A114B66EEULL,
		0x5A689B3080B7805CULL,
		0x189B5FB0E9B0FBECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3C6B11A558B6F1AULL,
		0x0526998A114B66EEULL,
		0x5A689B3080B7805CULL,
		0x189B5FB0E9B0FBECULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA78D6234AB16DE34ULL,
		0x0A4D33142296CDDDULL,
		0xB4D13661016F00B8ULL,
		0x3136BF61D361F7D8ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51AB86EA72C58BA0ULL,
		0xE8AC8FBDDD03974AULL,
		0x6849768F8162FAB3ULL,
		0x1C95FC866CF18E1FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51AB86EA72C58BA0ULL,
		0xE8AC8FBDDD03974AULL,
		0x6849768F8162FAB3ULL,
		0x1C95FC866CF18E1FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA3570DD4E58B1740ULL,
		0xD1591F7BBA072E94ULL,
		0xD092ED1F02C5F567ULL,
		0x392BF90CD9E31C3EULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2D9BCF48DD523BBULL,
		0x6E9C2F718117CC7DULL,
		0xEF7C2E26B4AA47EDULL,
		0x62DEA5F30FE30533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D9BCF48DD523BBULL,
		0x6E9C2F718117CC7DULL,
		0xEF7C2E26B4AA47EDULL,
		0x62DEA5F30FE30533ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x65B379E91BAA4789ULL,
		0xDD385EE3022F98FBULL,
		0xDEF85C4D69548FDAULL,
		0x45BD4BE61FC60A67ULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x864F5B1AF6EE3652ULL,
		0x4AA37FCD7AFE1F16ULL,
		0xC0BC520F0B0023AEULL,
		0x06F039CBE1A0FA63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x864F5B1AF6EE3652ULL,
		0x4AA37FCD7AFE1F16ULL,
		0xC0BC520F0B0023AEULL,
		0x06F039CBE1A0FA63ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C9EB635EDDC6CA4ULL,
		0x9546FF9AF5FC3E2DULL,
		0x8178A41E1600475CULL,
		0x0DE07397C341F4C7ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC0D7B6228EC6D8D8ULL,
		0xFB3A19C08E7B9537ULL,
		0xFD7B07E6FDBFDA86ULL,
		0x0785CD59628B7D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0D7B6228EC6D8D8ULL,
		0xFB3A19C08E7B9537ULL,
		0xFD7B07E6FDBFDA86ULL,
		0x0785CD59628B7D51ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81AF6C451D8DB1B0ULL,
		0xF67433811CF72A6FULL,
		0xFAF60FCDFB7FB50DULL,
		0x0F0B9AB2C516FAA3ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1357991F8C11A2ADULL,
		0x5B3CD973BBAFB512ULL,
		0xCD27282193BD80DEULL,
		0x3866BBD2D897761AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1357991F8C11A2ADULL,
		0x5B3CD973BBAFB512ULL,
		0xCD27282193BD80DEULL,
		0x3866BBD2D897761AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x26AF323F1823455AULL,
		0xB679B2E7775F6A24ULL,
		0x9A4E5043277B01BCULL,
		0x70CD77A5B12EEC35ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCD877E07AADDBDA0ULL,
		0xAD9979B53226B4A7ULL,
		0x90B76535CA6A3A88ULL,
		0x7C4688E36BEB31FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD877E07AADDBDA0ULL,
		0xAD9979B53226B4A7ULL,
		0x90B76535CA6A3A88ULL,
		0x7C4688E36BEB31FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9B0EFC0F55BB7B53ULL,
		0x5B32F36A644D694FULL,
		0x216ECA6B94D47511ULL,
		0x788D11C6D7D663FFULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7458DF9A4E6FE3A9ULL,
		0x5CDA623E0C2F3B09ULL,
		0x7BD8568F00B1C576ULL,
		0x2065D13C15D16D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7458DF9A4E6FE3A9ULL,
		0x5CDA623E0C2F3B09ULL,
		0x7BD8568F00B1C576ULL,
		0x2065D13C15D16D3EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8B1BF349CDFC752ULL,
		0xB9B4C47C185E7612ULL,
		0xF7B0AD1E01638AECULL,
		0x40CBA2782BA2DA7CULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF8814D92B86F456ULL,
		0x164AFDC684F85B63ULL,
		0x59328F66EF7A7C56ULL,
		0x53A0986F0FFDA4D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF8814D92B86F456ULL,
		0x164AFDC684F85B63ULL,
		0x59328F66EF7A7C56ULL,
		0x53A0986F0FFDA4D1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFF1029B2570DE8BFULL,
		0x2C95FB8D09F0B6C7ULL,
		0xB2651ECDDEF4F8ACULL,
		0x274130DE1FFB49A2ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x955FAA1DA202A4F0ULL,
		0xA7E41BB067A7D637ULL,
		0x19DDA86CAA725E99ULL,
		0x4EB0ED1EEDACE7DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x955FAA1DA202A4F0ULL,
		0xA7E41BB067A7D637ULL,
		0x19DDA86CAA725E99ULL,
		0x4EB0ED1EEDACE7DAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2ABF543B440549F3ULL,
		0x4FC83760CF4FAC6FULL,
		0x33BB50D954E4BD33ULL,
		0x1D61DA3DDB59CFB4ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x15C3A33E2C3D7BF0ULL,
		0xDA8A397B3A4303DFULL,
		0xD393A844B6ABAE5BULL,
		0x6EDC0E0F3E43DBA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C3A33E2C3D7BF0ULL,
		0xDA8A397B3A4303DFULL,
		0xD393A844B6ABAE5BULL,
		0x6EDC0E0F3E43DBA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B87467C587AF7F3ULL,
		0xB51472F6748607BEULL,
		0xA72750896D575CB7ULL,
		0x5DB81C1E7C87B74DULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x489C50F21619CDFCULL,
		0x5F00D15C1980D197ULL,
		0xCADF1A5CC06ED71BULL,
		0x70110D9C6003AA52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x489C50F21619CDFCULL,
		0x5F00D15C1980D197ULL,
		0xCADF1A5CC06ED71BULL,
		0x70110D9C6003AA52ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9138A1E42C339C0BULL,
		0xBE01A2B83301A32EULL,
		0x95BE34B980DDAE36ULL,
		0x60221B38C00754A5ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x63F7A53A16E0183DULL,
		0xAFD7B3FA2B6F4D70ULL,
		0xCB3ECE9600D55208ULL,
		0x0BAE380A9489AED2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63F7A53A16E0183DULL,
		0xAFD7B3FA2B6F4D70ULL,
		0xCB3ECE9600D55208ULL,
		0x0BAE380A9489AED2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7EF4A742DC0307AULL,
		0x5FAF67F456DE9AE0ULL,
		0x967D9D2C01AAA411ULL,
		0x175C701529135DA5ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD4891EE467505F4ULL,
		0x10C43CC685BB0E7BULL,
		0x70F781F69DE87ADFULL,
		0x200DB45C0CBFD32DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD4891EE467505F4ULL,
		0x10C43CC685BB0E7BULL,
		0x70F781F69DE87ADFULL,
		0x200DB45C0CBFD32DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A9123DC8CEA0BE8ULL,
		0x2188798D0B761CF7ULL,
		0xE1EF03ED3BD0F5BEULL,
		0x401B68B8197FA65AULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C0334EF29C4CF72ULL,
		0xC31B89EA99A201EBULL,
		0x969EAC42A833BEF2ULL,
		0x1177377D0B749CA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0334EF29C4CF72ULL,
		0xC31B89EA99A201EBULL,
		0x969EAC42A833BEF2ULL,
		0x1177377D0B749CA6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x180669DE53899EE4ULL,
		0x863713D5334403D7ULL,
		0x2D3D588550677DE5ULL,
		0x22EE6EFA16E9394DULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8F686EAC950217C4ULL,
		0xF9750DFE24AA0078ULL,
		0x191D2A5F51214286ULL,
		0x658D861447A55F96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F686EAC950217C4ULL,
		0xF9750DFE24AA0078ULL,
		0x191D2A5F51214286ULL,
		0x658D861447A55F96ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1ED0DD592A042F9BULL,
		0xF2EA1BFC495400F1ULL,
		0x323A54BEA242850DULL,
		0x4B1B0C288F4ABF2CULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB5D43B6229AD9313ULL,
		0x53712D366029E4C1ULL,
		0x715D98689C0CE864ULL,
		0x3E4DBF31687D6422ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D43B6229AD9313ULL,
		0x53712D366029E4C1ULL,
		0x715D98689C0CE864ULL,
		0x3E4DBF31687D6422ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BA876C4535B2626ULL,
		0xA6E25A6CC053C983ULL,
		0xE2BB30D13819D0C8ULL,
		0x7C9B7E62D0FAC844ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x07E58768B0F4D2D8ULL,
		0x1B03F21BB6E594ACULL,
		0x73C6970ACE3867AEULL,
		0x13476C2589DECEB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E58768B0F4D2D8ULL,
		0x1B03F21BB6E594ACULL,
		0x73C6970ACE3867AEULL,
		0x13476C2589DECEB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0FCB0ED161E9A5B0ULL,
		0x3607E4376DCB2958ULL,
		0xE78D2E159C70CF5CULL,
		0x268ED84B13BD9D72ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF9A6E2A256D9C74ULL,
		0xACEA400115AACFA2ULL,
		0xEAAF990781A86653ULL,
		0x41A3E82286C52A2AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9A6E2A256D9C74ULL,
		0xACEA400115AACFA2ULL,
		0xEAAF990781A86653ULL,
		0x41A3E82286C52A2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F34DC544ADB38FBULL,
		0x59D480022B559F45ULL,
		0xD55F320F0350CCA7ULL,
		0x0347D0450D8A5455ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE7AC64EC71F50E5ULL,
		0xC0FA75304A96D3FDULL,
		0xF8EDA2F96B98E68DULL,
		0x7CBC4E5CA3A4C757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE7AC64EC71F50E5ULL,
		0xC0FA75304A96D3FDULL,
		0xF8EDA2F96B98E68DULL,
		0x7CBC4E5CA3A4C757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7CF58C9D8E3EA1DDULL,
		0x81F4EA60952DA7FBULL,
		0xF1DB45F2D731CD1BULL,
		0x79789CB947498EAFULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x50C737FECA9484D8ULL,
		0x2894BE6673919936ULL,
		0x6B62832EA0BCB519ULL,
		0x792F5B001287DD67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50C737FECA9484D8ULL,
		0x2894BE6673919936ULL,
		0x6B62832EA0BCB519ULL,
		0x792F5B001287DD67ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA18E6FFD952909C3ULL,
		0x51297CCCE723326CULL,
		0xD6C5065D41796A32ULL,
		0x725EB600250FBACEULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x31A44CA8FDD9E564ULL,
		0xEF0BFB1E09971668ULL,
		0x1016171108D4B3CEULL,
		0x1605C7A3AE38F7D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31A44CA8FDD9E564ULL,
		0xEF0BFB1E09971668ULL,
		0x1016171108D4B3CEULL,
		0x1605C7A3AE38F7D9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x63489951FBB3CAC8ULL,
		0xDE17F63C132E2CD0ULL,
		0x202C2E2211A9679DULL,
		0x2C0B8F475C71EFB2ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x78C1A9CDCDEFAD14ULL,
		0xE2D7A8F81E53DE2DULL,
		0x9067CF6DE8CAB750ULL,
		0x70BF774302B94113ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C1A9CDCDEFAD14ULL,
		0xE2D7A8F81E53DE2DULL,
		0x9067CF6DE8CAB750ULL,
		0x70BF774302B94113ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF183539B9BDF5A3BULL,
		0xC5AF51F03CA7BC5AULL,
		0x20CF9EDBD1956EA1ULL,
		0x617EEE8605728227ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7557CEB62F65EBA0ULL,
		0x86A1256EE62F71BCULL,
		0x52FB938012C38BA4ULL,
		0x337264DB40C80785ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7557CEB62F65EBA0ULL,
		0x86A1256EE62F71BCULL,
		0x52FB938012C38BA4ULL,
		0x337264DB40C80785ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEAAF9D6C5ECBD740ULL,
		0x0D424ADDCC5EE378ULL,
		0xA5F7270025871749ULL,
		0x66E4C9B681900F0AULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04FB36E2CFE4EF73ULL,
		0xF41474B4957AD494ULL,
		0x0D483DEE29CF6EC9ULL,
		0x3A039D24FF88642DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04FB36E2CFE4EF73ULL,
		0xF41474B4957AD494ULL,
		0x0D483DEE29CF6EC9ULL,
		0x3A039D24FF88642DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09F66DC59FC9DEE6ULL,
		0xE828E9692AF5A928ULL,
		0x1A907BDC539EDD93ULL,
		0x74073A49FF10C85AULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC90334CB165AE328ULL,
		0x91482BCF9E1122E9ULL,
		0xF2F9DE4C64D78D8FULL,
		0x55BC512621D41BF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC90334CB165AE328ULL,
		0x91482BCF9E1122E9ULL,
		0xF2F9DE4C64D78D8FULL,
		0x55BC512621D41BF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x920669962CB5C663ULL,
		0x2290579F3C2245D3ULL,
		0xE5F3BC98C9AF1B1FULL,
		0x2B78A24C43A837F1ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x84DA99E7D54C2D9FULL,
		0x13B0E4F66D6B42C8ULL,
		0xAC2967317B933156ULL,
		0x307240F7B95F1429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84DA99E7D54C2D9FULL,
		0x13B0E4F66D6B42C8ULL,
		0xAC2967317B933156ULL,
		0x307240F7B95F1429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x09B533CFAA985B3EULL,
		0x2761C9ECDAD68591ULL,
		0x5852CE62F72662ACULL,
		0x60E481EF72BE2853ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7B63AE843451A6BCULL,
		0x4F828094F967DD61ULL,
		0xFB23FD12F8EF8E86ULL,
		0x667BFFDFE427301BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B63AE843451A6BCULL,
		0x4F828094F967DD61ULL,
		0xFB23FD12F8EF8E86ULL,
		0x667BFFDFE427301BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6C75D0868A34D8BULL,
		0x9F050129F2CFBAC2ULL,
		0xF647FA25F1DF1D0CULL,
		0x4CF7FFBFC84E6037ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB95D11069F6A9EA8ULL,
		0xC46CBB84F50FABEAULL,
		0x73E46854CD2C6B49ULL,
		0x27BB19C89289DB00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB95D11069F6A9EA8ULL,
		0xC46CBB84F50FABEAULL,
		0x73E46854CD2C6B49ULL,
		0x27BB19C89289DB00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x72BA220D3ED53D50ULL,
		0x88D97709EA1F57D5ULL,
		0xE7C8D0A99A58D693ULL,
		0x4F7633912513B600ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4D45786AC62D2C51ULL,
		0x38C3592B4C0E5706ULL,
		0x27A577F43A1D4880ULL,
		0x3ACD6DEC59D858FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D45786AC62D2C51ULL,
		0x38C3592B4C0E5706ULL,
		0x27A577F43A1D4880ULL,
		0x3ACD6DEC59D858FBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A8AF0D58C5A58A2ULL,
		0x7186B256981CAE0CULL,
		0x4F4AEFE8743A9100ULL,
		0x759ADBD8B3B0B1F6ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFC9292917AC9609BULL,
		0xC150A26D3EE03D59ULL,
		0x1AB895386D0EDF36ULL,
		0x54CE95875AD3E2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC9292917AC9609BULL,
		0xC150A26D3EE03D59ULL,
		0x1AB895386D0EDF36ULL,
		0x54CE95875AD3E2AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9252522F592C149ULL,
		0x82A144DA7DC07AB3ULL,
		0x35712A70DA1DBE6DULL,
		0x299D2B0EB5A7C55CULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEFCEE7FAD287A962ULL,
		0x39EFC1ADC2726E48ULL,
		0xA6EDD457C60C28F4ULL,
		0x55C197369ABEFFB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFCEE7FAD287A962ULL,
		0x39EFC1ADC2726E48ULL,
		0xA6EDD457C60C28F4ULL,
		0x55C197369ABEFFB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF9DCFF5A50F52D7ULL,
		0x73DF835B84E4DC91ULL,
		0x4DDBA8AF8C1851E8ULL,
		0x2B832E6D357DFF67ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B594F4A6DD2B2A6ULL,
		0x387C7CB3D8FC5823ULL,
		0x15608AB1A679FC78ULL,
		0x06E66347456C9048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B594F4A6DD2B2A6ULL,
		0x387C7CB3D8FC5823ULL,
		0x15608AB1A679FC78ULL,
		0x06E66347456C9048ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB6B29E94DBA5654CULL,
		0x70F8F967B1F8B046ULL,
		0x2AC115634CF3F8F0ULL,
		0x0DCCC68E8AD92090ULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x08191714C7B9D2F9ULL,
		0xBC17999AC475B544ULL,
		0xBE4535E38B51199AULL,
		0x363F733A39CC5BA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08191714C7B9D2F9ULL,
		0xBC17999AC475B544ULL,
		0xBE4535E38B51199AULL,
		0x363F733A39CC5BA8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x10322E298F73A5F2ULL,
		0x782F333588EB6A88ULL,
		0x7C8A6BC716A23335ULL,
		0x6C7EE6747398B751ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC660901DD3583927ULL,
		0x6EC05719BB29B7EBULL,
		0x7E0F7AFB283F2171ULL,
		0x71DC89933CDD939AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC660901DD3583927ULL,
		0x6EC05719BB29B7EBULL,
		0x7E0F7AFB283F2171ULL,
		0x71DC89933CDD939AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CC1203BA6B07261ULL,
		0xDD80AE3376536FD7ULL,
		0xFC1EF5F6507E42E2ULL,
		0x63B9132679BB2734ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x16F58C86797C19A6ULL,
		0xDA1B4B261662D372ULL,
		0x8B7B7CC09F4A729EULL,
		0x380AED427D3AF3A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F58C86797C19A6ULL,
		0xDA1B4B261662D372ULL,
		0x8B7B7CC09F4A729EULL,
		0x380AED427D3AF3A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2DEB190CF2F8334CULL,
		0xB436964C2CC5A6E4ULL,
		0x16F6F9813E94E53DULL,
		0x7015DA84FA75E74BULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC2B3E05F10D593EULL,
		0x52068B66F58BE2ACULL,
		0x3BD74DEADE69DCF7ULL,
		0x41A04BD2D23D9C12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC2B3E05F10D593EULL,
		0x52068B66F58BE2ACULL,
		0x3BD74DEADE69DCF7ULL,
		0x41A04BD2D23D9C12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x78567C0BE21AB28FULL,
		0xA40D16CDEB17C559ULL,
		0x77AE9BD5BCD3B9EEULL,
		0x034097A5A47B3824ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x195D6540C9D28990ULL,
		0x386B20DCB0EB0632ULL,
		0x7D7EB134ECB009F8ULL,
		0x68820D93B3D1467BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x195D6540C9D28990ULL,
		0x386B20DCB0EB0632ULL,
		0x7D7EB134ECB009F8ULL,
		0x68820D93B3D1467BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x32BACA8193A51333ULL,
		0x70D641B961D60C64ULL,
		0xFAFD6269D96013F0ULL,
		0x51041B2767A28CF6ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F77C06A97932A17ULL,
		0xA183900269D567A6ULL,
		0xC230BE5CDBAD1F52ULL,
		0x736E69DC4A27CC29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F77C06A97932A17ULL,
		0xA183900269D567A6ULL,
		0xC230BE5CDBAD1F52ULL,
		0x736E69DC4A27CC29ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEEF80D52F265441ULL,
		0x43072004D3AACF4CULL,
		0x84617CB9B75A3EA5ULL,
		0x66DCD3B8944F9853ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6A8E606671A92E21ULL,
		0x73718FDCC0BD8B91ULL,
		0xFD31939BB22C0E87ULL,
		0x500AD2C6A92380A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8E606671A92E21ULL,
		0x73718FDCC0BD8B91ULL,
		0xFD31939BB22C0E87ULL,
		0x500AD2C6A92380A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD51CC0CCE3525C55ULL,
		0xE6E31FB9817B1722ULL,
		0xFA63273764581D0EULL,
		0x2015A58D52470153ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB8923D108A859614ULL,
		0xEDE1C307988843E3ULL,
		0x519AEFBCF9FE7968ULL,
		0x1B8445E606F84520ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8923D108A859614ULL,
		0xEDE1C307988843E3ULL,
		0x519AEFBCF9FE7968ULL,
		0x1B8445E606F84520ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x71247A21150B2C28ULL,
		0xDBC3860F311087C7ULL,
		0xA335DF79F3FCF2D1ULL,
		0x37088BCC0DF08A40ULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x865C28E0AC223483ULL,
		0x5C4B30C7AE0065A7ULL,
		0x34182DD3FE975A25ULL,
		0x639121466F6FB164ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x865C28E0AC223483ULL,
		0x5C4B30C7AE0065A7ULL,
		0x34182DD3FE975A25ULL,
		0x639121466F6FB164ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0CB851C158446919ULL,
		0xB896618F5C00CB4FULL,
		0x68305BA7FD2EB44AULL,
		0x4722428CDEDF62C8ULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8262CBBDC900F1ADULL,
		0x1A8536144A9A283AULL,
		0x3E4F7780515F1549ULL,
		0x6B54C89FD9A0824AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8262CBBDC900F1ADULL,
		0x1A8536144A9A283AULL,
		0x3E4F7780515F1549ULL,
		0x6B54C89FD9A0824AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x04C5977B9201E36DULL,
		0x350A6C2895345075ULL,
		0x7C9EEF00A2BE2A92ULL,
		0x56A9913FB3410494ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB529DA1BA750943DULL,
		0x73C0E691958FEE8BULL,
		0xF7A699D20D0E6F4DULL,
		0x3B04B624A22299EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB529DA1BA750943DULL,
		0x73C0E691958FEE8BULL,
		0xF7A699D20D0E6F4DULL,
		0x3B04B624A22299EBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A53B4374EA1287AULL,
		0xE781CD232B1FDD17ULL,
		0xEF4D33A41A1CDE9AULL,
		0x76096C49444533D7ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D347EF22EFAEEBFULL,
		0x57E80662CBC6A855ULL,
		0xB4001457910B39C2ULL,
		0x624A4018E907FE66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D347EF22EFAEEBFULL,
		0x57E80662CBC6A855ULL,
		0xB4001457910B39C2ULL,
		0x624A4018E907FE66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA68FDE45DF5DD91ULL,
		0xAFD00CC5978D50AAULL,
		0x680028AF22167384ULL,
		0x44948031D20FFCCDULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2C8BE6EF4E55686FULL,
		0xBA76BAF0D05A77D1ULL,
		0x1EBE00E7D5140860ULL,
		0x43AFFCF656882B2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8BE6EF4E55686FULL,
		0xBA76BAF0D05A77D1ULL,
		0x1EBE00E7D5140860ULL,
		0x43AFFCF656882B2FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5917CDDE9CAAD0F1ULL,
		0x74ED75E1A0B4EFA2ULL,
		0x3D7C01CFAA2810C1ULL,
		0x075FF9ECAD10565EULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0EEA595C629D94A2ULL,
		0xA9449CA5F61B4DF5ULL,
		0x1F8FE1564FC447A6ULL,
		0x0C9292137966E21AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EEA595C629D94A2ULL,
		0xA9449CA5F61B4DF5ULL,
		0x1F8FE1564FC447A6ULL,
		0x0C9292137966E21AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DD4B2B8C53B2944ULL,
		0x5289394BEC369BEAULL,
		0x3F1FC2AC9F888F4DULL,
		0x19252426F2CDC434ULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x27A3C49B1F3DDA17ULL,
		0x05EC5632312EEC60ULL,
		0x7BC94AAD6301FB48ULL,
		0x3D045F97096FDC58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A3C49B1F3DDA17ULL,
		0x05EC5632312EEC60ULL,
		0x7BC94AAD6301FB48ULL,
		0x3D045F97096FDC58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F4789363E7BB42EULL,
		0x0BD8AC64625DD8C0ULL,
		0xF792955AC603F690ULL,
		0x7A08BF2E12DFB8B0ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x70F8215D7BC77F37ULL,
		0x919A0FF6E04C9D2FULL,
		0x9CD901FFDD9EFDB1ULL,
		0x3211A42EA2982C59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70F8215D7BC77F37ULL,
		0x919A0FF6E04C9D2FULL,
		0x9CD901FFDD9EFDB1ULL,
		0x3211A42EA2982C59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1F042BAF78EFE6EULL,
		0x23341FEDC0993A5EULL,
		0x39B203FFBB3DFB63ULL,
		0x6423485D453058B3ULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x181A8F0EFDFFE3DFULL,
		0x441410AF02FCC2E6ULL,
		0xA45148FC0EF3A7C3ULL,
		0x34E01EA2C0BC7CB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x181A8F0EFDFFE3DFULL,
		0x441410AF02FCC2E6ULL,
		0xA45148FC0EF3A7C3ULL,
		0x34E01EA2C0BC7CB6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30351E1DFBFFC7BEULL,
		0x8828215E05F985CCULL,
		0x48A291F81DE74F86ULL,
		0x69C03D458178F96DULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99F03BC867771884ULL,
		0x8CDEE743DA31BD1AULL,
		0xBE31C44FE403A535ULL,
		0x6FAA8907CF96E38CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F03BC867771884ULL,
		0x8CDEE743DA31BD1AULL,
		0xBE31C44FE403A535ULL,
		0x6FAA8907CF96E38CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33E07790CEEE311BULL,
		0x19BDCE87B4637A35ULL,
		0x7C63889FC8074A6BULL,
		0x5F55120F9F2DC719ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7887ADFF3F933A67ULL,
		0x601562FC95392A0AULL,
		0xB28B63ACEDE5B88CULL,
		0x5695508E8E5FC577ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7887ADFF3F933A67ULL,
		0x601562FC95392A0AULL,
		0xB28B63ACEDE5B88CULL,
		0x5695508E8E5FC577ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF10F5BFE7F2674E1ULL,
		0xC02AC5F92A725414ULL,
		0x6516C759DBCB7118ULL,
		0x2D2AA11D1CBF8AEFULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5B0AD8AC56CA66E9ULL,
		0xDB6D1CD27F8C21F4ULL,
		0x17B7657557D5BB4EULL,
		0x64E54DD27EC462FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0AD8AC56CA66E9ULL,
		0xDB6D1CD27F8C21F4ULL,
		0x17B7657557D5BB4EULL,
		0x64E54DD27EC462FFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB615B158AD94CDE5ULL,
		0xB6DA39A4FF1843E8ULL,
		0x2F6ECAEAAFAB769DULL,
		0x49CA9BA4FD88C5FEULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE101ABB66772C19BULL,
		0x62FCE198467B48BAULL,
		0x5ADE41F94D030A93ULL,
		0x4BFBE6E48DFADC36ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE101ABB66772C19BULL,
		0x62FCE198467B48BAULL,
		0x5ADE41F94D030A93ULL,
		0x4BFBE6E48DFADC36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC203576CCEE58349ULL,
		0xC5F9C3308CF69175ULL,
		0xB5BC83F29A061526ULL,
		0x17F7CDC91BF5B86CULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0894DC61F824C2B3ULL,
		0xC0E0486128BA5FC4ULL,
		0x54674E653FC26B76ULL,
		0x123D847E45A792FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0894DC61F824C2B3ULL,
		0xC0E0486128BA5FC4ULL,
		0x54674E653FC26B76ULL,
		0x123D847E45A792FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1129B8C3F0498566ULL,
		0x81C090C25174BF88ULL,
		0xA8CE9CCA7F84D6EDULL,
		0x247B08FC8B4F25FAULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD9C44989A06EEC09ULL,
		0x14B34C2336879DBCULL,
		0x29546BF713E90AC7ULL,
		0x6378925C65755F02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9C44989A06EEC09ULL,
		0x14B34C2336879DBCULL,
		0x29546BF713E90AC7ULL,
		0x6378925C65755F02ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB388931340DDD825ULL,
		0x296698466D0F3B79ULL,
		0x52A8D7EE27D2158EULL,
		0x46F124B8CAEABE04ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3A1486885ADD5DECULL,
		0xA8E5B293910962E8ULL,
		0x08DE03A9794A2412ULL,
		0x07C1A92ECE4B5F89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A1486885ADD5DECULL,
		0xA8E5B293910962E8ULL,
		0x08DE03A9794A2412ULL,
		0x07C1A92ECE4B5F89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74290D10B5BABBD8ULL,
		0x51CB65272212C5D0ULL,
		0x11BC0752F2944825ULL,
		0x0F83525D9C96BF12ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3395DA8CD3CD21C9ULL,
		0xBA4CD18F587E6B68ULL,
		0xD155064D28EC81C6ULL,
		0x37174D6E2D6F80E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3395DA8CD3CD21C9ULL,
		0xBA4CD18F587E6B68ULL,
		0xD155064D28EC81C6ULL,
		0x37174D6E2D6F80E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x672BB519A79A4392ULL,
		0x7499A31EB0FCD6D0ULL,
		0xA2AA0C9A51D9038DULL,
		0x6E2E9ADC5ADF01C3ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BF9AFD117CBC051ULL,
		0xF62772987274A91BULL,
		0x254CD27F3F4B82F7ULL,
		0x7E25A4D729630A75ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BF9AFD117CBC051ULL,
		0xF62772987274A91BULL,
		0x254CD27F3F4B82F7ULL,
		0x7E25A4D729630A75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD7F35FA22F9780B5ULL,
		0xEC4EE530E4E95236ULL,
		0x4A99A4FE7E9705EFULL,
		0x7C4B49AE52C614EAULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBD235B6FAAFE8F44ULL,
		0xA63F7746C26D069EULL,
		0x93A671D1DFBBC91FULL,
		0x33BD9D6C8E2475BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD235B6FAAFE8F44ULL,
		0xA63F7746C26D069EULL,
		0x93A671D1DFBBC91FULL,
		0x33BD9D6C8E2475BCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7A46B6DF55FD1E88ULL,
		0x4C7EEE8D84DA0D3DULL,
		0x274CE3A3BF77923FULL,
		0x677B3AD91C48EB79ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE965B279BCB14452ULL,
		0x4E15A405975AF138ULL,
		0x67D417F37CE834AAULL,
		0x5C82AC3403945F5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE965B279BCB14452ULL,
		0x4E15A405975AF138ULL,
		0x67D417F37CE834AAULL,
		0x5C82AC3403945F5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD2CB64F3796288B7ULL,
		0x9C2B480B2EB5E271ULL,
		0xCFA82FE6F9D06954ULL,
		0x390558680728BEB6ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF9BA32EF286BC368ULL,
		0x19EF5765B747B132ULL,
		0x9DF9C711517E08E6ULL,
		0x1D84D459BED1D1A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9BA32EF286BC368ULL,
		0x19EF5765B747B132ULL,
		0x9DF9C711517E08E6ULL,
		0x1D84D459BED1D1A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF37465DE50D786D0ULL,
		0x33DEAECB6E8F6265ULL,
		0x3BF38E22A2FC11CCULL,
		0x3B09A8B37DA3A34BULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45CAD75268E9A9C3ULL,
		0x360C32B8B0BF7792ULL,
		0x37D34E566CD1098BULL,
		0x3A46B3AE93703AB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45CAD75268E9A9C3ULL,
		0x360C32B8B0BF7792ULL,
		0x37D34E566CD1098BULL,
		0x3A46B3AE93703AB8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8B95AEA4D1D35386ULL,
		0x6C186571617EEF24ULL,
		0x6FA69CACD9A21316ULL,
		0x748D675D26E07570ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD71D3907D0247584ULL,
		0x0F018DA311320F2CULL,
		0x7BE8E5A3E962FB76ULL,
		0x0C1C7F9363C65E38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD71D3907D0247584ULL,
		0x0F018DA311320F2CULL,
		0x7BE8E5A3E962FB76ULL,
		0x0C1C7F9363C65E38ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE3A720FA048EB08ULL,
		0x1E031B4622641E59ULL,
		0xF7D1CB47D2C5F6ECULL,
		0x1838FF26C78CBC70ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1C2FFDCE8AB2D9DDULL,
		0xFDBFA8D807F1D433ULL,
		0xD23BD08B6F8168B9ULL,
		0x4C6DE4BC05AFBC66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C2FFDCE8AB2D9DDULL,
		0xFDBFA8D807F1D433ULL,
		0xD23BD08B6F8168B9ULL,
		0x4C6DE4BC05AFBC66ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x385FFB9D1565B3CDULL,
		0xFB7F51B00FE3A866ULL,
		0xA477A116DF02D173ULL,
		0x18DBC9780B5F78CDULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6311BBD7D8B35F8ULL,
		0xBC3DFFD94EE05274ULL,
		0x96C643A5EA378167ULL,
		0x45646325BD0CB2EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6311BBD7D8B35F8ULL,
		0xBC3DFFD94EE05274ULL,
		0x96C643A5EA378167ULL,
		0x45646325BD0CB2EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC62377AFB166C03ULL,
		0x787BFFB29DC0A4E9ULL,
		0x2D8C874BD46F02CFULL,
		0x0AC8C64B7A1965DDULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x854FF74AF75BD053ULL,
		0x5D4B74DA25247ACDULL,
		0x0C948986D205F07CULL,
		0x75DEACDC8216D455ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x854FF74AF75BD053ULL,
		0x5D4B74DA25247ACDULL,
		0x0C948986D205F07CULL,
		0x75DEACDC8216D455ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A9FEE95EEB7A0B9ULL,
		0xBA96E9B44A48F59BULL,
		0x1929130DA40BE0F8ULL,
		0x6BBD59B9042DA8AAULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x495DB79ECDA818A1ULL,
		0x098D9FCC9E6D1EFBULL,
		0x470874AB86D8D4C5ULL,
		0x1A1FFFBFBD44DFB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x495DB79ECDA818A1ULL,
		0x098D9FCC9E6D1EFBULL,
		0x470874AB86D8D4C5ULL,
		0x1A1FFFBFBD44DFB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92BB6F3D9B503142ULL,
		0x131B3F993CDA3DF6ULL,
		0x8E10E9570DB1A98AULL,
		0x343FFF7F7A89BF6AULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA9152A2BD4876047ULL,
		0xB21E53A361A578D4ULL,
		0xAC1779F0FAECAC4CULL,
		0x76382B7C6C54C841ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9152A2BD4876047ULL,
		0xB21E53A361A578D4ULL,
		0xAC1779F0FAECAC4CULL,
		0x76382B7C6C54C841ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x522A5457A90EC0A1ULL,
		0x643CA746C34AF1A9ULL,
		0x582EF3E1F5D95899ULL,
		0x6C7056F8D8A99083ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF028D32267213085ULL,
		0x87335ADC821A9280ULL,
		0x5CE43F08B8A4099CULL,
		0x2C60930F0D720318ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF028D32267213085ULL,
		0x87335ADC821A9280ULL,
		0x5CE43F08B8A4099CULL,
		0x2C60930F0D720318ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE051A644CE42610AULL,
		0x0E66B5B904352501ULL,
		0xB9C87E1171481339ULL,
		0x58C1261E1AE40630ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8A3A00074B312A8AULL,
		0x703CD7826D892690ULL,
		0x916A32087ED152EFULL,
		0x0B2474F3C2974051ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A3A00074B312A8AULL,
		0x703CD7826D892690ULL,
		0x916A32087ED152EFULL,
		0x0B2474F3C2974051ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1474000E96625514ULL,
		0xE079AF04DB124D21ULL,
		0x22D46410FDA2A5DEULL,
		0x1648E9E7852E80A3ULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51B4C0E9D1D3BF2CULL,
		0x3B72BF1406874B97ULL,
		0x393FEED8A7E30346ULL,
		0x4D6F1853B6AE51EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51B4C0E9D1D3BF2CULL,
		0x3B72BF1406874B97ULL,
		0x393FEED8A7E30346ULL,
		0x4D6F1853B6AE51EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA36981D3A3A77E6BULL,
		0x76E57E280D0E972EULL,
		0x727FDDB14FC6068CULL,
		0x1ADE30A76D5CA3D4ULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCB4AD9206432B21FULL,
		0x2D83FD9E819DC682ULL,
		0x2CDA5FB322F156F8ULL,
		0x4CDD5B2203FC0CBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB4AD9206432B21FULL,
		0x2D83FD9E819DC682ULL,
		0x2CDA5FB322F156F8ULL,
		0x4CDD5B2203FC0CBAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9695B240C8656451ULL,
		0x5B07FB3D033B8D05ULL,
		0x59B4BF6645E2ADF0ULL,
		0x19BAB64407F81974ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x134D7E0FD3C28211ULL,
		0x5216780679D29B7DULL,
		0xDB7A1372440AA789ULL,
		0x6372E31320DAB17BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x134D7E0FD3C28211ULL,
		0x5216780679D29B7DULL,
		0xDB7A1372440AA789ULL,
		0x6372E31320DAB17BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x269AFC1FA7850435ULL,
		0xA42CF00CF3A536FAULL,
		0xB6F426E488154F12ULL,
		0x46E5C62641B562F7ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
	res = curve25519_key_cmp(&r, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, STR);
		curve25519_key_printf(&k2, STR);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	return 0;
}