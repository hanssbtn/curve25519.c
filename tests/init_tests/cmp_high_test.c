#include "../tests.h"

int32_t curve25519_key_cmp_high_test(void) {
	printf("Key High Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0,
		0,
		0,
		0,
		0xAEF62A6D5D5BE050ULL,
		0xA7ADEDB55FCF5F3BULL,
		0xD1E0A8C02D691E06ULL,
		0x1D35F950CDCE871BULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0,
		0,
		0,
		0,
		0x7DD931209E450A80ULL,
		0xFFBF9F0ECB6B62C7ULL,
		0xAF4886A97F108848ULL,
		0x70A1EA8490F04CF9ULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5FDB0691B50823C1ULL,
		0xD8D35DD6B1C6FC7BULL,
		0x05D1089FF1DEDED1ULL,
		0x09F8E50BA184C105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x12D7BEB9FD342C25ULL,
		0xA222A27CDD2EAC32ULL,
		0x2EB493DF21C35745ULL,
		0x3B9914AD240635D6ULL
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
		0x8CB52372A5D54B9CULL,
		0x902543E278035452ULL,
		0x4DC3D1BE8A835596ULL,
		0x3B9D51C04EEE3D5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2A4260238C795667ULL,
		0x12962FD1C94AA918ULL,
		0xF3E923B7F5C2EDB2ULL,
		0x708799CEB64697DAULL
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
		0xD1DBB5609002532BULL,
		0xC48C8172DB361AF3ULL,
		0x732B04E8D226BF93ULL,
		0x1C23D2E4BEE6C055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD886A0F482FFC655ULL,
		0xA56CDB14FE8A01B6ULL,
		0xD0C1CC3381912E8EULL,
		0x06EDD49276E1835CULL
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
		0x05D5509C62ECE9A5ULL,
		0x7A81D291A1C3EDE4ULL,
		0xB2A361EC415ECEA2ULL,
		0x6C652CC0AB5EA19AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x05D5509C62ECE9A5ULL,
		0x7A81D291A1C3EDE4ULL,
		0xB2A361EC415ECEA2ULL,
		0x6C652CC0AB5EA19AULL
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
		0xDD42C917A9880036ULL,
		0xDD485BFD382AD9F9ULL,
		0x95EDBA35E901A65FULL,
		0x26F7228A9AEA7D2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x681037978492D8B4ULL,
		0x7FEDF21384485191ULL,
		0xA5D3058715EAC004ULL,
		0x15E6450E1DB26726ULL
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
		0x8AEF34B44D5A9BF4ULL,
		0xC4D179E8A5EA332BULL,
		0xE1D3F8DE8FC8AC2EULL,
		0x1A0309ADC741D3F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06BD23E210FD48EBULL,
		0x9FC38204CF50FC7FULL,
		0x289CFC4D16FF085DULL,
		0x34AEACABF5752EAFULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC2980D7A48F27317ULL,
		0xB045BFC6489A3C21ULL,
		0x878B4C957B93DF54ULL,
		0x1754BBB484FE9309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EB7B4671E8C0067ULL,
		0x018757425BE35CB4ULL,
		0x7D22ABD897A08B58ULL,
		0x2699EF69FDD5806CULL
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
		0x672C76B77B6311FBULL,
		0xE7778873E7E8D511ULL,
		0x67CF8E2FE2CD419AULL,
		0x2A8E8DF6726296A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x672C76B77B6311FBULL,
		0xE7778873E7E8D511ULL,
		0x67CF8E2FE2CD419AULL,
		0x2A8E8DF6726296A7ULL
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
		0x33F76B8741D9F048ULL,
		0x67D05D185C7967C1ULL,
		0x906C99AD5C4A212AULL,
		0x1D877B0F9B2DFC8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x08DFF8CB0649CCD7ULL,
		0x135E917B9E278AB0ULL,
		0xCE107CED3A599A5CULL,
		0x3393CDFBC77A7CF9ULL
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
		0x618ABE5E2670BF01ULL,
		0xAF8F8651115ABABFULL,
		0xD97850FBB6972058ULL,
		0x1DF5D81CC97C0601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0EB7E69E548CAD1AULL,
		0x741E04A8B9CC25D2ULL,
		0x0C8645EC7E48B7E0ULL,
		0x45E338874DA6821AULL
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
		0x1FE9D014C766B3E1ULL,
		0x4FCDE748128EA77CULL,
		0x3F2AA323597E259AULL,
		0x15A6015401591308ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x43FD9F1ED55C76B3ULL,
		0x73C87B41A30D1CB5ULL,
		0xE2B2720DA26EB48DULL,
		0x0FEBEA15CEFEAD8FULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x75B958C3F9E78CB7ULL,
		0x71DCF0961A7F70B8ULL,
		0xF6A7E2310113FA7CULL,
		0x2575255E2C935A8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75B958C3F9E78CB7ULL,
		0x71DCF0961A7F70B8ULL,
		0xF6A7E2310113FA7CULL,
		0x2575255E2C935A8BULL
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
		0xDDFFB5AE3EAA4C2BULL,
		0x5CEBB6D3C71303C3ULL,
		0x7F3BD1E466BCC61CULL,
		0x1C633806BD8D090CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9D567B564BA8154AULL,
		0x652D27CAA22D9E10ULL,
		0x1E8C8B0566145194ULL,
		0x7890E49291657AFAULL
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
		0xDA3023C99B8ABB2BULL,
		0x53A65D3181D1D253ULL,
		0x41FD0421EF9CEB25ULL,
		0x7C6C485C1A8403F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2409CEFD8E918805ULL,
		0xF7F2180A92FDBADBULL,
		0x2AB7B1C48128A562ULL,
		0x24415CE19EA7F1F1ULL
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
		0xC50BCA7F60F296A6ULL,
		0x318595398A75817FULL,
		0xB2A7C68ADBB80654ULL,
		0x069397AB362E2CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2734A635077F09FAULL,
		0x9BC518C34FA85F00ULL,
		0x4F4A4284EF83AE0FULL,
		0x24AB21628C4F164AULL
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
		0x70178152B12FA564ULL,
		0x01D5A4589E50C8D2ULL,
		0x16D8EE275BA51113ULL,
		0x36E4181CBE8C57A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70178152B12FA564ULL,
		0x01D5A4589E50C8D2ULL,
		0x16D8EE275BA51113ULL,
		0x36E4181CBE8C57A8ULL
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
		0x22306BDA1D24738FULL,
		0x4710EC5D4449F12BULL,
		0x583447AE7DA0FEBAULL,
		0x4BCB7C93410EB552ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B3089A8859F0C22ULL,
		0x35F4A31428713BE5ULL,
		0xA1292DC47FA787BFULL,
		0x5382A2485E0FA8C3ULL
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
		0x0C52B5C9F2CDA68BULL,
		0xB497291047A0D1E2ULL,
		0xCFDE69027139689AULL,
		0x2C52F86ADC9CC4FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B02DDA6C30EC062ULL,
		0x65BB5172C41E7547ULL,
		0xBB1315929C56D3C6ULL,
		0x7085B49444D82D04ULL
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
		0x5587CDD1048BE85DULL,
		0x408099FD42FAF7C7ULL,
		0x630EA784016E0409ULL,
		0x255B7E1BD51B4721ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9F47419A6644615CULL,
		0x94ABA0A36632E5AFULL,
		0xEEDE35BF672A99B4ULL,
		0x0AC116D1749A4BA9ULL
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
		0x5603502C0EC89EA9ULL,
		0x085549EA02943397ULL,
		0x44D9B1B08503FC81ULL,
		0x0C85ADEABA63312DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5603502C0EC89EA9ULL,
		0x085549EA02943397ULL,
		0x44D9B1B08503FC81ULL,
		0x0C85ADEABA63312DULL
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
		0x9A360DF5C682A653ULL,
		0x3DBA09989CDC9EF0ULL,
		0x47894C1C86DCB8FEULL,
		0x203BA61B31556864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAA3C35FF23268142ULL,
		0xB31D0EFD43003F0EULL,
		0xFA13D4C79D92776FULL,
		0x0D87D5960C8C70A6ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9A621F543A6804DEULL,
		0x88EAE6BA1284EAAFULL,
		0x86CA7255CAECC145ULL,
		0x1BF53A17CF8447C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x57753CCCF65AA3F4ULL,
		0xBD3A8CA96AEEF8D8ULL,
		0xE9F0DBD05DC8C57CULL,
		0x3913CBB83117F8B3ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x236BDA15000D8E77ULL,
		0x5671C867F921A07EULL,
		0xEFA2481D6D8E68C1ULL,
		0x565046BB335AC6ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1D8928B1A637907ULL,
		0xEF6E8201D0077C42ULL,
		0x9E136240F80B2260ULL,
		0x4F5A5CDED283876BULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x22E5BD9E7B036C78ULL,
		0xA72A025C052C5A8DULL,
		0x06F727C6D2346E3FULL,
		0x71F88A7867B8020AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x22E5BD9E7B036C78ULL,
		0xA72A025C052C5A8DULL,
		0x06F727C6D2346E3FULL,
		0x71F88A7867B8020AULL
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
		0x9FA688ADBA6B8496ULL,
		0xFEC65AB57466208CULL,
		0xA8EE039F41EFC950ULL,
		0x39395561959EA699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA27056EEE8D4857AULL,
		0x618770B77FDB7912ULL,
		0xAAB94D4B8C9BD8CFULL,
		0x0BD01939FADC8FF8ULL
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
		0xD4194090F1C00898ULL,
		0x62CD05DF8507C4CBULL,
		0xFCD7236D1D3340BCULL,
		0x40C5003B01022439ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x545784D24675CF2EULL,
		0xDE7609F2E23E997FULL,
		0x671EA2DCF8AE4BDEULL,
		0x3EFE45648E0731FDULL
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
		0xB86271E9A0D23705ULL,
		0x271E58B657D7C290ULL,
		0x9B36F1F6141F0ED8ULL,
		0x198A64D58D7EEA3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF61941D7B101182ULL,
		0xE8FD803BF464712AULL,
		0xBB7AEA9DB709FDFFULL,
		0x4595025EF178CC8AULL
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
		0x874309C8454F680EULL,
		0xCF3AD74E9BC21BFCULL,
		0x18D4CEDBE27A30D0ULL,
		0x542D81AD1BEA19E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x874309C8454F680EULL,
		0xCF3AD74E9BC21BFCULL,
		0x18D4CEDBE27A30D0ULL,
		0x542D81AD1BEA19E1ULL
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
		0xEF83D5D2E8B1E707ULL,
		0x4ACC67453BE58D1CULL,
		0x334314E7F76E7017ULL,
		0x2062CAE53470A212ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4F5DA9F662040931ULL,
		0xB14F7042D500CE97ULL,
		0x5D0527DCFAC3FA70ULL,
		0x444B30FA924D2D03ULL
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
		0x3A787D31EFFDB6CFULL,
		0x7B14F584C727B06BULL,
		0x05E96CE7F9FF0F8CULL,
		0x241F669013697563ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCC8F6CA93306FA3BULL,
		0x878001486D896FC9ULL,
		0x37D1439014E94353ULL,
		0x3681AF5DF495474CULL
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
		0x08A324ED89BEE349ULL,
		0xABC36468674DF3FEULL,
		0x43AD04E83E1357D4ULL,
		0x4C20B9E3887C7B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B5DD570BEE0DEE1ULL,
		0x14670875625F73A9ULL,
		0x28C140ACA3400588ULL,
		0x653995DC974D4BA6ULL
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
		0x5F0D7F1910B0D291ULL,
		0xC23AB375453DCDC0ULL,
		0x67AC2A6B0C493C09ULL,
		0x348ADC7CDD0F2826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5F0D7F1910B0D291ULL,
		0xC23AB375453DCDC0ULL,
		0x67AC2A6B0C493C09ULL,
		0x348ADC7CDD0F2826ULL
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
		0x10D38564675C96BAULL,
		0xB3EF4B8E46F4C2AEULL,
		0x90CB2D0657FA2F47ULL,
		0x1224BD57000A7EA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDF70BE0C6D5C427BULL,
		0x36CA06E0689EE02DULL,
		0x35A7F0C857ABB0FCULL,
		0x26450D2C65D55461ULL
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
		0xC9422B7777DE103DULL,
		0x243F5ACAF047A11BULL,
		0x6A6A31B2D08D154AULL,
		0x4FFDDB7BD68AC476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC13FA7F4F4D8336FULL,
		0xBC8FEC1F7227B0D1ULL,
		0x18A1E6A854B5F289ULL,
		0x05E6082CB4DF64A6ULL
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
		0xD15F2F7C52EAB9E9ULL,
		0xBBE36E646D8A9E7AULL,
		0x0365F206D29B67FCULL,
		0x2338ADBFFB22E900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE7AB0A854BBF97ADULL,
		0xFDAB859BD4AC6CBAULL,
		0x91852D548F9CF236ULL,
		0x101E2C2EDEF6C96AULL
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
		0xDC4C81A9F93974A3ULL,
		0x4131F35F7B7B304FULL,
		0x473A9F8C5FD3A10BULL,
		0x51EBC4AAC2E94C21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC4C81A9F93974A3ULL,
		0x4131F35F7B7B304FULL,
		0x473A9F8C5FD3A10BULL,
		0x51EBC4AAC2E94C21ULL
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
		0xC3DC872A0092DF49ULL,
		0x01E91D145531C604ULL,
		0x082BDAD70FAB75E3ULL,
		0x5C3A4CD7B493D900ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3AEB60ECC73D5858ULL,
		0x9EC362571DB260BDULL,
		0xD04BF1A4DD7E99C2ULL,
		0x429A385E152E050BULL
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
		0xEDF1EA85C43964AEULL,
		0x31BF04C6294936C9ULL,
		0x726D04BFCB2299EAULL,
		0x36FA47A1C6F3825DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC66BEF03F36328FULL,
		0xB929D384ED84FBCFULL,
		0xD16E0B1DDFC7C125ULL,
		0x5F79EE194A6641A7ULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE96260913A385C30ULL,
		0x2D45ABAF7E535E3DULL,
		0xBEB685458BDF3AA6ULL,
		0x0E4CDD39E17B9714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x77A61359C74D9AEFULL,
		0x9ED26774976696C6ULL,
		0xE6987A6039358F0BULL,
		0x3BEA07DBEE415459ULL
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
		0x8223350D6A1FDAD9ULL,
		0x4B8CDBF6CC435B60ULL,
		0x9E45588377F409CAULL,
		0x06E308300FE08072ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8223350D6A1FDAD9ULL,
		0x4B8CDBF6CC435B60ULL,
		0x9E45588377F409CAULL,
		0x06E308300FE08072ULL
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
		0xD747434D518ECFF1ULL,
		0x9B4ECE0E109485CBULL,
		0xB002F4558742AEC6ULL,
		0x772FF0E8CC93A406ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1139D00A93E9CA6BULL,
		0x9B317186CED1ECF0ULL,
		0x422AE4159011A06EULL,
		0x46949E146E7F3AACULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6BB324EE5DE5838BULL,
		0xA68851651E708D86ULL,
		0xB60D77D0BEB8D546ULL,
		0x20B6252388A7DA4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BFDA6AD3DED2865ULL,
		0x9BF5EFA0CED7BB73ULL,
		0x973E3BF81ADE2727ULL,
		0x2EC4FF27E66C4FCFULL
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
		0xCF8235E87368CDCBULL,
		0x7700B594D147B525ULL,
		0xA29ADB995B82AFD4ULL,
		0x52F2B136BEB779F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD21C1C43F706001EULL,
		0x9A34450788040AA4ULL,
		0x81833A18D108AC88ULL,
		0x119F35C4DDCE7187ULL
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
		0xF3AAA09B3010E6D9ULL,
		0x6C9907B9547C0135ULL,
		0xF28868ACDF80E2D3ULL,
		0x4901EDB188BE0F7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF3AAA09B3010E6D9ULL,
		0x6C9907B9547C0135ULL,
		0xF28868ACDF80E2D3ULL,
		0x4901EDB188BE0F7CULL
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
		0xC769A792667FFD4FULL,
		0x9CD201CAB451EBCEULL,
		0x0ECC31CCEF8AD5F2ULL,
		0x10DD3A4484598158ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD9864070F8755F44ULL,
		0xE3F2E2B2E75C1CC6ULL,
		0x739982A1AD63974AULL,
		0x1432A1814F37FB28ULL
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
		0x3CD35782FFBA1EAFULL,
		0x90697AD2AEC1CE40ULL,
		0x8763F89D01168D15ULL,
		0x7BA3D95F4C1F78C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E9B7A4AA62B80BCULL,
		0x0276AD783428B71EULL,
		0x7C7EAD15C39FF33CULL,
		0x12B717C71A2777D5ULL
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
		0x18C416D9A97BEFE7ULL,
		0xB71171E6572A3BCDULL,
		0xEA8616F6CD91D070ULL,
		0x630E1862D0072D40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x63AC08FBEEDD8D74ULL,
		0x09AF5ADA494E3ADAULL,
		0x7BCF596F820A17BCULL,
		0x06AD8C6BB4AFC5DAULL
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
		0x302F4703C51D0F58ULL,
		0xE0A4CC95A0C3E362ULL,
		0x8ACE14F19C3DEF40ULL,
		0x741F71E4A434AA37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x302F4703C51D0F58ULL,
		0xE0A4CC95A0C3E362ULL,
		0x8ACE14F19C3DEF40ULL,
		0x741F71E4A434AA37ULL
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
		0xBEF02119A7C9977FULL,
		0xCA919100A8F79931ULL,
		0xA1E677871F4DF3A3ULL,
		0x4861E119E7AC3BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7EEABA3434DA91CULL,
		0xE3F5F506944B103DULL,
		0xE71481646D511A1DULL,
		0x7FDAAAECB7B54E23ULL
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
		0x6374E2252538921FULL,
		0xD8291688D13B3FB3ULL,
		0xA912DCB21A8AE25DULL,
		0x686636DFD6DF8696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBF8104B101CDA9DULL,
		0xFEE13EDECC6940F0ULL,
		0x88A24FA154305BEFULL,
		0x13E062F3F61773A1ULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5BD3D0866F49A38CULL,
		0x717FFB9F959A9A24ULL,
		0x7452E43FA8E5FA6DULL,
		0x494A5D3C87A51B7DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB26D4A6C53CE27B8ULL,
		0xA395653AF4C608D8ULL,
		0x6A029C46E03EDD95ULL,
		0x5E502119E2BC0EC0ULL
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
		0xCDA95F06849BE29DULL,
		0xDA320B7562D118E2ULL,
		0x754C7A6C437BF6E4ULL,
		0x101F193E0A2EAF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCDA95F06849BE29DULL,
		0xDA320B7562D118E2ULL,
		0x754C7A6C437BF6E4ULL,
		0x101F193E0A2EAF9EULL
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
		0x82EFA356ECF8AAD3ULL,
		0x7A21C1B39904AF6AULL,
		0x1C5D109769460A7EULL,
		0x4AF2CD463A32F411ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x722E65F383E73441ULL,
		0x62F9B9259148B583ULL,
		0x04894D11034FAB97ULL,
		0x750D0A8184595227ULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x082BC4B2B8B2FD47ULL,
		0x71BA6B6C709178E0ULL,
		0xADD89136DDE9E628ULL,
		0x2CAA0A952AC95907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2FA2068BBBED1876ULL,
		0x24175A6C580D93DEULL,
		0xF8F8B8A2B1C49196ULL,
		0x7F75971E2DCC830BULL
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
		0x2C11F874CCB122B7ULL,
		0xCF4A15801C80383AULL,
		0x162EE32BC5956F74ULL,
		0x00A4FA7B4C0156BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x22C0B9B164F67A03ULL,
		0x7CD8DBA0E9FC0C0AULL,
		0x08DDC1B6E34BDD1EULL,
		0x637D421F97F5F46CULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x012CE9DDE229B935ULL,
		0x344E26EF97E992C9ULL,
		0xFBE5ECD6A68FB7FFULL,
		0x6EF2C7899D3B580EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x012CE9DDE229B935ULL,
		0x344E26EF97E992C9ULL,
		0xFBE5ECD6A68FB7FFULL,
		0x6EF2C7899D3B580EULL
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
		0x14CC13E2AE0DAED3ULL,
		0xF346B7E34B859C64ULL,
		0xE393603734DA3B04ULL,
		0x0C1B363DF4437432ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC32054B1E07F3A6DULL,
		0x166683B3CE2FE246ULL,
		0x372637F5D0CD0195ULL,
		0x65A228DD8CEE5CE2ULL
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
		0x1F174ECD2DC6D151ULL,
		0xA93C4298F147E915ULL,
		0xF04F77D6F7F82D34ULL,
		0x2DFCCBD1282EA661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC0DCA0B5368F667FULL,
		0xCC60847A13675F65ULL,
		0xAFC0155D17479EA4ULL,
		0x6A79262075E9B395ULL
	}};
	t = -1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE9BACFED7EA54577ULL,
		0x6BF4046BBB37947AULL,
		0x4D241E16685B3168ULL,
		0x240F18173F4F8177ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6A5FEFC0B8F302EFULL,
		0x2BF9003B2980EC2CULL,
		0x99C2C1FB31B38BBEULL,
		0x482D68A08E65EB3BULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD9EC3BD804E45EA0ULL,
		0xC1BD44D568696030ULL,
		0x9B57E4437670B591ULL,
		0x45A8E693C3687B84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD9EC3BD804E45EA0ULL,
		0xC1BD44D568696030ULL,
		0x9B57E4437670B591ULL,
		0x45A8E693C3687B84ULL
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
		0x3081DEB2296B00FFULL,
		0xBC48EED40442503AULL,
		0x6DB007FA1FCFB261ULL,
		0x15DC41D101062FDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE0986896C5B538CEULL,
		0xFFDF34FA4D521BC6ULL,
		0x2C97311EA85D23D1ULL,
		0x0E7FEA520A34008BULL
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
		0x71CFE3500D3C693DULL,
		0x55A756A413C33B0DULL,
		0xDDD75103B76F7C93ULL,
		0x227A0DA4FC81A0FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1719986439EE6B8ULL,
		0x084D7FF490204B6EULL,
		0xFA4A7CE5ED1876E5ULL,
		0x09CC6D6461938B5CULL
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
		0x819F9A362A18BDAEULL,
		0xF7FED807C27605C1ULL,
		0xC9E84E6A59FF36C7ULL,
		0x2E756FFFA13EB8E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49514C1209E5EEE7ULL,
		0xA8399218220BABC8ULL,
		0xD8A477F4144130B5ULL,
		0x564D10DF79FF5C4EULL
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
		0xB9931737FB7CEBA3ULL,
		0x0E5CADE7DE42BABDULL,
		0xC17E6AD22A9DC6A0ULL,
		0x2DE047EFD5226888ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB9931737FB7CEBA3ULL,
		0x0E5CADE7DE42BABDULL,
		0xC17E6AD22A9DC6A0ULL,
		0x2DE047EFD5226888ULL
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
		0x26C30098325C6B2FULL,
		0xF3E38EE25D8586DCULL,
		0x2A184EF138365253ULL,
		0x670BF21CF9C2847CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3BB9CDCB8B2F979DULL,
		0xCE2C677A0D3D9F9FULL,
		0x7D40BE87EA1C653DULL,
		0x413B3E7EED145737ULL
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
		0xE4F69DA04D8DE61DULL,
		0x40D0D085CAC4858DULL,
		0xA772B5600309BF1CULL,
		0x0D747224639E978CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8FAA3EDC5BFAD38CULL,
		0x34ADDE90C804FBB8ULL,
		0x88606F245EFC2932ULL,
		0x45CC81C82C3B16E3ULL
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
		0x71828883B55E53F0ULL,
		0xBF8119718ED47CE2ULL,
		0xE14733FB25F6AE43ULL,
		0x15498629FA9A7C84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D58A64D457296E3ULL,
		0x68191B761D785FADULL,
		0x90FC0BEA5F90E622ULL,
		0x3B195FEEA921AD49ULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1B89A835AED3B1EDULL,
		0x5A04F26C081C7CB9ULL,
		0x0B82B2BC990DB62EULL,
		0x06D7DF7AE38A837FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B89A835AED3B1EDULL,
		0x5A04F26C081C7CB9ULL,
		0x0B82B2BC990DB62EULL,
		0x06D7DF7AE38A837FULL
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
		0x8718D4A660223BCAULL,
		0xEB353A35F2D5B196ULL,
		0x52970A6A52D2144AULL,
		0x188E3B06C72D20DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5BDDA4015832C98ULL,
		0xA382D0AAE2CB0FFDULL,
		0x82B493ACF63B32BDULL,
		0x25AF0D027E95070DULL
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
		0x17EFDD75982D67BBULL,
		0x9D6FDA8E5EA51B6CULL,
		0xD7B81818996EA4BCULL,
		0x614B9633392BC397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6680C3410A21CD13ULL,
		0x858FE267D6D20B17ULL,
		0xE4D7D1353DF4B3ECULL,
		0x6C5987EF9F8CFED6ULL
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
		0x1EFB51758BBC2E5CULL,
		0xD5DA8DE0AAF63A7FULL,
		0x10A8C38370ABADF6ULL,
		0x7F9F4FCBF9203735ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6D1168A80D7BDB73ULL,
		0xA69A05E752C23CB6ULL,
		0x0E3B24B1B759E526ULL,
		0x5D45194F37D6B6F0ULL
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
		0x7B0C1A658A768CF9ULL,
		0x75B7E1A90F5F9250ULL,
		0x039AB8D04C0AE059ULL,
		0x0107C89AA1F8C54BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7B0C1A658A768CF9ULL,
		0x75B7E1A90F5F9250ULL,
		0x039AB8D04C0AE059ULL,
		0x0107C89AA1F8C54BULL
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
		0x3A202E62042D8FBCULL,
		0xCC6C5478D5DFD16BULL,
		0xC860500CE0059016ULL,
		0x34B6C076AC9E35BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7F6D861A1D778D1FULL,
		0x433773B648F5AFB7ULL,
		0x835926129090D47AULL,
		0x17AF7519AD0A8524ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDD0CF96DF828E99DULL,
		0xF30AC35D0271DF79ULL,
		0x820B81100A62DEB8ULL,
		0x3D4F16BB72462FFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB7342C8E51FC5AE9ULL,
		0xEC365811BB9A8AB4ULL,
		0x57CD05723539E937ULL,
		0x059E8F9E402058E6ULL
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
		0xD5CFB0AC473C8C18ULL,
		0x6C1D63F19EE34413ULL,
		0xCA36F2A0FF78A092ULL,
		0x15FFD992EFAA2F38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF51581D38BC249BBULL,
		0x13061EE1B5B729CBULL,
		0x7250AE8BF670EFC4ULL,
		0x54B70A1D09A6D50CULL
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
		0xD4ECCD4CC575F593ULL,
		0xE0A69C78E975111DULL,
		0x11377B0B2B993067ULL,
		0x57B36FD637B64876ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD4ECCD4CC575F593ULL,
		0xE0A69C78E975111DULL,
		0x11377B0B2B993067ULL,
		0x57B36FD637B64876ULL
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
		0xFB513761493931CCULL,
		0x9AFC59FA3E2E39C1ULL,
		0x7B107F61EEAA04E9ULL,
		0x4255B7FC96DB15C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEB2236FD485972C5ULL,
		0x778B3F2596A2EEADULL,
		0x1F7A15C2D525252CULL,
		0x0F213BE4BADE2B82ULL
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
		0xCFF14C1032AF7052ULL,
		0xD71533AE00BAC89DULL,
		0x91E8B08E6DE84E4AULL,
		0x476D22B6FE497750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x89B0EAF6B4D3E4A7ULL,
		0x0A8F46CFF0CD3382ULL,
		0xD9585CDF1E29BBF3ULL,
		0x5C91E0A190A423C0ULL
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
		0x75FEC94CC93C6E56ULL,
		0x0B442C0274CEBE30ULL,
		0x54613DA74BF23C65ULL,
		0x51C49D801C362F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E7515A91DA0889DULL,
		0x27809B7AB6E2E7ACULL,
		0xEF95867058CD2E1FULL,
		0x19DBAC1B537871A2ULL
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
		0xEBCD0B3AF3D75B7EULL,
		0x9C9238167BBC94B3ULL,
		0x80E715D9A5624BE1ULL,
		0x233EFC02D57E2835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBCD0B3AF3D75B7EULL,
		0x9C9238167BBC94B3ULL,
		0x80E715D9A5624BE1ULL,
		0x233EFC02D57E2835ULL
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
		0xB56D713B88E425E0ULL,
		0x2C0830D16D6C530AULL,
		0x1E6D9C3DB4CA2038ULL,
		0x79D29A0CB08E88FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEBB558652CD7C049ULL,
		0x65A9EA2E8D03E49CULL,
		0x13C4A76142109744ULL,
		0x0400DC0EA6367736ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x06B8CE5C72B5308FULL,
		0x6CD8BD063929EB01ULL,
		0x58462C8D5A0AE95EULL,
		0x70B3E06386904256ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEE3F3DA12DFF5CDEULL,
		0x9E05C13DFEADDB64ULL,
		0xF95E5E932F51E176ULL,
		0x5F8D6A9CE1231CB4ULL
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
		0x57939C86DB7D44DEULL,
		0x0545611EDA602F58ULL,
		0xC6B9BE2D9490ACD1ULL,
		0x725AA90F764DE8BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC1CCF6BFE2FC541BULL,
		0xF2B0C6598232436FULL,
		0xC64A64B41DA8DBC2ULL,
		0x2243087B9A83A81BULL
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
		0x3399B7F35868F1EDULL,
		0x0176155C5E49C554ULL,
		0xC9453489963F018DULL,
		0x64E5E9911A1F8685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3399B7F35868F1EDULL,
		0x0176155C5E49C554ULL,
		0xC9453489963F018DULL,
		0x64E5E9911A1F8685ULL
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
		0xB8E879F713CEB861ULL,
		0x1B0ECD91C6D0C760ULL,
		0xAA5AFEB60C761D7DULL,
		0x72C6E13F84D627B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD284B09F5F461F8EULL,
		0x40687D09582F4995ULL,
		0xAB44EF797159E376ULL,
		0x6EEFA89E8301DDB4ULL
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
		0x179888200E6914E4ULL,
		0xA789E6B569004786ULL,
		0x5D4134FF7D644E22ULL,
		0x2844B46B6EB2D880ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3674482176B427BAULL,
		0xE2B6C0D65CBB1723ULL,
		0x6D01B7B63246CEF9ULL,
		0x589853D74CF35918ULL
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
		0x634B7F8B38F0854DULL,
		0xB5D4B118D2E22EEEULL,
		0x22C045B806AEC331ULL,
		0x0DDC31AF727CF714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1301AB749D727598ULL,
		0xCC026CA5F47E7253ULL,
		0x3A83BE375555527CULL,
		0x33B4F335C3552856ULL
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
		0x87BAE1D7FE52C73DULL,
		0x5A4CA8E175EBBEAFULL,
		0x3AB6BFD1E623B992ULL,
		0x70501005D2A89CF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87BAE1D7FE52C73DULL,
		0x5A4CA8E175EBBEAFULL,
		0x3AB6BFD1E623B992ULL,
		0x70501005D2A89CF2ULL
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
		0xE88D7F3A0FEE874FULL,
		0x4DA4E1018D65C828ULL,
		0x8E3CF1F4BD143928ULL,
		0x4CFA373D2A4290CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBAFEFB1897702EA2ULL,
		0x903FA5BCEA59EA01ULL,
		0x22B0775163610783ULL,
		0x4B9614285BB60F08ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDC163A086DDA83ACULL,
		0x3233C5331F809B30ULL,
		0xAB258C7977C0674EULL,
		0x1CED9D1AA9806028ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCFC74B24E5EF8E79ULL,
		0x23310F157FB9BC85ULL,
		0xE0E5E4C703A35F35ULL,
		0x6093B58EFE385490ULL
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
		0xEE4F35CAFCBA5344ULL,
		0xEC1A8456CA6F9010ULL,
		0x2DCBF5EB1FFCC698ULL,
		0x37F16F20F1235059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x03617044B340371DULL,
		0x588F5C5327753941ULL,
		0xFF02C70FFBC16C9AULL,
		0x76C7E92B1612D59FULL
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
		0x667698BE23F62A0FULL,
		0x07DF4CC665C26B59ULL,
		0xDEEDEDD21CB2456FULL,
		0x37CCBC067BEE64BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x667698BE23F62A0FULL,
		0x07DF4CC665C26B59ULL,
		0xDEEDEDD21CB2456FULL,
		0x37CCBC067BEE64BFULL
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
		0x525A4554245E798BULL,
		0x332B39A6589C9AA3ULL,
		0xAB08B8123238959DULL,
		0x20BA69F862FC6B73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4835AD9BA86A7CE7ULL,
		0x61099084C5D09C38ULL,
		0xFF22ADE0631C6CBDULL,
		0x7332396D94706327ULL
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
		0x0FE9E8C28FA13BC5ULL,
		0xFC828BF1142D7D86ULL,
		0x20F07C36D9983833ULL,
		0x416944FBDB786D4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAE46430B23350433ULL,
		0xF1FBD8068301D24DULL,
		0x7BCDED6E262C4C8BULL,
		0x1448A2F1CB9965FDULL
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
		0xB5A98D3A1A24616AULL,
		0x605541617949804FULL,
		0xF02158A6B8FD0252ULL,
		0x4A514203D7101BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7062247B6B4A740ULL,
		0xCAA0F6CC3ED5167AULL,
		0x4C93EE11D22696D6ULL,
		0x783A0F66E3E84DADULL
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
		0x4916C811D645D44BULL,
		0x6EE8BF4893F7666EULL,
		0xCF6CBCB8C0BCF356ULL,
		0x3908A1F0DE7994B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4916C811D645D44BULL,
		0x6EE8BF4893F7666EULL,
		0xCF6CBCB8C0BCF356ULL,
		0x3908A1F0DE7994B8ULL
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
		0x8CA6693E39D05F90ULL,
		0x2DF9419A75FB94E3ULL,
		0x750A9F7E110F7983ULL,
		0x12BB9C35C3F21964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x36CEED09E38FDFA1ULL,
		0xED7732595A9D7546ULL,
		0xFC8D92771E0FD759ULL,
		0x2B9D4EA0F964B23AULL
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
		0xE348B3BB9A4F49C7ULL,
		0x005D7544ED51E43DULL,
		0xCB98036BB63491A7ULL,
		0x6180BF28F9431438ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB239D5CD63BD8FC2ULL,
		0xC4F2B4EBEF0D01D9ULL,
		0x71AED735F8376354ULL,
		0x4C916FB6988D43FEULL
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
		0xD0166E58C39EE028ULL,
		0xA67C80A9230E09C4ULL,
		0x5770C880626A4FCAULL,
		0x46B4B85E75D5A6F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEB88CB622CE9282ULL,
		0xC2D298E464EBA720ULL,
		0x51CC3BC248E252CDULL,
		0x604F6B21CBA06847ULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x71722AF093B6D666ULL,
		0x727606A09AAF895EULL,
		0x1CE807B4AFE1DF99ULL,
		0x5C11099C1E1A4A5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x71722AF093B6D666ULL,
		0x727606A09AAF895EULL,
		0x1CE807B4AFE1DF99ULL,
		0x5C11099C1E1A4A5BULL
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
		0x27B58177C59BDF9BULL,
		0xF1489AB95AFAA3E9ULL,
		0x6A724FAC76EA0111ULL,
		0x0F137AF8E9B23D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF3A06C19DF2CD4AEULL,
		0xF01BD587BB89DB09ULL,
		0x2313C214A0E19B77ULL,
		0x51FBB8D01A34DE2AULL
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
		0x6C749979FCFA66D4ULL,
		0xF9418ADA7EC7CE95ULL,
		0x743640F196ADFC0AULL,
		0x576683D7AED0A0AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC7F7C687A5DAB53EULL,
		0x22C4F6D46B6B471FULL,
		0x8E900D2901DDB5E0ULL,
		0x5F8052DF79FCB6E2ULL
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
		0xE0D34DC477BAF4F9ULL,
		0x5C2ED707786D97ECULL,
		0x19185754858E05DFULL,
		0x68CB17389C9B5BAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC94F5290372337EDULL,
		0x1455C9A81DFA6845ULL,
		0xAB6AA4AD8FFADA5FULL,
		0x7EA086BFDDB08554ULL
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
		0x7508AD623C4FF438ULL,
		0xB18FD823B2C7A0A8ULL,
		0x23FA5465ADBD83D8ULL,
		0x1118FCA4BEB57625ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7508AD623C4FF438ULL,
		0xB18FD823B2C7A0A8ULL,
		0x23FA5465ADBD83D8ULL,
		0x1118FCA4BEB57625ULL
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
		0xDBE09E31E684672BULL,
		0x0F61C5DD6E702F67ULL,
		0x525A896805F6B933ULL,
		0x3E4718BC8CACD887ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0AA8936EB546459AULL,
		0x151500990DFBC4BFULL,
		0x35543F36234613D3ULL,
		0x7B9D7A1ECCBAF88AULL
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
		0x43A04FD19F0B8DCFULL,
		0x58928291F52376DAULL,
		0xADCA9992F8E82F46ULL,
		0x23C79E1B2305E892ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA5FFD999D47B66A7ULL,
		0x94E8D811C569F230ULL,
		0x2BFD0E5F4A2FD102ULL,
		0x16D6EE47E14385F5ULL
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
		0xC7D57FAD2B8D7F82ULL,
		0x5944E211D2A54047ULL,
		0x80FB76C0975488FFULL,
		0x037095EACD60F3DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6B9D7BF48914A777ULL,
		0xD04246E18FA9290AULL,
		0xF00D5C88C851C0ACULL,
		0x1D62C70A7DB9690FULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDBC48703BED81CA2ULL,
		0xBBF6C949FCC5D27CULL,
		0x6D714D85FAB3BABFULL,
		0x4F4ABEC31D2B9C0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBC48703BED81CA2ULL,
		0xBBF6C949FCC5D27CULL,
		0x6D714D85FAB3BABFULL,
		0x4F4ABEC31D2B9C0FULL
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
		0xC27F25EF5F6EFCDBULL,
		0xA5C5C3556C683753ULL,
		0x37D4F50F690AD169ULL,
		0x19E78DD0FFD55CB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x319335ECB4ECE9ECULL,
		0x2448D9F7FF2FEFDEULL,
		0x453409587DD7F8F3ULL,
		0x3F09724D7C8A197AULL
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
		0xB96B63EC60818C0CULL,
		0xD94E2705A79F940DULL,
		0x59C29B99042C676FULL,
		0x425A731B27D546E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D3C93E8CDE42FAFULL,
		0xE870D684A57B4080ULL,
		0xCC3098149B49D790ULL,
		0x2E3D80581F0D31BEULL
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
		0xE16D5053103C9624ULL,
		0x2AFABF7E33EEFE9EULL,
		0x286F475A52406048ULL,
		0x029F335544596115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB0B4310236A748FULL,
		0x88F11D5A6AEB6D43ULL,
		0xDBD99B8440737474ULL,
		0x74C9F23A98B50ACDULL
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
		0xCCFC725B1C2CAA39ULL,
		0xFA88C44D0E489CEEULL,
		0xC2F4915D7DAC544AULL,
		0x26765ACF345ED970ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCCFC725B1C2CAA39ULL,
		0xFA88C44D0E489CEEULL,
		0xC2F4915D7DAC544AULL,
		0x26765ACF345ED970ULL
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
		0x60AECB44F0C44CC4ULL,
		0x031DB625615CAB83ULL,
		0x1073906517583E8BULL,
		0x6464B9CBE9FEB2F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xECFCC6155F256FBDULL,
		0x11E9857E8E3ADEF3ULL,
		0xCE909049EAE9D4EBULL,
		0x6BA4947E610C3E66ULL
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
		0x01B6769E6971779EULL,
		0xCE40F01E922ED642ULL,
		0x9D346EAB974AF1E5ULL,
		0x2F831DC17F3E41FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8FB399F2B0A9F87BULL,
		0x9B257C12165F75DEULL,
		0xDD4A5F1C51275E2AULL,
		0x109155ABC4343DE1ULL
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
		0x749FB64E8F781614ULL,
		0x73541FD07A3B0FE9ULL,
		0x0B12DD4E5D6CB53FULL,
		0x70D202F853A7C48DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD02E9D93AFCCF3DULL,
		0xE9559179426BFA87ULL,
		0x46AE824DB7774646ULL,
		0x40928763778B80B7ULL
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
		0x14228AD4443067AAULL,
		0xF8C6C6573A42383DULL,
		0x45992379A558076BULL,
		0x23A3CA0ADBC898C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14228AD4443067AAULL,
		0xF8C6C6573A42383DULL,
		0x45992379A558076BULL,
		0x23A3CA0ADBC898C8ULL
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
		0x40E00575A7DC14C5ULL,
		0x1FC55D3700C50BB2ULL,
		0x26B4C1F2A4322B86ULL,
		0x68399EBB0981229AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x46D3A6A55B8E073CULL,
		0x3C09D76C711DAA7BULL,
		0xEF800F6FBFD97A31ULL,
		0x04E002D6540C633CULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5C2F9472D079FCB0ULL,
		0xA8048A64F96C84E5ULL,
		0xEC16F859252E0CAFULL,
		0x6488116E1A6D782AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x71B725B79F62B65DULL,
		0xCF225DF5117BB9CDULL,
		0xC2F10652445AEFF5ULL,
		0x453CE2741346C9AEULL
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
		0xF47843D0BE1B223BULL,
		0x83735D5E8B545CCDULL,
		0x6388B369E1CB23EDULL,
		0x02F86EBF3D90C242ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06C27F7B7D0B9F51ULL,
		0x80D4A0AB295FAB2AULL,
		0x588687D56B6B69EEULL,
		0x0E09667A48136CFEULL
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
		0x3096AFD1EAA7CC57ULL,
		0x37FCB8EF612A0602ULL,
		0xAB1B1F784309D5ECULL,
		0x5BC4A219160C12E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3096AFD1EAA7CC57ULL,
		0x37FCB8EF612A0602ULL,
		0xAB1B1F784309D5ECULL,
		0x5BC4A219160C12E6ULL
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
		0xB420C78147E70E20ULL,
		0x64076663440970A1ULL,
		0xCF1EDF195CDEB468ULL,
		0x088C99D0BBFE0558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x706F3F38F72DE1A2ULL,
		0xBB69A370FAE08099ULL,
		0x901A54D100936055ULL,
		0x68EF71C34ACBA33CULL
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
		0x452CCE834EB93A5DULL,
		0xC7464DBA9F896657ULL,
		0x7104E3038F7E4CB4ULL,
		0x68DF817A070BEFD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x39BFA45DEA50DCF7ULL,
		0x760E68C3DAB59570ULL,
		0x9FDDD46E60A71F81ULL,
		0x22D4DE5917A0BFA0ULL
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
		0xBFCD147D273D1CD0ULL,
		0x61B5644F996A003AULL,
		0xD024F9FBD58D518FULL,
		0x0DF4132481869159ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CB8988045275179ULL,
		0x70334A5AEEC4FAD8ULL,
		0xB1C03CE49B0DA827ULL,
		0x4471591A4E3A133FULL
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
		0xE825BF51B0EDEE60ULL,
		0x1E7AACEBB5B7E9E0ULL,
		0xAD5334796A9680D6ULL,
		0x652D336C20BE5465ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE825BF51B0EDEE60ULL,
		0x1E7AACEBB5B7E9E0ULL,
		0xAD5334796A9680D6ULL,
		0x652D336C20BE5465ULL
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
		0x00EE69257CAF8350ULL,
		0x40CAD66440962999ULL,
		0xB70EF7309A3B43D8ULL,
		0x61455442E5B6DF10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x970221CC83782254ULL,
		0xCA6EE24060226B07ULL,
		0x4F09C829BCDCB11EULL,
		0x6D685B310A89437CULL
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
		0x28033E4B0BF06875ULL,
		0x7576DD31098F6F54ULL,
		0x6A872092D0DBFC96ULL,
		0x5E60B5D728E0A9B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4443C8926B9B36DULL,
		0xD48E53DA5940CC00ULL,
		0xAD80389D49708EB3ULL,
		0x0BDA583C8A54C396ULL
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
		0x8DEBD4A0BA54E3A8ULL,
		0xFD8E7A2639BA6386ULL,
		0x12876CD38A58884FULL,
		0x0829BDC1490CB8ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D11DA2CBA9D23DEULL,
		0x6FD0A70D9D2CE420ULL,
		0xDDDF5F6F1302FC54ULL,
		0x2A8BABA90C486517ULL
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
		0xA6D04F424D05ACFDULL,
		0x47D8EB901058BE2EULL,
		0x7DB8EFDC824B2D7BULL,
		0x6D010494E247706CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA6D04F424D05ACFDULL,
		0x47D8EB901058BE2EULL,
		0x7DB8EFDC824B2D7BULL,
		0x6D010494E247706CULL
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
		0x92E2523C12D20B4FULL,
		0x1460F551D3C8392BULL,
		0x8C76D217868EA0DBULL,
		0x512E28E19D8F047FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3794A1BDF84648B1ULL,
		0xED0DD526DA6EDFFBULL,
		0xFBBF71B47CA0DB07ULL,
		0x276F99BCEFCE3E8AULL
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
		0xE6E3A0215688E061ULL,
		0x59030C79AFAE624DULL,
		0x650EBC0EC9901A6AULL,
		0x70844BF362A0AA58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5D48F45466D0D07ULL,
		0x0E1F11DD22EE2439ULL,
		0xDA3099A557EF22C9ULL,
		0x723410C853612273ULL
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
		0xBDCAE5F97717B636ULL,
		0xBB910589CD9A1693ULL,
		0x9B252DECA90325BEULL,
		0x0C51515EE39C4C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF6E80C142677E9A6ULL,
		0x7788C89533C797D5ULL,
		0x8879B8005C18A02AULL,
		0x7353745DF0752480ULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x48AE6B3CB45B5401ULL,
		0xFAB08994CF5FCE78ULL,
		0x9E0795CF0F8E7B2DULL,
		0x43914B51441335A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x48AE6B3CB45B5401ULL,
		0xFAB08994CF5FCE78ULL,
		0x9E0795CF0F8E7B2DULL,
		0x43914B51441335A9ULL
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
		0x6AF4BF8D2F3384D1ULL,
		0x9BC019276BF1A7EFULL,
		0x95DF33E591CFB571ULL,
		0x55ED649B8B602803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x730129E0D5DA5B79ULL,
		0x5D0DF5D0C72664BDULL,
		0x81409B29BFAE38E7ULL,
		0x3A83EEB2D82778EFULL
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
		0x9C1F66FA06765441ULL,
		0x120AFAEED034A04FULL,
		0x81F6EBA885736147ULL,
		0x6A94BDF9306688A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF41ED37134CB5F7ULL,
		0xBFDE68BC0B9738A3ULL,
		0xB2937D87ED780B70ULL,
		0x2EACD374E461DCBCULL
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
		0x5BC3DE5E9A169C8AULL,
		0x4D835930072F4263ULL,
		0xFD6355693E8FB507ULL,
		0x337BC25C5DBE2252ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1B6E5DBC0DB542D0ULL,
		0x17C0112C7DACEA61ULL,
		0x132AF7B19134ED56ULL,
		0x7F7B376B14B3A3DFULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8B75257A34AFAEC7ULL,
		0x150CEA842AEF5474ULL,
		0xC2EA38DF9D49DB83ULL,
		0x3FDC2345421E236DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B75257A34AFAEC7ULL,
		0x150CEA842AEF5474ULL,
		0xC2EA38DF9D49DB83ULL,
		0x3FDC2345421E236DULL
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
		0x77B5E518ACDC3026ULL,
		0x8FDAB558C5BE29EAULL,
		0x3341A784E3285AC2ULL,
		0x4D73CC10B8554193ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83D9DD0A7C5A5E85ULL,
		0x40BA8AF2FFD7CDCEULL,
		0x86B7076A37075309ULL,
		0x4D991C32D315E85AULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x06F3B507C44439EBULL,
		0xFFD822ED2D285A57ULL,
		0xE0473CFF0C607084ULL,
		0x6B2F54351FBB4E77ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x49E212AD4FB264C5ULL,
		0x76BE37AA3C08CDE8ULL,
		0x6A832FF36EEDC57BULL,
		0x69CB2695391E8562ULL
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
		0xE31E242E87F692D7ULL,
		0x729EA7D3E9EA245CULL,
		0x278BA65502FA3E24ULL,
		0x23BACC2EB495EA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x64F1A0B24606F924ULL,
		0x90A0E4C7717EA55BULL,
		0xFD07EAA95A07334AULL,
		0x1ED2576A38506583ULL
	}};
	t = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x56741428DD633953ULL,
		0x81B832FDB360CF5EULL,
		0xAA96402FEE4BFB62ULL,
		0x4FF2FE2C8A376EEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x56741428DD633953ULL,
		0x81B832FDB360CF5EULL,
		0xAA96402FEE4BFB62ULL,
		0x4FF2FE2C8A376EEAULL
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
		0xAA19BF5EBE04B11AULL,
		0xED8F87873C228F07ULL,
		0x18BD6BC81857A231ULL,
		0x389D2AD97243D61BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4102450A2D1F1154ULL,
		0x2BA14DC663F7340DULL,
		0x6CD589502CE5111EULL,
		0x5130DD9307C2371FULL
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
		0x9A31D9B2DB1A9839ULL,
		0xD2A06ED7962DC586ULL,
		0xA12EACA5C7D72768ULL,
		0x489388A387D26D19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x684965491268DBA8ULL,
		0x716A9776FF8858F4ULL,
		0x71ACF34F1205CDC5ULL,
		0x745E910A15FFC652ULL
	}};
	t = -1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2BDB654FD8EDE150ULL,
		0xCFF0C722A7D2782DULL,
		0x00C50049B2CA0FDDULL,
		0x0DDCE213568182A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE9CD2E6AF8DA9F3FULL,
		0xCE4049E2DC59C19CULL,
		0x26162C21B49FABF2ULL,
		0x724B0EE8E6C39324ULL
	}};
	t = -1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA452FD0DE6DC7051ULL,
		0x250C58DEFAA44BDCULL,
		0x2130281CFE2EBC4AULL,
		0x601232C075EDA11DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA452FD0DE6DC7051ULL,
		0x250C58DEFAA44BDCULL,
		0x2130281CFE2EBC4AULL,
		0x601232C075EDA11DULL
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
		0x8E1ED465CDE6DF9FULL,
		0x08F1292D8CF06863ULL,
		0xF1E3082D2DB7A096ULL,
		0x4C150C2E6AA2D230ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16C71D2BDA1BFC50ULL,
		0x21F049F6D2D085E2ULL,
		0xEAE5360FE22EA375ULL,
		0x5B68AF79F2B235EBULL
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
		0xE7D177D7A48D0024ULL,
		0x8A8D5058E25ECF77ULL,
		0xC845B30BF3C1BB72ULL,
		0x4CC616706B513861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBCC5A2068E26D0E4ULL,
		0x8F7F8F94ECF8D44CULL,
		0xDD149CD37ED8D624ULL,
		0x4CCEE2F8C46A27C2ULL
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
		0xFBB5890A08BD9379ULL,
		0xAD05C1D8F9E056EDULL,
		0x473AAD9C778196DBULL,
		0x0A391A4F768B80A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2EB653D95B692431ULL,
		0x94E078B7B59B625CULL,
		0xE000D196221A57C3ULL,
		0x4268C39679891B70ULL
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
		0x62C3840A678D2F05ULL,
		0x946E066F5836152AULL,
		0x3C56227F19C4FDDCULL,
		0x6034958FB2BE41AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62C3840A678D2F05ULL,
		0x946E066F5836152AULL,
		0x3C56227F19C4FDDCULL,
		0x6034958FB2BE41AAULL
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
		0x447C52CEA35E67E6ULL,
		0x8D19B37B4759616BULL,
		0x081556AF59A0C072ULL,
		0x1056A9832188F7FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC573104728B4218FULL,
		0x5EFE2B6A23DA4171ULL,
		0x48A09415ADC7B4D3ULL,
		0x65C564F68E06623FULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCEE5D53828864D71ULL,
		0xBC825150CE9631F0ULL,
		0x33CBB6F09093178DULL,
		0x0CCD727FE8B8ED0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1014475F1BA7F9F9ULL,
		0xAD99F784387A0467ULL,
		0xB487DD9ED5FFB8E1ULL,
		0x60DCF492C9527A17ULL
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
		0xC3ACC91A458A126FULL,
		0xDFF7114C53526E10ULL,
		0x4680A273DC6FC679ULL,
		0x00057DDFA4924B8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x03567DED02B10703ULL,
		0x328600E20CF34D8EULL,
		0x2E11AA4C01B3D560ULL,
		0x544D539B88C2008CULL
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
		0x6C09516539433CABULL,
		0x857F40572F6D11EEULL,
		0xBF00023119A30E0BULL,
		0x692A27A16FBCA628ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6C09516539433CABULL,
		0x857F40572F6D11EEULL,
		0xBF00023119A30E0BULL,
		0x692A27A16FBCA628ULL
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
		0x7091FE252DA41996ULL,
		0xCCBEC7CD3FAA334AULL,
		0x787DF76A47EF5061ULL,
		0x06D6E58E5358C9BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF3270BF162AA7FBULL,
		0xB057594199C9AE56ULL,
		0x4C579567488F8E0AULL,
		0x4041AFBD7799240EULL
	}};
	t = -1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x550B5AEF62F260B3ULL,
		0x8A8D84FE56692586ULL,
		0x1A710939F2425D60ULL,
		0x2B07AD1AB222BBACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x69FAEBC23748BF7CULL,
		0xFD26C04FBF72A651ULL,
		0xA71A71AA7465F996ULL,
		0x1DC996A7F19FC1DEULL
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
		0xDDB15480B20C3A54ULL,
		0x6D32D0F8D2B567B2ULL,
		0x51C446412F35AA7CULL,
		0x48B1519210A78474ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC5C3AC3AC337405ULL,
		0x9B33D3DDC005514CULL,
		0x547562705604294DULL,
		0x034548EFCE2F781DULL
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
		0xB779B72D3AFB3598ULL,
		0x0B62F3BDF673A7E5ULL,
		0x735CB857C0E854E6ULL,
		0x14E5D4E3DC6BC441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB779B72D3AFB3598ULL,
		0x0B62F3BDF673A7E5ULL,
		0x735CB857C0E854E6ULL,
		0x14E5D4E3DC6BC441ULL
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
		0x1E8961190F98848AULL,
		0x8D545AE899F2365AULL,
		0xF6DADF77636D43CCULL,
		0x2565D6FD8D2817FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75F21077CDE8DB6FULL,
		0x8925E4E2F6C2E68AULL,
		0x0282381C0DCCB59DULL,
		0x23A290EA6A2DA0EDULL
	}};
	t = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAA77BB05F6DEC3BDULL,
		0x0447C261B28715D3ULL,
		0x37D2A58B541403C4ULL,
		0x19604877B37956B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x18AB433BD768470FULL,
		0xC56B596F80F64959ULL,
		0x9C4BD19A0D1B37ECULL,
		0x30AAF902FBB374C4ULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1DC3C31AAFC258EBULL,
		0x028E06CE08A66210ULL,
		0x3CF5E6CB96DD790BULL,
		0x1C7D4ED28388A300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEC2239FD62A2D54EULL,
		0x4EEE727A5250E07EULL,
		0xCC5825FBC0200A84ULL,
		0x287B4A4C000233FEULL
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
		0xF184BCCD4DAA6B21ULL,
		0xE07C92764FBF4DB2ULL,
		0x60444E24B23D8C13ULL,
		0x107DD0FDF2318C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF184BCCD4DAA6B21ULL,
		0xE07C92764FBF4DB2ULL,
		0x60444E24B23D8C13ULL,
		0x107DD0FDF2318C72ULL
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
		0xAD9BD0241288B0D0ULL,
		0x10570F7F90382679ULL,
		0xA78293BE8FDA6E79ULL,
		0x44C1D1FA5A4695A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x29DC13D96B9CAA65ULL,
		0xA31D24B184AE534AULL,
		0xC2F6E7EA61DB28C7ULL,
		0x5CC09E4C198B099BULL
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
		0xDB2BEDA16C02DB98ULL,
		0x7314FA72507FA4CBULL,
		0x0C3D0B9346CAB600ULL,
		0x5D236F1994FF51DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6831610037D06D1AULL,
		0xB210E5E7980B7A50ULL,
		0x298F055CBA169F75ULL,
		0x3467F1C9330D8A34ULL
	}};
	t = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC70AC9F0397F8BACULL,
		0x5D35BCCBE02CCFBDULL,
		0x7DD7D664F22E4348ULL,
		0x343CF2E7A1AA49B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFCA236BD623F7A1ULL,
		0x57014F9B164355B5ULL,
		0xD0C89659D9DE24F3ULL,
		0x1A6E4BC4E83BAA08ULL
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
		0x19FF5C5239CBB776ULL,
		0x6C6C561609B1FAC4ULL,
		0xEEC431EE235D2BF1ULL,
		0x30F744259E65F38EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x19FF5C5239CBB776ULL,
		0x6C6C561609B1FAC4ULL,
		0xEEC431EE235D2BF1ULL,
		0x30F744259E65F38EULL
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
		0x335A9FCE59C19976ULL,
		0x06F21B9BAE496B48ULL,
		0x2F3A40CAF8317624ULL,
		0x5A2C2793A9B67C3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC50C2AC03C96D03AULL,
		0x6E424B88A8F658DFULL,
		0xA4B977DDAAB3032AULL,
		0x47291A519D1EF3A8ULL
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
		0xF4BD51675F20396DULL,
		0xB3B48E382F9CCBC4ULL,
		0x94447189A3ACA56EULL,
		0x1FA44FD149A9FD5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4ED7B67B5E3863FEULL,
		0xF94D55E2BA9C6B74ULL,
		0x234000A7CF70C9B7ULL,
		0x6D32265209551651ULL
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
		0x7BC99C24C92C87F0ULL,
		0xDF60EFD19C1932D0ULL,
		0x04B1B4EB90955FDEULL,
		0x1E72F4D8875DC678ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x075A8DA7FB70D952ULL,
		0xBBAD522EE2419818ULL,
		0x31553D4F7335D22EULL,
		0x1FC32954FFE0B046ULL
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
		0xFFA7847DBC02B7C0ULL,
		0xA0EE040BCDA27AC1ULL,
		0x7601EAF1EDE319A9ULL,
		0x7F79D170756813AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFFA7847DBC02B7C0ULL,
		0xA0EE040BCDA27AC1ULL,
		0x7601EAF1EDE319A9ULL,
		0x7F79D170756813AFULL
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
		0x06A3B142F0E5ECD9ULL,
		0xE410EF08F7DE0D7EULL,
		0xCB6ED1F5F318A985ULL,
		0x75ABC2DC42835134ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x35BD6EBAAC9DF159ULL,
		0xC0976D7CC57ACF4DULL,
		0x5E423001DF7E05DFULL,
		0x5B54A66A6A3AD8FDULL
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
		0x5E4F13BF9C4A360DULL,
		0xDFC2240C7C9EBBEFULL,
		0x72166A4A4C430C2CULL,
		0x3759A7C9598B30E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59F1078B2D0BE3BFULL,
		0x3BDE274769C393F0ULL,
		0x0B6611AE61224A34ULL,
		0x503E0A6D26715CFDULL
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
		0xB7B27FD25D694637ULL,
		0x83993392E33D00A6ULL,
		0x92A54825D12CBFDCULL,
		0x28107D11166CC62EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD154B7F3E842819AULL,
		0x4FCCF601F319D4FEULL,
		0x4B6252F4F818FBAAULL,
		0x0924FAD77545EE29ULL
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
		0xAF7F26082652737BULL,
		0xA83E125C7AB2A50AULL,
		0x2206FF1690A2958CULL,
		0x368566E5C6DEAD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAF7F26082652737BULL,
		0xA83E125C7AB2A50AULL,
		0x2206FF1690A2958CULL,
		0x368566E5C6DEAD0BULL
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
		0x5CC107B9FCF1341DULL,
		0x2AB7FD7B91836237ULL,
		0xAA86D1CD23A7FC29ULL,
		0x22064166D1E134BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFA1FE48FA59BE56AULL,
		0x31C8054AED5A21FEULL,
		0x5E6978A23F3C1822ULL,
		0x46D057FFE078E539ULL
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
		0x99A2090BC9ED3C08ULL,
		0xC7A469402BBB2EDDULL,
		0x9FF30EB0B166911EULL,
		0x637EF88D8AFF3D6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8EBCAF214EA93976ULL,
		0x7656659311A86AF2ULL,
		0x512A85AE37625D40ULL,
		0x0EEBBE285466266AULL
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
		0x4902231F6214D6C3ULL,
		0x0F405E80C2C02652ULL,
		0x827F86B62C10DB17ULL,
		0x6D40E2D0DE85CA6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x52CA2923BFC68B08ULL,
		0xF626672396831600ULL,
		0x29C6CC2C2BADFB7EULL,
		0x45BE454C4412E2E2ULL
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
		0xE1F0994443414EFBULL,
		0xA3F9D76927E909C5ULL,
		0xCA4950063E8BF60DULL,
		0x6FDD47B3034CCE53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE1F0994443414EFBULL,
		0xA3F9D76927E909C5ULL,
		0xCA4950063E8BF60DULL,
		0x6FDD47B3034CCE53ULL
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
		0x680B04725FA51B15ULL,
		0x8662F8A5474A7206ULL,
		0x75D8DF0539D84DB3ULL,
		0x56E8CCE4674528A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C79EE7EED14324AULL,
		0x03C8C8DDC5F8FAD4ULL,
		0x2E7F7768D4C01289ULL,
		0x64991E7EA40FF4EBULL
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
		0x0B0D9456847A4008ULL,
		0x50140DB3B91996EAULL,
		0xE47AB47907677EEBULL,
		0x3024E6237884295CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF0E5084BB4CBDC71ULL,
		0xE4204229ADD4B0ADULL,
		0xAEE6A31AB56B30CAULL,
		0x324B0EEEFAE06E5AULL
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
		0x3A28F55F11E06174ULL,
		0x149EF8307C9914B2ULL,
		0xF5715E5215341504ULL,
		0x7CCD25974D5BE73CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCC4775049FB2F43BULL,
		0x1537062ACC9C2FB6ULL,
		0xB726C0D899AD282DULL,
		0x23EA4FBF04A28691ULL
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
		0x4673819CCB1D1C7AULL,
		0x66861C5EB92D8C64ULL,
		0x060B93AFE58C6CDFULL,
		0x336F99C08915BD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4673819CCB1D1C7AULL,
		0x66861C5EB92D8C64ULL,
		0x060B93AFE58C6CDFULL,
		0x336F99C08915BD92ULL
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
		0xA2F538B62EB064A0ULL,
		0x10FDEAC39A252B68ULL,
		0x81430AB009182E2EULL,
		0x035D80225A7DC75CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x00C491952C4CA103ULL,
		0x74D69A501264FB4BULL,
		0xCC1F1B59F92859E0ULL,
		0x04AD9082A6AAF368ULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2F222D93DA06FC07ULL,
		0xB73BD989E9765B16ULL,
		0x44716DD4D0A21619ULL,
		0x38416DB51E518FCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06845AECD2D97E68ULL,
		0x7BC0501A77BF4EF6ULL,
		0xCFC35F5A698A0F6DULL,
		0x41091FA576986162ULL
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
		0x42961E02629E05D0ULL,
		0x8F4A506CA50D7796ULL,
		0x704E1464EA4878C0ULL,
		0x468A0CDBA51E71DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x364BDEB5D8E39B5AULL,
		0xAC02E0C1C518837EULL,
		0xE9E703D967297E37ULL,
		0x291A537CA1255172ULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBE19D164821C2BDFULL,
		0xE5C3E1E192C9EEE8ULL,
		0xB949D2B1526B7BFFULL,
		0x27B576C1F92003E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBE19D164821C2BDFULL,
		0xE5C3E1E192C9EEE8ULL,
		0xB949D2B1526B7BFFULL,
		0x27B576C1F92003E9ULL
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
		0xA4DE7FA6815B69CCULL,
		0x40D1E20B51048F9EULL,
		0x642F68311F6304A2ULL,
		0x628B9E999462548CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC366D85546270317ULL,
		0x98FF48B582C24409ULL,
		0xDE90E0F04581A28DULL,
		0x17235D4F6BE41267ULL
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
		0x928AE6D087F9E3F4ULL,
		0x2FFD51CFEE27E752ULL,
		0xAB5DA337C2D07A32ULL,
		0x332F4666D7EFDFD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87150C114E02DF3FULL,
		0x0AD426B836AEB7E3ULL,
		0xA632542370380092ULL,
		0x56992D0F56ACD037ULL
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
		0x64758BA14C104012ULL,
		0x0958864D29281843ULL,
		0x3C96848E6E8B8879ULL,
		0x45EAEF3B5CDBD895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20B4B5F4E7AEF513ULL,
		0x106AFC802523F95CULL,
		0x8E8E6EC993FEB0C2ULL,
		0x328A85DEF988011BULL
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
		0x2CE971EC029EDDA6ULL,
		0xC60769500AA6E9D1ULL,
		0x48D1E4BA154632C8ULL,
		0x2173D3F27ECF98B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2CE971EC029EDDA6ULL,
		0xC60769500AA6E9D1ULL,
		0x48D1E4BA154632C8ULL,
		0x2173D3F27ECF98B6ULL
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
		0x4227C2D991D793D8ULL,
		0xD3FD2B5E7DAB7489ULL,
		0xBE6BEF60090DEE9DULL,
		0x63E2A62A1BA87755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE6B12856B429FE0EULL,
		0xCA79E19C30C60340ULL,
		0xC177C255425CD899ULL,
		0x6AA5A7239A53032CULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x00872AEC5299270AULL,
		0x76FC8BE3DD76092FULL,
		0x8545F36F4264CA02ULL,
		0x43958133AFEB0109ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1E1611042094C967ULL,
		0xF421C8A5E31D18D4ULL,
		0x6A3D26EEFD7FEBCAULL,
		0x015CD4445BFF6A2CULL
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
		0x4D046D7E2320FA6FULL,
		0xB278C59FBB585D7CULL,
		0x62FB3313EBA61F1CULL,
		0x580A053374A14B6BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9E7B63F49A977825ULL,
		0x2A1FBF04C058EC85ULL,
		0xBCFA3EFE9C485583ULL,
		0x20F5CB38FF20649BULL
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
		0xA143D23F6625CF97ULL,
		0xD73E22F73705DD08ULL,
		0x242A762671B522EFULL,
		0x488536BFAC03C6B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA143D23F6625CF97ULL,
		0xD73E22F73705DD08ULL,
		0x242A762671B522EFULL,
		0x488536BFAC03C6B7ULL
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
		0x304614B49A4F95EFULL,
		0x1C6D2EEF89A73332ULL,
		0x0521084ED43B0049ULL,
		0x41C970ECFFD155CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB669DC76BC0159D0ULL,
		0x4746E4C8023AD160ULL,
		0x675A6292BFCE8999ULL,
		0x2344E83F0B494956ULL
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
		0xE722A7778448D1BCULL,
		0x9AA88F6430F443A2ULL,
		0x1B04CA0FAD08BB72ULL,
		0x429C8951419F398FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x658CC5AFBAE9ADD2ULL,
		0x772C1C1004DD9EF9ULL,
		0x3EDD6DD3484040E6ULL,
		0x489F86D36273B4FCULL
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
		0xCF2C142FE42FAB64ULL,
		0xAD27D2092942AB7DULL,
		0x16D76EEFD763F006ULL,
		0x6BAEC290F67ACF72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC165C5AF57B9EECAULL,
		0x591DBACA264DA894ULL,
		0x9BB55452367AEE7AULL,
		0x0AE8429802E81BB2ULL
	}};
	t = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x07CEA8B5F4C5F308ULL,
		0xD66E1DB2BE8BA792ULL,
		0xFE5D7D74DD725D4FULL,
		0x5F175D4FD36CE3F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x07CEA8B5F4C5F308ULL,
		0xD66E1DB2BE8BA792ULL,
		0xFE5D7D74DD725D4FULL,
		0x5F175D4FD36CE3F9ULL
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
		0xB7824454FA6CFEFDULL,
		0x93B422BA10096314ULL,
		0x442D1EE17317AED4ULL,
		0x695EA1663B2EA6EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87F614D6F2082774ULL,
		0x3F01C53E95277423ULL,
		0x54CCDF5625EE0118ULL,
		0x1D0C3DF3CBEFCBAEULL
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
		0x876D91F5526902D9ULL,
		0x64C4BE8F9A5B9093ULL,
		0x59A64E6F28381169ULL,
		0x2CB99F1B30CDB709ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x68F2BC6021FDF0C1ULL,
		0x7837290006D97B88ULL,
		0x1BA27D84298333FDULL,
		0x5719301E83B5999CULL
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
		0x69EAE3BF7E481B26ULL,
		0xF9A48060F32D9009ULL,
		0x0AC9C2E8AEB97406ULL,
		0x297C25C0140E2247ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA83AC1F43063C13DULL,
		0xFDBB0DF77D100142ULL,
		0x16185189B049C2C4ULL,
		0x0CA1F67C0F81BF9BULL
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
	return 0;
}