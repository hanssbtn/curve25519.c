#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xEB9C29B3A68AA5FAULL,
		0xFB1DAD12899A2621ULL,
		0xA4F35F1A8FC1D2FCULL,
		0x8882512A3DBE691CULL,
		0xF79C35CDD55A6EFCULL,
		0x93F87AAF5CF88F24ULL,
		0xBCBAFD38D7DA4C05ULL,
		0x27FD86A72321ADC2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x872487C11339705EULL,
		0x7A8A6B5416AB5DD7ULL,
		0x023951D3489D64ABULL,
		0x09007479E3D0EA49ULL,
		0xEC7209EC0AA2EAC6ULL,
		0xFE0410FD51C01A64ULL,
		0xFB8EFA98937A11CCULL,
		0xDAA85CA0BE6AB89BULL
	}};
	int t = -1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("Expected: < 0\n");
	int32_t res = curve25519_key_cmp(&k1, &k2);
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
		0x3D0372219673FD21ULL,
		0x40CAD500869DA6D3ULL,
		0x7BC4925480E32D54ULL,
		0xE6E63F22104679E3ULL,
		0xB2972BE1679641D7ULL,
		0x5086E0AE941D5C23ULL,
		0x622CAA12B9A8B36AULL,
		0xA8921FD0F9AB9879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F4A71351B9C60AULL,
		0xE1E95D736F20C2E5ULL,
		0x436820F31A5EEAF0ULL,
		0xBE4DC74364BD69C1ULL,
		0xADB1D07406944EBBULL,
		0x8FFD0F938148575FULL,
		0x843E8B0F682F4DA2ULL,
		0xB33D0BB00A0E816FULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x54008EA94168572AULL,
		0x84E9BA80B2C87659ULL,
		0x4F7ABA47DD863AB1ULL,
		0xBE76972A56682969ULL,
		0x43897C16276BF3BCULL,
		0x13B6FD07C8B8291AULL,
		0xDA7EE45D745C4942ULL,
		0x008F6A99B3A32B6EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D419ABC0A6E8DB4ULL,
		0x1DB9E68B81A4733FULL,
		0x0DA688D4507BF2ABULL,
		0x376EC5BA6A20B125ULL,
		0x80C2AE0D60A032A9ULL,
		0x94024146EE092C01ULL,
		0xA2403DB454D849C7ULL,
		0x764C100A4092F767ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6381D5F8A3F6C3BEULL,
		0x82A7CAC4BD24173DULL,
		0x00BD85D3B26B6F91ULL,
		0x3C8A3BCE77543FEEULL,
		0xF53E31B30BBAC57CULL,
		0xE6A4867FAC947AD6ULL,
		0x3DFD69F395A7A9E9ULL,
		0x9AEE8D013D485278ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8A04D4CB2868B76ULL,
		0xDD6821DD0682DF11ULL,
		0xBBBADC6909887849ULL,
		0x324DCDA8F2A5D4BAULL,
		0x9FC3634E99657964ULL,
		0x64EE2558501564A2ULL,
		0xD1B4E93C3557D7F3ULL,
		0x2E6E8960DD52A5B4ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7317415AA54165B6ULL,
		0x3AD5379A057A6C4DULL,
		0xD86393A14D1F4577ULL,
		0x518E841946409FC5ULL,
		0x44423CB9B5F323D6ULL,
		0xAA0B22AE05B7EA6DULL,
		0x91E91840F1AA3AAEULL,
		0x4D7C21DEAB5BCCF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7317415AA54165B6ULL,
		0x3AD5379A057A6C4DULL,
		0xD86393A14D1F4577ULL,
		0x518E841946409FC5ULL,
		0x44423CB9B5F323D6ULL,
		0xAA0B22AE05B7EA6DULL,
		0x91E91840F1AA3AAEULL,
		0x4D7C21DEAB5BCCF1ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBCA1CF4FABE88225ULL,
		0x1F2F792071AF3AB0ULL,
		0xBB2E54B12390845EULL,
		0x1567FB97B8EDD87FULL,
		0x161248921A871375ULL,
		0xA744ECCA9CAC49A0ULL,
		0x301C4673DE778149ULL,
		0xF476DD6E414F36EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4A848076C718A6AULL,
		0xB5D14F7C90F24AB0ULL,
		0x81BA1B13C5F6ABA0ULL,
		0xEE37E43FDAC633DCULL,
		0xC5B8DADCA8D2B5F6ULL,
		0xF64D88428C5AA835ULL,
		0x14D08FF079C8168AULL,
		0x5EC31B61DEED42A4ULL
	}};
	t = 1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCAFF419DAADA16ABULL,
		0xA5F88E5823555E61ULL,
		0xAE4342F1E314E6E4ULL,
		0x25D986997008DF6FULL,
		0xE70A32EABEA2939BULL,
		0x260A45D59BA43E64ULL,
		0x3480A240B2702ED5ULL,
		0x31291E8EA36B487EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02C3BB3F1F44D3C9ULL,
		0xDFA487E0E043017AULL,
		0xF496E0A51F1F943DULL,
		0x40F80F1315AF7551ULL,
		0x32A338D0C500D4B3ULL,
		0x1724E778FFF2EBA6ULL,
		0xC586F8E8B9E965BBULL,
		0xDC2B8AA2F3DCE521ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x38E2FE3EE068B8EDULL,
		0xA3C98A25085951B0ULL,
		0xD01096A8CC371F58ULL,
		0x6E20D7A5149DEDF5ULL,
		0x48F187F96A86306BULL,
		0x3787760DFAF4B278ULL,
		0xB13C6E89D3A74400ULL,
		0x03EC487E9B07AAA4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1556327CE5033736ULL,
		0xB45DBDE3A69F4548ULL,
		0x35D367606B99F8CCULL,
		0xEDAC84CDBFBF0C47ULL,
		0xEB8DDD5DB982B60FULL,
		0x9480E5D5616E7B98ULL,
		0xBB77389E7E5A4FD2ULL,
		0x4AE0A2E70C5613D2ULL
	}};
	t = -1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x326CE17E55E94C8BULL,
		0xA45C96DC8A6152F7ULL,
		0xE1BA232F6EAE5A6BULL,
		0xA6E4FE2FC5CC95FDULL,
		0x940061C4F8DE5917ULL,
		0x20D4B42D5D1B5301ULL,
		0x3B19E18F5E066D6AULL,
		0xCFDC3BAB117C51D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x326CE17E55E94C8BULL,
		0xA45C96DC8A6152F7ULL,
		0xE1BA232F6EAE5A6BULL,
		0xA6E4FE2FC5CC95FDULL,
		0x940061C4F8DE5917ULL,
		0x20D4B42D5D1B5301ULL,
		0x3B19E18F5E066D6AULL,
		0xCFDC3BAB117C51D4ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x276ADA7FABE8F05AULL,
		0x8589DB519E4177A0ULL,
		0x1FC4F4203001A44FULL,
		0xEDD82511524751ECULL,
		0x947D03BB941D3814ULL,
		0xDF90EF437930B2FFULL,
		0x4AE9F2EEFEC97423ULL,
		0x4C65F49D78CE59EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2990973671EF2C8AULL,
		0x62E099CFDEFB37F6ULL,
		0x079F9401FADD7A01ULL,
		0x38E9ECF5B3131327ULL,
		0xE013DA50C298532CULL,
		0xB5B1BAA37AD04DBCULL,
		0x0952A3CD3EC0E9DCULL,
		0x5F1733D97EAC146DULL
	}};
	t = -1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4F3C47C227859C02ULL,
		0xB1C9E21A5ECCCFCBULL,
		0x4A30D0E118B468F4ULL,
		0xA4E9FC9BDF8D3C26ULL,
		0xA954AB794D81EAB5ULL,
		0xFB13E0AC7A0C5D8EULL,
		0x8FCF32319CA90D02ULL,
		0x64A939B45F971C32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A38A4AA647FFACFULL,
		0xD661BE45DDE38174ULL,
		0x77AB8F15259BBED7ULL,
		0x2EC9F125463E7C91ULL,
		0x31543093B32C0BC7ULL,
		0x6063842D6FD4537FULL,
		0xDECB07EC9142AEA6ULL,
		0xD7CF2625BDA6668BULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x16767B3594EC3095ULL,
		0xC7259D75DE8B9F45ULL,
		0xF7EC59B7B853DFFDULL,
		0x763ECA2E68D82537ULL,
		0xDD2199B8067962ECULL,
		0x18167CE3B5137D40ULL,
		0x3D6FF751032B39C5ULL,
		0x05C82A476A37DEF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82FB0E1E39EE0C70ULL,
		0xC7290FF087906BFFULL,
		0x36196DB92893E37DULL,
		0x9F58A1088DC28379ULL,
		0x9AA345CC73AD52ACULL,
		0xEE5228B20065756FULL,
		0xABB02E5E4DDE4839ULL,
		0xB1FA761EC5216827ULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x539E6C49A2B643DEULL,
		0xCD725F3CD7443D15ULL,
		0x3F0C0890F28EFDE6ULL,
		0xF8E5F5D586FB6FFDULL,
		0x168936EFBBD8E528ULL,
		0x1C8177719DB45C17ULL,
		0x3A15E6823F0EAB13ULL,
		0xA3CEF7F24E70361FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x539E6C49A2B643DEULL,
		0xCD725F3CD7443D15ULL,
		0x3F0C0890F28EFDE6ULL,
		0xF8E5F5D586FB6FFDULL,
		0x168936EFBBD8E528ULL,
		0x1C8177719DB45C17ULL,
		0x3A15E6823F0EAB13ULL,
		0xA3CEF7F24E70361FULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0A5C9E65C211A70EULL,
		0x6527D76046F0D726ULL,
		0x353E7605F9CE44A5ULL,
		0xA8E4FDED84C0CFB9ULL,
		0x6C2846151F272E18ULL,
		0xF7F427B18214E5F8ULL,
		0x2475CB85038280CBULL,
		0x957F065C2ED1EB6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x677D39485E4ABCF6ULL,
		0xE7DF04E8B1C8F579ULL,
		0x0EC739C2743C19FCULL,
		0xE7C368401DF377EFULL,
		0xC6EF22AF77F5F6FEULL,
		0xA4F614C00C5FD684ULL,
		0xB60AB2A06B03CC00ULL,
		0xB94E89698C2F6996ULL
	}};
	t = -1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDC5FDF7EDA2F38D9ULL,
		0xC3B3BC256180DE42ULL,
		0xD46B05112F658DC0ULL,
		0x24EDA76EE36C96E2ULL,
		0xA9F3B07E33B65FDEULL,
		0x857EF5A1C66DC41FULL,
		0x5CF378156FB41397ULL,
		0xCC263C0AEC6BEF9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1701156DC6559ACCULL,
		0x2818C223BEFCD218ULL,
		0x5083BB9B6397537DULL,
		0x0987A8907E8E6574ULL,
		0x39DE26C66DE8B541ULL,
		0x0777C3529E7B3100ULL,
		0xF2356BDFFDBCA932ULL,
		0xDE7664D245C27495ULL
	}};
	t = -1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF3F1B0C29B2A4449ULL,
		0x0FC461633DC81960ULL,
		0xF448C2FAFCBFFC64ULL,
		0x6F92B38FB21521ABULL,
		0xE4640C2C6A397CF4ULL,
		0x69DEC33718569FEDULL,
		0xB8F08BD6AF893C06ULL,
		0x248F96FB60453597ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C1D7FB9D78B91DBULL,
		0x3661CBE0047DDBE4ULL,
		0x4A65F2EBB53C4875ULL,
		0x95D865B74562F4F0ULL,
		0x29F7491AA41CBC86ULL,
		0x375B83C68F2CF167ULL,
		0x6405E38D3018A879ULL,
		0x2A6D6F2FF54B26A0ULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1B0A6D70718C7004ULL,
		0x73395E4CCF9D70DEULL,
		0x25C7142170C57D6AULL,
		0xCC1F3545A46E5B04ULL,
		0x7EDF1380C6F6A247ULL,
		0xD40D6C946FE80393ULL,
		0xE0DD510BD22FE300ULL,
		0x3122FD49B1AACEB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0A6D70718C7004ULL,
		0x73395E4CCF9D70DEULL,
		0x25C7142170C57D6AULL,
		0xCC1F3545A46E5B04ULL,
		0x7EDF1380C6F6A247ULL,
		0xD40D6C946FE80393ULL,
		0xE0DD510BD22FE300ULL,
		0x3122FD49B1AACEB1ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x33B03F39749BB508ULL,
		0xC3B1ED5333F2FC96ULL,
		0xB3F23FE9AF5170D4ULL,
		0xA73BA87160008E2BULL,
		0xCE3DC0649D8C1CE2ULL,
		0xBD67C96B59BB2655ULL,
		0x6FA424B618B5A02AULL,
		0xACA2430044721F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB93A224CA0BAFD88ULL,
		0xEDD815D5A5C13665ULL,
		0x7E516BD4655ED786ULL,
		0x6B0E68EB4FA148CAULL,
		0xE4C2A4289FFEAF74ULL,
		0x54DAB9B7FCFEEBA0ULL,
		0x81CF7ECC77563270ULL,
		0x38202AE7533D0D08ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x569AB102AF20D9FDULL,
		0x4C034E5C7823E4F5ULL,
		0x88871D124B0E2B84ULL,
		0x8B9A09A088B732CFULL,
		0x9473D7F60EB58785ULL,
		0x0CC7708F3CF871A6ULL,
		0x206EB890CB37DFCCULL,
		0x96F62297BE797685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x115A7CAE59DB8872ULL,
		0x55A31AE0D3800FBBULL,
		0xAC50E8AAF8A1B90BULL,
		0x3DD3AA9DB68C3AA8ULL,
		0xAD3C16431888C829ULL,
		0xED7787B25ACEF6B3ULL,
		0xED3C8285C7A003C3ULL,
		0x5B7646F2CFDAD53BULL
	}};
	t = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1A7DF3B57705C477ULL,
		0x5017E6A5E12243A3ULL,
		0xD5D94F2D6DEAA0F8ULL,
		0x7EE3D3278A10E3CEULL,
		0x0D4DF4A07C9F6B3BULL,
		0xDDF1111CA2AC33F3ULL,
		0x2126F30EE6393851ULL,
		0x5F7907EBF45086D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8213091E9BE1EAULL,
		0x74F01A8045B7674EULL,
		0x60C0CA4477A1029CULL,
		0xD45E644E32EB19DFULL,
		0xBAE128767F17C14AULL,
		0xE5CB9295008005EDULL,
		0xE54CD02C5E29484CULL,
		0xC621DE597251FF69ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x86B25FC84B7616B5ULL,
		0xE4B04DFE6971C20FULL,
		0x759A535DDC9C58A2ULL,
		0xEBBECBCCE8DFD5ECULL,
		0x577145947A05F650ULL,
		0x34943DEF01512A63ULL,
		0xC6E1C6AB69FD5467ULL,
		0xD9E6108BB895A16BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86B25FC84B7616B5ULL,
		0xE4B04DFE6971C20FULL,
		0x759A535DDC9C58A2ULL,
		0xEBBECBCCE8DFD5ECULL,
		0x577145947A05F650ULL,
		0x34943DEF01512A63ULL,
		0xC6E1C6AB69FD5467ULL,
		0xD9E6108BB895A16BULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCB947DAE588E16DFULL,
		0x69748EB566BA6C50ULL,
		0x2F28995666FBC183ULL,
		0x61EF2924F20CA56BULL,
		0xCAC1C64F441A4DC8ULL,
		0x6519A9E1F6181CE5ULL,
		0xC16C28609FD13DBFULL,
		0x5B8BB469C42ADEC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F75EAECB86E91EFULL,
		0x9220FD39509B6F31ULL,
		0x90A6DB375C3A172FULL,
		0xF7D992DDBDE4B6C7ULL,
		0x4142FF54F668195BULL,
		0x58CBA763619EB6E3ULL,
		0x4DC432E54D216218ULL,
		0x73EF71B8CCD66867ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFC4526DF22112D69ULL,
		0xD7157C1530BBF6D3ULL,
		0xC844EDDC3E325E65ULL,
		0x2F5A08D4E646D23AULL,
		0xF179FA71DA01767FULL,
		0x996B7218B54AA69AULL,
		0xF6607248BFD28C1AULL,
		0x600FDFCF73DE873BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0247F9640591D34BULL,
		0xE9765F21B2777F33ULL,
		0xA38BCFC41CC13539ULL,
		0xEABA8D94410A2005ULL,
		0x78548F84AB45F1DDULL,
		0xBA555D5456D57F1FULL,
		0x33D2B84D6D20CA69ULL,
		0x5E9EB5F3AB6548DDULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCB039F63424480AFULL,
		0x7C08623CFA2F84F5ULL,
		0x6414204DA8C91490ULL,
		0x4FF9186302458642ULL,
		0x82966D443E873531ULL,
		0x7B6059910F102E4FULL,
		0x422D821653A671B7ULL,
		0xD1BBA8DF4B91E018ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867E7921153ABC39ULL,
		0xE1DCFC8998820B68ULL,
		0x5FE038C297247ED2ULL,
		0xA47921CDED24B8E9ULL,
		0x568C1141B647BDD3ULL,
		0x4D4A444B98551323ULL,
		0x65D9AEE44FB1F688ULL,
		0x2573946D36AD2614ULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x68419330190A25A7ULL,
		0xA12C97309A583C42ULL,
		0x061921F80BECFA0DULL,
		0xAF3FCFBDCE3F0682ULL,
		0x341AB4E8FC10FD06ULL,
		0xF5505BB55AC862D7ULL,
		0x6C6285D2D844467AULL,
		0x419C7FB0EB0DDABBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68419330190A25A7ULL,
		0xA12C97309A583C42ULL,
		0x061921F80BECFA0DULL,
		0xAF3FCFBDCE3F0682ULL,
		0x341AB4E8FC10FD06ULL,
		0xF5505BB55AC862D7ULL,
		0x6C6285D2D844467AULL,
		0x419C7FB0EB0DDABBULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3D78D5967A05C6A1ULL,
		0x80548A0E954765F3ULL,
		0x2BD18BFF32D8C8ECULL,
		0x8E2AF0E5D9D6E870ULL,
		0x85FFC985C515172FULL,
		0xC6F858A3692F6AECULL,
		0xFDCB9EA5AD9778A4ULL,
		0x3E5A0C90AC08CA94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F6C17CD056A0C6ULL,
		0x787BC74A46F4D9CDULL,
		0xEC3ACDEADF665698ULL,
		0x680EEFF92B0C9B7CULL,
		0x52E2DBFC45C04A13ULL,
		0x98A0D9477319AAC4ULL,
		0xD7D24CA6EAC9DD47ULL,
		0x32A985C4974DF417ULL
	}};
	t = 1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0F392136429E356AULL,
		0xFAC987304403EC22ULL,
		0x3321C3BE02B4FB47ULL,
		0xEB36AF76FCE77E06ULL,
		0xC6825B0E0B04FEA6ULL,
		0x1B59876ABC659E9EULL,
		0x1F92D09E74831B1EULL,
		0xE2D7B198CD7EA3EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02157B16C93965C3ULL,
		0xBE176AA3B0472DC6ULL,
		0x4FB7A527300CAD75ULL,
		0x17103F5595C36D9AULL,
		0x879263A3D02EA894ULL,
		0x56746B262E3E9E20ULL,
		0x47B8EB51D789F686ULL,
		0x5FF807CAB206A264ULL
	}};
	t = 1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9E7ABE9DD777AF76ULL,
		0x9D1365D215121FEFULL,
		0xDD0956ECC8D436C2ULL,
		0xDAE8D718186CE8CDULL,
		0x3DE4B72DBF8E1338ULL,
		0xC898807F56AEAAB9ULL,
		0x3B2B8A033D445833ULL,
		0xF0B95C4D22C4C7CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x374342AFF1B9AEF8ULL,
		0x83CBD9FAABA16708ULL,
		0xBE15FCC87069A716ULL,
		0x89B213ECE416D988ULL,
		0x6E6197A458A4B90BULL,
		0xB1B5FB78F39B082CULL,
		0x760899C867EEB81BULL,
		0x3E3FB12F6E9182C4ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF389A27BDED7DA55ULL,
		0x601542160421725AULL,
		0x1135A0A46F1C0217ULL,
		0xB462C77001003A4BULL,
		0xE6AD2FC5D7A170A4ULL,
		0x783ADB4763D50704ULL,
		0xE114C0AE9E94F8C2ULL,
		0x0EED239A47F0326FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF389A27BDED7DA55ULL,
		0x601542160421725AULL,
		0x1135A0A46F1C0217ULL,
		0xB462C77001003A4BULL,
		0xE6AD2FC5D7A170A4ULL,
		0x783ADB4763D50704ULL,
		0xE114C0AE9E94F8C2ULL,
		0x0EED239A47F0326FULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x06BC1F904EFDFD4BULL,
		0x881A88303EEA5F82ULL,
		0x2647E1143AC47145ULL,
		0x0E89D647A6AF5595ULL,
		0xC6A966CCAEF81059ULL,
		0xF8C7C1B10EC39A95ULL,
		0xB06FD3B0A0CB2FD8ULL,
		0xD150058BFC6DFC57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD18EDF93BF68BE05ULL,
		0x706A3850B4D915CEULL,
		0x1D0D550682E15472ULL,
		0x2181468AB78D3F46ULL,
		0xF49298ECBF97141CULL,
		0x578C86B2F11EA900ULL,
		0x79667191524B7D62ULL,
		0xAA9B7E6FEBE329BFULL
	}};
	t = 1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA0AA456154EFF190ULL,
		0x2C050CA71FA93510ULL,
		0x5A700AA4291B735AULL,
		0x5F5E7BF3343B88BBULL,
		0x5E5240CB8052E3F6ULL,
		0x8566B67B16E83834ULL,
		0xBB295F30C4A1242FULL,
		0x7FA119E1FF7A84FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F88F9E42A2B5A0AULL,
		0x0614CD0F2F366C22ULL,
		0xAB63AD1981068E90ULL,
		0x8CD3405F395BE938ULL,
		0xA13402EFA46EED59ULL,
		0x1B016BC5EC993706ULL,
		0xB1FBE67685C9D915ULL,
		0x8196E4C44E26E903ULL
	}};
	t = -1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA32B02B81381D96BULL,
		0xA0D1FFA2F036E7E8ULL,
		0x34D5AC6EDE981AEBULL,
		0x6B07F422C5714885ULL,
		0xBA6295E8CEBA8C55ULL,
		0xF0450DB774BAA9E8ULL,
		0x56F91929DFC53A83ULL,
		0x9D8E87F35218FD1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x634CBD0B15ADD6A9ULL,
		0x1443BD3028CD68C6ULL,
		0x2C0E13C10CDC282AULL,
		0x155CCDFB7907A4DCULL,
		0x51E13F08748BDF35ULL,
		0xCE3A6E24EC49B15CULL,
		0xE5897DEF4FFE1BABULL,
		0xF9D90764C54FF7FFULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x983C80544E2C15ECULL,
		0x04C148411F63CB8AULL,
		0x988699556D247C64ULL,
		0x1CCC73935104D3FFULL,
		0x2CBC5027A86997B1ULL,
		0xBD66C9A648F7FBE1ULL,
		0x373C7E2212DC0EBFULL,
		0x3047E7566DCF155DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x983C80544E2C15ECULL,
		0x04C148411F63CB8AULL,
		0x988699556D247C64ULL,
		0x1CCC73935104D3FFULL,
		0x2CBC5027A86997B1ULL,
		0xBD66C9A648F7FBE1ULL,
		0x373C7E2212DC0EBFULL,
		0x3047E7566DCF155DULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x15540D9D13963D75ULL,
		0xA3EC138F80068769ULL,
		0x2C919FC6A41B7F4EULL,
		0x2BBBB10CFB8443BBULL,
		0x3383369F5D44C1E4ULL,
		0x4E9AE1E85AEAC0BFULL,
		0x4552D59480FA98C8ULL,
		0x6FC55B2F838D6B0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FC6F0D40E88CDE5ULL,
		0x88B792ECE51BB306ULL,
		0x2058A7D4B1F8EF28ULL,
		0xA084194742C962B7ULL,
		0x0FFCD0D7C8AC4960ULL,
		0x902D7560CD625E36ULL,
		0x8C827DCD79F656A7ULL,
		0xB90A998354BD0CD5ULL
	}};
	t = -1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x572BAC3C59196DEFULL,
		0xC1126B23DADF6BD1ULL,
		0x163DE2C6306ADB4DULL,
		0x9EC98DD1F7C16317ULL,
		0x50AC54324F486A64ULL,
		0x31FA9B82B715F9A9ULL,
		0x7C611EF179A25915ULL,
		0x3A296869096AE864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50F30182D6B47AFBULL,
		0xCB91E45E6C376EA7ULL,
		0xAF777C6345FA8CBCULL,
		0x1229103BF6F0A841ULL,
		0xBD342A75B33A8859ULL,
		0x4BCE9A6A51E71959ULL,
		0x115D129795418319ULL,
		0x390884B7DC6C5BE2ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x75F175A1B9692BCFULL,
		0xCB06947D96ACB17EULL,
		0x77BB2EEDA23D1FC6ULL,
		0xB1D5145E50AD7417ULL,
		0x304B03AE7137C207ULL,
		0x7278F29F0390B508ULL,
		0x816F6F3841DE1373ULL,
		0x6F4991353E677C71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29E54A396BA30F97ULL,
		0x077062B9CCC41DA4ULL,
		0x15A19483BCA6CF9EULL,
		0xA52F8F325F620E12ULL,
		0xD713277993E40702ULL,
		0x09AE489AA9027D2CULL,
		0x62DB9C3445ECFF8EULL,
		0xF611ED10AE63286FULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5AF3600CD99A8567ULL,
		0x4BD26EABE8487D9BULL,
		0xBF3EA1AB7CEA9800ULL,
		0x0A9AFEA5D4329C59ULL,
		0xE81B49379C4BD462ULL,
		0x44230D7BCC59572CULL,
		0x138497A0221FC720ULL,
		0x1E48B87865D8637AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AF3600CD99A8567ULL,
		0x4BD26EABE8487D9BULL,
		0xBF3EA1AB7CEA9800ULL,
		0x0A9AFEA5D4329C59ULL,
		0xE81B49379C4BD462ULL,
		0x44230D7BCC59572CULL,
		0x138497A0221FC720ULL,
		0x1E48B87865D8637AULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x36832164D8AE8A2BULL,
		0x3ED69836511D5F1FULL,
		0x73BC1E4D630D0AE1ULL,
		0x652624D0471A2774ULL,
		0x620E27F01CBF119BULL,
		0xD15AA9263EB9358AULL,
		0xBD8A1A868B42D710ULL,
		0x778389F4CE1FAF12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B63908D726AC37BULL,
		0xEF77063E5BA83E04ULL,
		0x0C020157611D0118ULL,
		0x807C44DA1E855A41ULL,
		0x4796388E309A4A12ULL,
		0x795F4CD5B0559B21ULL,
		0xAB7C3BFBC35497BBULL,
		0x388738445C25E450ULL
	}};
	t = 1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC3B0A30B97673AE4ULL,
		0x333EAF5C9FFD049AULL,
		0x71BF79864046363CULL,
		0x00BE6AA7232F80A0ULL,
		0x5D39CBDEB5D706E1ULL,
		0xDEA56CCED8771F49ULL,
		0xBA512D3DF9AEA97EULL,
		0xC200BCA9193F363EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CEC46DD8B284901ULL,
		0x341536CF8292842DULL,
		0x90BD76FFB171D520ULL,
		0xA80EBE1039E555D6ULL,
		0x79C8280A616372EAULL,
		0x3AFA1986133B921BULL,
		0x0BEC701C37912AF7ULL,
		0x5702FFB2B19BD496ULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x44CB9106D5DA4F8FULL,
		0xA006A4EFE6946E69ULL,
		0x4353A2C136C9AC92ULL,
		0x37F24EDA82D760D2ULL,
		0x80DB90343366BC34ULL,
		0x796C7C9CFAC2B3FFULL,
		0x9C53D4AD759BAB21ULL,
		0x74BF9D570F08E068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x948F89A723B4B83CULL,
		0x75FC6472BA3FEE40ULL,
		0xE2E52ABCF2C0F04DULL,
		0xC0B421D0739769C9ULL,
		0x2D6E157DD550A9E8ULL,
		0x16F7DB8321377CACULL,
		0x5550F481A8FC5E60ULL,
		0x5770D0A917E26B94ULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2FA2D2365DD284D1ULL,
		0x47C5CBA1D3670673ULL,
		0x230FB67795D06756ULL,
		0x1B16DA748E957E0BULL,
		0x630AD7FF28FA970AULL,
		0xA7893A050C41E3E5ULL,
		0xC9F558F7C48B179EULL,
		0x3FC9B09BA228A864ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FA2D2365DD284D1ULL,
		0x47C5CBA1D3670673ULL,
		0x230FB67795D06756ULL,
		0x1B16DA748E957E0BULL,
		0x630AD7FF28FA970AULL,
		0xA7893A050C41E3E5ULL,
		0xC9F558F7C48B179EULL,
		0x3FC9B09BA228A864ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x073FC07E7614DFB0ULL,
		0x4D0395F0ED937974ULL,
		0x99E58F095C1841B6ULL,
		0xF3E93CC43C1B3E7DULL,
		0x5D953FC0DB2FE700ULL,
		0x19C4936F4010168FULL,
		0x3DA0A22DDD73028FULL,
		0xDB8BBA29545091C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF37E48453AF3D2CULL,
		0xA41D16E5FF8D89E8ULL,
		0x20CE408C0FC228E8ULL,
		0x658F391E506B56E8ULL,
		0xFC584A4692AAB9C3ULL,
		0x0F028F20A8DB516FULL,
		0x3F0CEB4C07BD8276ULL,
		0xBC7F9CC86FDFD4C1ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x71B6B0C3E2E98FC0ULL,
		0xEC1187D513B134EEULL,
		0x4C6F7B6418CDD4FDULL,
		0x94ACBEE413B7B54CULL,
		0x5A3A3E2ED00ADEC0ULL,
		0xCD103897A5582D94ULL,
		0xA5A4F9CE1CB18BC5ULL,
		0xC80EA1D19C9A8D0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C00691EE1BB3C55ULL,
		0x0E2A746DD3851850ULL,
		0x78353278827AF933ULL,
		0xFF53662B40ABB3C1ULL,
		0x9A1FBC0100C73A23ULL,
		0x8CE267ECF597C8F8ULL,
		0x71585A0DE400E7B3ULL,
		0x6E86D42F8A627F38ULL
	}};
	t = 1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x38379E174A9442B1ULL,
		0x3DA3E797DCB2B847ULL,
		0xF493B5147B137EDFULL,
		0x9685ECDE4B81A8D0ULL,
		0x6C2D20CEEEB198E3ULL,
		0x60892587764218D5ULL,
		0xA2C1CC41296E2811ULL,
		0xC417E8C0F8AFD958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D59E5592B86450DULL,
		0xFCD6657D34E29D5EULL,
		0x40FC86FE6FC636A5ULL,
		0x70647DA3A105A1D0ULL,
		0x7FA5A24CFC81F2B5ULL,
		0x40DD0E7C8374CF42ULL,
		0xD52BADC4A37D43D3ULL,
		0x5E3B909B94B7F7C3ULL
	}};
	t = 1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x135C109301ABBDA3ULL,
		0x9CE55B3C92401400ULL,
		0x0F7FB03A9FFB09EEULL,
		0x85DFB39DED1CC39AULL,
		0x65EBF50927A4160AULL,
		0xC9E98DEE7598FD24ULL,
		0xB4835A16A72950C3ULL,
		0x58243A872E2CCC43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x135C109301ABBDA3ULL,
		0x9CE55B3C92401400ULL,
		0x0F7FB03A9FFB09EEULL,
		0x85DFB39DED1CC39AULL,
		0x65EBF50927A4160AULL,
		0xC9E98DEE7598FD24ULL,
		0xB4835A16A72950C3ULL,
		0x58243A872E2CCC43ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF369B7BB4332CB41ULL,
		0xD95C698A6B05950EULL,
		0xBE3E09F5C9BB36B2ULL,
		0xF57B9B4BD96A46FDULL,
		0x12CB575875754E16ULL,
		0xCC31636B788572DEULL,
		0xEED88B005306A078ULL,
		0xEA48EE2155050658ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC5B6C3F906E5F87ULL,
		0x2B306472E8A9DF0BULL,
		0xD8245FDF22943E31ULL,
		0x6490A7ABB3421107ULL,
		0x36011A653D174142ULL,
		0xDAEFD29682B71960ULL,
		0x7419EE89CDFD323AULL,
		0x7634D01802B56F0AULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3CCAF7A0580748A6ULL,
		0x6EB96C6C3FD80E97ULL,
		0xCC002D700B57BC4DULL,
		0x77862207CC3773A2ULL,
		0xE7017AB066CC6E0CULL,
		0x2493017B07BE7154ULL,
		0x47DD17C311CF11A7ULL,
		0x1FEA7428BC029D94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BFC298918030CB1ULL,
		0xF42C4728824CF169ULL,
		0x58D14159A9F58AE7ULL,
		0xC07E2306E0C8596EULL,
		0x0CB9B84228305123ULL,
		0x98351CC91953AF8CULL,
		0xD92A7894EF73F7DEULL,
		0xB8EA63E78474A29BULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2D10BBD89CA1C9CBULL,
		0x1B7E1ACF7A276778ULL,
		0x4676507C3132426DULL,
		0x45F0D831A9821DB2ULL,
		0x45E690B926A0C6F3ULL,
		0x24C1D84F76F02516ULL,
		0xFDEB38CDE880784DULL,
		0xDB6FF7FD2D2189A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3FA8463F4A048CF6ULL,
		0xA5C4FE086C517C3FULL,
		0x970CD2F8F62F9E40ULL,
		0x99EE43C21F3E8AA4ULL,
		0x4B0E8E0475961CF0ULL,
		0x928164D98B4AA4FAULL,
		0x522E31B3B5C6D1D2ULL,
		0xA3FD55FA83A0B7EFULL
	}};
	t = 1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB42E588AFFA1B072ULL,
		0x0675BFE96AF61BA4ULL,
		0x0B9AD23B2087226AULL,
		0x3BDD61DC4D489F02ULL,
		0x58262460B9C394FCULL,
		0xEF3F5DD399F94C8AULL,
		0x824B3E249BB5E4A8ULL,
		0x8DDB68897C580B90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB42E588AFFA1B072ULL,
		0x0675BFE96AF61BA4ULL,
		0x0B9AD23B2087226AULL,
		0x3BDD61DC4D489F02ULL,
		0x58262460B9C394FCULL,
		0xEF3F5DD399F94C8AULL,
		0x824B3E249BB5E4A8ULL,
		0x8DDB68897C580B90ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCF1A89C5F54DD024ULL,
		0xF4F900A16D1D7F7CULL,
		0x5B5EA6C758A6F7ACULL,
		0xCE3FF5B472B33F88ULL,
		0x7C5E409CFD21A09AULL,
		0x7016EB76EAC949DCULL,
		0x2E70F73DADBC9162ULL,
		0xD081971515E5B48EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCADF5B4873BB70CULL,
		0x353625B117EAA932ULL,
		0x3B15ADEE073E65CDULL,
		0x7C93DFF86D1E53B2ULL,
		0x5D331EA93ED97DACULL,
		0xBA592A8E729F9300ULL,
		0xB1C8CCFEDC70BCAEULL,
		0x0B2A817008BD30F6ULL
	}};
	t = 1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFF080855B778CA4FULL,
		0xA60EEFF66CCE9278ULL,
		0x9B71D6C93F99D915ULL,
		0x9C43E0E3980A0788ULL,
		0x0250E1FDFE7B8A7FULL,
		0x91A1979D6606073CULL,
		0x1E935F24B26AF25BULL,
		0xF863671E63DA4F43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B813260E05BB80ULL,
		0xA6D101BEA43A7E80ULL,
		0x2664715351475A33ULL,
		0x06CAFA92B5104DF4ULL,
		0xB11E1B7C2A639DE1ULL,
		0xEF252C65A137B8A4ULL,
		0x0236FF5FD1B60A43ULL,
		0x7E7C38BB2D19B40CULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE97B91C384919F46ULL,
		0x1568BF0CCDB8606BULL,
		0x303B9DDE57A9BE24ULL,
		0xE6F5894456BAA503ULL,
		0x56FAB823B9FA8211ULL,
		0xE41A0FF9CC8A06D4ULL,
		0x810729F7DD82A1A6ULL,
		0xE8795A46377FC397ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DAD697544DA2ABULL,
		0x58132FB9B8B5E431ULL,
		0x1C87FA2AEEBC7B27ULL,
		0x9FE9FEB8AA85DE53ULL,
		0x860F0DF95E8CF877ULL,
		0x6E7D76A0E8F0C7FAULL,
		0xF5073480A459321BULL,
		0xF3F9AA4DAF62D3EAULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x33AE144617DF546CULL,
		0xDBF3F6448BB9B6E7ULL,
		0x5EAA4DEFCCDC47A6ULL,
		0xE1BCBDA84937D982ULL,
		0xDE964030473AD8E7ULL,
		0x8622DB3D9224F2A1ULL,
		0x6E53FFAD4820578DULL,
		0x15D252D2B3605D1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33AE144617DF546CULL,
		0xDBF3F6448BB9B6E7ULL,
		0x5EAA4DEFCCDC47A6ULL,
		0xE1BCBDA84937D982ULL,
		0xDE964030473AD8E7ULL,
		0x8622DB3D9224F2A1ULL,
		0x6E53FFAD4820578DULL,
		0x15D252D2B3605D1AULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x01056F8F31C63E65ULL,
		0x5211AB41E1E73DCCULL,
		0x16B59C8E752317F2ULL,
		0x1E4BF46F9FBA111FULL,
		0x4C5D3C8F9359CE7BULL,
		0x3F46BDCAFF47050BULL,
		0x549E95E1936484D6ULL,
		0xA9E61F704C9610DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBE7A48DD9F9028ULL,
		0xEAD32E6E06A8260BULL,
		0x60D77F7CA8554FCEULL,
		0x09A126E090A566B2ULL,
		0x27739BB69E14A1EDULL,
		0x57F3C564751638A2ULL,
		0x5711C483A7369F5CULL,
		0x84E14A58C159A123ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x64189D9C56A6BC28ULL,
		0x69191F8D24F15675ULL,
		0x10CDBF354C4E65D0ULL,
		0x746A04B042468A99ULL,
		0xF3FBC5BCFCE83047ULL,
		0xFD38137125998027ULL,
		0x8FF8316880701ABCULL,
		0x2E8E5B0D19D55A79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF97AE39D1124A2D0ULL,
		0x859581BF18EE6C0AULL,
		0x9A1AFCB3D6325051ULL,
		0x2FD982D11AEBB05FULL,
		0x55786E8A9709ED6EULL,
		0xDC67A3475167F3E9ULL,
		0xA0D16FE8DDE4A186ULL,
		0x1155DAC0AC6EB7D1ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xABE5AFF4F15B7C07ULL,
		0x4B261B9DC64C0464ULL,
		0xA451B698E3FCC50DULL,
		0x8EACB05A511094ACULL,
		0x789887145F6DEC10ULL,
		0x101B55FBFE2776EEULL,
		0x4B88DC03D06A3418ULL,
		0xD8B5132DED9CE4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD51DEF319583E4ULL,
		0x0307BD99765AA67AULL,
		0xF47BE50CF0CAA741ULL,
		0x0A4646114F7608ADULL,
		0x4DA4222AD9181D93ULL,
		0x89AA26D3C90178D3ULL,
		0x92D5F70511D2BD10ULL,
		0xA55F079B0CC12FB6ULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFAEAABA8608243E3ULL,
		0x75F50A2ED6B548D0ULL,
		0x52045AD9AA9C0CA0ULL,
		0x22431F818494861CULL,
		0xC7D6385BAECCEBE1ULL,
		0xC9F04A862998D802ULL,
		0xF980AF844FD0ACAAULL,
		0x5AD7AAB7C13DFB5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAEAABA8608243E3ULL,
		0x75F50A2ED6B548D0ULL,
		0x52045AD9AA9C0CA0ULL,
		0x22431F818494861CULL,
		0xC7D6385BAECCEBE1ULL,
		0xC9F04A862998D802ULL,
		0xF980AF844FD0ACAAULL,
		0x5AD7AAB7C13DFB5DULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x751A02682D51CCFBULL,
		0x68A904D4D87B7395ULL,
		0x4FAE4C504D4BC567ULL,
		0xB549D5BB0F9633FBULL,
		0x019A623FDB68AABAULL,
		0x972F4F54710C5271ULL,
		0x82A766B1DA70432EULL,
		0x30D9E560B6ECE975ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D35B80A030A4871ULL,
		0xF0BFBE7898306A03ULL,
		0xB85F856C4ADFFE8BULL,
		0xDF845C00692C2705ULL,
		0xEBA49BF3CBFE807DULL,
		0x4F9E7F1D55DB3A25ULL,
		0xD6A3D470F5811686ULL,
		0xC8CFBC7188175BFDULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF1D0D13A3CB470C5ULL,
		0x7A160159170CCF82ULL,
		0x6031AF1E509EF79BULL,
		0x4461F646FC0C3ED5ULL,
		0x01AA6EED67445A74ULL,
		0x32F182D3F4931F08ULL,
		0x55C1E0FEFAE266DFULL,
		0x27D9BE0C20FA8231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108345C70F581233ULL,
		0x0D96F90427A91645ULL,
		0x32175F6AAFCE0498ULL,
		0x8919F6B11BAC820CULL,
		0x118012BC7A95EE66ULL,
		0x1A2FD6F58EB10F04ULL,
		0xBCAB1EF0CD257FE6ULL,
		0x20875F049A8697A2ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x78AC17BE61D3E6F7ULL,
		0x6301A66C9E9B399AULL,
		0xCC87E1888C00BE23ULL,
		0x353AE7CB6B411B7CULL,
		0x5D31F8F159214402ULL,
		0x75DE8C2F3B417E86ULL,
		0xCCE800EF562BC169ULL,
		0x008DD6B428844394ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE6C64EA2847FC7ULL,
		0x1AE5B3E8D128549FULL,
		0x6720EBF746776F1BULL,
		0xE6CBA56D68A4560CULL,
		0xBD69D6327CE07D19ULL,
		0xF4986B1419D2F52FULL,
		0xBD268F332E404E70ULL,
		0xBCDFBF692DD549E0ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8CB9CC5349D2179ULL,
		0x8D285614616C1743ULL,
		0x47E6076CC762FCC7ULL,
		0xED12E6BA7AF552B1ULL,
		0x61CD596D6AA935B8ULL,
		0x2ED696BD8FB9DD20ULL,
		0x512346C51898B3AEULL,
		0x829D865C1A6BD5EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8CB9CC5349D2179ULL,
		0x8D285614616C1743ULL,
		0x47E6076CC762FCC7ULL,
		0xED12E6BA7AF552B1ULL,
		0x61CD596D6AA935B8ULL,
		0x2ED696BD8FB9DD20ULL,
		0x512346C51898B3AEULL,
		0x829D865C1A6BD5EEULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0C78BCE79F20696BULL,
		0x2BC9F2FF649D9536ULL,
		0xD628F73A2780A4E5ULL,
		0xEBA97ADDA7DC540BULL,
		0x0E3A852376621D7FULL,
		0x0B3A883FEC795CC4ULL,
		0x70893F78222C824EULL,
		0x7AFF766B3E5D7ACAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E4DE31E68F8777FULL,
		0xC10B4E3C371F4208ULL,
		0x2CBDF18E261588F0ULL,
		0x3DFD2F4388174BB1ULL,
		0xC63FB58BEABDDCCAULL,
		0xF9C4FDA0C8A83F6DULL,
		0x93D0BE9182FB3AF9ULL,
		0x1072E977FD234336ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x231DDB5CA58C5830ULL,
		0x06F5647A70B9A088ULL,
		0x17D9B93497E80B8DULL,
		0x7B517AAFCA78CAF5ULL,
		0xC3460FB7398D7D2CULL,
		0x50A4593252789005ULL,
		0xB023F6F6C970BC83ULL,
		0xA43504050293571EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE93FDA81D37F36B3ULL,
		0xAD4FE556382417FFULL,
		0x2223B7354BAD10E0ULL,
		0x1C74E9403522296FULL,
		0x08CE6AA1C8D9F3CFULL,
		0xA5F8D647BBBE68B4ULL,
		0x7C2D0FA8B24726A3ULL,
		0x2BB2ED7E3FA563BBULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF4C6954DB885FC1FULL,
		0x30FAC67A14AE16C3ULL,
		0x8E71E304563A39ACULL,
		0x817167E706156AFBULL,
		0xD6B364FD59F51177ULL,
		0x13E540FE0F0BF81AULL,
		0x5BF567815F12B2F3ULL,
		0xCE4D0E50835DB7DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9F7B5F04EED7E84ULL,
		0x2C1F7CB9D5643CC4ULL,
		0xE8266220AF99D9DFULL,
		0x1F1BB222D4A80621ULL,
		0xEF93D064038BA45AULL,
		0xCFAF39DF87318DBDULL,
		0xC260F375F8E7D89BULL,
		0xC510D5F7CB01797FULL
	}};
	t = 1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x84BAA68EB8B6008CULL,
		0x04FD2BAB27409A28ULL,
		0x10E3ACEDC4E681C3ULL,
		0x1E2D32D212BF70B2ULL,
		0xAA8E691B8EDA59B8ULL,
		0x38F9EAA0DF42188BULL,
		0xE5D22EA2D095E0E4ULL,
		0x7C86B940D079EB34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84BAA68EB8B6008CULL,
		0x04FD2BAB27409A28ULL,
		0x10E3ACEDC4E681C3ULL,
		0x1E2D32D212BF70B2ULL,
		0xAA8E691B8EDA59B8ULL,
		0x38F9EAA0DF42188BULL,
		0xE5D22EA2D095E0E4ULL,
		0x7C86B940D079EB34ULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBEFC19DE0F0E23CFULL,
		0x0E5C977C553081D1ULL,
		0x2F428ABA7FADB3CEULL,
		0x9ADE43C8AC82BF32ULL,
		0xB4633421C7105464ULL,
		0xBAAB9CED25BF3567ULL,
		0xA525203FD6F7E33DULL,
		0xA88D019E156B7DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC306C23E2AF572B3ULL,
		0x3DFA309ECA729B4EULL,
		0x4743A7E847129652ULL,
		0xDE42BBAD02AE9CB9ULL,
		0x148FB559FD839137ULL,
		0xDDCF385AD58F507BULL,
		0x76BA98051BFC4B70ULL,
		0xAA153A7B233E95D8ULL
	}};
	t = -1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x67E4BC87028FA00BULL,
		0x3B7D049140D352C0ULL,
		0xB57D838479C5C512ULL,
		0x6853C360F5A2EE08ULL,
		0x3BE17AF1D66FB6CDULL,
		0xAF6A9F11AF136D23ULL,
		0xD82A661FFD4BC200ULL,
		0x21B6E676911CC6B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DBE5F2BF9E2A5AAULL,
		0xA99772539FB4FB72ULL,
		0x4F8AC917EDFA4330ULL,
		0x6B4977396EA96E54ULL,
		0x2131A5F5A84BE8CDULL,
		0x2D3EA4511BCE0F53ULL,
		0x544A3F7DDFE6D5C3ULL,
		0xC13D075482490AFAULL
	}};
	t = -1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF4B5A4ED755219CDULL,
		0xD89A4A55041186A6ULL,
		0x586386E35B5E14D4ULL,
		0x4573C9424B3D77D6ULL,
		0x4909848BC01D780FULL,
		0x13A6E185FE2A7F9FULL,
		0x6ED8C772748B4D3CULL,
		0x8277642ED754BEE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2462AFA751D4E532ULL,
		0x30F331A99396809EULL,
		0xA6AF327168505649ULL,
		0x96F0A480A8B21D30ULL,
		0x57DF2BBB9D4E052EULL,
		0x87E5E34E670A1EA9ULL,
		0x7234702DA384BA5AULL,
		0x11161280F5AE0D13ULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x280834CB5EFE4924ULL,
		0x293A568D2EE4B862ULL,
		0xE0CFAF6E56D9587AULL,
		0xE1D30268CE675773ULL,
		0x24BD55E523609D7CULL,
		0x75588775CC8DC12FULL,
		0xDF886AD7CC1DC113ULL,
		0xA3291C2587268B8BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x280834CB5EFE4924ULL,
		0x293A568D2EE4B862ULL,
		0xE0CFAF6E56D9587AULL,
		0xE1D30268CE675773ULL,
		0x24BD55E523609D7CULL,
		0x75588775CC8DC12FULL,
		0xDF886AD7CC1DC113ULL,
		0xA3291C2587268B8BULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8ADBEDE5F44E9AB0ULL,
		0x79C35DA21B5EC2C2ULL,
		0xF6166D502A70B51BULL,
		0xF94778E2CDAE568BULL,
		0x7963BD69B8749A24ULL,
		0xCC74BC42C9EE0545ULL,
		0x400219B744A37F08ULL,
		0x5447790F987A9311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7599ABF071C29885ULL,
		0x84EFD4EE1208A2B9ULL,
		0x714EA0A9E8A207ACULL,
		0x68874FD3212DAC3EULL,
		0xEB19C9B6C02B8743ULL,
		0x087EBCC6A2A9424DULL,
		0x4071E594002DE4D9ULL,
		0x7B77E8AFFA1A2CBCULL
	}};
	t = -1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x36C6FEEDFAD6D81BULL,
		0xDEF45A32E0904B33ULL,
		0xFC9DE5DE8A095352ULL,
		0xB8B7B5F31C25F8DDULL,
		0xCA0E89C900BD62A3ULL,
		0x4272D448B84D5E37ULL,
		0x0372A168336E56E3ULL,
		0x62AFAF642B4DC10FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB17304543CFF101ULL,
		0x536ADD82539E618FULL,
		0x61B040E7A5E9DB56ULL,
		0xD9087EC527FE6F34ULL,
		0xBC8FAE1AEBD47152ULL,
		0x4D041853FCF38C67ULL,
		0x13345F98DBE73422ULL,
		0x3EDD5EC944186A57ULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFAFB4046EFADF9D6ULL,
		0xD859BC946D29FB2EULL,
		0x0CA0E6917588747DULL,
		0xE0FA700159ACFEEDULL,
		0x593A236FED2B9D52ULL,
		0xDC824EA4FE8265FBULL,
		0x5872F1EF5B9447B3ULL,
		0x35F99F75B7D17F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EF9B7B9352C6724ULL,
		0x4ADD36DFCEA6915DULL,
		0x39612F6FEEB7D768ULL,
		0x755F6F362D802D99ULL,
		0xB10BDB27C6E70B6CULL,
		0x35F6EE946E77616AULL,
		0x60E04685146EAF97ULL,
		0x5311F9413AF1E513ULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3AA26CD7C4CCFE22ULL,
		0x809AF1F5CC194350ULL,
		0x150BABA828265CA7ULL,
		0x16AD7E2B39D54062ULL,
		0x866CC12D32CC9C0EULL,
		0xAC48F482991DD7B7ULL,
		0xCB290BED9F8E3333ULL,
		0x6D5521F4B3A45904ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AA26CD7C4CCFE22ULL,
		0x809AF1F5CC194350ULL,
		0x150BABA828265CA7ULL,
		0x16AD7E2B39D54062ULL,
		0x866CC12D32CC9C0EULL,
		0xAC48F482991DD7B7ULL,
		0xCB290BED9F8E3333ULL,
		0x6D5521F4B3A45904ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x184AC0956C94F59DULL,
		0x5E46845D1688ABB1ULL,
		0x4AF5F5C4330F6A59ULL,
		0x78EF9E6C5C0A7A41ULL,
		0x7CC8876105B3AB4BULL,
		0x1870DA42522E01B3ULL,
		0x3782FEFD90971C06ULL,
		0x5005289ACE086AF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F1CDA7C1EDD3EAULL,
		0x30AA6910EE5A07A8ULL,
		0xE93DABD479BBFE29ULL,
		0x530EC33ACFCFDAD9ULL,
		0x1757C4CB53856235ULL,
		0x1FD625335F8241D4ULL,
		0x503FB2A924B8885CULL,
		0x4D78A66806077A01ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBA2FC8F2552D0105ULL,
		0x3DF66C4A6B341C72ULL,
		0xB17ABC872817D39FULL,
		0x50D1DB61409A144FULL,
		0x5A0AEC433B6F0383ULL,
		0x1E3DCC714D32C1B4ULL,
		0x1F58EC6F224448B6ULL,
		0x84A2E55E4B1B1DA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8832A18B1B5DC4ULL,
		0xEEFB1DC9F7FCFDAFULL,
		0x5E911EE2AACEF783ULL,
		0xB2B4CDD5CEA91B87ULL,
		0x6962F037051ACFCCULL,
		0x9D24D0FCF7404952ULL,
		0x0E0DF2BC819EB452ULL,
		0xB1D3EC0606BF1198ULL
	}};
	t = -1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9287E5664A10A509ULL,
		0x5988DA5F4FAC5ACBULL,
		0x4EB526D4A0477720ULL,
		0xE51C6E73DA3ADF88ULL,
		0x389388F5640A7A13ULL,
		0xFD760C62DC1CBD11ULL,
		0x352799FA38FEAB28ULL,
		0xF56FF113F7854B02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A564CB273DA433ULL,
		0xE8AEA00C1F8B2044ULL,
		0xE0893A9F16E9CDDBULL,
		0xD6E2F53DC34F79AAULL,
		0x8BFB4CF570D44659ULL,
		0x9D9523D045667901ULL,
		0x81AB21018BABD4DDULL,
		0xED31613063A91E22ULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3D288D0922DB925FULL,
		0xD3C2765F7C64C1F8ULL,
		0xDD0E8CF7492F1289ULL,
		0x9E3C4C3B885133F5ULL,
		0x356257FD1A906A7BULL,
		0xD777D4CD5478252AULL,
		0x239E31E77CD64B49ULL,
		0xF8C92730F16D23A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D288D0922DB925FULL,
		0xD3C2765F7C64C1F8ULL,
		0xDD0E8CF7492F1289ULL,
		0x9E3C4C3B885133F5ULL,
		0x356257FD1A906A7BULL,
		0xD777D4CD5478252AULL,
		0x239E31E77CD64B49ULL,
		0xF8C92730F16D23A9ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE6412C6D2C9050CFULL,
		0xD00629B1F042EBC0ULL,
		0x0BDAEB8F6788968AULL,
		0xE2263098AD93FE12ULL,
		0xB981E7946323D63CULL,
		0xC90EBCBC18969706ULL,
		0x1BE8B6223C44E5FEULL,
		0x8C163EC978FF0D4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEE1A1045BE1906BULL,
		0xFB9A1683621BD5A7ULL,
		0x2A7ADFD4776B8853ULL,
		0x1FED480CE8B88010ULL,
		0x5636EB505001AF41ULL,
		0xE5F1B261A0944B1CULL,
		0x40EA12EFAD263137ULL,
		0x48F5941D7BB4B282ULL
	}};
	t = 1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1B306EC3718CBE05ULL,
		0xF70F45C2A8B43E23ULL,
		0xFDBE84B80F018D0FULL,
		0x8F92A25A90805919ULL,
		0x44C647E3A3C2266EULL,
		0x3655D1533510B0C4ULL,
		0x62A6AFFA4E0C1F86ULL,
		0x30A7A2FEC7D75FEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428C15802E9C7897ULL,
		0x925668AB9C6A4347ULL,
		0x983F6D2DF8227F1BULL,
		0x9D7F723FE144BD72ULL,
		0x8AE27CA3C1797EBEULL,
		0x2322C0AC4F8BA866ULL,
		0x6095DE01CFCD5D75ULL,
		0xF87DE6A036E500DBULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD258FA13CE519F7BULL,
		0x167E899C6F5F58BAULL,
		0x22A26DC7FC605EA9ULL,
		0x7C5A2C4575690DB8ULL,
		0xA8C6A0949E6176DFULL,
		0x00B4A53DC68AB6CAULL,
		0x9787948E2FD7B04EULL,
		0x42377CC37D24118DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x027B864DAB004E2BULL,
		0xF4DD59EC08661EF5ULL,
		0x6A6FCB87028D3B2DULL,
		0x5A60D488DFE42ABAULL,
		0xE6D717C55DF19E57ULL,
		0x18F2E40B74F59FA9ULL,
		0x3648E0F8898F10E7ULL,
		0x3A184CB096ADA3B5ULL
	}};
	t = 1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7C70A42FD5B0C5CDULL,
		0x3F1EDB94B35D1843ULL,
		0xB2048608C4764157ULL,
		0x32FC2002E9A407C1ULL,
		0x489F3C60FFA9E467ULL,
		0xE20FCF3CF7826668ULL,
		0xA2A1B1724E5F17A4ULL,
		0x0951108F089974C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C70A42FD5B0C5CDULL,
		0x3F1EDB94B35D1843ULL,
		0xB2048608C4764157ULL,
		0x32FC2002E9A407C1ULL,
		0x489F3C60FFA9E467ULL,
		0xE20FCF3CF7826668ULL,
		0xA2A1B1724E5F17A4ULL,
		0x0951108F089974C3ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC8EC6AD577978D0CULL,
		0xD585499C03BDC22FULL,
		0x0390DF811CFCC11FULL,
		0x72FFDA1E079A2A86ULL,
		0x4F9D60EDD1C467AAULL,
		0x5D5673A7ADB804DAULL,
		0x5FE3B3F6F44E66E9ULL,
		0xB951F7538E79335CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6814E2B0E88A7C96ULL,
		0xE927BAF98836D011ULL,
		0xAE357A611BA92401ULL,
		0xB8D6EE2BD2179C0FULL,
		0x5C4EACFA4FF15C89ULL,
		0x2BE596DC29A0A95DULL,
		0xAF7A4D483BBC347FULL,
		0x8A37FBC7DCABC352ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE4DA587A82C4C520ULL,
		0x5709D6C3DF48E4ABULL,
		0x217BAFE4478697F1ULL,
		0x05A837AEEE02609AULL,
		0xE5BE12CD28A3FAD1ULL,
		0x6DE7F1F1A151B9F5ULL,
		0x2B0FF73555ED133BULL,
		0xB6C16C38B8FCDF00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9FDEC211EE3DA35ULL,
		0x3F7D69FBE2A980C0ULL,
		0x93413E003391848AULL,
		0x30CCD21EA7FD898CULL,
		0xE24CF8060DC3086CULL,
		0xCD3783331A5945D0ULL,
		0x70B0DF317E8B415EULL,
		0xBD05D760DAD9FC22ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEE347CCBFED3B259ULL,
		0x9AF9A0DEAD4C7239ULL,
		0xDD1C50CDFEEA5252ULL,
		0x229E0A84534D2241ULL,
		0x9AD860D411F4BF3DULL,
		0xAB2A19D0513A577AULL,
		0x8E2E8DDAA7E5D1D4ULL,
		0x3219F042C127F0C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x085E5DC4F2F1D0EFULL,
		0x042EFE8186A51344ULL,
		0x73CDD557D902E4BCULL,
		0x046DD455B1F975B7ULL,
		0x0223825C6D628573ULL,
		0x07FB3780B1E64E9FULL,
		0x88C568A9E3F4769EULL,
		0x84B8BF0BC525FE6EULL
	}};
	t = -1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x43624CA357868649ULL,
		0xAC0452C07BEF84CBULL,
		0x74BE9E876C3F48CFULL,
		0xC0542A05D4305216ULL,
		0x0D7AF22D3C42EFCFULL,
		0xECF24B3D7CD66D68ULL,
		0x0A1D21A15674E732ULL,
		0xF3079B38F00FBAC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43624CA357868649ULL,
		0xAC0452C07BEF84CBULL,
		0x74BE9E876C3F48CFULL,
		0xC0542A05D4305216ULL,
		0x0D7AF22D3C42EFCFULL,
		0xECF24B3D7CD66D68ULL,
		0x0A1D21A15674E732ULL,
		0xF3079B38F00FBAC9ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC7CC68BCE3BC5E85ULL,
		0xDA4F67F78B2D1652ULL,
		0xD19ABFA819AA6C30ULL,
		0xB63741A9720EDA95ULL,
		0xC2DBBB03331573AFULL,
		0x59477FC82E78B0BDULL,
		0x46788755CE536F53ULL,
		0xA94C0B4BC3BD8C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB1BDCA31BAE6BCEULL,
		0x84831228765A27E6ULL,
		0x1A0B536FDD74F1D3ULL,
		0x94672568CDC0CEF4ULL,
		0xB83C119F8ACFF3D5ULL,
		0xD82AD2C3F19DF6EBULL,
		0x7AD73C834EED95A3ULL,
		0xE075BABB2C1F90AEULL
	}};
	t = -1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x42F7A31908463E5EULL,
		0xBC7FAE5704F6AD50ULL,
		0x43F141A7869D4A51ULL,
		0x4B0F529457A077DEULL,
		0xA2AB81D174AB3790ULL,
		0x43F9E96D3DBDFB7AULL,
		0x53A41EB56CA76832ULL,
		0xE84D52ED70E9932EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77EB6D26D7CF387CULL,
		0x917761777BB4705AULL,
		0xAB6335B15B1191E3ULL,
		0x8F0669029693A8F0ULL,
		0xCEE3FEF893E32EC0ULL,
		0x746139BC250AE0E4ULL,
		0x55FE6B7AF62F99D0ULL,
		0x46042A6672AA854DULL
	}};
	t = 1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA50D14E9532B7276ULL,
		0x43A6F41B8BCEBB4FULL,
		0xE14033505AB5D9A1ULL,
		0xD8B907941797E58CULL,
		0xE6CA173DD085B312ULL,
		0xA75FBB7579B24764ULL,
		0x26758372A8A597DDULL,
		0x2DB50E7EDD5A68DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x468E206003749683ULL,
		0xBEF5ABB7EC528885ULL,
		0x4F047A1DE4594179ULL,
		0x9E454DDDB053EF8BULL,
		0x68CE258EE42D9225ULL,
		0xED73758E5CD19D26ULL,
		0x53E892DC568339ABULL,
		0xB6DE0209C27465D0ULL
	}};
	t = -1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x867B761609F7E053ULL,
		0x56F94D093B5C02B9ULL,
		0x35DE60D2DEA2F237ULL,
		0xD9AF62DC3EE7F5D9ULL,
		0xB0B207F02A30E6B8ULL,
		0x8CAD06071B0C21FBULL,
		0x986CBE69F3371B76ULL,
		0x314FBCB08A190D2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x867B761609F7E053ULL,
		0x56F94D093B5C02B9ULL,
		0x35DE60D2DEA2F237ULL,
		0xD9AF62DC3EE7F5D9ULL,
		0xB0B207F02A30E6B8ULL,
		0x8CAD06071B0C21FBULL,
		0x986CBE69F3371B76ULL,
		0x314FBCB08A190D2CULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x204C56FF75745049ULL,
		0x0926981AC14293F9ULL,
		0x727CF5D5633CCE37ULL,
		0xF8BCC692B631EDBDULL,
		0x44BA33CEE0CB3A30ULL,
		0x1366E78002197D6EULL,
		0xD998A25A7E8EAEC5ULL,
		0x764F41042D3FD337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E6E5BA66A4E1E82ULL,
		0x075CC5FB64C82FBDULL,
		0xCCB401AD703AEA25ULL,
		0x4771DCBD1AF1D8F7ULL,
		0xCA55F6BD293BC8F2ULL,
		0x15EA2F7A4F789A99ULL,
		0xCC6735F80F68FE95ULL,
		0x2CA8D9AF8CA91973ULL
	}};
	t = 1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0186A8415589733FULL,
		0xD9819ED2BC06E78CULL,
		0x92DC8B316209A608ULL,
		0xB97B2FA58B99544CULL,
		0xD8C0ADCFDF7029C3ULL,
		0x8C7CD8BBD8CDA050ULL,
		0x00380AD2EB452459ULL,
		0x3C89EE18628E0BCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2782205DDD62CF3CULL,
		0x3472B000E3F0F4B0ULL,
		0x20386F20A312498BULL,
		0xE63B3C7EC80B111EULL,
		0x927664B9CB575CE8ULL,
		0x3DF5EC7D418798EDULL,
		0x1E840434E45141B0ULL,
		0x2C29499E0C77DCA6ULL
	}};
	t = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x897C544BB9C89529ULL,
		0x669BEC540F41C288ULL,
		0x0FF370C1ED34EC18ULL,
		0x4E634F653110B222ULL,
		0xE25FBE3949B4D801ULL,
		0x7D9DCF84FACA71A0ULL,
		0xC03C53C6E83C7B43ULL,
		0xA8153E1EFE7D6980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD80B4BD3E3A78245ULL,
		0xF849987B0717BB83ULL,
		0x749634F15F5638DEULL,
		0x98E7720928CD3FCAULL,
		0x58754D585617AC2EULL,
		0x109CFE0AA788B863ULL,
		0x663A96D98EC150B7ULL,
		0x6EAB3F847E00E5E9ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8187EFD8661B3887ULL,
		0x705A33B76CFE02C1ULL,
		0x6F9D67F6FA4D430AULL,
		0xD0560E48A101EEA3ULL,
		0x445BAA0E8586D92CULL,
		0x0E5E6620D0284FD4ULL,
		0x6ED78144A0CFDE24ULL,
		0xAD98CDBF97D18EF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8187EFD8661B3887ULL,
		0x705A33B76CFE02C1ULL,
		0x6F9D67F6FA4D430AULL,
		0xD0560E48A101EEA3ULL,
		0x445BAA0E8586D92CULL,
		0x0E5E6620D0284FD4ULL,
		0x6ED78144A0CFDE24ULL,
		0xAD98CDBF97D18EF9ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x47FD99C949DE25E5ULL,
		0xDCED1FDE87FCDD44ULL,
		0x0AE312C000253FA0ULL,
		0xD4ED05EE3D64B9ADULL,
		0x6EF45F9154383413ULL,
		0x489324A7C51D51F3ULL,
		0x501C3DD2A9FAAC9FULL,
		0x0A78EA22E3B7032CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD51EB4CC228018C9ULL,
		0x22028D429F731379ULL,
		0xE8FEBBB51E4DFE2AULL,
		0xFF206A436CAF19A2ULL,
		0xC5113C253D63A858ULL,
		0xC580328BAF5FF96BULL,
		0x97DBC72A3B59FA0AULL,
		0xB4EFA328AAC571AEULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3EF7373BAF6029BCULL,
		0xA6F26D9823AC9DF7ULL,
		0xE4891DC81D913AA4ULL,
		0x1AFA8E77AEC0E3FEULL,
		0x365FF73F698588DFULL,
		0xAB681FFAF936396DULL,
		0x45A738F363367654ULL,
		0x36A4AADBC9DD8925ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB401CB51C6E70A75ULL,
		0x8B46A21E535E5A9AULL,
		0xC42362D3FD573D23ULL,
		0x9047DCFFFD66DDC9ULL,
		0xA0AD7E760DC1BD84ULL,
		0x05A79D0CDE23299BULL,
		0x6663303B2191F140ULL,
		0xB60AAA779C769FEBULL
	}};
	t = -1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0FDF79A0AAFFD741ULL,
		0xE0D972B8C0727B71ULL,
		0x1E17F303A2590A09ULL,
		0xF747EFE719302041ULL,
		0x1CCEC3EC87CE2B4AULL,
		0x7B0B5CD0F2B25644ULL,
		0x31CD1C67AE7FD5C5ULL,
		0x733B872D7AEFD41DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB2B59CC3BDBBD3DULL,
		0x319CB752B7D9B000ULL,
		0x2C8D55C01D12E78CULL,
		0x002FF478754F265EULL,
		0x73B9CECDFA8FAD6FULL,
		0xD755CFED93B5AAD1ULL,
		0x7A9BE4F19A23F16BULL,
		0xA8D0D8BB67913CBEULL
	}};
	t = -1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6D9ADCF6BB0AB809ULL,
		0x8B3FEC232CF23573ULL,
		0x88FCA38B53BAB166ULL,
		0x08242E5870D1F850ULL,
		0x49D53926797BB524ULL,
		0xE44A971942A6523EULL,
		0x4A9A6F1B40B5B869ULL,
		0xDE4BD81DAC5A7EF0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D9ADCF6BB0AB809ULL,
		0x8B3FEC232CF23573ULL,
		0x88FCA38B53BAB166ULL,
		0x08242E5870D1F850ULL,
		0x49D53926797BB524ULL,
		0xE44A971942A6523EULL,
		0x4A9A6F1B40B5B869ULL,
		0xDE4BD81DAC5A7EF0ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4806A6888F9F1211ULL,
		0x752324D894FEDAC8ULL,
		0xBAA263F303DC47BBULL,
		0x293319266C08498BULL,
		0x1D40F96F42C70050ULL,
		0x78B3C5C5832B54B6ULL,
		0x2664F00D4E87493DULL,
		0x52E2428381B1C591ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x749505CE51E30B63ULL,
		0xFC36C4875F846A9BULL,
		0x15BE9BFFD10DC09CULL,
		0x4A9B846F3CF14A36ULL,
		0x6D9106B85FB76F2AULL,
		0x6A4A53ED9DCD2829ULL,
		0xD734FAC7B8469415ULL,
		0x4A0B1FBE09FEF69DULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x87C7F924A00D948EULL,
		0x8D82093B60D5713EULL,
		0x8893C92D8F266D85ULL,
		0xEE3DA6E3F923EC43ULL,
		0xAF4E297770DBB18FULL,
		0x0AAE8B4D7ED6EB33ULL,
		0xDFFAA6DDC5245DF5ULL,
		0x495F9CACD4F40441ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x655397BD3A030B4BULL,
		0x5F3C04B28F4F8440ULL,
		0x73D31643440CF2ECULL,
		0x3E2FF9E374B8D62EULL,
		0xA22006C5227E6D59ULL,
		0x2E32233A77995F5EULL,
		0xC12997A94DD03C0FULL,
		0xD8316FBEDECBBF71ULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4D1F0B11555C98E0ULL,
		0x042B07DD7A2E4941ULL,
		0xB2A91C522D4B58F4ULL,
		0x3F8EC045DC4A36A7ULL,
		0xC45459FBCCF2DB1FULL,
		0x6E08A09CBEC28966ULL,
		0x62B96C84DE4D8E01ULL,
		0x783664C156A0AD78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD17B56D9151A2BEAULL,
		0xBDEDF198E959595BULL,
		0x99BE73083D7FF465ULL,
		0xEF44C01745E0EF7DULL,
		0x0B4342D381DD31FDULL,
		0x9C6BF23DA4025908ULL,
		0x21EAF7DC83BB3153ULL,
		0x860FA784BA64E3DAULL
	}};
	t = -1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD3F60B155196FD0EULL,
		0x5351BAE4DD1AA98DULL,
		0x07A3ADB429F59D04ULL,
		0xB04C7DCE707AA785ULL,
		0x0144780277686555ULL,
		0x403D333BC4676A6BULL,
		0x60137259099609CAULL,
		0x772E3204C4DC6AD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3F60B155196FD0EULL,
		0x5351BAE4DD1AA98DULL,
		0x07A3ADB429F59D04ULL,
		0xB04C7DCE707AA785ULL,
		0x0144780277686555ULL,
		0x403D333BC4676A6BULL,
		0x60137259099609CAULL,
		0x772E3204C4DC6AD6ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF26B1B8BD751735BULL,
		0x73D49724AB7F9DDDULL,
		0x137D6506FB5B02EFULL,
		0x6DF1290F06FBF55CULL,
		0xECB21AF16D243A17ULL,
		0xAA6D816D65ACA3B9ULL,
		0xC2DFD1AB3D07E322ULL,
		0xE7DFB4AF6B164689ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B5DAC79EAC4A7C4ULL,
		0x268075645197E79EULL,
		0xAE16D98C8F687AD6ULL,
		0x6A92FCEE273C762BULL,
		0x7351AB9D4A063C0BULL,
		0x06A8F937C5A1C98BULL,
		0x6E3010C095EDF05DULL,
		0x587B40BCEFE76758ULL
	}};
	t = 1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD1D79D7F2E7F0BDAULL,
		0x07CBF4F29A3ACE20ULL,
		0x00F8A7AA75D60B03ULL,
		0xD237D69C4503C8D1ULL,
		0x84D2225384BB65EBULL,
		0xB024B4CED7312245ULL,
		0x704E63F869240F11ULL,
		0xBB9D4F0B3DAB9928ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0713BF57BB8E4CD4ULL,
		0x0A9B2AD0D8F8A3A4ULL,
		0x9503077F9552C05EULL,
		0x27C2E4989F9C604AULL,
		0x6B474D46D32684D2ULL,
		0x5AC185633E76A6E3ULL,
		0xB3F74346F0188D4DULL,
		0x1EA2C7EB4B5A278CULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x30EAA9564442906EULL,
		0xEF8C860E830DCD09ULL,
		0x1106B5D8DF4337D1ULL,
		0xAA88F608E45C7FC5ULL,
		0x270DC3B972CE9BC0ULL,
		0xB85929F6BA3B5D66ULL,
		0x16D5129A134C50B4ULL,
		0x1A095F6EEBCDBCD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C9B82AB0E5E366ULL,
		0x260460E1CE682DC2ULL,
		0x9F3D7A83214181A2ULL,
		0x2CDF3A00EDE5F5A2ULL,
		0x0A9D7CAC5586A4B5ULL,
		0xD6F400C84E2D90B0ULL,
		0xA36243AC246BE19BULL,
		0xA57975874A719923ULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9E0B5C739256552FULL,
		0x3777E6222ACB7872ULL,
		0x3776162C268B252EULL,
		0x4742D7730329911BULL,
		0x2A20AF9A935432DFULL,
		0x6765DEBDDD865124ULL,
		0x46AA0981BD72BC6CULL,
		0x8D12C692FC7FF7A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0B5C739256552FULL,
		0x3777E6222ACB7872ULL,
		0x3776162C268B252EULL,
		0x4742D7730329911BULL,
		0x2A20AF9A935432DFULL,
		0x6765DEBDDD865124ULL,
		0x46AA0981BD72BC6CULL,
		0x8D12C692FC7FF7A5ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x275DFC0DA68FF392ULL,
		0x9EF6D9F7A3C2FC48ULL,
		0xC3A9936AE17B133DULL,
		0xDF2F1DFD1A2590AAULL,
		0x06E617F42EB39B6DULL,
		0xF91E81BB85B8DE26ULL,
		0x65C4BD2AB17F6729ULL,
		0xAC4BBD00B9CD4F46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFA3A4AB13182537ULL,
		0x1B2ACB7A575FDEC1ULL,
		0xBCCAB43AADEF79FFULL,
		0xA4AF731919E155A7ULL,
		0x8FDCE2F44478B3D4ULL,
		0x167E685DA0856640ULL,
		0x7ECADF803E62E4B2ULL,
		0x45D4F90973EC68FBULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x95F1426D6D7931D3ULL,
		0x6032EAA10CC565DFULL,
		0xA05F393E5EA32D43ULL,
		0x7434C7B7F5CDDB4CULL,
		0xA30434273C6A8942ULL,
		0xCD86E8E60F8F7717ULL,
		0xC6C3571CDCBF94CAULL,
		0x42EAE23F87F60B99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C4F5F54CF45B1AEULL,
		0x33EC519822BEE9D3ULL,
		0x0AAD7C9B90D90331ULL,
		0x0AD6839F5652EA63ULL,
		0x353C4A87E4387AEEULL,
		0xA3909A94BF3335DBULL,
		0x0092EAA1173A997AULL,
		0xE0FBA2659772C3FBULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9A5623177345AB56ULL,
		0x9BF608A2738A8D29ULL,
		0x46070DBE41EF45D2ULL,
		0x188847071D9B693EULL,
		0x77B2EF9E93D4FC04ULL,
		0x0FEC03A576B51D6BULL,
		0x420CCDAF630D7C29ULL,
		0x0987923B2ACC2A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53F6FAC3A06D68D4ULL,
		0xCB35A8A605E05A47ULL,
		0x0DACA650B4DDCECCULL,
		0x981024F4B4BB0D67ULL,
		0xC4B248A248B3DB0AULL,
		0x9E7F7378C0B1E259ULL,
		0x01840CB8F8C44CCCULL,
		0xB90B083385E5F555ULL
	}};
	t = -1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1AA8963B334D2EF0ULL,
		0x6DC104306FB2EF5DULL,
		0x603CF2E59119AECDULL,
		0x935A29126956C2C6ULL,
		0x4412A814E66437A9ULL,
		0x96A00A11018DE3C5ULL,
		0xB01FF1915EB0E7FBULL,
		0x715EEF392F7858C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AA8963B334D2EF0ULL,
		0x6DC104306FB2EF5DULL,
		0x603CF2E59119AECDULL,
		0x935A29126956C2C6ULL,
		0x4412A814E66437A9ULL,
		0x96A00A11018DE3C5ULL,
		0xB01FF1915EB0E7FBULL,
		0x715EEF392F7858C8ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6E7588F25A1FD9DCULL,
		0xF71DBB1E2173E0A1ULL,
		0x23B7EAEF1222418BULL,
		0xDC513875B5C693C8ULL,
		0xA75B106DD97DAE96ULL,
		0x99FBB8954740E6C1ULL,
		0x97739B3913D649EBULL,
		0xEC7A7D616269E85FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A4102400B0F69EULL,
		0x96D8B8448A03BBB5ULL,
		0x28C3D9365EB94A37ULL,
		0xD42A2F86075520D7ULL,
		0x2C8ABF7E132C36CBULL,
		0x1F29CDDC216024ABULL,
		0xA5B8D0A6F36C5B22ULL,
		0x9F1AF3BF7BF93130ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB2916ED8E606DAEDULL,
		0x1A9513F5F83CE5C2ULL,
		0xCA8D0BE71DAFD810ULL,
		0x0DF84C689CB2B170ULL,
		0xD10497D56533548EULL,
		0x235ACFBE27D5B196ULL,
		0xCFDEE3025F629928ULL,
		0x83418893D0FF62DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9CED9B1A3E9D496ULL,
		0x41CD148F331F061BULL,
		0x6D1C96E5C8B557EBULL,
		0x243F29821F82DDBEULL,
		0x3156A187AAC39D2BULL,
		0xDB89F6901949C7D4ULL,
		0xB356212108BB1D81ULL,
		0xC8232EDFFC3D71FEULL
	}};
	t = -1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x35869F3416465104ULL,
		0x779405E00C65B4B4ULL,
		0x1A39431D89F7D769ULL,
		0x90082D4A1BC748FFULL,
		0xA2C310A8391C8F16ULL,
		0x75DA8C1767D2BA08ULL,
		0x3AE040E648047E8DULL,
		0x83865F85B1AF02C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E16D453341E6B9ULL,
		0x1BD855D88DFCF7ACULL,
		0xE1C1A5E24BD36901ULL,
		0x6452FBD27D607DA8ULL,
		0x0D6DC298B736B42FULL,
		0xB7393D37F4C60177ULL,
		0x77FF85BE5CED8E6AULL,
		0x1A70B0254B0212A9ULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE3652B71505D79D7ULL,
		0x54BF3603421E0BA7ULL,
		0x4AF8BFD21BC1CCC6ULL,
		0x9079D61D4CE686EAULL,
		0x4EDD087BB336499AULL,
		0xE69A1515DE06F632ULL,
		0x5D6341D0ED626EB8ULL,
		0x18AD083CB3DACD23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3652B71505D79D7ULL,
		0x54BF3603421E0BA7ULL,
		0x4AF8BFD21BC1CCC6ULL,
		0x9079D61D4CE686EAULL,
		0x4EDD087BB336499AULL,
		0xE69A1515DE06F632ULL,
		0x5D6341D0ED626EB8ULL,
		0x18AD083CB3DACD23ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8E6B11C1E28DF894ULL,
		0xDF41ADC152921BF0ULL,
		0xEC3ADCE447565681ULL,
		0xC62D4DA938DA969EULL,
		0x72EF3EDA69CDF5AAULL,
		0xB2CB65846D9C98E8ULL,
		0x853D48BD3D6CD7D3ULL,
		0x2B9964787990F363ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x700D39E9E9DC3451ULL,
		0x76BF7130AD9D27B9ULL,
		0x3DAD9BB055E42682ULL,
		0xC8D124A5301B0541ULL,
		0x0941B637B4975308ULL,
		0xA4828C85DFFD310CULL,
		0xADBBB850AC119C81ULL,
		0x6965BF4299A69B20ULL
	}};
	t = -1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0FC126F87629E52EULL,
		0xEEBCC5DA930E3A76ULL,
		0xD6B5F12E51B3ECC3ULL,
		0xFE875D3B388930C3ULL,
		0xF35CF946F2C36BA8ULL,
		0x84B89904D6E883EDULL,
		0x84CE95476F6135BBULL,
		0xFD2A0D966E64057DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9EE98ED77DB39FE2ULL,
		0x06BB00A7151FC493ULL,
		0xBEF6938DEDABDBDEULL,
		0xB09CC6C08DFC88C6ULL,
		0x8F400EED65891EBFULL,
		0x9C720597B1498B2BULL,
		0x939AEF09F5CE1CBEULL,
		0x7A76300C26B71D32ULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8DC9916CCEC8CF68ULL,
		0xE3180C7209F214D7ULL,
		0xB0868BFA62923E0AULL,
		0x2B763FF130B97E1EULL,
		0xA89C193AE19D7ECDULL,
		0x9C5295126D77782BULL,
		0x53223B00CBD35161ULL,
		0x321FD70E9DFD74F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE933630EACCEE1ULL,
		0xC2302834E2D78E02ULL,
		0xFB2D2B7EBAF1AC4CULL,
		0xE21C80A00CC209FFULL,
		0xF9F4221914BB7775ULL,
		0xE57DDFF2AE31BE7BULL,
		0x18ABA620510C21F6ULL,
		0x9EFD8C4DAA71C928ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x98C1F4CEE9F8DE9FULL,
		0x15D8542B2B5DB460ULL,
		0xB93F9E7E3B3B7AAEULL,
		0xCCED2BDB2B894625ULL,
		0x135D82EBD2936034ULL,
		0xB1C0963EBA7654ECULL,
		0x00AD8366FD284795ULL,
		0x55DC4C8AB19CE1ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C1F4CEE9F8DE9FULL,
		0x15D8542B2B5DB460ULL,
		0xB93F9E7E3B3B7AAEULL,
		0xCCED2BDB2B894625ULL,
		0x135D82EBD2936034ULL,
		0xB1C0963EBA7654ECULL,
		0x00AD8366FD284795ULL,
		0x55DC4C8AB19CE1ACULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDDF2AFC6380FB637ULL,
		0xC8D53EF64ACBDB8EULL,
		0xB983C2E1AED00280ULL,
		0x4A10B515A658E7E2ULL,
		0x2F1A4EB7807AE2B4ULL,
		0x63BB092E688DD903ULL,
		0x70EAE6A831735D84ULL,
		0xA8F8AE819A47FF2EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37485A3D54AA3CF5ULL,
		0x47760EDE4356997BULL,
		0x26F11FEC4125624FULL,
		0xDA5EC9CD27674FDAULL,
		0x7F289E57FB029B30ULL,
		0x81768C989DBB3A90ULL,
		0x3FA15E99685B9795ULL,
		0xEC5AF69CB0E037F7ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8C93683CF7DE11FULL,
		0xD41149A6753FA02FULL,
		0xBB9C6983CD8029AEULL,
		0xEF298DBDFE3BC4BFULL,
		0x59B800758F3A403BULL,
		0x553D2A2A5EE6272AULL,
		0x077D7682761FAEAEULL,
		0x44ED76AC7AAC4F93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDACF9637A83F28B3ULL,
		0x570D3FF95976FF92ULL,
		0x7FE353F8751601CDULL,
		0x1CD7F55864D44448ULL,
		0x60DC1C2CAA176FA9ULL,
		0x8CD9D7D487AE0E6BULL,
		0x0A80568E67616A8EULL,
		0x8ED384B38C813FBFULL
	}};
	t = -1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x90AFF484FB2CC340ULL,
		0x2A21DD6B9EDC66BFULL,
		0x4BD123B910E1EE8EULL,
		0x2E0B8C555FE1EE6FULL,
		0x94441E787873B1D4ULL,
		0xEF52C44618C7E367ULL,
		0x92AD67E7C5FF2C29ULL,
		0x89A917660F507A54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AED61DED4809004ULL,
		0x2EAD8BDF95D9BCBFULL,
		0xD7206BD5EB1C5598ULL,
		0xFFADFF1995C369A6ULL,
		0xAE3E98F05CDADE8BULL,
		0x8DF2DD02F518ACEEULL,
		0xBA3E3C861B245DC6ULL,
		0x7243450529F798E4ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6F58B899009C9E1DULL,
		0xF67854ADFC7D4029ULL,
		0x7828D025771809C9ULL,
		0x853357981213CDE2ULL,
		0x549B75883C51DE61ULL,
		0xF8F68EE1452F7AE8ULL,
		0x0B7AEE427A0CCA23ULL,
		0xD9D367422AC33DB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F58B899009C9E1DULL,
		0xF67854ADFC7D4029ULL,
		0x7828D025771809C9ULL,
		0x853357981213CDE2ULL,
		0x549B75883C51DE61ULL,
		0xF8F68EE1452F7AE8ULL,
		0x0B7AEE427A0CCA23ULL,
		0xD9D367422AC33DB9ULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x57B10D989BD99E56ULL,
		0x118E9141FD069538ULL,
		0x66BB41E9BCF58638ULL,
		0xED4AF4380E059E51ULL,
		0xE194377C982D496CULL,
		0x25DB2834495BDC8BULL,
		0x35A91D2D12D040CAULL,
		0xE3CFA7F2FA6D0560ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBBA79DD11C72400ULL,
		0x62025BFCA8E0772DULL,
		0x2C97B730B688B205ULL,
		0x25475AC7CE9332ACULL,
		0xD544556C824EE4D0ULL,
		0xFD176634CC5A511BULL,
		0xE77C4507C4957B2DULL,
		0x8D5BCB091B0238F4ULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAD9711B7F342F9FFULL,
		0x530E0F55066373FBULL,
		0xA20D54BE700AC78AULL,
		0xB962A17256430F90ULL,
		0xDE654C964A478E08ULL,
		0x0276BB1B10C5797DULL,
		0x4189E8700C99CB26ULL,
		0x6E88B041717C2BF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB39EB260069F12DULL,
		0x3595606F0C450A67ULL,
		0x499DB339FFE603ECULL,
		0x786AA393D53E6B22ULL,
		0xCCE82D48CD420A11ULL,
		0xD654543D16084655ULL,
		0x0EA67C8D02C7FE82ULL,
		0xDC8E45B0C25203CFULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD34BCC4A8B7CCB10ULL,
		0xDFA855CDC5722357ULL,
		0x90EEFA8E1D578502ULL,
		0x68D75C235977CBD0ULL,
		0x4EE4CF1CB9B9672DULL,
		0x463333AE4416BAC1ULL,
		0x4B66372BE746CB59ULL,
		0xDBAA018B0B193048ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31BDC379AA43AC44ULL,
		0xD544F0BA09F7943EULL,
		0x29F9DDCC04CAAB31ULL,
		0xD090AC55FBD429B4ULL,
		0xF3A63D3B8AB7A42FULL,
		0x669DD7215C166DF3ULL,
		0x4136A01F224013C4ULL,
		0xCAEF1E39E3D78726ULL
	}};
	t = 1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x182A99E9110870BDULL,
		0x2F5A1A316479F204ULL,
		0xF5A3825E561B26E0ULL,
		0x0CFCA91958B944FFULL,
		0x2B16B62B3B1B22F0ULL,
		0xC9626F93134ED977ULL,
		0x2A58CAB2DBBED19FULL,
		0xD3F3F5C73B20B8CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x182A99E9110870BDULL,
		0x2F5A1A316479F204ULL,
		0xF5A3825E561B26E0ULL,
		0x0CFCA91958B944FFULL,
		0x2B16B62B3B1B22F0ULL,
		0xC9626F93134ED977ULL,
		0x2A58CAB2DBBED19FULL,
		0xD3F3F5C73B20B8CDULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3BB8B52A0982E670ULL,
		0x882B78880241C7C2ULL,
		0x3A259A8F420611B4ULL,
		0xE8EC4110EC073373ULL,
		0x3473695D5B1A51E3ULL,
		0xFAF9605EE86B1F45ULL,
		0xD09FEBFD9AB68966ULL,
		0x8A88058DB6E07BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EAFD064E7899977ULL,
		0x6D134904396D19DAULL,
		0x6DFD2C6F7C705F4CULL,
		0xC818ACEB2A516173ULL,
		0x9C212846F61A4675ULL,
		0xB1C1E1EEE25833B1ULL,
		0x52DE37055C148948ULL,
		0x5CB698848BA27B41ULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6F6B2AFB58F300B8ULL,
		0xCD113C8C43F834C1ULL,
		0x862242BB3770BB22ULL,
		0xB4424B1FA73D2370ULL,
		0x81AF713705F8B69EULL,
		0x2679C50CBDE7ED96ULL,
		0x5D97A8E0230192E2ULL,
		0xE983687CBF46FCE7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5562703E762E90ULL,
		0x3C509DED6D12D9EEULL,
		0x7115F3E9BE39CB34ULL,
		0x38E8115D6C7707F2ULL,
		0x4D773B21FE0D0427ULL,
		0xD7A3A3E91E8907B6ULL,
		0x250ABC03C2947105ULL,
		0x6FF4241C45DD33A4ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x77DF1A78DA325E1AULL,
		0xB918B207DEA39BC8ULL,
		0x0F71A3FE6D3F9B62ULL,
		0xDCBF6B49E2E0A742ULL,
		0xC727020C88D3692AULL,
		0x4689DA9FCAC02E99ULL,
		0xF16AAABD95448BA5ULL,
		0x45AEA7E840FC1C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF402E03B098D43F7ULL,
		0x70EEFBC9EDE444FFULL,
		0x04C478A2E4DFBFE1ULL,
		0x979B09FBF5F250B3ULL,
		0x4FC4226C9EFF61AFULL,
		0xFC265A87486F7E67ULL,
		0x511174297298CA42ULL,
		0xFEF252CD4832682DULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFA43EC553EE2AF88ULL,
		0x5289A3DB8045683CULL,
		0xBD8D216AE7918B56ULL,
		0x9334674E49A77BACULL,
		0xC51F2F8717DC69FFULL,
		0xE8729D5063709CFFULL,
		0x53E04A9EDF7E91D0ULL,
		0xB01EE49F44EF56B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA43EC553EE2AF88ULL,
		0x5289A3DB8045683CULL,
		0xBD8D216AE7918B56ULL,
		0x9334674E49A77BACULL,
		0xC51F2F8717DC69FFULL,
		0xE8729D5063709CFFULL,
		0x53E04A9EDF7E91D0ULL,
		0xB01EE49F44EF56B5ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBDBCB0817DA084BFULL,
		0x00BFFAC551FE1B10ULL,
		0x021677AE61985FFEULL,
		0xF094FEAD69A82DBAULL,
		0xC795215C37E53EEAULL,
		0xBF5209B85D1EADAFULL,
		0x31D54217A8BB5DC5ULL,
		0xCD2BD3FC6AC02203ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1EEED9FA05D44559ULL,
		0x37506F9E4AC667FAULL,
		0xCFB164B444EBDC39ULL,
		0xE49DD35316360A8CULL,
		0xEC3954DB609D58FAULL,
		0xD1F2A30C3EE85CCEULL,
		0x9F1002EBCC0D8D02ULL,
		0x91003D45FC116F04ULL
	}};
	t = 1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x066282AD01897C27ULL,
		0x70D8E3D3F25DF17AULL,
		0xE8DB85DB1197D2ACULL,
		0x5B65DECA9316D7E4ULL,
		0xA39A7428540C3C96ULL,
		0xF198667BDB678C76ULL,
		0x4EA1D61D856F534DULL,
		0x0347081A015A6C96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBD53BEA687A570ULL,
		0xBD9AC371A67B33BDULL,
		0x05C731B51CD52E2AULL,
		0x8FE7685B49D55673ULL,
		0x29A831D5201647BBULL,
		0xA396B92154CDBDB2ULL,
		0x1D73C2FE20893B5FULL,
		0x435D13BEED524629ULL
	}};
	t = -1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC4E2250BFCF974F2ULL,
		0x06D756B31ACD9F6FULL,
		0x952CD9F19F781C75ULL,
		0xCFA6CE9A17194A57ULL,
		0x2B9BB75E322A3C76ULL,
		0x28209D218D154081ULL,
		0xBC820A773E573FE3ULL,
		0x7340738B2E5B9BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DD6C97DF5EB21C1ULL,
		0x5C28B0BC1A740B03ULL,
		0xF28A2F4E0A31EAABULL,
		0x699EE04E35455BBDULL,
		0x9236FA27543FD41FULL,
		0xA0A44FAC5EA9CF40ULL,
		0xE43069894323F285ULL,
		0xFB25CA102E016194ULL
	}};
	t = -1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4EB1C214C07E4228ULL,
		0x1120073ECE81288EULL,
		0x1D05A1DDC7E5340AULL,
		0xBD80CC9CAAC01B28ULL,
		0xEEDE505741128E24ULL,
		0x0331E23272A26B5EULL,
		0xA3F33498B8D1E903ULL,
		0x7CB98FF06C624449ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EB1C214C07E4228ULL,
		0x1120073ECE81288EULL,
		0x1D05A1DDC7E5340AULL,
		0xBD80CC9CAAC01B28ULL,
		0xEEDE505741128E24ULL,
		0x0331E23272A26B5EULL,
		0xA3F33498B8D1E903ULL,
		0x7CB98FF06C624449ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8013CA42643F0581ULL,
		0xEEF2BD4CD489DC4DULL,
		0x342EDC57ABF9C572ULL,
		0xB0B00C8497CA707BULL,
		0x7D385F0196FBA57EULL,
		0x2DF1261E1C827ABDULL,
		0x9686C9AAF297E9E6ULL,
		0x571E5AB7ACBF51F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F9125BDDE88F32ULL,
		0xE0EB39E90AF212DAULL,
		0x58EB86E9655F9A73ULL,
		0x985BF869B768FFA7ULL,
		0xD176465987383DA3ULL,
		0x207049008A49BC29ULL,
		0x1F17E4EA642AA305ULL,
		0x170370EE00146F23ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9C484562A4DAE4C8ULL,
		0x58F576B8F1AE3607ULL,
		0xF35B892AB2027917ULL,
		0x62D64E369B9A035DULL,
		0x4970225A4E511D21ULL,
		0x2A02D571A1F1B0D6ULL,
		0xC97EA1F998A6FC92ULL,
		0x5AF127ECB514F570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF72E5B69274BBBCULL,
		0x99AA886056884132ULL,
		0xEDACF1F59E8DFDB5ULL,
		0xAAEEF2F1A34349FDULL,
		0x180352BD4008C016ULL,
		0xBF3C481C39C4AFA6ULL,
		0x083753BED2E762C0ULL,
		0xF42308803A2C13C8ULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCC0B4AF1415E317FULL,
		0x414E4DBF09DC4F5AULL,
		0x1AB39C9D1F3D8144ULL,
		0x45E31C5D00F5DD82ULL,
		0x645AB9A47D8ACAA0ULL,
		0x4620D3944BF19FBEULL,
		0x4D96CE009EA827E5ULL,
		0xBEF09CEC4E38987BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8739A77E790A44C8ULL,
		0x7E7D38FC67BFBA5EULL,
		0x20C99E07174FC89CULL,
		0xB72FFCE83ECE5355ULL,
		0x66372AB745535EC4ULL,
		0x6AFFB548C52F9E19ULL,
		0xB64104C5B3BD789EULL,
		0x810D3935EF586B0CULL
	}};
	t = 1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE912AB69276DF22DULL,
		0x2FB3165A652B6F5DULL,
		0xD2D53BC4B522D040ULL,
		0x9116A09368546FD7ULL,
		0x5740B341DC27EBE0ULL,
		0xC180AC51576FD206ULL,
		0xC41CC36CF51DDE12ULL,
		0x2820206F3C5C02B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE912AB69276DF22DULL,
		0x2FB3165A652B6F5DULL,
		0xD2D53BC4B522D040ULL,
		0x9116A09368546FD7ULL,
		0x5740B341DC27EBE0ULL,
		0xC180AC51576FD206ULL,
		0xC41CC36CF51DDE12ULL,
		0x2820206F3C5C02B1ULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC4FE9921C15AB207ULL,
		0xBE4AEB54BEFE8CB2ULL,
		0x202E4627B389E5B6ULL,
		0x261D24FFFA01EA48ULL,
		0x65341913A24292F3ULL,
		0x03E3AF6C9F5DA8E6ULL,
		0x6D7CFDD7BCD97249ULL,
		0x7BD1B5824FE89AEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7F016C5BDE360D5ULL,
		0x1A34B6BBA02DB611ULL,
		0xE4C8B2C93B62013BULL,
		0xFDF57AD8B4ECF29EULL,
		0x95D5A8B310D0CE74ULL,
		0x8F3E08EC876A8C8AULL,
		0xDD8FFB7E8C13D655ULL,
		0xDCB47D470202B206ULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF43A6554BF851B01ULL,
		0x91C841FA190249FDULL,
		0xB93731263E89BD91ULL,
		0xFCE2EF05081D9577ULL,
		0xAE7413CC3516D732ULL,
		0x9F502E4A1F823862ULL,
		0x65A5246BBF82B1CFULL,
		0x9004FF3B17B02086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79BA3B8DF204F841ULL,
		0xDA4B27BB4E08CFE8ULL,
		0x0CDBB7A35B272527ULL,
		0xAC0DB18977E02C65ULL,
		0x20442C9F772DBE9AULL,
		0x880F38385D662370ULL,
		0x18B4574EA5790752ULL,
		0x474AE80D89719E5FULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x48E7E48904478B66ULL,
		0x3F136C5BE75E1034ULL,
		0xBEBC70A079AD32F9ULL,
		0xF215A1690F1006FFULL,
		0x7B746803FE14C281ULL,
		0xF036CDE356C1E418ULL,
		0xD43899B001C0D816ULL,
		0x790AFB54999DDA38ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB9790C0FE83B3C0ULL,
		0x35366064AB4CA3E6ULL,
		0xC81E8DD2F7955331ULL,
		0x1C8B8F74DA8D4935ULL,
		0x8A58BA1B153F8612ULL,
		0x96574B32EBD336C2ULL,
		0xF613E61799531B6BULL,
		0xC766603A04D030A0ULL
	}};
	t = -1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x538A07414CCEBB4BULL,
		0xC136E88E7839536FULL,
		0x35E6A7F7F267A51FULL,
		0x1D024A17BEB4114BULL,
		0x0B522287CF3FC0D0ULL,
		0xBD92D9FFC6E9FAADULL,
		0x12115B02BD6431F7ULL,
		0xF95528225FB22C79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x538A07414CCEBB4BULL,
		0xC136E88E7839536FULL,
		0x35E6A7F7F267A51FULL,
		0x1D024A17BEB4114BULL,
		0x0B522287CF3FC0D0ULL,
		0xBD92D9FFC6E9FAADULL,
		0x12115B02BD6431F7ULL,
		0xF95528225FB22C79ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCBF4C358A691529BULL,
		0xB64A33369F9F2E77ULL,
		0xF767F73102BC9995ULL,
		0x7CCD18457BB3B222ULL,
		0xF236097051FCBCDDULL,
		0xC7964F1DA2DBAECDULL,
		0x5D6848A3D37FDBFCULL,
		0xC2EEE15796DFEEE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2ED757F0B43389FULL,
		0x0AF3905985897879ULL,
		0x6E2BC21A377344E8ULL,
		0x7A280E90F7F19CE3ULL,
		0xC83ABC855742D640ULL,
		0xABE1CBA5FB910FA4ULL,
		0x2B0BD942D9264F34ULL,
		0x7AB6DD8F83A59F42ULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8441E568A0343E03ULL,
		0x98A5E902E9242C8DULL,
		0xFCC0646B0CA0FFF4ULL,
		0x3491320615F14614ULL,
		0x2384A175E589B0EAULL,
		0x0C90D076D4E960CBULL,
		0x1B04E6EEE1053B28ULL,
		0xE84D1F7BA39BD773ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF519DE48422F168ULL,
		0x285CA47673FA6234ULL,
		0xB89722125FD1F35EULL,
		0x74D9041877544974ULL,
		0x6C5E6313D3A8C5CDULL,
		0x28701CC89AFE6E0DULL,
		0x674DDB0FE67864DDULL,
		0xE801981B1F251E87ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB053872F6477470AULL,
		0xE7CD13E2EB68CCD0ULL,
		0x570DFB5579BE0C23ULL,
		0xB814A672D5D37CEBULL,
		0xBA80B5888D6EEFFEULL,
		0x0B2D361DC3E7EAA3ULL,
		0xEB3A3FC829F5A535ULL,
		0x5CA701A8208BA45FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B88981847D637ADULL,
		0x91E87B8DE33A904FULL,
		0x93DD7A64631E4620ULL,
		0x754CE856F0FE733CULL,
		0x9DB7FB538844D40FULL,
		0x4AD3C2C6253AB865ULL,
		0x1397DA49E5A988E8ULL,
		0xBCECEBD112C62589ULL
	}};
	t = -1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9E23CCF945B3DB06ULL,
		0xC7E2C6C6BE26093EULL,
		0xA077FBF77983EADAULL,
		0xDCF9A746BB971ECFULL,
		0x7104248BBE792605ULL,
		0x12D61C9965341ED1ULL,
		0x955E97EA9254323EULL,
		0xA3D208AFDDBCB352ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E23CCF945B3DB06ULL,
		0xC7E2C6C6BE26093EULL,
		0xA077FBF77983EADAULL,
		0xDCF9A746BB971ECFULL,
		0x7104248BBE792605ULL,
		0x12D61C9965341ED1ULL,
		0x955E97EA9254323EULL,
		0xA3D208AFDDBCB352ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x050BAD0DDD9C9214ULL,
		0x753EC8CE74A5EE63ULL,
		0x3B51AD5AC357624EULL,
		0x9EED21F81550E3A3ULL,
		0xF6FD13D565FB057BULL,
		0x102FA01A2CDA8D0DULL,
		0xC47EBF40A8E76F31ULL,
		0x514A203F3C16DC46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED1921F32880C7F2ULL,
		0x6AE9B8854EBE3F71ULL,
		0xB466ACA5F8F093CFULL,
		0xFFC32FEE0DAB0084ULL,
		0x8D5D3F347291559FULL,
		0x1D58B4DF14E88830ULL,
		0x5BA7D3924A937DE1ULL,
		0x02DB5F7CA9539C61ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x86AF01349AB85B16ULL,
		0xEE88BA41E8F14396ULL,
		0x188EB8771F666FBFULL,
		0x3890D664A6ABE90FULL,
		0x40519025CD88E553ULL,
		0xC6E95127E1EB9B9FULL,
		0xCFDC92BFF3D6B582ULL,
		0xA33EE162A7EE9FA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF1D4DA33A1B718ULL,
		0x723AACF1A8BCB159ULL,
		0x4AFD7DBEECD094C9ULL,
		0x9523AB933B2D0118ULL,
		0x116088D35C2C607CULL,
		0xA11D142909E802F2ULL,
		0x734DEE77C6B32EDBULL,
		0xC2271D35ED480E74ULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF6DE8729BEFCF671ULL,
		0x1894CCCDC8DD6CADULL,
		0x98565CFC041FD444ULL,
		0xDC10E1D423275987ULL,
		0x71F96A9329B403BFULL,
		0xA4C733C87399E09EULL,
		0x75C545E7E6261867ULL,
		0x528672EA720294E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC011CFFF36AB1A72ULL,
		0xF417AAB40D866F44ULL,
		0x201A9EE3C5BFFFB4ULL,
		0x31E8EBF6D7EB1977ULL,
		0xCD18E0BFADBB8C4CULL,
		0x456661A69058C3E3ULL,
		0x51D5B87CA631F7D0ULL,
		0x002E97F41671A907ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFD645F3038ED67B5ULL,
		0x2034A0C701731445ULL,
		0xFDF6DCC7F1B9E3B6ULL,
		0xD1D58008CC2E35E3ULL,
		0x0EE4C7D2DBC56B7DULL,
		0x60EF389ECC9FFC42ULL,
		0x059720BC1A8A3798ULL,
		0x67429EF23926E786ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD645F3038ED67B5ULL,
		0x2034A0C701731445ULL,
		0xFDF6DCC7F1B9E3B6ULL,
		0xD1D58008CC2E35E3ULL,
		0x0EE4C7D2DBC56B7DULL,
		0x60EF389ECC9FFC42ULL,
		0x059720BC1A8A3798ULL,
		0x67429EF23926E786ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0006F5CF52494D3BULL,
		0x1F3442CB5AD92178ULL,
		0x42AD61AFDA8D0D77ULL,
		0xF4DB74C48243D2C8ULL,
		0xD807D49A557479E5ULL,
		0x0FBD7527DC5BCAC5ULL,
		0xFCF9C2CF3DC208FAULL,
		0xF0CAB039A30B9652ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27A649CAEC80F7D5ULL,
		0xC6791ADAA3322B16ULL,
		0xFD46850229BF2EE9ULL,
		0x37676DB0391FB5A6ULL,
		0x972CA5FDE5B12ABCULL,
		0x645581F0DE1226E4ULL,
		0x776E8640AF1BFC58ULL,
		0x912A7E6864399B7FULL
	}};
	t = 1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE1555183A708F0BFULL,
		0x6FD561E46F23EA18ULL,
		0x744C9DD3F1093E1BULL,
		0x8C527B07284B381BULL,
		0xF5BFA0F041217B88ULL,
		0x82A8DDB8A8D14EE8ULL,
		0xE95E76BA82F931C7ULL,
		0x5735BB2AD29BF984ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB86DEEC1DF9F1438ULL,
		0xE2084BCFC28A1969ULL,
		0x731F82878858FA31ULL,
		0x5529BB9A40D54DBBULL,
		0xA9CA70DA7E86F3EEULL,
		0xFE3599617AFB1D26ULL,
		0x5B61B32D9FBC49F3ULL,
		0x9BBA15F1EBA27CBEULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x021C97B9B2C69F19ULL,
		0x532FF90B163A2A76ULL,
		0x2D7037371E7D1E8BULL,
		0x70F457F9E7FB2EC8ULL,
		0x85496DF250474DE1ULL,
		0x6AD926426637EC89ULL,
		0xCEDE05A98F930CB5ULL,
		0xF7E3ED0541A76B9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AD031A23C5CDC0AULL,
		0x7FB3C676ADDB53CDULL,
		0x05E196AE92D5455DULL,
		0xD37A56F019785D2BULL,
		0x1D20A496E443C00FULL,
		0xEDF0F16C4AD55D67ULL,
		0xCEB1B7AC3058E64BULL,
		0xBFA62D9928F4E8B4ULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA23976BA2B1BB573ULL,
		0x79E09025AAA761BCULL,
		0x0E74908E89B30577ULL,
		0xF91D63D4D31E7BE5ULL,
		0x55C2B859AB246FDBULL,
		0x4AA514BA1E71D9B3ULL,
		0xBBD7DE195BFC5C59ULL,
		0x30452F7036D610CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA23976BA2B1BB573ULL,
		0x79E09025AAA761BCULL,
		0x0E74908E89B30577ULL,
		0xF91D63D4D31E7BE5ULL,
		0x55C2B859AB246FDBULL,
		0x4AA514BA1E71D9B3ULL,
		0xBBD7DE195BFC5C59ULL,
		0x30452F7036D610CDULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCE7C41502BCA74FBULL,
		0x632138AB20D5569FULL,
		0xFE60124CDA811FDFULL,
		0xD2E96BAAD4DDB362ULL,
		0xA7C92ACA853B7251ULL,
		0xB766872F352A65CDULL,
		0x652511F60FA4CEC6ULL,
		0xA5E36E39B0B1BFA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x682565287D7B4667ULL,
		0x0E5DD76CECE296DEULL,
		0x5A9DD3CCD3C17428ULL,
		0x0AD727526A3E5438ULL,
		0x95181B094E93B06FULL,
		0x2D36C8EE952B4D60ULL,
		0xC5457083520EB85BULL,
		0x4124FDA7C2FE1530ULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3ABFE08840069710ULL,
		0x1D5AE35A3A8FA1D3ULL,
		0x32FD8BF3414FEA02ULL,
		0xB22694C04019A64BULL,
		0x261788A913E2D90FULL,
		0x8A4BBC3CE6FA8847ULL,
		0x46DD93AE9216B671ULL,
		0xC09E9C141FF13288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE97028AB4CA17ECEULL,
		0x2B75DE80371DE933ULL,
		0x3EA3C092CAFE2C1CULL,
		0x2D2D0AB8DFE29AD2ULL,
		0xCF79897298E3CC04ULL,
		0x5729564601CD83F1ULL,
		0x32DC26B15378D0D5ULL,
		0x1E5ED40E14A5AD37ULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5A22278BBEC2B9A8ULL,
		0xD5E505BA4A486E1CULL,
		0xB4A98B52665D9C47ULL,
		0xB9B86E0E2772076BULL,
		0xE64610547CBFF349ULL,
		0x731F2A7E55F03079ULL,
		0xAB02E6B4CAD3C008ULL,
		0x51F9D63C72E4C2AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5796692321E8B6C5ULL,
		0x3B35F0B53BD53CCEULL,
		0xC40F3C333F341826ULL,
		0x68303BA39FEF853DULL,
		0xD0DEDC081F2FCDC1ULL,
		0xC5BD46A17A9DC529ULL,
		0x48A1D76DC4C9389BULL,
		0xC7EC55F37312BCF4ULL
	}};
	t = -1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x42C59EE7C3619CA6ULL,
		0x36ECA5ADF126E3A1ULL,
		0x6FAD171C58BDAD53ULL,
		0x93F3B0C248E62688ULL,
		0xBE10EAF40191AF98ULL,
		0x290D1FA5A7962E0FULL,
		0xB24FC8727F92CC96ULL,
		0x475928DE68DA0AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42C59EE7C3619CA6ULL,
		0x36ECA5ADF126E3A1ULL,
		0x6FAD171C58BDAD53ULL,
		0x93F3B0C248E62688ULL,
		0xBE10EAF40191AF98ULL,
		0x290D1FA5A7962E0FULL,
		0xB24FC8727F92CC96ULL,
		0x475928DE68DA0AE8ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x09DE9EC2A017150BULL,
		0x555B931AD35D3B6EULL,
		0x474EC691B97F5EB4ULL,
		0xF45B4A6F9C8163EAULL,
		0x9E581737AC6AC9F0ULL,
		0xCD1B0327E31F1D85ULL,
		0x8D9EEA314ADF4C66ULL,
		0x329C6AE7093F17A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x843A53FBF30A9DCBULL,
		0xF2303FC3E4F9C51DULL,
		0x6FA8A599CD2C04E4ULL,
		0xC83CBAD3DFD401E6ULL,
		0xB4EE0FF40EA460C8ULL,
		0x25B483F5C6612B4EULL,
		0x52635D35CBCD6313ULL,
		0x5521FC7D7BDE4C4FULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2C43EEBA175CEA13ULL,
		0xD53BB3D8C507E28AULL,
		0xBE7888A1706B8167ULL,
		0x7A40772510730419ULL,
		0x91D80114752B12E6ULL,
		0x1CF8C8C8B125C650ULL,
		0x436ACE560ECCCA2BULL,
		0x6BD81815BBA33B33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E2327EB129CD0CULL,
		0x9CFC46EB43973417ULL,
		0x3190CFCBA0C55560ULL,
		0xAD7BA07DFBAA5086ULL,
		0x8F10E865AC3EB236ULL,
		0x2DD887DA713FAA5FULL,
		0x157481602963D259ULL,
		0x7E2CFEAF6D80E67BULL
	}};
	t = -1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF1FA22649E5C8E8CULL,
		0x527075DEDEBF6B0BULL,
		0xC4269722083F488FULL,
		0x37B6E30290A08EC9ULL,
		0x104A83BF8DD6E1F5ULL,
		0xCAE22F9901336E3DULL,
		0xCEFA5181543B1C8BULL,
		0x47C69668BD22186EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53773244EC8260D6ULL,
		0x4EBA2F5A8C9AEDA0ULL,
		0xDADDC78B7B726522ULL,
		0x276B90A0564DBB75ULL,
		0x974DE8DBA6490560ULL,
		0xFA5688A3E117EF33ULL,
		0x03529C63D1436E15ULL,
		0xEE3D391577BDA018ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8BC051B28759CDB2ULL,
		0x27D4859847E2A5A2ULL,
		0xC5E87B7BF68B4ABEULL,
		0x49F2FB3CB5E1F2F1ULL,
		0xE0AF8961152B879FULL,
		0x7159F585AEB20D37ULL,
		0x8C3C0E0743925D17ULL,
		0x3BE3DB8EF2C0EEE5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BC051B28759CDB2ULL,
		0x27D4859847E2A5A2ULL,
		0xC5E87B7BF68B4ABEULL,
		0x49F2FB3CB5E1F2F1ULL,
		0xE0AF8961152B879FULL,
		0x7159F585AEB20D37ULL,
		0x8C3C0E0743925D17ULL,
		0x3BE3DB8EF2C0EEE5ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF27CD15D1A874FD8ULL,
		0xBE2841013243E405ULL,
		0x7A0A04BD6E2C7D64ULL,
		0x5C62E881A30AC043ULL,
		0xDFD9491BBAB53B2DULL,
		0x08FE9E3680F31D9BULL,
		0x64F5EA98AD85F6C4ULL,
		0x8445B96280E09787ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEC5E9EE3356A5B9ULL,
		0x0AFE24373FA62C8FULL,
		0xA86AE21345C98FA1ULL,
		0x8E2099EF66E8CFBFULL,
		0xF735B3165176EAADULL,
		0x7CEED9BA1719391CULL,
		0x8508CD0322053EB3ULL,
		0xCDD9874D69904615ULL
	}};
	t = -1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x472D63792FCF29A4ULL,
		0x8A6A6E5720DD6197ULL,
		0x9E4DAC4482BEBA77ULL,
		0x8B7F63155DC2E2A4ULL,
		0xC27CE3B8CE15A8FFULL,
		0x9C5E4059A5B55767ULL,
		0xCBBE1F84C9EDCFD0ULL,
		0x82B08D92B2F43A80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4B75DF6B1428C30ULL,
		0x15B6A3F4009EA664ULL,
		0x67C3CAC4B45F831AULL,
		0xAD1053BDEF40BC53ULL,
		0xF3E2679383FAFD13ULL,
		0xBAFF6311004C5B1EULL,
		0xA86F1AEB838A8BDEULL,
		0xCB39E902F84EC2DDULL
	}};
	t = -1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA39A099FB73B9176ULL,
		0x2BD33C48B6673BAAULL,
		0xA346DEA0707915DAULL,
		0x1D2D77F2DF7A9E78ULL,
		0x75071FF9FE2874F3ULL,
		0x698D842ED6990CFFULL,
		0x9C5D856827B65E04ULL,
		0x090C48ADA67E4E71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x092F7F770ECBC7A7ULL,
		0x95712F847A4855C1ULL,
		0x4321E303EA1D9283ULL,
		0xA968D10BDA13BCD1ULL,
		0x1E4C6FCC6637F7DAULL,
		0x4C71C3A216A30FBBULL,
		0x3C529C13467A9D3AULL,
		0x3926F5C75C006A9DULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4115AC8E4DE03DC9ULL,
		0x78CAC7FF299346A4ULL,
		0x009347F5B4C3EF82ULL,
		0x94DD6893E616892BULL,
		0x9A457F5F059430A3ULL,
		0x80D8749A7700B61DULL,
		0x9D1DF1B9B5B9A807ULL,
		0x30C34FB99E808E4EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4115AC8E4DE03DC9ULL,
		0x78CAC7FF299346A4ULL,
		0x009347F5B4C3EF82ULL,
		0x94DD6893E616892BULL,
		0x9A457F5F059430A3ULL,
		0x80D8749A7700B61DULL,
		0x9D1DF1B9B5B9A807ULL,
		0x30C34FB99E808E4EULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0976730A4B570E2BULL,
		0xCE6AD6673B201B22ULL,
		0x00B4FED852E5DCCDULL,
		0xFD656A798588FF32ULL,
		0xEC6D3D1BD813F283ULL,
		0x21E9C134A3738DA4ULL,
		0x3F39138DBA7040CAULL,
		0x6FBE80AB1FE8C220ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D26178EDCD87C35ULL,
		0x7841D2E5E4D423E7ULL,
		0xD05BF9F6269DA102ULL,
		0xE8BAD56E6511D1F9ULL,
		0x154936C5058C2E94ULL,
		0x93BD51E42DADE00FULL,
		0x8ABA0F58E441275CULL,
		0xC3A54910234B7CA1ULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6B2E22A26262F3FFULL,
		0x883381A978534F86ULL,
		0x41D04AB004111D97ULL,
		0xA9FBF3CCBCB0488AULL,
		0xD764BF7C48DCF299ULL,
		0xC55001AFDAEC8AAAULL,
		0xF341D4FB32ED5B44ULL,
		0x8C91E28FD246D26EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0B5458F80DDEF8EULL,
		0x2DF21FA2048EDBCEULL,
		0x23D03F55CEEE3016ULL,
		0x51D61FE21621B35DULL,
		0xC528A8D90F8785A2ULL,
		0xD93CA683FAAE36EDULL,
		0x68234403C35FA15DULL,
		0xCB3D422FF9425ECAULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAFF589587B93F427ULL,
		0x75648A40E7BABCECULL,
		0x05C51CFE79448FEBULL,
		0x19F64E2D29481E97ULL,
		0x16C18D4BE46474FCULL,
		0x98A5007337B59D62ULL,
		0x8082D230671EE99DULL,
		0xAC80C66D9CBF9191ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED3FF0EA58367745ULL,
		0xC079EF4AE20E94ADULL,
		0x5F12004511B9C218ULL,
		0xED8616B9B89FB855ULL,
		0x7B03780C4E389F40ULL,
		0x36205F7A6000A532ULL,
		0xDD02A3818507EA5CULL,
		0x5A185B7B37FA454DULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x48FD4FE77CA032A3ULL,
		0x6C2F5A8D7E86E4D1ULL,
		0x81AC3B68968A067FULL,
		0x4CCA42F435EA26C2ULL,
		0x3F1373E80ABD3F2BULL,
		0x2E67962C7741F99AULL,
		0xD90AF1D0785F3274ULL,
		0xE7C5A1B0ECE64E34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48FD4FE77CA032A3ULL,
		0x6C2F5A8D7E86E4D1ULL,
		0x81AC3B68968A067FULL,
		0x4CCA42F435EA26C2ULL,
		0x3F1373E80ABD3F2BULL,
		0x2E67962C7741F99AULL,
		0xD90AF1D0785F3274ULL,
		0xE7C5A1B0ECE64E34ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBD6AD30F7F8C2E3AULL,
		0x1E7E43429DEE57E2ULL,
		0x344F344A17E7CBEBULL,
		0x72CDAECAD359F06FULL,
		0x1A43A3F496B6E3E1ULL,
		0x44CAD14E755689ADULL,
		0x63024EFBDE05EDABULL,
		0xE246D4C4FD8EA8F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F764841B3E415B0ULL,
		0x7A4DDED6C3C3D1CFULL,
		0xC92B2D4D858121DBULL,
		0xF1ED579628C67128ULL,
		0xE8053AEC104C8961ULL,
		0x3B9A27F729AD9DD2ULL,
		0x266C29CE5AFE72E2ULL,
		0x5CA87839FDB16938ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x157668FFEC1DDF1AULL,
		0x8EEB0F9831AB4A09ULL,
		0x1BF90AC3AC200018ULL,
		0x1AD94895D451E0C0ULL,
		0x87BB6D84DF961189ULL,
		0x967E89A14EB15C2AULL,
		0xB99D2195462549C2ULL,
		0x524D72AE711A2B0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDD0AE57D3EBB2FULL,
		0x37FA0061C619FD88ULL,
		0x87EF79FA715292D4ULL,
		0xC20F9D36EBBFB19CULL,
		0xD2B1057B6E38B35CULL,
		0x86682C25E3A4B58BULL,
		0xAA1015E5997185C5ULL,
		0xBE79AFF41682F569ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9613E884FFE025BDULL,
		0x73BAB90362316B4FULL,
		0xEAEE65560081B00EULL,
		0x417C5199777ECE9BULL,
		0x3D078E58C50C5F49ULL,
		0x4A227C0877E3CC16ULL,
		0xDA46E0B345C1243DULL,
		0x89132A2609E82B74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2AC4F5E35947508ULL,
		0x2C506748E5466B71ULL,
		0x01EA4721BCA1E0E9ULL,
		0x5C1525ECEA7333A0ULL,
		0xD67582C050886D18ULL,
		0x83E24CDB7C54DB57ULL,
		0x1908B34DA2DD84FDULL,
		0x632CDA71D9155307ULL
	}};
	t = 1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x607F8F59B6E9CC17ULL,
		0x91CF860F66E1FF44ULL,
		0x978FC95B2BB6A889ULL,
		0xED5A8AF5362B2AF7ULL,
		0x8EE00BCFCA2CE7BEULL,
		0xF1351CEDC94160A2ULL,
		0xF832A96408236D49ULL,
		0x80ED2BE2A9CC8C98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x607F8F59B6E9CC17ULL,
		0x91CF860F66E1FF44ULL,
		0x978FC95B2BB6A889ULL,
		0xED5A8AF5362B2AF7ULL,
		0x8EE00BCFCA2CE7BEULL,
		0xF1351CEDC94160A2ULL,
		0xF832A96408236D49ULL,
		0x80ED2BE2A9CC8C98ULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x487E9C5606AAFB8CULL,
		0xD0A64B222648539FULL,
		0xF52C930B84975670ULL,
		0x129099125426A8D6ULL,
		0x94682B600F0F77E0ULL,
		0xB045AED31CB8F78DULL,
		0x6FED21A4CEA26D64ULL,
		0xCFCD968D86811E2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3308CC2B2F51A45ULL,
		0xD84BE58AB7124A20ULL,
		0xDB2CD309A9750410ULL,
		0xFCC00FA67353646EULL,
		0xBA4F49B3967A9BA9ULL,
		0x23862F91E8BF0226ULL,
		0xF9C424C436727143ULL,
		0x82647E60B385C6F4ULL
	}};
	t = 1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDF5E4D7E2C6994E3ULL,
		0x980ECB5156A2BA26ULL,
		0x36A196BFFAC5E240ULL,
		0x3D8266C4589E5D07ULL,
		0x0AFEB73BD2F5082DULL,
		0xCAB03D8CEBDC6728ULL,
		0x081F964E51EC8803ULL,
		0x13446ECE5B89C87DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F675BE939DC516FULL,
		0x420CC7237B8DAE46ULL,
		0xB0588AA370471888ULL,
		0x0182FCECC0B5D749ULL,
		0xEE76DE2D8C9A7105ULL,
		0xB0D474A508A5B8EDULL,
		0x27822B50C9AAFAD5ULL,
		0xD9BCAFEDAE335D96ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB44CD07DB422B62AULL,
		0xD3744294AE2B5002ULL,
		0xF68D6CD319FB65B6ULL,
		0x96B1E5FF47249A4BULL,
		0x98FA238C2F6481E7ULL,
		0x7156900BB25A4FD8ULL,
		0xAA0EC559DF08071AULL,
		0xE2D3B9D60D45A581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x129E488A47E53C56ULL,
		0xDEAE5F165B5B3A9CULL,
		0xFAF15F1E16587A10ULL,
		0x357BF328A7D3392FULL,
		0x8102F6AD8E01E8D5ULL,
		0x2A0325D77E2FE149ULL,
		0x246739C79E67A811ULL,
		0xC988D5BEBA6232DCULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF70E61C9E7622CF9ULL,
		0xC33C7C7AE9D5D14FULL,
		0xBE7C890C6FBEBA1BULL,
		0x027449D325EC0EC2ULL,
		0xBE89969AF6B8E7F0ULL,
		0xEB9D0CBDEF6F250FULL,
		0x2D54BAD26CA2FFA7ULL,
		0xF654BC4535C40740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF70E61C9E7622CF9ULL,
		0xC33C7C7AE9D5D14FULL,
		0xBE7C890C6FBEBA1BULL,
		0x027449D325EC0EC2ULL,
		0xBE89969AF6B8E7F0ULL,
		0xEB9D0CBDEF6F250FULL,
		0x2D54BAD26CA2FFA7ULL,
		0xF654BC4535C40740ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFE306A4064C41D5EULL,
		0xB0EA9A30B67EE7A2ULL,
		0x0315796F27DC07ACULL,
		0xE6E58E1077EA40B6ULL,
		0x4081A856B9F8F7ADULL,
		0x0158F6CA1B1529AAULL,
		0x27FA43241839A7F2ULL,
		0x41179BA501C13594ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD41A13E947CB0B8ULL,
		0x4323D21F129A5119ULL,
		0xDEB15AE0FB9C0CAAULL,
		0xFF745F8B77E569FCULL,
		0xA803703F81D4E70CULL,
		0x26CF74E40DA361EFULL,
		0x079152AB1D10AD9CULL,
		0x739C1E5DC173F11BULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5C229C71879074E6ULL,
		0xF11B39A24522D4C8ULL,
		0xF5E8B5C62D82EE77ULL,
		0xF720AD3A2E62D66DULL,
		0x40451C5DB0EB8B0EULL,
		0xE8804D23AD14D09CULL,
		0xFD45F4F26780F7A7ULL,
		0x4D06C308080D5511ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6014B659B475F0B2ULL,
		0xF721C0E5FEE482B3ULL,
		0x4083DA7930D0C55DULL,
		0x2BCA8473CEC7E413ULL,
		0xFB6CBC9F56D18D30ULL,
		0xF3A9551B32618DE8ULL,
		0xCA04A4D03ACDA531ULL,
		0xFF73C3EDBC1291E2ULL
	}};
	t = -1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5C9B34A70488F668ULL,
		0x9648110951CEF5B3ULL,
		0xF979E14AC6903857ULL,
		0x11FD27D1B59683A2ULL,
		0x617B74D8707E1529ULL,
		0x77CD41B0EC7A16B1ULL,
		0x50FA65ECB62AA3DFULL,
		0xCE6C241A42EC7D22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74832DD3AF7ADDDEULL,
		0xCDA84B270315D216ULL,
		0xF9DDF4460A1848E5ULL,
		0xFA2B753089758C5DULL,
		0x226FEFA14DCE63A0ULL,
		0x9417EA4D28F3BED6ULL,
		0xA712D4709C2F7997ULL,
		0xCEB4B3DEB5790A0FULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x043FCF899E06CEF6ULL,
		0x019A1C29603C5FBDULL,
		0x139AC24B6EEA836BULL,
		0x39881FA68AECCAAFULL,
		0xDAC9991B26F34A48ULL,
		0x5E34DB6113928F7FULL,
		0x7915E51A8FB32117ULL,
		0x9C7A5677C54D3393ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x043FCF899E06CEF6ULL,
		0x019A1C29603C5FBDULL,
		0x139AC24B6EEA836BULL,
		0x39881FA68AECCAAFULL,
		0xDAC9991B26F34A48ULL,
		0x5E34DB6113928F7FULL,
		0x7915E51A8FB32117ULL,
		0x9C7A5677C54D3393ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0B9FA0C12D5E1C44ULL,
		0xC1C374200DA36ED5ULL,
		0xE5F7DCB1F356D771ULL,
		0x7A6754599E6DAE3AULL,
		0x016CE196ECE2A6CBULL,
		0x8CBB8827EEF2E451ULL,
		0x441A5EA19B50D530ULL,
		0xD7D60D667120E5B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x895AF5505872C2C5ULL,
		0x63153EB14CC24E09ULL,
		0xE1E98735BC0EC318ULL,
		0x42B45040795B1993ULL,
		0xB3AAA142F6079B67ULL,
		0x533EF0F953E35F1AULL,
		0xC7CAAD682E738059ULL,
		0xBD3C7A89A77CBF19ULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x171BC574BD25A154ULL,
		0xCB218AE5CDE3FDF6ULL,
		0x075CAC17DF8FBB5EULL,
		0x26955DDB795D9D6BULL,
		0x189614281D29D606ULL,
		0x7A91594D00BADA63ULL,
		0xA121D1A80971A396ULL,
		0x5C03D5847CC90F8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85AA206366C04FDFULL,
		0x2E750699BC8F181FULL,
		0x27AACDBA84912A71ULL,
		0x974A03A89C04FBA0ULL,
		0x6E81E397EA512323ULL,
		0x3562B5B9488E1233ULL,
		0x59F9A2CB1D593D44ULL,
		0x99A76EABA7EE1A5BULL
	}};
	t = -1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD49FAD4367F00FF5ULL,
		0xA3BD3D9D33998F1FULL,
		0x466A283A3F37C411ULL,
		0xCFB043A0816798D6ULL,
		0xF672CA5EFC50587AULL,
		0xCB428F2A924D85A0ULL,
		0x5B0D2C47EC2D79CDULL,
		0x1C821AB8A4DBC604ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8976460AF7CFA286ULL,
		0x4DC6F0B076EA7613ULL,
		0x9F3C3660858A7BFEULL,
		0x8FA563474BE06AF7ULL,
		0xDEE765BEE09EC11BULL,
		0xA09757006262C64DULL,
		0x42D6F06E8710F75FULL,
		0xC77CCE480F7BEA7DULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9FB6B53506840610ULL,
		0xB53141D1EF284ADDULL,
		0x71F7E7A345932879ULL,
		0x534CC51D2616FC8BULL,
		0x296F25ABC1180B43ULL,
		0x5FB3F23E01FBD50FULL,
		0x3F1B7B2CBAC5CA6FULL,
		0xEEA9017A032CB477ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FB6B53506840610ULL,
		0xB53141D1EF284ADDULL,
		0x71F7E7A345932879ULL,
		0x534CC51D2616FC8BULL,
		0x296F25ABC1180B43ULL,
		0x5FB3F23E01FBD50FULL,
		0x3F1B7B2CBAC5CA6FULL,
		0xEEA9017A032CB477ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x41F03D9B9EEB6F56ULL,
		0x364250C912ABFD2AULL,
		0x0D2AFA9DF312FC04ULL,
		0xA7BC538A486BE517ULL,
		0x3218A888AFBEAA11ULL,
		0x9CC01E227C2980F4ULL,
		0x387D733F76EF7A8CULL,
		0x4FCD248E90FB66C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4C0AA6B8B40CD07ULL,
		0xD98CB40C339E443CULL,
		0x70422E0065487E25ULL,
		0x8CFFB381AC85831CULL,
		0x03107867293A8C05ULL,
		0x494DA9A1B4917251ULL,
		0xB50017C6B231A754ULL,
		0xC9BD327192B1E548ULL
	}};
	t = -1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4B590D4FF83C740FULL,
		0x3DC165E5207FCBC1ULL,
		0x8EDB0C5C9FCC82ABULL,
		0xF63412D6D84C4283ULL,
		0xF89D500A163C07DBULL,
		0x7509BC311BE58978ULL,
		0x0B373BAF03A0E3ABULL,
		0x70A6A2942BEC0381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D14B6CF296402CULL,
		0xB184FE3C00E23875ULL,
		0xA50F35FB5502EAB4ULL,
		0x061934574BC55A94ULL,
		0x80EE47BC3AF31C30ULL,
		0x28B516537435D11AULL,
		0x44E68645BE9AB594ULL,
		0x04A43F11F674F533ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x730AB14D4F81978FULL,
		0xF3BCE954C1B70AB4ULL,
		0xE7004F9F386F7894ULL,
		0x2A502333430F7687ULL,
		0x701480FE481DB0A1ULL,
		0x50BFB284BD644C96ULL,
		0x576900DCA89ADA54ULL,
		0x3D2DCD42040374A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x784F62AA8996C1A9ULL,
		0x0761C069B7CB9281ULL,
		0x0EC0DDB8BCBA4AFCULL,
		0x629145D9A5351332ULL,
		0x4B3686F168A1DB7CULL,
		0x159E2BF370AB6860ULL,
		0x289D419D4EDA5FF2ULL,
		0xF71EBC7028E3360CULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1FF41745639FC963ULL,
		0x9177130D7AC3C444ULL,
		0xC8E554559E74CD3EULL,
		0xAFE4B5C4CA47F199ULL,
		0x096C73E260FEF98BULL,
		0xF6E8AB8091F3CCE6ULL,
		0x6066A8F9AB7875E2ULL,
		0x3E043DE9DE25459CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF41745639FC963ULL,
		0x9177130D7AC3C444ULL,
		0xC8E554559E74CD3EULL,
		0xAFE4B5C4CA47F199ULL,
		0x096C73E260FEF98BULL,
		0xF6E8AB8091F3CCE6ULL,
		0x6066A8F9AB7875E2ULL,
		0x3E043DE9DE25459CULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6F78104705410A4DULL,
		0xEE8939228F33A768ULL,
		0x8E9961AD96550B64ULL,
		0x2DC79DF502E45422ULL,
		0xD98F32C3E9770EABULL,
		0x30DBDA1456CE3105ULL,
		0x26776DFA1EB530CAULL,
		0xD9C595BCAD8B3FC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC64B6F922FEF7903ULL,
		0xE141EAFE82B47CB8ULL,
		0xAEA2837EA4DE5629ULL,
		0xA9DB2B15DCC460ADULL,
		0x5E370D6F423ABF22ULL,
		0x520191D2C39A4D03ULL,
		0xAB4494EDC8313142ULL,
		0x626668BB9249022DULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAC0E2A6D04513728ULL,
		0xE05C9C17E2BD3362ULL,
		0x6CB821AE2D75CA30ULL,
		0x99758D6846AA4A0BULL,
		0x24487AE51B57F25EULL,
		0x65733EF76AE321EBULL,
		0x9E9CEEB0C660A1AAULL,
		0x3659A67BB3819CE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B30AFF5B295F87ULL,
		0x7EEE515914DE1319ULL,
		0x1A7380DE83B2320DULL,
		0xC6C989E2D6198724ULL,
		0xC9D8DB0EDD9C574DULL,
		0xB56F3F81231E5F29ULL,
		0x98D5ADE7C8A3D6F7ULL,
		0x08D1D1D9954B138FULL
	}};
	t = 1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x02D71D4FF0B5B24CULL,
		0x69D6D2F7D743E969ULL,
		0x331C792F0596CA59ULL,
		0x7A4819A2D0437C92ULL,
		0x39FD05067C3CDF42ULL,
		0x89C7955058546FFCULL,
		0x6C7A4DC01B986043ULL,
		0xF0101E52B9C6008BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3701C10FF4B342A6ULL,
		0x15D8FC017879AFE0ULL,
		0x61AE5C2B06867D69ULL,
		0xB53093AC6B9B9C05ULL,
		0x9BD0A82AEA0D0373ULL,
		0x4C6A9624BADB14B6ULL,
		0xCF635B7691B6D436ULL,
		0x2637818C48904452ULL
	}};
	t = 1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7D4B84ABBD6FF056ULL,
		0xC611C5F0585C7E2FULL,
		0x12DD920AC2EB3988ULL,
		0x0390200B639BB9D2ULL,
		0xAC81F38CA03801A3ULL,
		0x40C0881DD985573EULL,
		0x4DEAB2C9992E234EULL,
		0xE97F16FB6651F810ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4B84ABBD6FF056ULL,
		0xC611C5F0585C7E2FULL,
		0x12DD920AC2EB3988ULL,
		0x0390200B639BB9D2ULL,
		0xAC81F38CA03801A3ULL,
		0x40C0881DD985573EULL,
		0x4DEAB2C9992E234EULL,
		0xE97F16FB6651F810ULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x11065A1E2864B851ULL,
		0x470228EF52149957ULL,
		0xBDA7A923FF18F777ULL,
		0x77991F2CCFD464ABULL,
		0x2181C0B480F3210FULL,
		0x59F23F87027B607DULL,
		0x5C0048CB42587EA1ULL,
		0xF9924E9B2F05998EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C6E30263B2202BEULL,
		0x91E2AAC9F6C0746DULL,
		0x22A0883CEDFEFCACULL,
		0x8ED9B34384E6AEB6ULL,
		0xC154031F89E90500ULL,
		0x8B2B627ABEDC80BFULL,
		0x6531EA9D76CE5519ULL,
		0x456AE0E4D0C7EDC9ULL
	}};
	t = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x90B33D9085CB0416ULL,
		0x8F99F4CCBC35C7ACULL,
		0xD2DCA4DC9FB40131ULL,
		0x1675A78A7DFE9582ULL,
		0x914EAE7529BF62E8ULL,
		0xD0802A509C8BD384ULL,
		0x37A9D1A885F65597ULL,
		0xEDF61B574C3399E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BBCB68F2E3C39BEULL,
		0x32CB2E9A1297CDC8ULL,
		0x240B9330BE1DA786ULL,
		0xBA6703D428CACA23ULL,
		0xE156B7446041A841ULL,
		0x6E8623D0C5D53FA7ULL,
		0xF515AE67FBF7A9ACULL,
		0xC243A3C3E4805ACCULL
	}};
	t = 1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD38C8E72705958FAULL,
		0x540A6AF2E96157B8ULL,
		0x97890965B53F032FULL,
		0x173C5A4208F4B33BULL,
		0x2492DBF68E679087ULL,
		0x4844E70F3CE5F934ULL,
		0x4969C4224CE4009BULL,
		0xF8BA3E7681DE159BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C43581C44DCED69ULL,
		0xA36F7C8565C948E4ULL,
		0x03F151CD13A0E8FDULL,
		0x85FEC525BD5DC638ULL,
		0x4A7AFE3E30A0DE46ULL,
		0xF8EBE289CA13FD0AULL,
		0x6DE414D64A678722ULL,
		0x285137F8A9671818ULL
	}};
	t = 1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCF84BA5608D1E8FCULL,
		0x9FC8B3AE22C725B0ULL,
		0x95DA06C52AAB80FFULL,
		0xC77C76E800AC9458ULL,
		0x3615B46EB71A91E2ULL,
		0x03A4D7F2B67272B1ULL,
		0xE743A7C7AFB3F5AAULL,
		0x1BD9D3E2C8100AA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF84BA5608D1E8FCULL,
		0x9FC8B3AE22C725B0ULL,
		0x95DA06C52AAB80FFULL,
		0xC77C76E800AC9458ULL,
		0x3615B46EB71A91E2ULL,
		0x03A4D7F2B67272B1ULL,
		0xE743A7C7AFB3F5AAULL,
		0x1BD9D3E2C8100AA6ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFAF97F1EEF8F5B68ULL,
		0x8319EBD58D2AA7C3ULL,
		0x5246841E89D211F5ULL,
		0xC1BBEEFF622C4C69ULL,
		0x4882F9026E7EA1C0ULL,
		0x43C98515564AA085ULL,
		0x26B3A39CA256564CULL,
		0xF7F8C7CD7056C32AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F07744E1C3BF7E5ULL,
		0x4992992B08FA8768ULL,
		0x78703B8831C7B675ULL,
		0x9FF57ECF25BDE63DULL,
		0x1B124883275A18B2ULL,
		0x7B3F3806F25E0ACFULL,
		0xD44C8DF4C5207521ULL,
		0xA3C26B38F7DBA201ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x955B0D8E116F18EEULL,
		0x386849C68B6266E3ULL,
		0x41E84F92FC38F398ULL,
		0xD772C6EBFBB9B16CULL,
		0xCFC83281EB1CCA44ULL,
		0x319FAC221A353C4CULL,
		0xD3862BFBEB5C9B8FULL,
		0xACAC66AB874791E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66A137B2F89FB979ULL,
		0xD40AC7F80AC7EB23ULL,
		0x4CEE312F288A6C67ULL,
		0x087E37CCB5572C75ULL,
		0xF545E4A5746F1BD1ULL,
		0xF8AF75B17C0BEA4AULL,
		0xE69B712A0549C3E5ULL,
		0xF024621BB4EB36CDULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x84468ACE23CEE4E4ULL,
		0x94140374D0E8B15DULL,
		0xD6ECC11C210E6E90ULL,
		0xCE353DD6576ADC59ULL,
		0x41116AB095E08D1BULL,
		0x282A85215490659AULL,
		0xD021C49C4AA16386ULL,
		0xA3BE9F9CCA94DD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x848FB5A705FBAA72ULL,
		0xF0E5895DF453D1ADULL,
		0x03D48DD8978A849FULL,
		0x882C5402B73CA08DULL,
		0x42C9EA8967E59BA4ULL,
		0xE0069AB781AD99EDULL,
		0x7AE623BE1D7D19D7ULL,
		0x26CA05CC74C09F4CULL
	}};
	t = 1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7FF4A365D426B251ULL,
		0x469DD44A6D7008C2ULL,
		0x59FCD332BE1C935CULL,
		0xB041F9FA0EECCD23ULL,
		0x8F0C9AFA6E986FDDULL,
		0xB0480B9A623E3DBEULL,
		0x9ACC7D4CBC35A71DULL,
		0xFDF4DCB2AC267330ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FF4A365D426B251ULL,
		0x469DD44A6D7008C2ULL,
		0x59FCD332BE1C935CULL,
		0xB041F9FA0EECCD23ULL,
		0x8F0C9AFA6E986FDDULL,
		0xB0480B9A623E3DBEULL,
		0x9ACC7D4CBC35A71DULL,
		0xFDF4DCB2AC267330ULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6EB755C07FFA1365ULL,
		0x82225721F5E542FDULL,
		0xD4AEDA612AA3683AULL,
		0x4DF90A18E0F2D620ULL,
		0x9172A6993F9BB159ULL,
		0x930DD8E6241FD48BULL,
		0x426C9EDECAE2071AULL,
		0x9853B0B01DE09722ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x009E9943C477F4CFULL,
		0xACE3075E845DF46BULL,
		0x6283881AE49F62EEULL,
		0x4DB022CBFFD4AA62ULL,
		0x7034807A9446422CULL,
		0x05A1115CAC17FDFCULL,
		0xFE85952F90C42FD0ULL,
		0x45D694D3BA9903DCULL
	}};
	t = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x564AA0E0AECF0D1CULL,
		0x9906924761724C8DULL,
		0x99EEF8C258EDDA82ULL,
		0xE378D7A572FCB9BBULL,
		0xA93F9F41BBAED3B7ULL,
		0xDF8D1D74CC0F28BEULL,
		0x44A296F5FAF4EE3CULL,
		0x6C0C23E58C7542E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x631EB097D312E2C7ULL,
		0xF0C05080C420E769ULL,
		0x6EB197BDDE5BD503ULL,
		0xB4467E7AD7AE4893ULL,
		0x0F0F56F5CA0068D0ULL,
		0x77488A16FC1E2C69ULL,
		0xB78059773FC75F13ULL,
		0xB7A8DFE2C21486FAULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAEA8647FEA9232E0ULL,
		0x34C64E5345B5D868ULL,
		0xF6163930BA46A48EULL,
		0x34FA60B084B08E1CULL,
		0xAA4E271E69C48CC3ULL,
		0x85B0493FA5297C8FULL,
		0x6022BD300C538948ULL,
		0x4808371D8B165FBFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C8640A9C4005DFULL,
		0x6D05ECF2AC667B9BULL,
		0x3B4EA493EB7CD9B0ULL,
		0x95E776EE9B84D7C5ULL,
		0x0939D182776972FCULL,
		0x77F9D9735AD09334ULL,
		0x5A4AC99E439AAC01ULL,
		0xD9D5A7ABF6B60CDAULL
	}};
	t = -1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x108947DD2120ED4BULL,
		0x93A5512BBEC05A26ULL,
		0x816E3FCBD4DAAEDBULL,
		0x665A4BA44C479C2CULL,
		0x27FE54D2EE1D4D94ULL,
		0x37E8C2C5E8DB3B0DULL,
		0xE4C69392ED3E8398ULL,
		0x73DF7AB5ECCCFB04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x108947DD2120ED4BULL,
		0x93A5512BBEC05A26ULL,
		0x816E3FCBD4DAAEDBULL,
		0x665A4BA44C479C2CULL,
		0x27FE54D2EE1D4D94ULL,
		0x37E8C2C5E8DB3B0DULL,
		0xE4C69392ED3E8398ULL,
		0x73DF7AB5ECCCFB04ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x19757C4E30CD58F0ULL,
		0x018E52ADFDE2D10EULL,
		0x5417A8608F69C343ULL,
		0x19CA6C483ECAADB1ULL,
		0xDAFE6BC7738DA2D3ULL,
		0x4812536B6D159C42ULL,
		0x87F357860A3B3F3EULL,
		0x3BC75FE0910C0189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABB50EB29004F097ULL,
		0x39C25ACB6973E7D6ULL,
		0xB9C5D9AB7BA10ACEULL,
		0x2A9178CB8846B386ULL,
		0xDCAFB18B2DABB728ULL,
		0x3B40DC32EE197765ULL,
		0x96BB88DB6E8BD32EULL,
		0x0D272AB3E1E4F4B4ULL
	}};
	t = 1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5896F5FD6BCA54FBULL,
		0xAEC0C55D8E54F4A0ULL,
		0x4196DD39C377395EULL,
		0xBBCEE066A534C194ULL,
		0x3F17058D93F57710ULL,
		0x75D421C66BBF5242ULL,
		0xC276D8BD6350A1D7ULL,
		0x1C8758B15FE95E84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x857692966DF829A4ULL,
		0x3FA2CB2AFA3CAFE1ULL,
		0x82456E0AD8D57917ULL,
		0xD04AB8F58AA6CADEULL,
		0xE76001F41E070D58ULL,
		0xA35CCE33F8B393B0ULL,
		0xD1928B7963A3FC99ULL,
		0x87A8EACD1227B232ULL
	}};
	t = -1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6044EC5D5F7798C6ULL,
		0x0918F6166BF16F53ULL,
		0xB4A49E950AEE162BULL,
		0x9737A42EDFD00E6AULL,
		0x30E53318786BA5DCULL,
		0xD43F1BF382B406ACULL,
		0x5876D8BB3964441EULL,
		0x95C12336528C8536ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1915E5333C1DF62ULL,
		0xFC4C2638AE414E70ULL,
		0x2E9E2F29A66CE8DEULL,
		0x0A7E6C04094D540DULL,
		0x21F776C8525EBFBCULL,
		0xA6EC156602FA43F8ULL,
		0x207FB17709E304DDULL,
		0x92ECF0208120DD2DULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB67783DCD5F6FAB4ULL,
		0xCB737C36C3B0D241ULL,
		0x2FC425496A05D769ULL,
		0x57D9E9C47D99D942ULL,
		0xDB4E9C9FA16BC7F9ULL,
		0xC0D26033E9B23D13ULL,
		0x56FDB45F64C60EB5ULL,
		0x9797AB7833D5492EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB67783DCD5F6FAB4ULL,
		0xCB737C36C3B0D241ULL,
		0x2FC425496A05D769ULL,
		0x57D9E9C47D99D942ULL,
		0xDB4E9C9FA16BC7F9ULL,
		0xC0D26033E9B23D13ULL,
		0x56FDB45F64C60EB5ULL,
		0x9797AB7833D5492EULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2BC42CC11C320282ULL,
		0x5377487DA43F6C7EULL,
		0x3F3515D2D6CCE12AULL,
		0x4163E2373533413BULL,
		0xCE15247AAA0741C9ULL,
		0x32FF21C4A4145057ULL,
		0xF4D16D5F23B2EFFCULL,
		0x1946958719F9C931ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C977F353E64D173ULL,
		0x6B8955173D95B0CAULL,
		0x7A58782E0C78960EULL,
		0xB7BFE0B6FADA3F95ULL,
		0x699E5B3F727721FEULL,
		0x85CBEAF2538849D5ULL,
		0xAFB7E100742E4976ULL,
		0x28508F100C67186BULL
	}};
	t = -1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA42548A8D6123393ULL,
		0xF7EB248EAEA21318ULL,
		0x0E76EE0081EE6946ULL,
		0x88D090BE8084AB6BULL,
		0x4549395CF4C41138ULL,
		0xCA40438DE0B1E84FULL,
		0xD6BE3B0D36ED6416ULL,
		0xBA3B5BA286562C39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x762182EE34208F04ULL,
		0x55ABCA7212B6B03AULL,
		0xEB323BC685F1C2F9ULL,
		0xF1D45B35D8B25B4EULL,
		0xC69CA437E631BF79ULL,
		0xB69C7893E8B4DA6AULL,
		0xF9524560E4E1F41BULL,
		0x5721766AC9B4F24BULL
	}};
	t = 1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6BDF8EFF7306E123ULL,
		0xCE720BCA88C167DCULL,
		0x18EC6ED950199686ULL,
		0xCC62CF662E53F5A1ULL,
		0xD6197AF299F83E56ULL,
		0xBC7018866F028ED5ULL,
		0xCC2C88014DB099E8ULL,
		0x5F7003CBB2F8B54EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756BAC8FEE0F742BULL,
		0xCEA061B6EAB16CECULL,
		0xD1A62DBF7729C7A7ULL,
		0xB4151853CA39AFECULL,
		0xBA0A7701A1036EE3ULL,
		0x5A0E0284FD15CBF8ULL,
		0x7A544671EABE2783ULL,
		0xA8B5C9753D856F21ULL
	}};
	t = -1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8250373752BF783AULL,
		0x92014D47B0950863ULL,
		0x5C5341F8F98EC999ULL,
		0xCF0CCBBC23E138EFULL,
		0x671CF5A822022E30ULL,
		0x7D5F6C87A28612F3ULL,
		0x09756310A242045CULL,
		0x8442276E0074F740ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8250373752BF783AULL,
		0x92014D47B0950863ULL,
		0x5C5341F8F98EC999ULL,
		0xCF0CCBBC23E138EFULL,
		0x671CF5A822022E30ULL,
		0x7D5F6C87A28612F3ULL,
		0x09756310A242045CULL,
		0x8442276E0074F740ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4BB944D8B842803ULL,
		0x9A768AF4005062F6ULL,
		0x69ECCB49A14C7B88ULL,
		0x8A5031631F36E953ULL,
		0xC578CE03A9EB7B4AULL,
		0x47EF9B8A0668961EULL,
		0x02CD0DAB2D93AC84ULL,
		0x2BABAD122AAC2347ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17E5C78F89037DAULL,
		0x0E88C25F6C3BE78BULL,
		0x8F4CEA833660CEA6ULL,
		0x3C6E20F36BED2AF2ULL,
		0xF0B5D2C09A09248AULL,
		0x0C1C0B2B899B68F0ULL,
		0x047051751F591412ULL,
		0x473615ADB5F80646ULL
	}};
	t = -1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4CF027ED6F113D8ULL,
		0xC6435ACB7DD2980EULL,
		0xBF301E2B4D38F3D2ULL,
		0x6EFAE346DF2FF134ULL,
		0xC9DB6D480C264634ULL,
		0xFC243B27A2E28923ULL,
		0xED4280EE2B07B4F1ULL,
		0x5C69C62BC9E2A1EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F8181CC112146AFULL,
		0x974BAC39DE627226ULL,
		0xEBCD9359CBA10615ULL,
		0xE725B1CAE87698F9ULL,
		0x591E9A5F0E8CAF8DULL,
		0x115CCE2DB8B6AAF0ULL,
		0xE0A4189976E04178ULL,
		0x2CFA663413352C3CULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x45A92144CD50BFF3ULL,
		0xC1FD1C967719A3BBULL,
		0x7B0EBFD313A39D3AULL,
		0x33624D7D520ED66DULL,
		0xF9BA78970CC98362ULL,
		0x6FD3063F0CF29EEDULL,
		0x1A5524479DC382FFULL,
		0x53074FAB44BCFFB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9709D90C5E6D53BULL,
		0x5F0A68E74BD6D7CEULL,
		0xA6226C7F30C54441ULL,
		0xE1C683F67BFAF45FULL,
		0x1B3EF1763B5C04FAULL,
		0x4E43F58FD3221702ULL,
		0xE98CFCF930DC96A1ULL,
		0x8A3B25272B277886ULL
	}};
	t = -1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x08E48F723D8D97D8ULL,
		0x6EB2498FADA439F6ULL,
		0xFD74474A29E2F6A6ULL,
		0x162F2D3DF25D4D23ULL,
		0xEB0204A85B7C983FULL,
		0xB2E23AF78285AB82ULL,
		0x72D3969589FE6F76ULL,
		0xF9E38AB08DCE6C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08E48F723D8D97D8ULL,
		0x6EB2498FADA439F6ULL,
		0xFD74474A29E2F6A6ULL,
		0x162F2D3DF25D4D23ULL,
		0xEB0204A85B7C983FULL,
		0xB2E23AF78285AB82ULL,
		0x72D3969589FE6F76ULL,
		0xF9E38AB08DCE6C63ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0A60DB88E4C501DBULL,
		0x9052FE01246AB879ULL,
		0xF2957275F2202AE3ULL,
		0x9255E9535E47EEFCULL,
		0xD1B865415E34ECF3ULL,
		0xB7C3CEC423EF3955ULL,
		0xB69B6FFEE92457F4ULL,
		0xFAFDD408E2011879ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022B03FBE23A4309ULL,
		0x0B7BC319DB22150AULL,
		0x5C3804D816601843ULL,
		0x7D2F844FD4F7FE7EULL,
		0xF9150B4E728261D3ULL,
		0x9D24705954354666ULL,
		0x4A2CF39DB00E27D7ULL,
		0x704B471E06E0124CULL
	}};
	t = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x488E97053AD33344ULL,
		0x4B5D381E0277F38BULL,
		0xDF756FE8EAB26FE7ULL,
		0x60DE2952133EA7F9ULL,
		0x61EE4CEA66D635E4ULL,
		0xB39E0D1D11D33947ULL,
		0x1C98420827F7C3CFULL,
		0xAE27278FAEABE2F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6FD8B3CA9C89157ULL,
		0xFB7C56DE2EF1E59AULL,
		0xF2D64EF47BDB09F9ULL,
		0xD03C57DAA6E4C84AULL,
		0x958378943601942CULL,
		0xF90A89F6C0FA2A3DULL,
		0x3714E72FA08879A2ULL,
		0x96E0AC1254B2F31BULL
	}};
	t = 1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5F3A8D92131D6228ULL,
		0x2002CBA85B79A37DULL,
		0x4D89517287B22358ULL,
		0x034E9DF944F743EAULL,
		0xEFA2DDD275176A3DULL,
		0xB74F2FED0E80C274ULL,
		0x0ED450E7E7ED21D4ULL,
		0xBF53D4446BB609E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6069CA0F0FC94DFDULL,
		0x29864C90F0D0A590ULL,
		0x9C3428890067089FULL,
		0xD706EE1D0033532EULL,
		0xCE06404877869B49ULL,
		0x9ED7F8D17D2F5DBAULL,
		0x0DF939221925976EULL,
		0xA6FD12DFA30F862CULL
	}};
	t = 1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x90EA065D6A1589EBULL,
		0x19BA4F10C702E5ACULL,
		0x92F5AA36564487DAULL,
		0xCBF5F615D33F2001ULL,
		0xD86189D731E34043ULL,
		0x138074B9AFCBD348ULL,
		0x6490DA56B527608FULL,
		0x06A6840484A4CB57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x90EA065D6A1589EBULL,
		0x19BA4F10C702E5ACULL,
		0x92F5AA36564487DAULL,
		0xCBF5F615D33F2001ULL,
		0xD86189D731E34043ULL,
		0x138074B9AFCBD348ULL,
		0x6490DA56B527608FULL,
		0x06A6840484A4CB57ULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x217C41909003B492ULL,
		0xF39B326FC284BB72ULL,
		0x19E25B403CCD15EAULL,
		0xEB9684A718FA3C76ULL,
		0xC3B8012D8D556149ULL,
		0x6E6E0316AE27566BULL,
		0x2777B732AFC28009ULL,
		0xCE1EC2697D163038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B706E28CC1C5BC9ULL,
		0xEE499369DB03BC72ULL,
		0xA6AAAADF72E8F58AULL,
		0x5F56DDCF3E0E585CULL,
		0x0541B66313B33641ULL,
		0x1E7116FB2E1BC647ULL,
		0xF46681B280CABA84ULL,
		0x7716DF8DF121D3C1ULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5392BA2C2F12BE15ULL,
		0x84778CF9732BBED1ULL,
		0x57C71C7971C7CE17ULL,
		0x152A70F9371E705BULL,
		0x42C08269095C445CULL,
		0x0ECA1313A4DF5270ULL,
		0x15122B232A0773F3ULL,
		0x9F9E4203AD3F4F80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD6455ECD1AA18399ULL,
		0xB5A57CAD5C2BE018ULL,
		0x5E3F1C6583D69823ULL,
		0x83730F75010BFD69ULL,
		0x4557005694AE275AULL,
		0x67D2C3F7F050877AULL,
		0xDFE0A346028BE987ULL,
		0x01024F38FD8D7B7AULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAEF45133FE6B1A55ULL,
		0xEA384F4B57EDA54BULL,
		0x893217246BB6399FULL,
		0xA7BD799C4541DDF6ULL,
		0xDAF40686C4809A4EULL,
		0xA37BF1472E0F6B0EULL,
		0xAC53B34DFD80CE0EULL,
		0xBD5990B2980DDBCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B3DF01ECF550E06ULL,
		0x60487A230FCD3CCDULL,
		0x93F19710AC404D55ULL,
		0x9CE9817B78454E1AULL,
		0x62D036D182A1687BULL,
		0x7A8C3EC5233627EAULL,
		0x752CDCA65CBAB78FULL,
		0xDB99BCE77A0B7F77ULL
	}};
	t = -1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x190F4C014CF81DE6ULL,
		0xC60D6B4148443508ULL,
		0x9AB774AE8C9B87A5ULL,
		0xDD1F2CCD8D48DB08ULL,
		0x7D9BA32F98D9475CULL,
		0x8A21AD2398703126ULL,
		0x5454F152C7AF7614ULL,
		0x03D691A3E54BA28AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x190F4C014CF81DE6ULL,
		0xC60D6B4148443508ULL,
		0x9AB774AE8C9B87A5ULL,
		0xDD1F2CCD8D48DB08ULL,
		0x7D9BA32F98D9475CULL,
		0x8A21AD2398703126ULL,
		0x5454F152C7AF7614ULL,
		0x03D691A3E54BA28AULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB20C747B633C8B7FULL,
		0xC74A8FB1C1C198A8ULL,
		0xDD0E1C17E0283241ULL,
		0x031A4E65B5CB5205ULL,
		0x97D7ED3B1E2D61A7ULL,
		0x9718CCD1E13E58DBULL,
		0x3C3A451B4904ED2AULL,
		0x2E0713BE00F3C9BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AACCD2B28C09FBBULL,
		0xAC9954026F5C79E7ULL,
		0x85EA7A39C71E75A3ULL,
		0xB0871ED1F204368AULL,
		0xA81FB3AB1E4035BCULL,
		0x0244703560B06960ULL,
		0x8551C268FE0A1E66ULL,
		0xD100482DD7EF4987ULL
	}};
	t = -1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x47CDE6F369F02CFAULL,
		0xDD2DBEB5FF6631DBULL,
		0x8AC5DEE94D6E2A8AULL,
		0x6D805DB1C5E4AD62ULL,
		0xC639D09722325F8AULL,
		0x6AF576F487E9F6A2ULL,
		0x995F301E2FD4D701ULL,
		0xC5375F66C5F03F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1DA03232C650DCA9ULL,
		0xC90A520569E38FC0ULL,
		0x49D027D67AB12D2EULL,
		0xA31E596B19D5D8B5ULL,
		0xF6E6889286CB0CAFULL,
		0x5DE0507A2EAE7A09ULL,
		0x276C46A0CA69DAC9ULL,
		0xB081304E72E18436ULL
	}};
	t = 1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x860F459CFDEB46B4ULL,
		0xFD19E0EC55169F39ULL,
		0xBF71F9F2249874BAULL,
		0x0C2E4592E19A9EEDULL,
		0x2E2590FF26F34F41ULL,
		0xFB9B8053A98AA123ULL,
		0x4CF774FCD8B7F796ULL,
		0xEB8917D8AEF5D408ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x678E53EBD8084FDFULL,
		0xD363AEF6F811E36CULL,
		0x6C7F82ACF5173F8FULL,
		0xA771CC51ED009D9AULL,
		0xC1C9D8ACD4C97F3CULL,
		0x430175A8DDC7B5C9ULL,
		0xD36256AA78E76A71ULL,
		0xE24642F3037C59D4ULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEA121E48D10E40FDULL,
		0x4BF9C1758D908193ULL,
		0x1C5D165E41B5C056ULL,
		0xACEEF2E68F194BCAULL,
		0xE6C5D30E7FC54ABBULL,
		0xBCDE2A120B68F7F4ULL,
		0xB613A36B36612A5EULL,
		0x782506033B0723CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA121E48D10E40FDULL,
		0x4BF9C1758D908193ULL,
		0x1C5D165E41B5C056ULL,
		0xACEEF2E68F194BCAULL,
		0xE6C5D30E7FC54ABBULL,
		0xBCDE2A120B68F7F4ULL,
		0xB613A36B36612A5EULL,
		0x782506033B0723CDULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6C37B7DA55B91DCDULL,
		0x659D77775372F967ULL,
		0x3E9EC5ED759AACF2ULL,
		0x42B1F1F2660E268BULL,
		0xAB9D1420DB9C4BC3ULL,
		0x155181681ED2228EULL,
		0x5822BC76641FA2A1ULL,
		0xB944A4A19454E37FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5D07DE36838CCF9ULL,
		0x874E38755DE4A327ULL,
		0x8B9C1599EAE1626AULL,
		0xDA316D57BA9506A4ULL,
		0xD7ACCD78E6D0A7D9ULL,
		0xF2E3C35F8F5E51B0ULL,
		0x6A5F1B66FEF2016EULL,
		0x99BA8F4D415E39C2ULL
	}};
	t = 1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA91331D6F30CEB07ULL,
		0xFE157F81A7F61840ULL,
		0xF6F13674FAAD0420ULL,
		0xC0A3CD608955E179ULL,
		0x5AED4EB763F7D614ULL,
		0xEF05CBB709E63590ULL,
		0xDDA43E77CDCA73D3ULL,
		0x24C1FE2FD814E384ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA34C0EE8B383ABF4ULL,
		0x0FD60A2F4BAFA4A4ULL,
		0xA9DC125ACDB61004ULL,
		0xF2B65EFCC48E30ADULL,
		0x95EE8FF3B97DB240ULL,
		0x316220C96FA5C2E5ULL,
		0x6DC3D1E6D733D3E5ULL,
		0x8E1F4CF281692FF7ULL
	}};
	t = -1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x114BDE87D383ADEEULL,
		0xF45D9F7FAD9C8DE9ULL,
		0xDD2FDFD37EEF768BULL,
		0xC087FC21DB6CD5ACULL,
		0x29ABD7B18F01547CULL,
		0x903D6A9FB6BC8FCEULL,
		0x9A8394504260C593ULL,
		0xB5A30CD0A295EA95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71214061C4EFCCD2ULL,
		0xB038123DB0DB81C7ULL,
		0x7A5DE872777CC222ULL,
		0xFB645FCA2BB2F58DULL,
		0x7660A19069633809ULL,
		0xE14ECE6485E4E727ULL,
		0x20A402E0B1A88A01ULL,
		0x18D8278A61F79278ULL
	}};
	t = 1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x56B3D5DA099DEE03ULL,
		0xF88D03CC0E19A084ULL,
		0x2F003B3FA5B917BEULL,
		0x8DE056CD7D4BE104ULL,
		0x512134817BEE9A1FULL,
		0x80866CB433511215ULL,
		0x00DD1C8DDC776C3DULL,
		0x7E3547165A921CB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56B3D5DA099DEE03ULL,
		0xF88D03CC0E19A084ULL,
		0x2F003B3FA5B917BEULL,
		0x8DE056CD7D4BE104ULL,
		0x512134817BEE9A1FULL,
		0x80866CB433511215ULL,
		0x00DD1C8DDC776C3DULL,
		0x7E3547165A921CB5ULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD2F6628AB027D6E6ULL,
		0xED2AF49AB9516F87ULL,
		0x1288B2E4E85DFDBFULL,
		0x8762990D1837354EULL,
		0x80CE3CE34F1BD4E1ULL,
		0x01A7AF8D14129B8AULL,
		0xA713A700C901C32DULL,
		0x2C32888382E656C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x786ADA03023C2769ULL,
		0x975648EF3E47759EULL,
		0x4CA9782D325978FFULL,
		0x72B8B5BB1066F16BULL,
		0xDDFF28FB89EAF5C7ULL,
		0xA37103909B4D5CE8ULL,
		0x944D8D721407553CULL,
		0x488042C057F0D626ULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6C3DCCDE88187422ULL,
		0x0F16FD3593EEA4A0ULL,
		0x22BCEAA1A42C2408ULL,
		0x1022F34A0AF139D7ULL,
		0x634CE97628C74B5AULL,
		0xF836B3D94FFE2CDBULL,
		0xCEA1E598F9D44C12ULL,
		0xB95CA07FC334F87DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x154E1898E16ACE0CULL,
		0xE80FFBB70A55A19BULL,
		0xA748790437AD536BULL,
		0x15C006DBC2F41648ULL,
		0xC6F78DCF1B1EA048ULL,
		0x8D762F1D3A7A3536ULL,
		0xF6D6EDC24B975FD2ULL,
		0xA173EBFCE9C77F65ULL
	}};
	t = 1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x827377CAA0CB60A6ULL,
		0x01FA491DF2481022ULL,
		0x6705ABC0D581D833ULL,
		0x37155300D02B266FULL,
		0x37FF45C3497A4403ULL,
		0x8340844C39667D5EULL,
		0xF0F3D613717C1FA5ULL,
		0x52548AB6E832D946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B25AFFE11ABFD45ULL,
		0xFA05050F9ED039B1ULL,
		0x3E3AB8C40747463DULL,
		0x831D78C4C8AF7A41ULL,
		0x247D98AF69D41CC8ULL,
		0xFD279634DECC33F6ULL,
		0xE303DF7B9880AA9EULL,
		0xC77E03CD10A9EF85ULL
	}};
	t = -1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x3491EB3FFC24BDFFULL,
		0xA2EF18F00A551566ULL,
		0x29FBEE9FD2B4F352ULL,
		0x481BBFA2C8B069A0ULL,
		0x0193D932EE9E98C7ULL,
		0x05E231C2D3FA06F6ULL,
		0x6B72E487D17D79E0ULL,
		0x9883B1B891C2230CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3491EB3FFC24BDFFULL,
		0xA2EF18F00A551566ULL,
		0x29FBEE9FD2B4F352ULL,
		0x481BBFA2C8B069A0ULL,
		0x0193D932EE9E98C7ULL,
		0x05E231C2D3FA06F6ULL,
		0x6B72E487D17D79E0ULL,
		0x9883B1B891C2230CULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE6A8A417FF411690ULL,
		0xD05AB9FF9841EB59ULL,
		0x9BF8576BC3ED824BULL,
		0x342275FA5ABE0F60ULL,
		0x6590DE749EB40369ULL,
		0x074FBFD07B2D8C0BULL,
		0x60AB5B39428E7DA4ULL,
		0xC98A4572B7B3311CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE458F525C02150DULL,
		0x878529D9C64D43A8ULL,
		0xEDDD912334667F31ULL,
		0x96DCF1FF08206A20ULL,
		0x492634D73000CF6CULL,
		0xAA785F186312C3A1ULL,
		0xBE9193CCAAFBEB21ULL,
		0x827B272CDC2D4950ULL
	}};
	t = 1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x196AF7644F6ADD84ULL,
		0x9BB755A483348EB1ULL,
		0xB52572B76BA8C95FULL,
		0x55F4D99B3D7EC99DULL,
		0xD4542EEA3C413472ULL,
		0x01F2EA49FE081011ULL,
		0xFA971756F163AC76ULL,
		0xCB9F4D5B8388976EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF68295C12E0FDCULL,
		0xA91C2EBDFCB5C208ULL,
		0x71CAD86147F1E8DDULL,
		0x3B6B369B067D39B9ULL,
		0xFC6800D8D070BD64ULL,
		0xF3516E1B8C991BE3ULL,
		0x57B69B3122C11CD8ULL,
		0xCE90C6417DF6A5CBULL
	}};
	t = -1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x46136B1AD6BDF32CULL,
		0x35D40FE005A71FEDULL,
		0x61F35851C6694F23ULL,
		0x5240600303AC5981ULL,
		0x00884286C9DF4EC0ULL,
		0x2C9F1B9EB0DA7ADEULL,
		0x30CA9487CE221831ULL,
		0x90CA8F77145454A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82FBACBBB30C1EF9ULL,
		0xB4A8974CE667A549ULL,
		0xE68E55E6E33D1B0AULL,
		0xB6521A339B91E2FCULL,
		0x0EA5E1269FC38101ULL,
		0xF83425D8C4445ADCULL,
		0xB8EC3FFC18CF9916ULL,
		0x8114EB52966497B3ULL
	}};
	t = 1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE7758BC448D6E9D6ULL,
		0x1374BA173DC2DEB2ULL,
		0xA2B05F87520DB206ULL,
		0x0C790630DEE0C06AULL,
		0xE7970AE699150563ULL,
		0xBA85F0A08024841AULL,
		0x445101D18F87FAD2ULL,
		0xF56A6880D828C978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7758BC448D6E9D6ULL,
		0x1374BA173DC2DEB2ULL,
		0xA2B05F87520DB206ULL,
		0x0C790630DEE0C06AULL,
		0xE7970AE699150563ULL,
		0xBA85F0A08024841AULL,
		0x445101D18F87FAD2ULL,
		0xF56A6880D828C978ULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2BAF20E8504D6841ULL,
		0x1E526928FDE2A725ULL,
		0xA214D6F12F4A35B0ULL,
		0x305C9102634B87AFULL,
		0x4CF14BBE9E6072CFULL,
		0xD3E2C001634B1EE3ULL,
		0x61E3459154B5B21DULL,
		0x1AD97A79DF05CB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C2EA4473FAADAAULL,
		0x6EE7C815A36BDC49ULL,
		0x7A75E65DE1881424ULL,
		0xB14371158A6E9536ULL,
		0x0EC73C6EF5B3E5DFULL,
		0xC25CA368AA92FC56ULL,
		0xEA14A28A4BA58068ULL,
		0xD86C00BD1D8F9598ULL
	}};
	t = -1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB926D454FAE30E61ULL,
		0xDF68C3ECEA1FF58CULL,
		0xCC2789ECD4969F06ULL,
		0xEED53ED7AEE9BD4DULL,
		0x1C681148F67E67DFULL,
		0xF594F6EAB989E82FULL,
		0x69333A4EDF5A1835ULL,
		0x973F305B01C00A19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AD005A6067D223EULL,
		0x05B4B57BC771C45DULL,
		0x55A411F61A34F50EULL,
		0x3DFB91EC8A0858BCULL,
		0x5511EC28CD1CB0D0ULL,
		0xE6651E13A43ED980ULL,
		0x0D467DFB5475A988ULL,
		0x9F4461463A07D447ULL
	}};
	t = -1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAE0812328A14F95FULL,
		0xA3AD474AFD5E101DULL,
		0x9B4962859151A521ULL,
		0x14EC008EB75458B0ULL,
		0xCF359A550F95C0BFULL,
		0x83D760D2D2AE26B5ULL,
		0xDBA900E957B9BE01ULL,
		0x2262E580AC8820CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02DE96565412EF5BULL,
		0x967C05A88791BD99ULL,
		0x4E7FD507D5BDDC47ULL,
		0xDDF77A2C0FE38506ULL,
		0xCC24D5EDC81F4537ULL,
		0xCC653BA695C35E1AULL,
		0xA7D6A41316710AF9ULL,
		0x85A88AF0DF3E6656ULL
	}};
	t = -1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6BDA3323F0836F4FULL,
		0x66442E79C74AF47AULL,
		0x83F845F73AD22794ULL,
		0xA769E1E4F965CCB9ULL,
		0x8B8D8AC881628AA2ULL,
		0xE5E0FD61A037ED0EULL,
		0x52B86AC842B43679ULL,
		0xA74437023AACDAF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BDA3323F0836F4FULL,
		0x66442E79C74AF47AULL,
		0x83F845F73AD22794ULL,
		0xA769E1E4F965CCB9ULL,
		0x8B8D8AC881628AA2ULL,
		0xE5E0FD61A037ED0EULL,
		0x52B86AC842B43679ULL,
		0xA74437023AACDAF2ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDE00A18A9DCD9CDBULL,
		0x7174E93115BB2107ULL,
		0x3B6485604CCA6A24ULL,
		0x8716372FAADF29CFULL,
		0xBA3781E9D6B9CF86ULL,
		0x096A858309FFDFCBULL,
		0xD060B8B58556537DULL,
		0x8FE289157D79F21DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F1AA310EDE448DULL,
		0x453766721A5EC054ULL,
		0xB1A66EC85BAA79AEULL,
		0x60318B2E15E836A8ULL,
		0x902A76C9116581CFULL,
		0xE302378BB584460DULL,
		0x0AEDD141AC5FAFB1ULL,
		0x1759DF298A08EF98ULL
	}};
	t = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6E9307CEFC22FFF9ULL,
		0xEF0AD149424331DFULL,
		0x6DD80FDBCA8B3A6DULL,
		0x430448FF306D8A11ULL,
		0xC18CEC11E6784BE6ULL,
		0xD3125DD3667FDB44ULL,
		0x356E633DC2EFFC2BULL,
		0x3EAB3C3D820372C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDEFEFBFD19FEE54ULL,
		0x8F674A2D48043E11ULL,
		0x896AED0FE6A58272ULL,
		0x53665C6BB20BB1E8ULL,
		0x60EEE9C36564306EULL,
		0x53441E3D28873AD5ULL,
		0x6929C31DE7F1ED9AULL,
		0x2C6B28D8592102C9ULL
	}};
	t = 1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xECC1EAE76226F903ULL,
		0x409D40C27C461091ULL,
		0xE9E37C31F253C5AAULL,
		0x32F9398B114BE197ULL,
		0x38AFF6D3789425FEULL,
		0x9887612D186D7493ULL,
		0xBF52D7287E71D1BBULL,
		0xEC42C3DD889217D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFD694C0E25248CULL,
		0x8602A8471F1E84D0ULL,
		0x16E7FB3A3BEE890BULL,
		0xD23DDB05B0A6654EULL,
		0xA7FFC5AD38FA3963ULL,
		0xB193FA5275CDB9B2ULL,
		0x59044537DEE70A79ULL,
		0x91723FF9CF2BEBB9ULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0E6AC5777FA854E1ULL,
		0xCD3D6A980A96182BULL,
		0xC7714F82B7E06520ULL,
		0x88C2ACAD3CC279B3ULL,
		0x865C1D6E0147A37BULL,
		0xFD6F53BB50595304ULL,
		0x94575D1BDCA69500ULL,
		0x37E4E9C3287735D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E6AC5777FA854E1ULL,
		0xCD3D6A980A96182BULL,
		0xC7714F82B7E06520ULL,
		0x88C2ACAD3CC279B3ULL,
		0x865C1D6E0147A37BULL,
		0xFD6F53BB50595304ULL,
		0x94575D1BDCA69500ULL,
		0x37E4E9C3287735D3ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x998F2E7E12166648ULL,
		0xE862476183AFA657ULL,
		0x3F4F749818A5BA0BULL,
		0xC55A384AE099E074ULL,
		0x2A879CA5D73022E9ULL,
		0xF66E997BE27F9BCEULL,
		0xB581BAA7FC7C20BCULL,
		0xF542DD1814B3F2F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06098B3C8844EB5AULL,
		0x5CD67C58FD2C8BDDULL,
		0x9B7DAE81270D3E7CULL,
		0xB05520A2E9C8F589ULL,
		0x50CCF8F039C1A7E9ULL,
		0x85D65FBB190C7D6AULL,
		0x6B24C0C6661374AEULL,
		0x6B1920D9DD688E9FULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE1BEDD0706B440DAULL,
		0xF4C05A5709C6E1C2ULL,
		0x537F8F9BDF62EE77ULL,
		0x6407A6F237EDB27BULL,
		0x092A0FE0E4B3DD76ULL,
		0x013BCD0943FB0743ULL,
		0xF639E1061484B93BULL,
		0x220CFB22B257A648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A80AAC7C89BFC0FULL,
		0x41F312BBB6FBDCDBULL,
		0x8D4AB354E5C77FDCULL,
		0x8387CA5E1C12147AULL,
		0x2B1A30018EEB8A46ULL,
		0x8E475EE411C7CA68ULL,
		0x55B5831F696ECC8EULL,
		0x4794B8349197054FULL
	}};
	t = -1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4D5F2140F4C0861ULL,
		0x85198D4B54E28D7BULL,
		0xD394396C5F54501EULL,
		0xE4815D7D3132A3C4ULL,
		0xFD3FFC05BD81D480ULL,
		0xC2BC11E2A904F356ULL,
		0x63300B69ECBA70D8ULL,
		0x0C48CE6774CFBA16ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40EE7BC4E5602289ULL,
		0x110213E804F10821ULL,
		0x711C43219CBC60B3ULL,
		0x65485FAA58354548ULL,
		0xAB8ABC2E7A4E3AD8ULL,
		0x2BDAEC98A7125E72ULL,
		0x213D9135E7DCEF28ULL,
		0xE8DE2698B06D7886ULL
	}};
	t = -1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE13AF46DBAD6A4C3ULL,
		0xCAF8FE50D4F98C3BULL,
		0x0F02F92BA5D4D3DBULL,
		0xF2590CC883011ED5ULL,
		0x893A7F5B01E8ADFAULL,
		0x7A53CFBDD679084EULL,
		0x3673618CDA30922DULL,
		0xA2A7133584DA2E7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE13AF46DBAD6A4C3ULL,
		0xCAF8FE50D4F98C3BULL,
		0x0F02F92BA5D4D3DBULL,
		0xF2590CC883011ED5ULL,
		0x893A7F5B01E8ADFAULL,
		0x7A53CFBDD679084EULL,
		0x3673618CDA30922DULL,
		0xA2A7133584DA2E7AULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE47FBD8B3374996BULL,
		0xE2067A04B5248DABULL,
		0xD31BE6F9F38CF4CAULL,
		0xC57CCA47BF69F49BULL,
		0x0E12C11A190B2964ULL,
		0x0469237526BF9537ULL,
		0xF6C3EA06250FEC08ULL,
		0xD4FADBBC05E5AD57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97080368AC6CFAD5ULL,
		0x21DBB404FFAE4F04ULL,
		0x47B10DC082C08CF3ULL,
		0x1C0664AFB58E6FB6ULL,
		0xAB7FE127794235DEULL,
		0x98CF0FF7D1E24F20ULL,
		0xC9134AE815821380ULL,
		0xEB2E554FDEC07248ULL
	}};
	t = -1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDEFD66700E6484EBULL,
		0x3DDA61BCC5764A0CULL,
		0x6686CD52A500E57CULL,
		0xE51592FCD782F959ULL,
		0x9853634C187E82EFULL,
		0x6D90EBE428C82927ULL,
		0x718C5C2888298F09ULL,
		0x852CBB6F3EBEC173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x001FDAE32C21D896ULL,
		0xD383918CFBE24F0DULL,
		0xC70DD7EF28D054CEULL,
		0x94D6BCABED24D9E5ULL,
		0x87DC30D3CA8F653EULL,
		0x6A3850AE5C888FE6ULL,
		0xB02CA9EF2BF2EF30ULL,
		0xECD193A3325C6839ULL
	}};
	t = -1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEDC71809F1740F39ULL,
		0xE37404C19303C322ULL,
		0xD843767AF45885FAULL,
		0xD7C13C400DA0E26FULL,
		0xC7C555812DC057BAULL,
		0x903649399F439F20ULL,
		0xC532AED5EF44FDEFULL,
		0xD383D4F4A7C55605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x057E6EA38B6C7624ULL,
		0xCA87FCC0FEB67E4EULL,
		0x3263787A0E5FB443ULL,
		0x8CBE4A2C36D545BDULL,
		0xA44F2B45F7C1EB8BULL,
		0xF7DA28331667F410ULL,
		0xCBCC838404726775ULL,
		0xC1763BC66746C1F5ULL
	}};
	t = 1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0E26B7FA884D6303ULL,
		0x64AE2538F1EDC287ULL,
		0xD30F083BCB5710A8ULL,
		0x03F1C168C5215ADCULL,
		0xF7D1DE261B81A936ULL,
		0x224DF649D197125AULL,
		0x996BEF0B6AC2E673ULL,
		0xB31CB4E29B8F27A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E26B7FA884D6303ULL,
		0x64AE2538F1EDC287ULL,
		0xD30F083BCB5710A8ULL,
		0x03F1C168C5215ADCULL,
		0xF7D1DE261B81A936ULL,
		0x224DF649D197125AULL,
		0x996BEF0B6AC2E673ULL,
		0xB31CB4E29B8F27A5ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x360A219A4A44063FULL,
		0x2A80AF8A134A6398ULL,
		0xA95320BA0377259FULL,
		0x3C5BEE0F0D01CB4AULL,
		0xBBC7858313867C23ULL,
		0xFE8CABBFC952D6E4ULL,
		0xBAABB2FAACDF35E0ULL,
		0x3BC6C044A2FA0AA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C7D36B52DEE37A5ULL,
		0x995ACCE5A7C0C6FCULL,
		0xF3849E652F7575C5ULL,
		0x8EADA037CFD5BB88ULL,
		0xA0E7BD070C0FC33AULL,
		0x1924BB6B70467BBDULL,
		0x13852577DC2810BDULL,
		0x09895BF5C6279E22ULL
	}};
	t = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD7EE83035E714E13ULL,
		0x3F0945E977F15F99ULL,
		0x09970FB59CD4BADDULL,
		0x0B4A5DA533A9D9CEULL,
		0x1CCAF0D1F6458A30ULL,
		0x4F76AF4038CF0780ULL,
		0x67B76568897B937AULL,
		0x80BC885841ED1284ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0A7214ECCDEB85DULL,
		0xDA6A9E572B1016F2ULL,
		0x40EAB85B739EFE4EULL,
		0x60A4EC2E9AC1DAD8ULL,
		0x5BF056CD4FE69184ULL,
		0x9B6E8E45E3ABFA0EULL,
		0x64DBDFD0F260EB4EULL,
		0x761EDEC5EE932C61ULL
	}};
	t = 1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB15757E9C96C992AULL,
		0xE7A37A97CB76BF88ULL,
		0x080AE8A3F20C7EB9ULL,
		0xEF1FB2039578B2C4ULL,
		0x24373A14E3E206BDULL,
		0x469F69A106068E06ULL,
		0xD2B850DBB7DD3DC5ULL,
		0x7C9C6DB3EAF5254EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93D0BDDF28BAA381ULL,
		0xF66D93B4CC4C2489ULL,
		0x5BA0CC3F7C71B9C1ULL,
		0x80A4ABBE9AA12B58ULL,
		0x2F2A2C6ECB2A468AULL,
		0xBBA61E942AFA768BULL,
		0xC3B416CDB0E23C91ULL,
		0x0E898232D36518C6ULL
	}};
	t = 1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDD343744EDC65906ULL,
		0x6C03CD7F3DE32EEDULL,
		0x0C2B1452AEAABA73ULL,
		0x61BDEB47B5556FA4ULL,
		0x16B7E820C83477A9ULL,
		0xFA3C8A9958F4C6E6ULL,
		0xF86E873BE3340581ULL,
		0x644DD71001D08617ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD343744EDC65906ULL,
		0x6C03CD7F3DE32EEDULL,
		0x0C2B1452AEAABA73ULL,
		0x61BDEB47B5556FA4ULL,
		0x16B7E820C83477A9ULL,
		0xFA3C8A9958F4C6E6ULL,
		0xF86E873BE3340581ULL,
		0x644DD71001D08617ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAF3645F5804D21A5ULL,
		0xC774644528DCE565ULL,
		0x5457A99B8F5A6B30ULL,
		0xE290C14834676978ULL,
		0xB69063AD000A1EDEULL,
		0xAEAC665B56E97F75ULL,
		0xFACBC81AEA221217ULL,
		0x4A63E6FE4AD7D0E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5B668F34B01529ULL,
		0xC8909C6BDC7A0FE8ULL,
		0x9A4C5494CC10F89BULL,
		0x1F756407653EB35BULL,
		0x1456E096EDEA17B6ULL,
		0x40C8089EB5D045A4ULL,
		0xF8E54EC07F859E44ULL,
		0x7F7BF6CBE88D4A80ULL
	}};
	t = -1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD56B3E3D5F9F0843ULL,
		0x533E1EAAA36EDFC7ULL,
		0x70C71E05917800A9ULL,
		0x6393A40304C003ACULL,
		0x57668D59FC6F0F8EULL,
		0x0BFD853FCC8BC9D7ULL,
		0x0C8B67312613AF68ULL,
		0x4308CF91F276A26BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEEA8037B6B00F581ULL,
		0x7FF1F6F950F8DEF3ULL,
		0x441D1316C09FC830ULL,
		0xB3E12E01594342E2ULL,
		0xD94F72D4AEE7EF97ULL,
		0x12C98BB74E9CF377ULL,
		0xC29649D13F54630BULL,
		0x7E943123485D355EULL
	}};
	t = -1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAAB901F4FFBC08E1ULL,
		0x429703F2D5150305ULL,
		0x7867AC390B15F837ULL,
		0x3EEECF4729FB512DULL,
		0xDFCF106D9E5072D5ULL,
		0xB6521106E9170648ULL,
		0x41744110A9DCD452ULL,
		0xC94AAC22F273F1EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFDE81A77752212AULL,
		0x00A999A9B12EDAE8ULL,
		0xC64483724E6DD953ULL,
		0x3B856A6D3F81D05CULL,
		0xD327E78A5FE7AA0CULL,
		0x0EBFA789FB7F5BBFULL,
		0xD0FC1170AE3E0E2FULL,
		0x91D5DD88AFD77E64ULL
	}};
	t = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x172058EB96CBF267ULL,
		0x20544DC09DDA1F3CULL,
		0x32BCEB5634C91104ULL,
		0x208C5666F8B63222ULL,
		0x8532FFA236A3F4D7ULL,
		0x38A32A4C59035739ULL,
		0x530720458ED4F99DULL,
		0xC70CAC209C56D601ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x172058EB96CBF267ULL,
		0x20544DC09DDA1F3CULL,
		0x32BCEB5634C91104ULL,
		0x208C5666F8B63222ULL,
		0x8532FFA236A3F4D7ULL,
		0x38A32A4C59035739ULL,
		0x530720458ED4F99DULL,
		0xC70CAC209C56D601ULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAE4F22D0FCC4E7E1ULL,
		0xFAA0D4CC2F405151ULL,
		0x5F7938D2488D8DCBULL,
		0xF33B066D6B71D1E6ULL,
		0x24EF65E0C972062DULL,
		0x25BB551C92190C94ULL,
		0xF722C33FE5F85BE0ULL,
		0x3BFEC3E35C855B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x951DC6DF62AB27D3ULL,
		0xCDEFF8FF077C0964ULL,
		0x1FD10D0E6FFDC4C7ULL,
		0x3B291C1612285891ULL,
		0x0BB5DE6102CD0F22ULL,
		0x4488845EB6EA88F6ULL,
		0xC2F4BFF381944EE7ULL,
		0x0A41149F3ADE7A22ULL
	}};
	t = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFA00EE042438C5C3ULL,
		0xB5E7DA6C7F9DC016ULL,
		0x8206EEA8A2D294ABULL,
		0x8276CEB5606986F5ULL,
		0x6811FDAD88F9CC63ULL,
		0xA6F4310277197D3DULL,
		0xBCBE2AA8EFCC9181ULL,
		0x1091D11AB65AB4F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EFBBEC4A21A2491ULL,
		0xFF6C276B93E3E75EULL,
		0x8CEF424AEAA930E5ULL,
		0x8BCA184B130C5D36ULL,
		0xCEBFA71BC6712B37ULL,
		0x8DE64CA3787E770EULL,
		0x9C161C8A1C93B4B7ULL,
		0xE07E0F3DDF1C6A9CULL
	}};
	t = -1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8388FDFF9B29701AULL,
		0x2F96A5414ED4524FULL,
		0x3040D053B152C4F8ULL,
		0x9D104B22C727E138ULL,
		0x689551973D114266ULL,
		0x02C9C52CDA7BC03FULL,
		0xF467D9B859471AABULL,
		0xC17BF55E0534EAA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB7476DDF010DF48ULL,
		0x0F5B91124DBDCEA7ULL,
		0xD4EA7BA6DFB74F6DULL,
		0x51D61E19846EEB2AULL,
		0xBE5107C6AEE1E8B1ULL,
		0xEFF70AE75B0C7371ULL,
		0xD9D55D740A24D0FBULL,
		0x2AAA72A373F4EF9FULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA70AD086F79B6A00ULL,
		0x0E171858A64B4A41ULL,
		0x49D7076378A94F9FULL,
		0xBD0E5347DABAD96FULL,
		0x25BD0693CCAE8B2EULL,
		0x75B676B0A1DA21DCULL,
		0xE4DB0AC070DF6397ULL,
		0xEC527B9D014EAD92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA70AD086F79B6A00ULL,
		0x0E171858A64B4A41ULL,
		0x49D7076378A94F9FULL,
		0xBD0E5347DABAD96FULL,
		0x25BD0693CCAE8B2EULL,
		0x75B676B0A1DA21DCULL,
		0xE4DB0AC070DF6397ULL,
		0xEC527B9D014EAD92ULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x73D1C6D5EDB6A34BULL,
		0xF47CF4A4C80C42A9ULL,
		0x2DD4C75481B2FAA4ULL,
		0xA39E9C9C4F739222ULL,
		0x374C5A9BCAFB562BULL,
		0x8B233901080C654AULL,
		0x0334F79A759FC920ULL,
		0xE293167A30263306ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5DE4BD148EC5C9CULL,
		0xB46AE74C1F2192E8ULL,
		0x9D8387243BBCAA9CULL,
		0xE13A26F485AB9E1FULL,
		0xE7847E8430726058ULL,
		0xD35C7F3D0C9796BFULL,
		0x983816F0A251A257ULL,
		0x0BB3A166ECD785A0ULL
	}};
	t = 1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF1819ADB4CA505AEULL,
		0xA171600DEC135068ULL,
		0xF0D15E4B426AA70AULL,
		0x1468835F34143384ULL,
		0x9C296A5C02966B6FULL,
		0xCFE5CDDBA1D5FE3AULL,
		0x4B1CF6DF3E79FFB9ULL,
		0xB2936E91DD09DE31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD675B86CDA332BCULL,
		0x9E1FBD15C5F5584BULL,
		0x9525E42E29A12BF5ULL,
		0x71AF5353DF73FC78ULL,
		0xDB64E02E0623024EULL,
		0x465DF419825DF0B4ULL,
		0x78A9C198D296A774ULL,
		0xF5A84162DD235DDDULL
	}};
	t = -1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE527585F87746CADULL,
		0xDDC52C0D567B5AFEULL,
		0x8D8AD518F5E09590ULL,
		0xF30160F9C12F6709ULL,
		0xFCB0F08BC8333B19ULL,
		0x32CB516FD30412C9ULL,
		0x791BC3545102CE36ULL,
		0x37D041D2ACFAA748ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED98BBC5ECD4F745ULL,
		0x222F8E8D5E8804C1ULL,
		0xC2B86EFB00895FA9ULL,
		0x14845999F70B6025ULL,
		0xC18B1130D7B40838ULL,
		0x7F75B6DAF8B603B4ULL,
		0x85E0B84F30A991BAULL,
		0x4B509047995D0311ULL
	}};
	t = -1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAFD8DA6C0488189FULL,
		0xCE4F40BE8B4CCFCDULL,
		0x0F7D43CD97E2D7F6ULL,
		0x3024D86BC067C211ULL,
		0x96E993ED258A921EULL,
		0xDC356FB0E84C8038ULL,
		0xAB73500706115B53ULL,
		0x6BEB6D1FCBA8251EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFD8DA6C0488189FULL,
		0xCE4F40BE8B4CCFCDULL,
		0x0F7D43CD97E2D7F6ULL,
		0x3024D86BC067C211ULL,
		0x96E993ED258A921EULL,
		0xDC356FB0E84C8038ULL,
		0xAB73500706115B53ULL,
		0x6BEB6D1FCBA8251EULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC7F864DC2E976A77ULL,
		0x8AB55DC84B4AC664ULL,
		0x2CEFE0E0A34CAA08ULL,
		0x0C171E142B9A70EDULL,
		0xAC0EDC4012A08634ULL,
		0x64171161123DDA0CULL,
		0x255D3750403362F3ULL,
		0x6B0D7AC1F9C8700FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EF0267A55263CA0ULL,
		0x1A3AB4CEE6093E10ULL,
		0x82235C7BB26CF758ULL,
		0xED0A4F750A7756F8ULL,
		0xFB7D13E055C557E5ULL,
		0x6D17B7AF4D95A4D5ULL,
		0x2EA630D616A654B1ULL,
		0x1159EEC3B3CCD272ULL
	}};
	t = 1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAAC7C7199692CA59ULL,
		0xAFB0BB88AA1E9613ULL,
		0x4CD0DFD13C372806ULL,
		0xB6A02B8AFEB56D0FULL,
		0x3070A18FBA386616ULL,
		0x5961589C8389B4DDULL,
		0x5B34FBBBF70D98CAULL,
		0x6E6B829BBFEE3BEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EAA0EFCC97CF71ULL,
		0xF6B86EDD29CED47DULL,
		0x499B0BA4A21A1D7AULL,
		0xEDA288443B12A191ULL,
		0x76CEE2B30C8336CDULL,
		0xA7A951351FCDA34CULL,
		0x445E631652D9E221ULL,
		0x2D703BD85C8BD332ULL
	}};
	t = 1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x635F9384D65AC120ULL,
		0x7CE7A78CD14B932BULL,
		0xCC4B75771AB12EF9ULL,
		0x3C5D1C7D07919136ULL,
		0x8AA658F227A74991ULL,
		0x53EEA13D625D92C6ULL,
		0x810AE785521367DEULL,
		0xE76B02D89D2BD486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x606B4D91BC160DBBULL,
		0x89B36271057A9B1EULL,
		0x7676C2928896A2DCULL,
		0x304E3E7287E2046CULL,
		0xD833176D4D3FA996ULL,
		0xC024F115750C93DAULL,
		0xE56B6682CD00016FULL,
		0xEB7A74BFF4A48EFCULL
	}};
	t = -1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x24CC80502E283B98ULL,
		0x4200494F9CB313E7ULL,
		0xB744893D151B1A5EULL,
		0x3095A4B743EB4E60ULL,
		0xFD8EDE4EF086155CULL,
		0xE8F2CCD3185157A0ULL,
		0x3EB85BF28FE06BFCULL,
		0xCDC64714DA28177AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24CC80502E283B98ULL,
		0x4200494F9CB313E7ULL,
		0xB744893D151B1A5EULL,
		0x3095A4B743EB4E60ULL,
		0xFD8EDE4EF086155CULL,
		0xE8F2CCD3185157A0ULL,
		0x3EB85BF28FE06BFCULL,
		0xCDC64714DA28177AULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x570C9DD03C7EDDB4ULL,
		0x1609A80998C0FC23ULL,
		0x68595D4D6BC51941ULL,
		0x6C5EB59228A533FFULL,
		0xB69649F2E8D00A1DULL,
		0x52EF216A0A07479CULL,
		0xC793ADF750017954ULL,
		0x273A14EED2C9F6D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8F05B3DE477BA79ULL,
		0xD04CD67A7D5DD0B7ULL,
		0x6A10D020C31AA6F1ULL,
		0x851446010CE21E98ULL,
		0x25F20AC1170732DEULL,
		0xC2A077B55B9302D2ULL,
		0x9259BD43189BBA9AULL,
		0x4D139DA0C07CBC6AULL
	}};
	t = -1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB17B901942213249ULL,
		0xF22308EC5E1E2EA9ULL,
		0x5B29BF9EEE7FE3B0ULL,
		0x0AAED63D0C6196EEULL,
		0x86E47BC0207EF23DULL,
		0x4D4E042D89FEDAC0ULL,
		0x9AE4DA13561400D1ULL,
		0xB9150882763C7173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D61798DA480F1A5ULL,
		0x4386F10C075344C4ULL,
		0xF36800F49A900E5EULL,
		0x9C7483BDAF331828ULL,
		0x7A5C903A86A8577AULL,
		0xA78945E751872013ULL,
		0xA7A2C748C445CA70ULL,
		0xE6A86C6470897C26ULL
	}};
	t = -1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1D0F4D48C6ED5990ULL,
		0xF5DA5444538ABDEFULL,
		0xF0C2D1956B962E98ULL,
		0xA286BB3EC578BD52ULL,
		0xC833469D366C42CBULL,
		0xCF2D8250382D825DULL,
		0xE3C0E401F73ED244ULL,
		0xDC00A134F3A52309ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA884574CCD1BAF24ULL,
		0xB8C816CBC903B95FULL,
		0xA3C4FF423A013D56ULL,
		0x55CA35A7A83708F4ULL,
		0xA765D5FD3798B49DULL,
		0x8D54375AC3C8CEEFULL,
		0xCD1962A5DA7D58F5ULL,
		0x753F4B639BFB747BULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x49D07F2015C7D523ULL,
		0x31FFED2C3C9B21E8ULL,
		0xFFBAB20C959F0A2FULL,
		0x2CD6EA980F79B468ULL,
		0x7770ED1ECD6148EFULL,
		0x44AC9779947A0BD1ULL,
		0x27126B9D5D98E90DULL,
		0xCFED4FA1B248B682ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49D07F2015C7D523ULL,
		0x31FFED2C3C9B21E8ULL,
		0xFFBAB20C959F0A2FULL,
		0x2CD6EA980F79B468ULL,
		0x7770ED1ECD6148EFULL,
		0x44AC9779947A0BD1ULL,
		0x27126B9D5D98E90DULL,
		0xCFED4FA1B248B682ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x26990395803DFBFCULL,
		0xAC5A31AD756A9128ULL,
		0x2AB1337BEEA8CEC1ULL,
		0x32E6D99D566E4092ULL,
		0x4DEC94F885BC0AC2ULL,
		0xB2FBEDB4EA68CCA7ULL,
		0xF8B71A83E0A1E4CEULL,
		0xAA79694571E4163EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E7BE04CB6CDE9FFULL,
		0x38D928908F6F86A8ULL,
		0xA89BD0668393CC62ULL,
		0x291777FA6C2D5A82ULL,
		0xA257B2B39E2D8740ULL,
		0xF28C3671C34C301FULL,
		0xD6B636A0D6D08934ULL,
		0x5673E4EBBD4B4CE4ULL
	}};
	t = 1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAAEC9A8D1ABBA9CEULL,
		0xE8F21741813C5040ULL,
		0xAF060A61FED2C4E6ULL,
		0xB5A43BE212ACF46BULL,
		0x1B4C0720C98202CFULL,
		0x11FD92A13C956FC4ULL,
		0xF06355ADE7EDF753ULL,
		0xC584183CF4DFBE32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30A174C48E87F002ULL,
		0x7BDAFDB1D1622678ULL,
		0x40DE86573F675E0BULL,
		0xA9B6F07408411F73ULL,
		0x7CFA85EC75643419ULL,
		0xA96D13991806DBE0ULL,
		0xDF45F77A52886C25ULL,
		0x0AC9C62BF927AC6DULL
	}};
	t = 1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE3EBF8BE6BB7DD54ULL,
		0xD800B66B60F30F15ULL,
		0x6D1CE3D98ADD0CB9ULL,
		0x829CDB4077FC6FA8ULL,
		0xA5395AC6AD57C71DULL,
		0xF448DBC3759BBE56ULL,
		0x07A990F44FD59AFAULL,
		0xEE8524BC97BD8E65ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF894BC5F7929C969ULL,
		0x2D6BE46F6BDF91B1ULL,
		0xB2ADB37ABA4F2D24ULL,
		0x6904D2840210E830ULL,
		0x3E0A22BBEA18116BULL,
		0x2410797435A4B84BULL,
		0x0DF65853F1FDFA91ULL,
		0x048F22C43CE1033BULL
	}};
	t = 1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1253EBF414F1B807ULL,
		0x7B2B2A5AF7CE99A8ULL,
		0xA89B4CDB7D47B8D6ULL,
		0xB13F9C0008ACA09AULL,
		0x323754ED6D91736DULL,
		0xF89E1DF730800C94ULL,
		0x1D1468ABE3238C87ULL,
		0x8D507C14BEE84B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1253EBF414F1B807ULL,
		0x7B2B2A5AF7CE99A8ULL,
		0xA89B4CDB7D47B8D6ULL,
		0xB13F9C0008ACA09AULL,
		0x323754ED6D91736DULL,
		0xF89E1DF730800C94ULL,
		0x1D1468ABE3238C87ULL,
		0x8D507C14BEE84B29ULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x40AC94C34A44CBC1ULL,
		0x14E18465A3F8F791ULL,
		0x014433B2CC72E3EFULL,
		0x8F3F38684A154FC6ULL,
		0x9A2A659399F8406CULL,
		0xE8DED7D445CFD25BULL,
		0x35B31F905EFD5BE1ULL,
		0xF08C8B189F379A74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF7B3DD31F7A677FULL,
		0x578963E10E43BB9DULL,
		0x39249DEE9BC00371ULL,
		0x645C26CA8D07BDB8ULL,
		0x53C38BA928788DA4ULL,
		0x232837A388698725ULL,
		0x4BCEC6BB97E2E856ULL,
		0xD097EC8F9CBCEC35ULL
	}};
	t = 1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8FB9CBB932396813ULL,
		0xB9EAF2B6A3BF8830ULL,
		0xCCA43ED7F8FCB8CCULL,
		0x88C493D9FC91470AULL,
		0xAB5623583897D193ULL,
		0xC4E1E3612D040EFAULL,
		0x2CE5DD02474CEC0CULL,
		0x0A11A72E3A453952ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CA348B5542BC235ULL,
		0x35AE1916D550DD32ULL,
		0xA5045666C551C791ULL,
		0x694412DF5B84D4E2ULL,
		0xA5052DE1F3E82210ULL,
		0xAC52FDDBA5EB8EE0ULL,
		0xD8DE31D57C59CC6BULL,
		0x57445B1D75C67EB7ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5427D96816B9784DULL,
		0x1E1F1411BE0B81CCULL,
		0x0296E8E70526C179ULL,
		0x5C391C4471267D01ULL,
		0x382E4BEA3E2533E7ULL,
		0x2ADEF61AEF402ED4ULL,
		0xD87180FE5B54C5B3ULL,
		0x7EE44285737918E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDEE35AE1095084CULL,
		0x9F69C54AD9B2CF41ULL,
		0x52308140634911CBULL,
		0xCCF93AE658570CD2ULL,
		0xE4F9CAA2766D4660ULL,
		0xED9C5897BAFE537BULL,
		0x689DCEFA771F9DB5ULL,
		0xB22BD5DB3BDD55F0ULL
	}};
	t = -1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE51DF69CFEE20B0FULL,
		0x789E870FE7115202ULL,
		0x010B184E142C61C0ULL,
		0x44CC9FF6577580CFULL,
		0x20BCDF0B65BA4DC3ULL,
		0xC79C9F86E8B34F7EULL,
		0x308472AAE83F7B0BULL,
		0xA2DDBAA4D13A9C73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE51DF69CFEE20B0FULL,
		0x789E870FE7115202ULL,
		0x010B184E142C61C0ULL,
		0x44CC9FF6577580CFULL,
		0x20BCDF0B65BA4DC3ULL,
		0xC79C9F86E8B34F7EULL,
		0x308472AAE83F7B0BULL,
		0xA2DDBAA4D13A9C73ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x92F3C59A77B80C30ULL,
		0xFA862A7145B190B0ULL,
		0x225EDA62A4845835ULL,
		0x6770C5ACCC993D86ULL,
		0x9AA4AD6DDD52994FULL,
		0x51E8F174DBF7A84AULL,
		0xC6798B7538B2FF69ULL,
		0x96D6619ED763C70AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ED2A94E51E7A251ULL,
		0x4126FC2220AD6457ULL,
		0xABDDF29ECD84C772ULL,
		0x1FC613462FD79AD0ULL,
		0x12CAC336CD028342ULL,
		0x2431F19F86360C05ULL,
		0x01EC55E34540FD8EULL,
		0xB07B743ADA36565CULL
	}};
	t = -1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x738A77DD8D9C912AULL,
		0x8042322757103894ULL,
		0x465E5F25AC87A75FULL,
		0x8FAA28CE69D6A4CBULL,
		0xB1B29EEA216C5337ULL,
		0xB990DF845BFB7E5EULL,
		0xEE22FDFB3823FED9ULL,
		0x6079EBA9A8112798ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1112507E4AEF76AEULL,
		0xFF5C51C97F60D07BULL,
		0x36907DC3EBADDF2CULL,
		0xB9C9CC0F02ED6DD2ULL,
		0x639AE356513970C5ULL,
		0x67F197E34AD621DEULL,
		0xFC3ED1968BEE7082ULL,
		0x4FA9AF3CFCA360CBULL
	}};
	t = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x476AB9E16B720963ULL,
		0x5ECB3FF31271E5F8ULL,
		0xB2AFD857BA5C19A8ULL,
		0x0D2C3A07FE396CE2ULL,
		0xA1261465E14901AFULL,
		0x0D41B8343F2DED0EULL,
		0x33FE3F224C27D778ULL,
		0xFC9BE85977FBD803ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07685CD4209D79BFULL,
		0x3D6CF636E4D8A464ULL,
		0xEB3DE755ADF3F1F0ULL,
		0xFD931B002B44ED78ULL,
		0x9E82E5EAE0A2F511ULL,
		0xA8EF399BB5174733ULL,
		0xDEBAC84487743EAEULL,
		0xAFDF0B6FD8A8E658ULL
	}};
	t = 1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAA5FD0F5CE889606ULL,
		0x7C07FF4445D560BCULL,
		0x4344B51978D2B514ULL,
		0x7F128B42751C818CULL,
		0x7ED4BB84E454749AULL,
		0x0B9421E0E24B4F34ULL,
		0x441D7B0FE7A1CD3BULL,
		0xF44C6940CDF6BC95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5FD0F5CE889606ULL,
		0x7C07FF4445D560BCULL,
		0x4344B51978D2B514ULL,
		0x7F128B42751C818CULL,
		0x7ED4BB84E454749AULL,
		0x0B9421E0E24B4F34ULL,
		0x441D7B0FE7A1CD3BULL,
		0xF44C6940CDF6BC95ULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2553F04EE4C79E1AULL,
		0x935D7D6B992AB7C0ULL,
		0xAB05196CB3C9B355ULL,
		0x013B02F7A93D3411ULL,
		0xDFD82D49F0D21FDCULL,
		0x4350A3EEA9957578ULL,
		0x6CF861855BDA7F04ULL,
		0x960D27AB515A3605ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75D551FC3C939282ULL,
		0x9C7FD62C51E8E0E2ULL,
		0x91FD988155D829D9ULL,
		0x5C63E1916CB604C1ULL,
		0x61A2E8FD527A79B0ULL,
		0x58C96F55E2407335ULL,
		0xA989A2B2867FDB4DULL,
		0x743AF0101442AA56ULL
	}};
	t = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE0D23575AEB1F6ADULL,
		0xC896FD712ECBC54EULL,
		0xC435BDA9C9180246ULL,
		0xB6CE2E35016F035BULL,
		0x4A12791AD543E292ULL,
		0x378B1A4EB70D5A6FULL,
		0x91B1D760D7816941ULL,
		0x68BC9E92B65FE878ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2868A1D12BB7D82FULL,
		0x1ADAABB54E189FA0ULL,
		0xB8B1FEA123429477ULL,
		0x2806BF240190E688ULL,
		0x0BD03C1206AD9D8AULL,
		0x6EB8AD78C0DF128CULL,
		0x6F7D3BB40EADC214ULL,
		0xCF765A39A3EB960BULL
	}};
	t = -1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4CA2F15D7CFDE62ULL,
		0xA77CEF515BE0BFAEULL,
		0xA2922ED3CD41422EULL,
		0x06A60DBDD7E32AE1ULL,
		0x81C646C4312C4F69ULL,
		0x561E3330566BB83DULL,
		0x5A427AF9AA62C828ULL,
		0x9EC895E93B46EDDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x640A8065B60ABDE4ULL,
		0x0186E8F1834662C1ULL,
		0xD9D7C7CB63681F31ULL,
		0x0A0E12EC13E9FC0AULL,
		0x5E82421DED484E6AULL,
		0xA665B949E7EFBF24ULL,
		0x77958673D055A084ULL,
		0x756740D432FEBD16ULL
	}};
	t = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x60FA766C6981C042ULL,
		0xC1316BBC1D070026ULL,
		0xC480B437D7B2587BULL,
		0xA4F4ED7AF98A840BULL,
		0xE6C6BA131DCC0DB8ULL,
		0x688A9CC36F8214B6ULL,
		0x99FD278EF0F51170ULL,
		0xF2459DB42AB161E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60FA766C6981C042ULL,
		0xC1316BBC1D070026ULL,
		0xC480B437D7B2587BULL,
		0xA4F4ED7AF98A840BULL,
		0xE6C6BA131DCC0DB8ULL,
		0x688A9CC36F8214B6ULL,
		0x99FD278EF0F51170ULL,
		0xF2459DB42AB161E6ULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA60D03EB7F9C12BFULL,
		0x527B1541D87D274FULL,
		0x8E4CBD5A0589260FULL,
		0x3546AA29F7D94D63ULL,
		0x02DA3993CB9DE582ULL,
		0xB1BE845DE760A17BULL,
		0xDF6DF14893990FCAULL,
		0x8D1352B544821EB2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x924AA950DDFBCBA7ULL,
		0x44A465A21DE177FDULL,
		0x530D6C1BA7362914ULL,
		0x75688D0C0759F54AULL,
		0x1BCD1A054473A54EULL,
		0xD73E0EEEDD3C5644ULL,
		0xB6E715ACCD354B61ULL,
		0xA022C23A6A121638ULL
	}};
	t = -1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE70155E209B14CDFULL,
		0xB24417D388F3B75CULL,
		0x4BCEC62CA0959789ULL,
		0x01BBED70DBE164E9ULL,
		0x953EF09A0A82B84AULL,
		0x5DDE7E3381EB8E74ULL,
		0xDD70649B79757D21ULL,
		0x5C8C9ACE69E32F32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF08DCC18EEBB8DB6ULL,
		0xAD5CA8F829A8A50CULL,
		0x9447FF45C09252B8ULL,
		0x9ADB8F92D8E2C35AULL,
		0xC5AAD021C7985274ULL,
		0xCA781DEB2441B179ULL,
		0xF0F7A1BBB0749C6FULL,
		0x548409AA84C2748AULL
	}};
	t = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9EDE578AFFF387E0ULL,
		0x26564314B39D0C43ULL,
		0x804122BA8E18864AULL,
		0xC36BE58FA40C8DFEULL,
		0xC4DF4DDC2C650F29ULL,
		0xF0294EB71C7439DEULL,
		0xFB5E2C6C97222826ULL,
		0x109609B3851688A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4792105CB4DDABF7ULL,
		0x677C8DF5B63913CFULL,
		0x3A6E846AF0B109EDULL,
		0x3F3A702D6871E479ULL,
		0xFA4AA7943E001A7FULL,
		0xF1C5D4D74A9BB6D9ULL,
		0x248D9FBAD9E21C70ULL,
		0xDE29EAB943A4C077ULL
	}};
	t = -1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x740965E8FCEAEC58ULL,
		0x82386A1400CE0386ULL,
		0xDE5789C9AB7D7A34ULL,
		0x14BAB05E1A220160ULL,
		0xD0A77D9BEADC5001ULL,
		0x6F69A1079879A5DBULL,
		0xB87E8410399F906CULL,
		0xE9BFE6D20A165B86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740965E8FCEAEC58ULL,
		0x82386A1400CE0386ULL,
		0xDE5789C9AB7D7A34ULL,
		0x14BAB05E1A220160ULL,
		0xD0A77D9BEADC5001ULL,
		0x6F69A1079879A5DBULL,
		0xB87E8410399F906CULL,
		0xE9BFE6D20A165B86ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA001293FDBEDE00BULL,
		0xA6B3236E20275FC4ULL,
		0x7EE531C19FBA12C6ULL,
		0x1446F5B4897DCB5DULL,
		0x6AF828D805F5494AULL,
		0x0FAE7F2053F62692ULL,
		0xD7459E267B47C0C0ULL,
		0x81E12620FE57AD42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4173C6423357B13ULL,
		0x7520E6A356CD2FB9ULL,
		0x7CD90E39BEC429E3ULL,
		0x5E629AA89660831EULL,
		0x18E248E4E0EC61C6ULL,
		0x9ECEA18F2EA54063ULL,
		0x8D09A13B4E5ED4EBULL,
		0x28366AA3AF65FCE1ULL
	}};
	t = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE14D52FBB30689DCULL,
		0xB5901A9C50727D9BULL,
		0x580D9C6D219A8838ULL,
		0xC3F1052266099640ULL,
		0x0DEDFF9BADA681BEULL,
		0xAF848009CCFD0603ULL,
		0x6B517761C6A36AC1ULL,
		0x3F2542E5F8F12BCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EAF0F725B995EE4ULL,
		0x2C270DE8032F1F2CULL,
		0xBFFD6104D9CBF6DAULL,
		0x7071FDD398043FEBULL,
		0xC788548A5CF4EA0EULL,
		0x414E15655EA1B5A6ULL,
		0x536327427E33C73EULL,
		0xE03EFA8670306612ULL
	}};
	t = -1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF9FA1BF403B3C6C7ULL,
		0xA452A7F532EA1EA4ULL,
		0x5B3E75E855447928ULL,
		0xF0F82F91A32287B8ULL,
		0x4B20E4C0FDA69AEDULL,
		0xFA18FA1BB9441283ULL,
		0x0DFA1B7851B4BB00ULL,
		0x6B41867CEC1F782DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B6CBE645CD0D3D8ULL,
		0x0BF4178108EB7672ULL,
		0x6EB2C836DBCE8602ULL,
		0x8B9D7BEFB75E73C9ULL,
		0xBF24CABB585CE6B8ULL,
		0x72C9531EBA267859ULL,
		0xDD484B10FC9E9FEAULL,
		0xBA6464C0285AC18DULL
	}};
	t = -1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x058ACDCE9DBC4EC1ULL,
		0x9B817BC97C56DB0AULL,
		0x46A1BF4C49170BFFULL,
		0xD909D45B0F476600ULL,
		0x7B9196A5D10BDC1FULL,
		0xA25A2F6B75DDA310ULL,
		0x97B60333A43E54CEULL,
		0x20A79D5CBD93F651ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058ACDCE9DBC4EC1ULL,
		0x9B817BC97C56DB0AULL,
		0x46A1BF4C49170BFFULL,
		0xD909D45B0F476600ULL,
		0x7B9196A5D10BDC1FULL,
		0xA25A2F6B75DDA310ULL,
		0x97B60333A43E54CEULL,
		0x20A79D5CBD93F651ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4D1737F6B55E644DULL,
		0x96E6ECC36D39BFF4ULL,
		0x6F6188CD4ADA7E87ULL,
		0x17F5950CE74D483FULL,
		0xA4A0C4662006B27BULL,
		0xC92752BD723D9665ULL,
		0x40544A5FC6FE4B07ULL,
		0xED5CEF25B45F8086ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF9DBDB8BC3B0DCULL,
		0xA316142D62651F5BULL,
		0x3124C3F1EBA8B1AEULL,
		0x7E16FF42CD269012ULL,
		0x7E0CA4FC204F97C1ULL,
		0x13694C67B18F582BULL,
		0xA49C8F2615BC23F9ULL,
		0xD51BD6224AB752C4ULL
	}};
	t = 1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2D19334F8513584CULL,
		0x31D58B027C51E1A8ULL,
		0xF1A88846F41F1B69ULL,
		0x430157B06D10A14BULL,
		0x9F253479FB64436AULL,
		0xFB64AE17F40C47B8ULL,
		0x53766A7D854026CAULL,
		0x45932FF2B8379F9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2267B291CBE7FE32ULL,
		0x23FAE22656F32128ULL,
		0x7A3A406BACBC9B7FULL,
		0xD47F5220DDB5A32BULL,
		0x5347747F0FC1F3B1ULL,
		0xC444C19471C61484ULL,
		0xE57232F8522A6E7DULL,
		0x5EBA83D229A08150ULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x17DEC0BF354858A8ULL,
		0x38C7321609910A1FULL,
		0x2B97467C69D6DDD5ULL,
		0x211C3E1183C8B091ULL,
		0x92730B54FFB284F3ULL,
		0x769EBA52C17BC753ULL,
		0x2D3B47545FB0F03BULL,
		0x0941291362CFF446ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0039B94E8E2DA9EFULL,
		0x4AF920EDC8AECD94ULL,
		0x18A6C1E4C2F9A690ULL,
		0x49FD4B404FB3E06BULL,
		0x55DCB23EA4181159ULL,
		0x35462A1B74C6F1DBULL,
		0x3AD22692F6035C75ULL,
		0xF29C607E106E4091ULL
	}};
	t = -1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDD05C531CE52F439ULL,
		0x886A2C4E9F89CA9BULL,
		0xE5B3AC36A232809EULL,
		0x300CACD509AE8BB8ULL,
		0xB9544A484D903689ULL,
		0x308B8974A37843A0ULL,
		0x15D88355F99CB50EULL,
		0xC492F005576D9932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD05C531CE52F439ULL,
		0x886A2C4E9F89CA9BULL,
		0xE5B3AC36A232809EULL,
		0x300CACD509AE8BB8ULL,
		0xB9544A484D903689ULL,
		0x308B8974A37843A0ULL,
		0x15D88355F99CB50EULL,
		0xC492F005576D9932ULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x16BBACE152292247ULL,
		0xF23F12121F4F2988ULL,
		0xF620F5DDC11E5BD2ULL,
		0xCDF3EBA34709F4E8ULL,
		0x98A0DF2E23E98056ULL,
		0x27D6358462280094ULL,
		0xA6523880BB379CE1ULL,
		0xBEC3C9F6F02A32F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AE880A9EC5B0EFCULL,
		0x7EAA595E6DD97281ULL,
		0x468CA9D275F1C335ULL,
		0x266EBD8574EE8201ULL,
		0x56C44542036AE3ABULL,
		0x80793105F22E08FDULL,
		0x789E5FE796E2CA60ULL,
		0x52C95B4A33B8688AULL
	}};
	t = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x78D24B3B0836170AULL,
		0xD53C504756CFE5B5ULL,
		0xE80133A30C64F229ULL,
		0xF2A8E2563F9B4D79ULL,
		0xF699F3A343756222ULL,
		0xF4D58DCDEFE01FD1ULL,
		0x50780AB4863E71C2ULL,
		0x797720660A9B2DD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D8920B3CE26861BULL,
		0xF9AB8CD9E929D7CFULL,
		0x48E696C7AC299582ULL,
		0x0F45729E52FE992CULL,
		0xEBD184C80D3D128AULL,
		0xDD7CCCC17816C3BFULL,
		0x00D93C11FAE1422DULL,
		0x386BA7524BFE1E65ULL
	}};
	t = 1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA558F8E43AA71DECULL,
		0x8D83942EB966B4BFULL,
		0x3ADE2A4E937AA334ULL,
		0x750293CAEA29FBAAULL,
		0x40415093919E198AULL,
		0xF2216508DC8465D8ULL,
		0x76027EE048A49DDAULL,
		0x7A9518E61C395A89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x403B309E085162F0ULL,
		0xD27F3AECFB05B28AULL,
		0xAB81BB400D972B91ULL,
		0xC00B873C7A4B8839ULL,
		0xE32796E07A919B6FULL,
		0x7A2DFBC596BFBE4EULL,
		0xB0FAAE1CC3B50C21ULL,
		0x85FCB225856FD599ULL
	}};
	t = -1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB78D7D7EBE0BCDC5ULL,
		0x716C08642B4ACA37ULL,
		0x832B68EE85520127ULL,
		0x7071FEAC3027BDFDULL,
		0xACE342AD5EA7D88EULL,
		0xC4DB33D45A4D3600ULL,
		0x49FE43DE50069EE3ULL,
		0xBE26AE4C9C6FE6B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB78D7D7EBE0BCDC5ULL,
		0x716C08642B4ACA37ULL,
		0x832B68EE85520127ULL,
		0x7071FEAC3027BDFDULL,
		0xACE342AD5EA7D88EULL,
		0xC4DB33D45A4D3600ULL,
		0x49FE43DE50069EE3ULL,
		0xBE26AE4C9C6FE6B2ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFD4721740B4C02D6ULL,
		0xE59C57F876C86A8FULL,
		0xF3B1B4A69E2F2934ULL,
		0xB5F17405FAEB9780ULL,
		0x2B03DC5DCDECFA5DULL,
		0x5402741332B15BE6ULL,
		0x0FC67F69D6FFD667ULL,
		0xE13AB114C319464EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F42BD75A41AF40FULL,
		0xE763ED1325F8D00BULL,
		0x1F5B278B526641C3ULL,
		0xF8D515049B6CAC40ULL,
		0x968DB67AB5DC23DDULL,
		0xDFA4B4F1069C5107ULL,
		0xACA74DA2E0A6E001ULL,
		0xB6AE5BF4E217871EULL
	}};
	t = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x35581CB4D7043B40ULL,
		0x612A0A2356BA62DAULL,
		0xB0C7BB7588970E6BULL,
		0x28BA2BDE3BE2D444ULL,
		0xD7D4ED421593BA47ULL,
		0x9EB131AC7A8A9356ULL,
		0x1108307771959B58ULL,
		0x08C1546F5D11280AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C50F2CAEF875D28ULL,
		0xB147964388BE4BABULL,
		0xE956FB6FE3326A3EULL,
		0xEF3FC4F0F1B2D87CULL,
		0x494D7EC77F673347ULL,
		0xEDA55E6E3D1F48E3ULL,
		0x85C4DD5D40E06C4CULL,
		0x67EF29BDA95E60F0ULL
	}};
	t = -1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xECCE8FF8632C059EULL,
		0x3B7A4CC978D112A5ULL,
		0xAAA032F90AD30A8BULL,
		0x7BBFE44A62CA0859ULL,
		0x0B735DDA8C9A4835ULL,
		0x0A3B1525F4F8D768ULL,
		0xBEDA75BE826D8FFBULL,
		0x44984E958B7B64EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x863F10F310B62F19ULL,
		0x14DC93B276B908D4ULL,
		0x66FF77C3DEBAAB3BULL,
		0x9E30CD624423FEE0ULL,
		0xD6F9BD63B910576AULL,
		0x20B6CF35FFE63EE3ULL,
		0xEB883FA282AEC3FCULL,
		0x26B9B21F5CC521A2ULL
	}};
	t = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1D8F0078CEC97ADBULL,
		0x311906138484C701ULL,
		0xF29F3D1304CCDC04ULL,
		0x11899D90AA3AB68FULL,
		0xC21CEB2C42E50853ULL,
		0xD83ADCA04AC02B7EULL,
		0xE3996FD992B9469DULL,
		0xEA813F54604CEDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D8F0078CEC97ADBULL,
		0x311906138484C701ULL,
		0xF29F3D1304CCDC04ULL,
		0x11899D90AA3AB68FULL,
		0xC21CEB2C42E50853ULL,
		0xD83ADCA04AC02B7EULL,
		0xE3996FD992B9469DULL,
		0xEA813F54604CEDB0ULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1DEE0F5424FEABD7ULL,
		0x0501006BBEEB5AC7ULL,
		0x8A660DD1D672E8FFULL,
		0x8026CAD9CF72DE36ULL,
		0x91D2E3E7D30F5BD2ULL,
		0x46630338F7AD96C7ULL,
		0xCE5E3CE0CBE290FEULL,
		0xF90710DC83A53CC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCD55BBA823555FFULL,
		0xA3772B999617569FULL,
		0x40D570F8B824BB3EULL,
		0xBDB2F411FF1EEB32ULL,
		0x88E0792CE9EC812FULL,
		0x6F0533F307391523ULL,
		0xC5B0F3BA818F3335ULL,
		0x4218B31F70AE2D4AULL
	}};
	t = 1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x80DEF7D79A641B2AULL,
		0xEFD4E9B7301B7810ULL,
		0x0B706F42E3C41169ULL,
		0xE2453F7B7D45358DULL,
		0x12A4F4B41574F488ULL,
		0x205FA40A59B62754ULL,
		0xE9012EE420763294ULL,
		0xABFA7C03B596AF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2510908B5E05B46ULL,
		0x42D386FF790C3D00ULL,
		0xBB06EDB40363899DULL,
		0x70366FA89D67B6C0ULL,
		0xB61BB48C9E141090ULL,
		0x4FF3E940712A1F6AULL,
		0xA2EF9E2924FB77C3ULL,
		0x16C3CA1CC091B621ULL
	}};
	t = 1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDB616D7A1C183CB1ULL,
		0x4A1B1B491EB5032BULL,
		0x3E1E9DE20067BDF9ULL,
		0xA8C07B587465FBEBULL,
		0xD90E7B05BCA40D7CULL,
		0xF94CC61A51BD17C3ULL,
		0x5AB1BB506CCB7781ULL,
		0xBDBF1B7449F8C4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x448D5EEAC3AFF0B2ULL,
		0xE1C5C1439A29994DULL,
		0x11393393F0D77E49ULL,
		0x8733ED1929C44490ULL,
		0x133B5BB23F7CD7C7ULL,
		0x605743B67A4AEB6CULL,
		0x2EDA622E622E0A1DULL,
		0x7E14711F3423E9ABULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7DB39342000C448DULL,
		0x00478F8CAB91165FULL,
		0x4F347EB921363DD4ULL,
		0x6E4412594A466201ULL,
		0x264EA3FF86F1D41BULL,
		0xB64E3D38806FF0C6ULL,
		0x4EE54AFBDD682CB8ULL,
		0x6FC6DAFFBECFEECEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DB39342000C448DULL,
		0x00478F8CAB91165FULL,
		0x4F347EB921363DD4ULL,
		0x6E4412594A466201ULL,
		0x264EA3FF86F1D41BULL,
		0xB64E3D38806FF0C6ULL,
		0x4EE54AFBDD682CB8ULL,
		0x6FC6DAFFBECFEECEULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x543337126C368176ULL,
		0x2DB5C70C56F3939FULL,
		0xD1DB31C1FA65C63CULL,
		0x41DE4D87BBBD361EULL,
		0x81DA2FAFDC8E6740ULL,
		0xE6966D71CFEF895CULL,
		0xF59BC24724FBF9BCULL,
		0xBC3C4AB57AD4C42BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CD3597982135CACULL,
		0xB6AF1ECD5FAAF300ULL,
		0x84E0FFDD23A2ECC8ULL,
		0x1DB1C07C71C2490DULL,
		0x515EF2908335F2CEULL,
		0x64BCE0450FE7D132ULL,
		0xAB1B9B1B85D2B67AULL,
		0x04E10C84FFBB6036ULL
	}};
	t = 1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2CB542F0C237588DULL,
		0xDE41E2916E5CB0E1ULL,
		0x4DA96B8EAC462467ULL,
		0x7450D23B48842458ULL,
		0x00FBC052BC7C5DFAULL,
		0xB04D87D9524A7465ULL,
		0xAA282D1A4B3EB084ULL,
		0xEECB8A4EBCBC5980ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF5CB022ADD70338ULL,
		0x018DF462193306CFULL,
		0x3C11C48FACF6975BULL,
		0xE36F42C5715E1F8CULL,
		0x266819D25857036DULL,
		0xB2F97B662229856AULL,
		0x7931F64381C7A52FULL,
		0xF3C784D02B9AFFE1ULL
	}};
	t = -1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE7BF701105795F81ULL,
		0xB287185A63D121B2ULL,
		0xD3540E83E0A243FFULL,
		0xE4F9C6ADE6D390F6ULL,
		0x870C969CCBD657E3ULL,
		0x8A5D82B5B74A487DULL,
		0x41CDB2910A664E70ULL,
		0x367F4F41F8B4400BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB58B44D3121CB6AFULL,
		0x77CD5678DB0EA283ULL,
		0xBB5FAA0F7F117BB2ULL,
		0xDB742D7B5B00AD41ULL,
		0x5487D68CE3D5DC82ULL,
		0x85A4D6AA22E2B56FULL,
		0x7B11FD0A7136D7DEULL,
		0x710C232738DED912ULL
	}};
	t = -1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD0FA0382F539ACA0ULL,
		0xD2498EF1DF822140ULL,
		0xD398860ACF58F793ULL,
		0xD15E3594991E2472ULL,
		0x1B522FD49C69B5B9ULL,
		0x69AA652B26138ACAULL,
		0x35988B03E3985E57ULL,
		0xAF582DDF6E409052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0FA0382F539ACA0ULL,
		0xD2498EF1DF822140ULL,
		0xD398860ACF58F793ULL,
		0xD15E3594991E2472ULL,
		0x1B522FD49C69B5B9ULL,
		0x69AA652B26138ACAULL,
		0x35988B03E3985E57ULL,
		0xAF582DDF6E409052ULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6CE4D939FF4AC97FULL,
		0x3E0CF3DBC221B565ULL,
		0x4AE3968A3D4AD36EULL,
		0x63AA5F525106A7A0ULL,
		0x351A8DBE550158A1ULL,
		0xB8403C47B9CE8087ULL,
		0xDCFA4B3A314D5A47ULL,
		0x26F21AF87E6B1B35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F2E8E90B7978505ULL,
		0x4F2EEF428A6DCA1DULL,
		0x85FF7EFB95AC47E1ULL,
		0x44A7EA755F477E22ULL,
		0x5488606FBD37DCA9ULL,
		0x7FC04FA843DD1AB5ULL,
		0x2A7A60BEBD9D7474ULL,
		0x9CD2AF6CF4C57D46ULL
	}};
	t = -1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE355019AEC7E5089ULL,
		0x496A65C5A92771C0ULL,
		0x3F06D0E45758AD0FULL,
		0x81A755E98AE1F528ULL,
		0x4429EEC2C95439E7ULL,
		0xEAD1ED13AB64D7FAULL,
		0xDBD4E98C7293E879ULL,
		0xCF03090EDBB4999AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01666E2E41715A4DULL,
		0x80C4EBB887987767ULL,
		0x41B5DF5B2C673395ULL,
		0x27F173CFF60ECA1AULL,
		0xE0D0EC13422515F9ULL,
		0xF2F9C28D8FF9E191ULL,
		0x5DB209A8EBE71241ULL,
		0x93843F0CAB3A4145ULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x07340238B5731D2DULL,
		0x7D1ADDCC8934E13EULL,
		0xF654059EA5F043A0ULL,
		0x1798F802453360A3ULL,
		0x1853F58FE620C3ECULL,
		0xE4B094859F457290ULL,
		0xDE95A43724EBF878ULL,
		0x62AEB14D1C3ECE89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87B5A819912CA9F0ULL,
		0x4EC5F2CE45FA3FFDULL,
		0x8AC7DD33F82FB523ULL,
		0x750D162FF9726217ULL,
		0xF0878352D8943004ULL,
		0x6E0BFFB984FAB16CULL,
		0x85D1F9A8A2391E73ULL,
		0x774FF9EEDCB3B15CULL
	}};
	t = -1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1E32ABB65C3D4D49ULL,
		0x34B4D4C626132B79ULL,
		0x01565EAA28EC111CULL,
		0xC8D2EE0BCC89F9EBULL,
		0xB80EA7B8895414FAULL,
		0x52071694225B38B7ULL,
		0x6904F377086D7C1FULL,
		0x9407507A85B3EFECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E32ABB65C3D4D49ULL,
		0x34B4D4C626132B79ULL,
		0x01565EAA28EC111CULL,
		0xC8D2EE0BCC89F9EBULL,
		0xB80EA7B8895414FAULL,
		0x52071694225B38B7ULL,
		0x6904F377086D7C1FULL,
		0x9407507A85B3EFECULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7E28A9697E1BCB92ULL,
		0x8C7A41338B86E46EULL,
		0x61CDB018CFC51A54ULL,
		0x8F57215B290C5584ULL,
		0x70562DD7432089DCULL,
		0xFF1C9B87433033AEULL,
		0x9B876D2429834FA5ULL,
		0x126318D91998A319ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4BD734A358041B7ULL,
		0x7A4ED70F3A45CDE9ULL,
		0xC30394CC02A98607ULL,
		0x61AED5FBF4DE9B48ULL,
		0x59B62FE2D47E38D6ULL,
		0x3956D7029F19B9A4ULL,
		0xFA34AC1F36B1EF78ULL,
		0xE19F56392F0B3A8EULL
	}};
	t = -1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCE8AA46E4E44E57FULL,
		0x8B77834617D6684DULL,
		0xEE6000D70B1134C5ULL,
		0x5F1DB5B2976CD847ULL,
		0xBD1E84587893F66CULL,
		0x2B91D4F8CB970070ULL,
		0xEDD4A95E62A4CD6CULL,
		0x023361CE64C23DB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x124BDB0E6725BF72ULL,
		0xB671A4C1975FED2EULL,
		0x5E222B58D4D787F1ULL,
		0x7AEAE83359963A2BULL,
		0x3F7E81623190FD74ULL,
		0x815E0A500146D737ULL,
		0xB31AAB5B1D16AD58ULL,
		0xA3376A2C0F2992A1ULL
	}};
	t = -1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x482633C97D279D86ULL,
		0x77ABACF93C7A5ECAULL,
		0xD339E13283C5E704ULL,
		0xADAD5F133A6BDA30ULL,
		0x0574408A4A4AAB5AULL,
		0xC8754653653FA665ULL,
		0x574EBE152B724854ULL,
		0x7FBBB3ACDD382BD2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x363E68B301AC6CF1ULL,
		0x24A9FB66B12EB1CCULL,
		0x87AD25FA1B047356ULL,
		0x5C6054BB0DDCA446ULL,
		0x7882DA283A912057ULL,
		0x480626E316673AF3ULL,
		0xEDADF7221B7EAA34ULL,
		0x90E357238C1A30B8ULL
	}};
	t = -1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8026871C85D3D08ULL,
		0x15F8F248E3D4CC77ULL,
		0x89F652E660039CB7ULL,
		0x57295A538547D86DULL,
		0x79478C8791EB95F0ULL,
		0xA2CC5EBB2EF571E1ULL,
		0xD5EE71343452B75CULL,
		0xDB3A63191D249275ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8026871C85D3D08ULL,
		0x15F8F248E3D4CC77ULL,
		0x89F652E660039CB7ULL,
		0x57295A538547D86DULL,
		0x79478C8791EB95F0ULL,
		0xA2CC5EBB2EF571E1ULL,
		0xD5EE71343452B75CULL,
		0xDB3A63191D249275ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB589A9A620503426ULL,
		0x9706E5338A24853DULL,
		0x21DF1273796D827AULL,
		0x76535FD1B78976ECULL,
		0xB4102F8D8E446118ULL,
		0xD62A8F650859721AULL,
		0x9D36942A1A824AEDULL,
		0xB3AC0A7F1DDC0B76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8474E8D0AF0884CAULL,
		0x3E6E1764CE91ED57ULL,
		0xB671EE0A183B2792ULL,
		0x0F5C8C0AD8BA4416ULL,
		0xB0D4E0567800B0ADULL,
		0xA44557F66EA1EA9BULL,
		0x3DADD66A1ADE3083ULL,
		0x5C9C9CBBBBD44E29ULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC5CE0F3AEF42F332ULL,
		0x3091FCE513C9C696ULL,
		0xEB518FAF6DF4E1DCULL,
		0x2F2B079073624C0DULL,
		0x008A6E5670426218ULL,
		0xC547E80FE29CC349ULL,
		0xDF194E14578A916FULL,
		0xBF6AA572BC11DE47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE778725016AD09D5ULL,
		0xBA0DDFAEBBDE83DAULL,
		0xC5E8DA055BF3A760ULL,
		0x07ACDB8A0316C0E1ULL,
		0x02713C7CACAD3AAAULL,
		0xED88B2F3C7F0F985ULL,
		0x07831E6BAF78B9A9ULL,
		0x387AB53057A64782ULL
	}};
	t = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8EA373E5264B14F0ULL,
		0xF11E1E7EC6BF4AD9ULL,
		0xF6EF616BF3C5DD4EULL,
		0x114A183FC105630DULL,
		0xEDD1D6F3370E9FAEULL,
		0x8D59E08DC96BA6C5ULL,
		0xACEFAB20D792178AULL,
		0x02AFD6E69DB70E2BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x775688B4B94F4FE9ULL,
		0x9032A2AC5FC324D3ULL,
		0xDF41A35BBAE9CED7ULL,
		0xA51083E1B5F012C6ULL,
		0x80D3F2CA248E76F8ULL,
		0x846027454E2B3274ULL,
		0x096E6D225805C24AULL,
		0x799469DC8004BDF9ULL
	}};
	t = -1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x27686B5B7A3CADD4ULL,
		0x4DCC9C9C89240314ULL,
		0x15A11D2C140C18C2ULL,
		0x93A0718DB8D3A6C0ULL,
		0x58BCF98F43A146A4ULL,
		0xD7F1BDFF462F7D4BULL,
		0x2156C56AFAD1A809ULL,
		0x40F714D064E58729ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27686B5B7A3CADD4ULL,
		0x4DCC9C9C89240314ULL,
		0x15A11D2C140C18C2ULL,
		0x93A0718DB8D3A6C0ULL,
		0x58BCF98F43A146A4ULL,
		0xD7F1BDFF462F7D4BULL,
		0x2156C56AFAD1A809ULL,
		0x40F714D064E58729ULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x18D4CA74012D275EULL,
		0x8BB42611F7325679ULL,
		0x25CC13F1C04ED3B0ULL,
		0xC9C00CDBAF019AA5ULL,
		0x0BD16C5E4F0F4006ULL,
		0x139130871E4EE836ULL,
		0xAEC7AC9DEB141078ULL,
		0x01F887A2F391F774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE612A289923BA555ULL,
		0x476612E7003ECDA5ULL,
		0x945598CB530B4D58ULL,
		0xD5EF7F5CED2B4962ULL,
		0x614E9588B5C299A7ULL,
		0xEE09D79649E5C2F7ULL,
		0x17248289A158D0F0ULL,
		0xB22465423781C490ULL
	}};
	t = -1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAA680FD9EF074192ULL,
		0x3FBAED8A5DA6AE6DULL,
		0x68D21225129FECD4ULL,
		0x9B454AA76601D801ULL,
		0xE67EA4A516418920ULL,
		0xC88029D6EA4C4BFCULL,
		0xFBD1B6D5DFDF89E9ULL,
		0x6686DE7B4B003D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD845577710BA79CULL,
		0xDF9A28C55ACABA9EULL,
		0x1A5854E85C1FD700ULL,
		0x38DC8A83E7466E60ULL,
		0x2FA49147AB668CA2ULL,
		0x530A80A89F7BFD50ULL,
		0xA3DB5C59A1C54787ULL,
		0x9C9A8AE8E29267C2ULL
	}};
	t = -1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8ED26B60DA4ED837ULL,
		0xE20A7A9ECA77F19FULL,
		0x4D630DBE2252E183ULL,
		0xDAFDE4E8DFA6CBDEULL,
		0x52D032CBD8A5E480ULL,
		0x3B5882ECA42B9E74ULL,
		0xD9FE32A7DE874005ULL,
		0x1E370D06D3BC1732ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09C794C9D92A0097ULL,
		0x6E54DE4F58C08FDAULL,
		0x30B2B0341F648C21ULL,
		0x365A58A19B928C4DULL,
		0x9B9FE2B08FC4B142ULL,
		0xD487DBE227BE188EULL,
		0x349D5890B53A0794ULL,
		0xCCAA5FEC30611D09ULL
	}};
	t = -1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE45DDEC7FCE218D0ULL,
		0xCA2968903F5CF733ULL,
		0xB1FEB7FDF4EBEEA5ULL,
		0x572BF1EE98B8B960ULL,
		0x3186AACA9E3AB7B4ULL,
		0xF6BD4BC3CF2D7635ULL,
		0xF81352B1F1BB67DDULL,
		0x79DA4B1FEEA8CE59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE45DDEC7FCE218D0ULL,
		0xCA2968903F5CF733ULL,
		0xB1FEB7FDF4EBEEA5ULL,
		0x572BF1EE98B8B960ULL,
		0x3186AACA9E3AB7B4ULL,
		0xF6BD4BC3CF2D7635ULL,
		0xF81352B1F1BB67DDULL,
		0x79DA4B1FEEA8CE59ULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEF5EC4B7E9D8A258ULL,
		0x2423BBFAA40A62ADULL,
		0xC4ADA4B1DEA57FD2ULL,
		0x0591E74D8C7D7456ULL,
		0xD0D6480CAEB0293DULL,
		0x3BD5AFB3D498C800ULL,
		0x77E73DFBA68ACA78ULL,
		0xD494D0E1199FE1AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD50D62C98EB7B0FULL,
		0xBC497957F26A3CF2ULL,
		0xA71776DD028FCE5FULL,
		0x286B4EFD1CD92D05ULL,
		0x0651394236B3CAACULL,
		0x355DA87A864F8BDEULL,
		0xD3DFCE199DCEA912ULL,
		0x1297E6FD7B7832B1ULL
	}};
	t = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8FD7F11FF0223139ULL,
		0xA0D372E55B0BA2E5ULL,
		0xAC6BD0084A663298ULL,
		0x5FFDF5B54F7E8969ULL,
		0xA90BC7FE824CB12EULL,
		0x739FCCEC3312CF45ULL,
		0x5AD84C2349222A08ULL,
		0x8F59BB17529FF665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F14C3A074DF4453ULL,
		0x127ED8478D0073B0ULL,
		0x1948B1504EB38E66ULL,
		0x0E4041BF19103BEDULL,
		0x6D3B8AAA802D4FA6ULL,
		0xBA076F6E83C1878DULL,
		0xD0BDF60BA56D1254ULL,
		0xDB2BB39503B2925EULL
	}};
	t = -1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x202BCFD2468A530AULL,
		0x5255601CF100AEFCULL,
		0x2D8106B889FA6182ULL,
		0xFECA7E3955DBA66AULL,
		0xC956EB2A53FB14A7ULL,
		0x79D4B2027CD87C0EULL,
		0x544F499832D6BE72ULL,
		0x79A25D81CEB571D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x597CE47539358A41ULL,
		0xC65C91EB601098AFULL,
		0x4AFE7AF58EFCC770ULL,
		0x46EBFCA6706869FAULL,
		0x9A11A26AF6275EE5ULL,
		0x2201E9962EAD5DFBULL,
		0xE7F59CBD0CB5913FULL,
		0x8583D3E3E6C3A53FULL
	}};
	t = -1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6D804B4627123AA1ULL,
		0x0C21E1CDB75F156EULL,
		0x993DEA55AD18AB9BULL,
		0x2C26796A6F80824BULL,
		0x8DCCEE68EFDB2F1DULL,
		0x54EEDAAF119A72AAULL,
		0x8DA6AD39C2A08271ULL,
		0xA8013ED6F9665FA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D804B4627123AA1ULL,
		0x0C21E1CDB75F156EULL,
		0x993DEA55AD18AB9BULL,
		0x2C26796A6F80824BULL,
		0x8DCCEE68EFDB2F1DULL,
		0x54EEDAAF119A72AAULL,
		0x8DA6AD39C2A08271ULL,
		0xA8013ED6F9665FA6ULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9263ED6256D071D0ULL,
		0x1526BB96A6B6CB2BULL,
		0x02F35181E2AB0662ULL,
		0x971A980ED6C9AA31ULL,
		0xDDAD634B8900B4FEULL,
		0x3EC14A499326A1DAULL,
		0x1963EACCFED99F9CULL,
		0x2F9830FA18474DCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46BE06B347B7A1E2ULL,
		0xDCA1C4DA43517C48ULL,
		0x2BB6290992AC486FULL,
		0xA65C55800E7E1335ULL,
		0x20099CAB9C4EFA89ULL,
		0xD7BA7CBB0772F232ULL,
		0x52D6E44093FF78E4ULL,
		0x38E435CEA6701111ULL
	}};
	t = -1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE5664D3F9D388C53ULL,
		0x7D5999FDE9E2B232ULL,
		0x5FE4EB7760E02FBEULL,
		0x2E443C3E802B2686ULL,
		0x9133008C3D62526DULL,
		0x1A77B9211078D0D9ULL,
		0x65DB0E44E7BA21F3ULL,
		0x12A2D774F12E318EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54D5FED8E34960B0ULL,
		0xE362DB221DED997CULL,
		0x5BA86E3753286BFEULL,
		0xC3D00A77C293F28CULL,
		0xBF305F857BD0CAA8ULL,
		0xC7D6DE2E049F9FCDULL,
		0x4F6A07F8BF1E9390ULL,
		0xF47DC891510BD7F2ULL
	}};
	t = -1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x1D7E01CF4B50FE99ULL,
		0xB0692A56CBADD352ULL,
		0xB07230E9AD23B3A8ULL,
		0x8D56E77B657D721EULL,
		0xD587DDDEEC1E2382ULL,
		0x2362D8D46AADEB44ULL,
		0xF7FE755E73CC63BDULL,
		0xF27B008B00173DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D37A437C4A8EC11ULL,
		0x339359D584AA5F87ULL,
		0x4716478087271778ULL,
		0xE5E22A92C804801BULL,
		0x5DDDF994C73CA3AAULL,
		0xC7924693EA6DADB4ULL,
		0x8DFD862E8340E5BBULL,
		0xFD690D033AE6B9CEULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5C8D926D1EBB641DULL,
		0xD122B4EF9B28DB58ULL,
		0x3400A602265BC952ULL,
		0xFCAF2D143F1BF944ULL,
		0xDF0154C238CC394AULL,
		0xCAC3061214CD03F4ULL,
		0x536944A11DB61E50ULL,
		0x72EE74381969C85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C8D926D1EBB641DULL,
		0xD122B4EF9B28DB58ULL,
		0x3400A602265BC952ULL,
		0xFCAF2D143F1BF944ULL,
		0xDF0154C238CC394AULL,
		0xCAC3061214CD03F4ULL,
		0x536944A11DB61E50ULL,
		0x72EE74381969C85EULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x74F959A41F82697CULL,
		0x207FCF3860A02EF7ULL,
		0xB391F63CA7FF2813ULL,
		0x4BFB645BB0827439ULL,
		0xB50FB50D41C4632DULL,
		0x658E99FD912E0A23ULL,
		0xC51E3B60BFDA7ACAULL,
		0xFA4944256C18BCEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A4D6BC4BA9B9B9CULL,
		0xC1D007191EB9DE2BULL,
		0x832EBEBC24E85471ULL,
		0x5CD7BB92C052D5FFULL,
		0xA17E89FC2A308DC1ULL,
		0x1E66539635287022ULL,
		0x7D518BEA0FA1F3D9ULL,
		0xCEBBD73CCBC6933FULL
	}};
	t = 1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x578B7F6C118099C3ULL,
		0x6F78B11440BBF1D6ULL,
		0xE29778F7DE84DA11ULL,
		0xAD0654354C27C9CDULL,
		0x061E55E171B15BAAULL,
		0x12C774A61E21A789ULL,
		0x2EA30DACE556E6A4ULL,
		0x1484674123F71DBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE25341C7F73F6FEULL,
		0x7B55F12AD2141E6CULL,
		0xAAE568C7277AB943ULL,
		0x35D41017009E0667ULL,
		0xD38A035E49AEDA43ULL,
		0xB23E4EA7DA17A577ULL,
		0x160E789DA9F25FB8ULL,
		0xC50DB19C60A1EAD6ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB0006AC5867FFB41ULL,
		0x4461D5F242E60A1CULL,
		0xB9EC25F6995E3D5FULL,
		0x6E273C070E7FCBB0ULL,
		0x089544842F4EFB71ULL,
		0x999A26D1B9C12EB3ULL,
		0x41F0D021BC15D823ULL,
		0xBBCFD75ED14285C0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C963820E56D3C03ULL,
		0x4FC91C33A50489C0ULL,
		0x104F6C2AD7614AD1ULL,
		0x683D99473595FF57ULL,
		0x1EBD5160F27C21D5ULL,
		0xFB2A58F13F5DB4F5ULL,
		0x68C9E50D719FD0A8ULL,
		0x694E9F8CFF554B23ULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5AD7B6FCA721E377ULL,
		0x17AC86FD9748977EULL,
		0x9651704602DA9BA8ULL,
		0xFB29A6436B017950ULL,
		0x3DDC7392209E2AC7ULL,
		0x898CE89FE515D4ACULL,
		0x251909A1F1F45DEEULL,
		0x54CE8BE5EDCE9125ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AD7B6FCA721E377ULL,
		0x17AC86FD9748977EULL,
		0x9651704602DA9BA8ULL,
		0xFB29A6436B017950ULL,
		0x3DDC7392209E2AC7ULL,
		0x898CE89FE515D4ACULL,
		0x251909A1F1F45DEEULL,
		0x54CE8BE5EDCE9125ULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x34F11341ADF7EE2EULL,
		0x12078F1BEE3C11C7ULL,
		0x5C2BAA5CC813C229ULL,
		0xF87482C493F0B0F9ULL,
		0xF7807A7C33737BEAULL,
		0xD71FABA12C159A19ULL,
		0x1BB7D744BBCF86F3ULL,
		0x35469CF4C126AF3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A6C3225EC39D611ULL,
		0x8DA10E1A4CFA28C2ULL,
		0x027E76FB12094912ULL,
		0x259B495682A684B7ULL,
		0x9496E37A36ED8A15ULL,
		0x039497BFC884B18DULL,
		0xD260F75A33D2B4D4ULL,
		0x8598D3C722665F5FULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8FC80ADDB022A924ULL,
		0xCB3C634C6DCDAA62ULL,
		0x599F9ECC6772C27AULL,
		0xCA5562F569954959ULL,
		0x703CFA7B0EEF6C77ULL,
		0xE7D7558B74030CEFULL,
		0xA7211C9BDA33C47FULL,
		0xDB239FB741B4D476ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D0803DFD5B931E0ULL,
		0x7F80AA8DFEF7EBBDULL,
		0x1E3981856679EDC5ULL,
		0xA88EB9AD1B32B1C2ULL,
		0xD5EB9DA608A5E36FULL,
		0x6F34811F20857BAFULL,
		0x3AEA89FFDB5E3CF9ULL,
		0x610B017424FB7166ULL
	}};
	t = 1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x69DF5C510BE69558ULL,
		0xDD2E1D5C197F8A1FULL,
		0xBA543C94BE73499DULL,
		0xBF2C5C70827680F2ULL,
		0x564509C36967A564ULL,
		0xD90E712135DCB4BCULL,
		0xEE849E775E666E35ULL,
		0x139D60DC306BC715ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4F054CF35B389C2ULL,
		0x45BBA9E59F39AB9DULL,
		0x9776712CFBCDAB53ULL,
		0x5C1BD61987967447ULL,
		0x50D979D8FF54BF63ULL,
		0x79DD0D64D0E67A8DULL,
		0x7E7042E25B824E36ULL,
		0x784BFF0BBD5301EEULL
	}};
	t = -1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x00A10A16BFC1A6FEULL,
		0x99F37F1EDD31A7CCULL,
		0x939789DBB246B94EULL,
		0xAADE8F5E6D523BACULL,
		0xB3EEF782663BCD65ULL,
		0xFC02751AABD8F1E9ULL,
		0xABEED65B3A23F0F4ULL,
		0x3F786BC233876E00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00A10A16BFC1A6FEULL,
		0x99F37F1EDD31A7CCULL,
		0x939789DBB246B94EULL,
		0xAADE8F5E6D523BACULL,
		0xB3EEF782663BCD65ULL,
		0xFC02751AABD8F1E9ULL,
		0xABEED65B3A23F0F4ULL,
		0x3F786BC233876E00ULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEA13951FA8E39240ULL,
		0x5EEB4254E3524510ULL,
		0xE9B66A8182693432ULL,
		0xBA3F59DDBBD3DDA4ULL,
		0xBE9C3CA4FBF66C82ULL,
		0x40C1D76CFDAA665DULL,
		0x0640CC6060A45FEFULL,
		0xC21B669E5838C775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9918FBCA49CF7616ULL,
		0x20D229EFDBE83CA8ULL,
		0x41049A28F345D645ULL,
		0x93D3AB78F6A079ECULL,
		0x13F143CB68345A6EULL,
		0x79A60CCEAAEB47A3ULL,
		0x7626189AC3CF3E56ULL,
		0xE7A0E443D52E9547ULL
	}};
	t = -1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x516FB9B3080C9ADFULL,
		0x010ECE174D12F4CAULL,
		0x3866A66D0AE6A58AULL,
		0x5C1963F35B12BD74ULL,
		0x6B9ECB46BF654083ULL,
		0xB15CC3C7C842472BULL,
		0x0FC4A048F8161E7AULL,
		0x372671F421042F91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F16CE1D27A10D96ULL,
		0xA13CE9151B5FDB74ULL,
		0xD030C7566D4B5FEDULL,
		0xBB2BB0D729D2D95EULL,
		0xC6654594E8727CDAULL,
		0x0E01195123F7C128ULL,
		0x62A6E7257AF67E1EULL,
		0x8EA7E1485F4C2124ULL
	}};
	t = -1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x01F095B66EB603CEULL,
		0x818F82B764208ABAULL,
		0xDDC348A97DA4AB12ULL,
		0xCACA825CCDFCDFDBULL,
		0x66C33413611749FFULL,
		0xF9EEB240D3808085ULL,
		0x58D7A978BF97FF53ULL,
		0xE588D5ADE43DE576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85D9D1015D0891F2ULL,
		0xC2BB4ACA29612434ULL,
		0x455EB3DDF5193DF1ULL,
		0x4930FB8215B492CFULL,
		0x140CE91FB31CEDA8ULL,
		0xF40448B5CEBB563FULL,
		0xC4EBA68A46DBE72AULL,
		0xEC35316AEE1ED6EAULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0947247DCEAAC5B3ULL,
		0x5A25636B0B14A3D0ULL,
		0xA6CCC9AB64F94284ULL,
		0xD37D7C47EED618DAULL,
		0x69065C05DB0C87B2ULL,
		0xBAF37936B38738BBULL,
		0xE2DB18BE483A9199ULL,
		0x24B7A79EF6407C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0947247DCEAAC5B3ULL,
		0x5A25636B0B14A3D0ULL,
		0xA6CCC9AB64F94284ULL,
		0xD37D7C47EED618DAULL,
		0x69065C05DB0C87B2ULL,
		0xBAF37936B38738BBULL,
		0xE2DB18BE483A9199ULL,
		0x24B7A79EF6407C61ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF844A4AAEAF6D9C3ULL,
		0xFEE260EAD3BD5C2CULL,
		0x8660FC19974A3238ULL,
		0xCC9B4B00F9670120ULL,
		0x439672F6A157DC5CULL,
		0xA625EC7CECC2D086ULL,
		0x2373E38D708FEBE9ULL,
		0x83BCB8C4B828A758ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9857C494F802DAA6ULL,
		0xED1A0F8812FC14E8ULL,
		0xA308495094CB94A6ULL,
		0xF9C51AFD68999BA7ULL,
		0x622B8E04E03B25DBULL,
		0x15213D677F3691CFULL,
		0xB09D4B01EBB0BA3AULL,
		0xCFA2CC74E19A7E94ULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x96C09CD91CDE1E49ULL,
		0x92650D5D092D9458ULL,
		0x53421B4D2384808FULL,
		0x2DC946AC99470491ULL,
		0x72A312390CCF7589ULL,
		0x7815883608D688B9ULL,
		0xD84E3F48EF22CF88ULL,
		0xC21C953623F92DBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x256173406D8AFC11ULL,
		0x4EEBCBEA9A102DF2ULL,
		0x34E6C8AD7C0E8C1CULL,
		0x8FAC0227F3B1312BULL,
		0x6C79E66926A5996EULL,
		0x9F693A86CE114C29ULL,
		0x556E12596F04D8AAULL,
		0x47398A1EEEB4510AULL
	}};
	t = 1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9A1B40A9E629C028ULL,
		0x0BCA002EB3DF5599ULL,
		0xF35F089367D443F3ULL,
		0xC23FD4C858FB40C5ULL,
		0x677BE76AE70F0D91ULL,
		0x70F314BD724B1253ULL,
		0x7E44973BAD7AA2CEULL,
		0xE28AAE03CD27AAC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68D22EF6BF795EFAULL,
		0x7ECE22CBB244889CULL,
		0xE7128C8E6CB42489ULL,
		0xD8670447085E0941ULL,
		0x414E2D8735BCB539ULL,
		0x537A64BD231E0E00ULL,
		0x9988CA67208FC095ULL,
		0x37AC462CBE07DBEAULL
	}};
	t = 1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x78354AFCCD20B38CULL,
		0xA820E109A7D0E00AULL,
		0xD1CEB1207BEC06A9ULL,
		0x5A0F4F81DBC539CEULL,
		0xE2508FD0BCCA074BULL,
		0x30AF41944F10B7BDULL,
		0xA7B140D13A584FA2ULL,
		0x90720637FAF2A1DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78354AFCCD20B38CULL,
		0xA820E109A7D0E00AULL,
		0xD1CEB1207BEC06A9ULL,
		0x5A0F4F81DBC539CEULL,
		0xE2508FD0BCCA074BULL,
		0x30AF41944F10B7BDULL,
		0xA7B140D13A584FA2ULL,
		0x90720637FAF2A1DCULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x903EC20473F45760ULL,
		0xC779AE60112B89D1ULL,
		0x48D5D56E0D9A1335ULL,
		0xC9904A5322F0086AULL,
		0xA96A819DFB6A54BAULL,
		0x8BCB122CCE43168FULL,
		0xD1515C692BFF6B2DULL,
		0x5EB5071C0B41AD7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891F5132463944CDULL,
		0x79A06055725D7E76ULL,
		0x3264A63565385618ULL,
		0x2EE2D994A0E86E3EULL,
		0xC3204D08328E88D0ULL,
		0x593879C66310E14EULL,
		0x5F545CEB7EDB79EBULL,
		0xC400E512544AC664ULL
	}};
	t = -1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBB5623A8FFD76CCFULL,
		0x00A2BF988ADAED2AULL,
		0x12D97E1094844C8CULL,
		0x73E602E52F05B494ULL,
		0x94693E4BAFC48905ULL,
		0x7C6725481EF7947EULL,
		0xE316D4312921F033ULL,
		0xA08B6ABBBF913898ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF77B1853D48CF0ULL,
		0x960B57421C22ACA8ULL,
		0xC7420F15164FE6DEULL,
		0x292AD2B6F87EFAA5ULL,
		0x02B336399CD5A969ULL,
		0x6BA1B5A021AF5DEAULL,
		0x85CC569C7B41DEDCULL,
		0xD4E1C1F92C3910B9ULL
	}};
	t = -1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9C67292BA701EA04ULL,
		0x3A041E96F9E7278FULL,
		0x757DA2C0DC61C25EULL,
		0xE47B7A50C5C1FC10ULL,
		0xA66CFB44CE203D1FULL,
		0x34E0F18E2D712CDEULL,
		0x7FBD277B13563C0EULL,
		0x7CB0BF133D67E153ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8165138110BB0BE4ULL,
		0xA2EB38C57C7AAB13ULL,
		0xD7889FC59B5310D0ULL,
		0x887039080D52F824ULL,
		0x077621A7EE04CC55ULL,
		0x9CB933E346EE56E3ULL,
		0xCA2DE368F320FE3FULL,
		0x699B64E820D46DD7ULL
	}};
	t = 1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDD1DB0BACC635E84ULL,
		0x03441D8176620FE0ULL,
		0x9A3B3E950D913889ULL,
		0xAAA322DB6CC148A5ULL,
		0xDF1B6C3A4EFB7AC2ULL,
		0x60DCB73521489C58ULL,
		0x383B8ABA407FAA42ULL,
		0x1F19110D757A95EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD1DB0BACC635E84ULL,
		0x03441D8176620FE0ULL,
		0x9A3B3E950D913889ULL,
		0xAAA322DB6CC148A5ULL,
		0xDF1B6C3A4EFB7AC2ULL,
		0x60DCB73521489C58ULL,
		0x383B8ABA407FAA42ULL,
		0x1F19110D757A95EAULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x71422269E76B48DEULL,
		0x587F844DDA53ABFEULL,
		0xA443407F9FA8EC78ULL,
		0x2532668D76CDEBE4ULL,
		0x8B5EB3EA14AAC7EFULL,
		0x2BA47D4264335F15ULL,
		0xC9E499920F56EA9BULL,
		0xEC371C156D1B8EF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB76B5C796083C4ULL,
		0x6ACEE718896D3746ULL,
		0xB288FBB60FFECD4EULL,
		0x9628B1BF14686AB9ULL,
		0xCE061B4F2838FC29ULL,
		0x6E90B8DB0F02BFC7ULL,
		0xA43BADC03BA9719FULL,
		0x7F4760AB863B15E2ULL
	}};
	t = 1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAE03995A08C41AF0ULL,
		0x848650C48FCC121CULL,
		0xB810444A79A311B1ULL,
		0x6C2EF850A96A7EB7ULL,
		0xB0BB1AE51DB890BDULL,
		0x05577EE5C3B0EDBFULL,
		0x7FC90085A9347ABFULL,
		0x8F1DA7F1CE38EEA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28F797A52E75B115ULL,
		0x465C2D375FFA5BAAULL,
		0x8A079E12D7074585ULL,
		0x64DB76438BBB3898ULL,
		0xA641672E24681740ULL,
		0x56CF1FF686471E54ULL,
		0xA72B13C5EA93521EULL,
		0x54AADE79F106F9B4ULL
	}};
	t = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF185980AB0CD67BDULL,
		0xF25AEB287F6283BFULL,
		0xBCC75E965CB8A8C6ULL,
		0x8D18E53C7D5C63A5ULL,
		0xC66B25DD59680065ULL,
		0xBD2A8A4C9C35BECDULL,
		0x769F3A8D6EB470C4ULL,
		0xBEA2A5BA695FC762ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3AD4BB79D2AF2AULL,
		0x320BC490859845ADULL,
		0xAFA0F7D24E742AE0ULL,
		0xB67D96A6DD6EBE5CULL,
		0x0B9630118FB1F429ULL,
		0x6CFEC165BA08FECDULL,
		0x40BA1DBEEE994CE4ULL,
		0x9700592291B4BC4BULL
	}};
	t = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x05CA7EB46FA114E2ULL,
		0x8506701D2068B9E6ULL,
		0xA99423C6BE7A0289ULL,
		0xACCB473684941534ULL,
		0x56C7DE3B101E3D2CULL,
		0x75C34D03B519FC90ULL,
		0xD7FA0A04AE63F6CCULL,
		0x70A8E9389C859C72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x05CA7EB46FA114E2ULL,
		0x8506701D2068B9E6ULL,
		0xA99423C6BE7A0289ULL,
		0xACCB473684941534ULL,
		0x56C7DE3B101E3D2CULL,
		0x75C34D03B519FC90ULL,
		0xD7FA0A04AE63F6CCULL,
		0x70A8E9389C859C72ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE81F5CC6341F7BE6ULL,
		0xD7F5A40F9909ED20ULL,
		0xC164A84A0367FADFULL,
		0x2BA3C91284FB3296ULL,
		0x47C9533838E8F73AULL,
		0xAB87DC051E4006A1ULL,
		0x302DC5AB05190B76ULL,
		0xD691C44930B3476DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6438624663E5D65ULL,
		0x2B3943D124652381ULL,
		0x9AF569836C656220ULL,
		0x9C04D7E380A63790ULL,
		0xBB963B68E8616AE7ULL,
		0xB31847231F1E7484ULL,
		0x2D86CD648BE02F4DULL,
		0xB873989EE2CF3E84ULL
	}};
	t = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2A6D2E65FDF89CD6ULL,
		0xD35939FFF4873F5FULL,
		0xDF9734146A94221BULL,
		0x294A5E37E005D518ULL,
		0x817DE031E588B2DAULL,
		0x72441E910FBF3948ULL,
		0xB99AA1C8C1A8D057ULL,
		0x49BAFC6C9F35CF29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B7A32F430144B4BULL,
		0x8302BC4A1AF8964AULL,
		0xEFB0E6160F5F194FULL,
		0xEEC86A2151017122ULL,
		0x76F6EAE8E4EC09B5ULL,
		0x820B57C9DD2F576EULL,
		0xC2AF26FD7DFECD27ULL,
		0xC0BFCC4635AC5232ULL
	}};
	t = -1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x263E9E842EB6633EULL,
		0xF8022FFF2D1B7C04ULL,
		0x025B70AEFA028649ULL,
		0x0F4634F9C62D5391ULL,
		0x3CBCFEF858FF6A4AULL,
		0xF196090E3482907FULL,
		0x89C2861393902F48ULL,
		0x35207876599A177DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01A867441E83BD85ULL,
		0x0D0021AD72CFA384ULL,
		0x9C4825ED6E51FD56ULL,
		0xCED87F96FC050F34ULL,
		0x6DB7022ECF06F8A6ULL,
		0x8516AA5CCC67FEE6ULL,
		0x443F7A359C8D8326ULL,
		0x6BF425A730D940E2ULL
	}};
	t = -1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x918E2B7BBCBCC280ULL,
		0x7B6C2113B8ABDA45ULL,
		0x0EA76E55985A9ED8ULL,
		0xB8C8F47CC0052283ULL,
		0x1F7A2926B609469EULL,
		0x8B9453E827E2FE2AULL,
		0xE0ED45080EB7E4D2ULL,
		0xDAC7C2B69C092B71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x918E2B7BBCBCC280ULL,
		0x7B6C2113B8ABDA45ULL,
		0x0EA76E55985A9ED8ULL,
		0xB8C8F47CC0052283ULL,
		0x1F7A2926B609469EULL,
		0x8B9453E827E2FE2AULL,
		0xE0ED45080EB7E4D2ULL,
		0xDAC7C2B69C092B71ULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x728939678CBCA827ULL,
		0xD5FE28BD7255F28BULL,
		0x2C8D09EEC5BBFEC0ULL,
		0xAC6EE97A136B06B0ULL,
		0xAE0E78EB55ADB17EULL,
		0x78FC07FE0114E38DULL,
		0xA786A5B4D2E3B173ULL,
		0x322D2517EC42B7FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBE724D98C7347D6ULL,
		0x96FAA06FE9BA193BULL,
		0x4BE56775206BDCB8ULL,
		0xABEBB99368658183ULL,
		0x80566C3E9858BA15ULL,
		0xA229CE663EE4A64DULL,
		0xDB6EBBBFB730ABA7ULL,
		0x7406EA0456DB0CADULL
	}};
	t = -1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0E736078A0BBD184ULL,
		0xAF0A1A9A3848F16CULL,
		0x34E46502E8E1B37EULL,
		0xF0609113E97007ACULL,
		0xD238F9D651F4FE9CULL,
		0x8174DBBAADA9A171ULL,
		0x886968289CB32DADULL,
		0x51354BD5B1E1704EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD38C19C69D373A02ULL,
		0x3BE30C125567AE68ULL,
		0x01FAEEAEC5653880ULL,
		0x268C21CAD0B79DC8ULL,
		0x8A081DBE37230FE3ULL,
		0xE928FD1D23EB0C57ULL,
		0x5530177F6ED952EDULL,
		0xEC96F676A6FE410BULL
	}};
	t = -1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD30F22D3863BE9E5ULL,
		0x368B09609B592B4FULL,
		0xBBDCFECF52308A7FULL,
		0x780AEA5E04AD47DEULL,
		0x1B99769D99B60D30ULL,
		0x38E0301F9D4249A9ULL,
		0x00F52F824B1ECE34ULL,
		0xE9FC7F05BA3A595DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6399721328B59EA6ULL,
		0x7425DC795C284EB2ULL,
		0x45C6ED80A4F56FE8ULL,
		0x973E6B796CE73C3DULL,
		0xA8715DF359A47C13ULL,
		0x06BE28EA73E65D87ULL,
		0x5A7550CB1CEBAB2BULL,
		0xE8056D50423873F6ULL
	}};
	t = 1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x218832CB0B498AEFULL,
		0x8663160700368AC9ULL,
		0xD1DF285A8269A5AEULL,
		0x3666AEE4E83013C9ULL,
		0x3197D6CE5A6D9925ULL,
		0x0E790D4D660B56DAULL,
		0xD0F3821F731E5DEBULL,
		0xC3B7B3C271BC135FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x218832CB0B498AEFULL,
		0x8663160700368AC9ULL,
		0xD1DF285A8269A5AEULL,
		0x3666AEE4E83013C9ULL,
		0x3197D6CE5A6D9925ULL,
		0x0E790D4D660B56DAULL,
		0xD0F3821F731E5DEBULL,
		0xC3B7B3C271BC135FULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF4EC06E742AAF2E6ULL,
		0x9D003922A598614AULL,
		0xB6C3AF4E6D12BEBAULL,
		0x5FB921B3E38A868DULL,
		0xA5E356A941C42C0EULL,
		0x7492363EAF81CA52ULL,
		0xCF01C3D7A0621265ULL,
		0xB6089C807912068AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE640EBF4FC5F4104ULL,
		0x942AEABA9E24F920ULL,
		0xD3EB056E207C72BBULL,
		0x15D4883053168E69ULL,
		0xEA6EEEF6BBD0A54FULL,
		0x45CD4BDDAF2948C9ULL,
		0xC44547DF59984417ULL,
		0xC34038B8DC095ED1ULL
	}};
	t = -1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAB74F8F6D801995AULL,
		0xC8DBA3A3E8743E5CULL,
		0x133771E5CBC0A231ULL,
		0xF6195CEC3772A88CULL,
		0xF3897D27AF9F0DEDULL,
		0x2F8ABBABFAF5D23BULL,
		0xB3345848DF54504AULL,
		0x0BC69D0C691C96C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7AEDDC72399E31BULL,
		0x2B329C6AFD787E0EULL,
		0xBDD1F2B7D7190C83ULL,
		0x9E1A4FEDC569051DULL,
		0x4E82B4B508E507D5ULL,
		0x82B21E4A730BD4E2ULL,
		0x192667F36F58BB09ULL,
		0x57B7953326DBC1BFULL
	}};
	t = -1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF5CA02E076A65C72ULL,
		0x48DABD86E51544A3ULL,
		0xC6D28365230CB75BULL,
		0x89DFCEFAEE7BD91AULL,
		0x5969495655C91AC7ULL,
		0x3C0D6B024C102AD2ULL,
		0x06068D38E83E461CULL,
		0x24724C286AA94E72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4DCBA0D0E168892ULL,
		0x9DEA6673DFC33DA9ULL,
		0x269168E0CBA41AF4ULL,
		0xC18DE610EB1F2CECULL,
		0x95BEA68C68E05C3BULL,
		0x1141A83456CFB494ULL,
		0x2E2057253A6BA082ULL,
		0x0EA140FC18B266BFULL
	}};
	t = 1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2A86D1090BE60820ULL,
		0xBAF5A3D74B514C5EULL,
		0xF6BF2B1135E98037ULL,
		0x5C4CEE816D7D8F55ULL,
		0x709170F178936F8BULL,
		0xBC4B777869FB24F8ULL,
		0x510622A0DE6E37A7ULL,
		0x52FB9DFD1A576461ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A86D1090BE60820ULL,
		0xBAF5A3D74B514C5EULL,
		0xF6BF2B1135E98037ULL,
		0x5C4CEE816D7D8F55ULL,
		0x709170F178936F8BULL,
		0xBC4B777869FB24F8ULL,
		0x510622A0DE6E37A7ULL,
		0x52FB9DFD1A576461ULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x445A747410F398EBULL,
		0x15E75BB152D1F1EFULL,
		0xD0B23C19A2C5E24AULL,
		0xC0C512C7835DA4D0ULL,
		0x76BA3C1B72563A4EULL,
		0x2F14674A32DEF678ULL,
		0x15EE6E12DCCD9274ULL,
		0x7B1B2413730089AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9C951612CAE037ULL,
		0xC6D984266EFA77FEULL,
		0xE6D2286F7F14737AULL,
		0xD79A504513970C01ULL,
		0x0A9BE72B8A47E0E0ULL,
		0x35DDCEA176B649E5ULL,
		0xD72EE7D8FB044A87ULL,
		0xAB97DBB57CD17D6FULL
	}};
	t = -1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x177550B94BE56CB1ULL,
		0x6FB5536059AC8711ULL,
		0xF5AA7E2EF70D25F1ULL,
		0x43755C002A915F18ULL,
		0x71C2B005E22876B8ULL,
		0x5BB009FE93678268ULL,
		0x84A65A829599E263ULL,
		0xCA00ABD87A171FCBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12A157491E08A3A4ULL,
		0xDA6BDC7B4B3CAF37ULL,
		0x95F2C2747660ED62ULL,
		0xAE15BA92935EC0C9ULL,
		0xD227E0CCF232699BULL,
		0x15E967AD2C96C301ULL,
		0x60A7AED2C998FCC3ULL,
		0x2E4450E54F049212ULL
	}};
	t = 1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE5BC21517EF3B406ULL,
		0x1AF0395224A5EB87ULL,
		0x6752DA462E122C87ULL,
		0xA14234773DA52516ULL,
		0xA0864E33F15B46B7ULL,
		0x1DBBD1E46237881CULL,
		0x62385A409FBA1ADAULL,
		0xDEB8007ED01657C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D9971BEB28D3D6ULL,
		0x867CCD521EBB3DAFULL,
		0x8365D936BA7B97D2ULL,
		0x1583B614A1A6227DULL,
		0x29F18E4BEE569F31ULL,
		0x791BD30FE8AE067DULL,
		0xD4EE5FD97E9DFB9FULL,
		0x151F42EC2C849630ULL
	}};
	t = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE8D9B4CD57A903E8ULL,
		0x12CD7BE9FF448633ULL,
		0x622708CB2835C057ULL,
		0x60B812A8199E7B3EULL,
		0xC814FAAC26F91DF4ULL,
		0x1988A8FE6876E44DULL,
		0xAD60CE42A9D6F32DULL,
		0xBBA8821C5D529A76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D9B4CD57A903E8ULL,
		0x12CD7BE9FF448633ULL,
		0x622708CB2835C057ULL,
		0x60B812A8199E7B3EULL,
		0xC814FAAC26F91DF4ULL,
		0x1988A8FE6876E44DULL,
		0xAD60CE42A9D6F32DULL,
		0xBBA8821C5D529A76ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAAAAACB7D3373572ULL,
		0x0968C6184DF52D00ULL,
		0x1F3A7C9E4005ECA0ULL,
		0x3F221893FD651CDFULL,
		0x7B08C451A1C778BEULL,
		0x4744F5215EB38FF0ULL,
		0xBE614028C4D2565FULL,
		0xD1144FFAF7F76E89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB20C347E0B7E4EFEULL,
		0xDF71DAC46C3CE540ULL,
		0xCCE394179162319AULL,
		0x63813E8C535E5255ULL,
		0xDDD7195BF4646B7FULL,
		0xED8CFF3F1C8869D8ULL,
		0x1CF33D4272A69C8EULL,
		0x4DEF9BA94259E1EBULL
	}};
	t = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x04B9FA0D925C3AA8ULL,
		0x8AB4CA54C03C53C8ULL,
		0x97901DF0969015F6ULL,
		0xAF768FE863AFA8E8ULL,
		0x8BFB0ED8BB0AC385ULL,
		0x28669D71C2B4BD0BULL,
		0xD906302DC62FD240ULL,
		0xFDAC5276AFBE5E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF67CCBFD0223B38DULL,
		0x925888756C92584FULL,
		0x8F9CFE0E0DD9A816ULL,
		0xB245225344122FB0ULL,
		0x9F178D0E197DDCF8ULL,
		0xECB830D975F1D80CULL,
		0x3C58F8A202395878ULL,
		0x89F85400F769057EULL
	}};
	t = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDD0E75752B87CF7FULL,
		0xB97951E2B8C558A5ULL,
		0x592E1786B6085A13ULL,
		0x8E538A9A339BFBD2ULL,
		0xC8469A353C9E2F1CULL,
		0x160F33840E5E48A1ULL,
		0xDF775B30DEA3EC3FULL,
		0x4CC57C229AE13C8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E67AF4D0177A66ULL,
		0x4F911D8C69F5BA71ULL,
		0x31BED8152A730670ULL,
		0xB85E3E67217EEB80ULL,
		0xB9411A3EE11D2EE5ULL,
		0xCCD9C6A37AC34AB2ULL,
		0x5E2A3BB2DE11848BULL,
		0x376B1FAA72FCA681ULL
	}};
	t = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFC61C20E2651C1DDULL,
		0x99823E66BBBDA043ULL,
		0x8B37AF59F0C70A00ULL,
		0x4A5A42A9405BEDB2ULL,
		0xECAB5F161A5E86A9ULL,
		0x3552937479476CC9ULL,
		0xD76DB473368F64FEULL,
		0xFA6C85613B8C6C83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC61C20E2651C1DDULL,
		0x99823E66BBBDA043ULL,
		0x8B37AF59F0C70A00ULL,
		0x4A5A42A9405BEDB2ULL,
		0xECAB5F161A5E86A9ULL,
		0x3552937479476CC9ULL,
		0xD76DB473368F64FEULL,
		0xFA6C85613B8C6C83ULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9F42218E9F079841ULL,
		0xAC4E50CECA44028EULL,
		0x6B53CC32BB5091AFULL,
		0xA2DF5073DA68EBAFULL,
		0xEE49F2069EC82F70ULL,
		0x46F71415C55DC471ULL,
		0xF1DD341D4C3F2871ULL,
		0x8275DE4C4959F685ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08999FD713E5D0ADULL,
		0x743D88F62929A88FULL,
		0xC4181E3200CE8E6AULL,
		0x32B2D58A4447E882ULL,
		0xB0F589F9E3A2F31EULL,
		0xF35CE1D7B8A06B76ULL,
		0x210F0D153A39F49CULL,
		0xADCB97F0D051F40BULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4A65E6306BD0B89AULL,
		0x8075F7A2FD170AF4ULL,
		0xFA7D3600FC22354BULL,
		0xD0152AC1657F9FF1ULL,
		0xF02C5A6F798CD31BULL,
		0xBF8FFD67EB1038CFULL,
		0x87EFEA868A14DA3CULL,
		0x3C88D7D66E460B6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB643A57D6B48A610ULL,
		0x7E3C6FFED95454BAULL,
		0xE1F9B7F2B5FFDAC7ULL,
		0xEC1CD47883C04AE0ULL,
		0x571824BD7E66CB5DULL,
		0x95A5ED1BF30F388BULL,
		0xDF28BA983FE0E13EULL,
		0xBC673F735CD6AD63ULL
	}};
	t = -1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD383CEE3ED6B2BAFULL,
		0xA718C2BA80BE6FB2ULL,
		0xB19395F0944823A1ULL,
		0x664F96F168A8C789ULL,
		0x1A6B1B3E41539DDAULL,
		0x8E01578B4DCD7EFFULL,
		0x6E697CE5FB873316ULL,
		0x15C821C88C6F696EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82300887271416B3ULL,
		0x07189633CCA5F5E7ULL,
		0x2BAF89573F0C497AULL,
		0x2C29633DA5BB762EULL,
		0x6F079F13344E29F0ULL,
		0x18AE1273C02E799DULL,
		0xCAB92A4167891BD6ULL,
		0x204C3B15E6918A48ULL
	}};
	t = -1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x01AAA191750CB151ULL,
		0x8968E02C6D8ECBF4ULL,
		0x82D692067A639643ULL,
		0x4C1E24C640EEA453ULL,
		0xC943A07FA574FFC6ULL,
		0xCE4A229877DD673BULL,
		0x5EA5D36C80AB7D6EULL,
		0x217F0A9DC9AD07F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01AAA191750CB151ULL,
		0x8968E02C6D8ECBF4ULL,
		0x82D692067A639643ULL,
		0x4C1E24C640EEA453ULL,
		0xC943A07FA574FFC6ULL,
		0xCE4A229877DD673BULL,
		0x5EA5D36C80AB7D6EULL,
		0x217F0A9DC9AD07F9ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE88E7AFD3582B20EULL,
		0xD4A9E9C454895E11ULL,
		0x2FC71432DF6A173FULL,
		0xB559A68CE4F96033ULL,
		0xA25D64272AE6E931ULL,
		0x557D56A4C1F48B77ULL,
		0x6598A9C4DEE7042DULL,
		0x78B869B053534C37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97E572AE6C9ED5B9ULL,
		0x8F3005EACDAD12DAULL,
		0x0183F4BA5BDF2D01ULL,
		0x7731DB9CE88D75CCULL,
		0x56B8CAD764292306ULL,
		0x381184EA06A42B58ULL,
		0x6E5E7D7CD87D354DULL,
		0xA7718E4D210CC878ULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x99FB7A4BF985B607ULL,
		0x661B0CB4DBF9F975ULL,
		0x5C8A394D72EAC8ADULL,
		0x14DE0E3A2F255801ULL,
		0xDD509E3F0ABA84B4ULL,
		0x192B23557C357521ULL,
		0x791199615C1547B1ULL,
		0x855426375EAA33C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB76BF5617574FEB8ULL,
		0x1CD6CFA637EF0540ULL,
		0x209E161171A3C370ULL,
		0x013F6C4DA421484EULL,
		0x3B61C63B53A19126ULL,
		0xB6D39CE647E2E212ULL,
		0x85221A63D05CDA66ULL,
		0x1C037E8AECEC65DAULL
	}};
	t = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x78CEE4D1924675DAULL,
		0xAB47E4797445B3D9ULL,
		0x1D88F4449F0B02F0ULL,
		0x5F7E1711C5FE0171ULL,
		0xE3A87956BCCE1617ULL,
		0x9DD8584EE4D4E279ULL,
		0xE6E8E209D5FB9AB9ULL,
		0x7DA3ECB23B499902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEF541E7729296EAULL,
		0x9435EF86E38A12AFULL,
		0xF306189F021A9C13ULL,
		0xA4D5B315A4C4792CULL,
		0x8AB603DF6D6D6444ULL,
		0x61625A65E62C77F1ULL,
		0xB42D7BC0444F4406ULL,
		0x9F8372AA5423A30BULL
	}};
	t = -1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x711100C8D603804DULL,
		0x2E2625EBBF2013E1ULL,
		0x5E17D3B79E2D4685ULL,
		0xC9E44A962263E646ULL,
		0x015CB0D4A35FEC4BULL,
		0x1B9B382718AA5B48ULL,
		0x9AD25E0D318FA125ULL,
		0xF44789830030C50DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x711100C8D603804DULL,
		0x2E2625EBBF2013E1ULL,
		0x5E17D3B79E2D4685ULL,
		0xC9E44A962263E646ULL,
		0x015CB0D4A35FEC4BULL,
		0x1B9B382718AA5B48ULL,
		0x9AD25E0D318FA125ULL,
		0xF44789830030C50DULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x60CE6A71E481990DULL,
		0x5F5A74A38450964EULL,
		0x050750A68D252A2AULL,
		0x4184133F4C3B261AULL,
		0x323C8E2981EB7B93ULL,
		0xB7D320BDDB07799BULL,
		0x5AFD21D48067CC9AULL,
		0xBEE58164002DCEBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x836C024556359F25ULL,
		0x3A3F3F24C0FFB008ULL,
		0xCADE83B947486BABULL,
		0x6CF07F01B068B45EULL,
		0x9C6E4F81F60443AFULL,
		0x152672CB40FE426DULL,
		0xEB54AD55C1B33A15ULL,
		0xB6A4BE98FBC9E43EULL
	}};
	t = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB4E9368DF046CA55ULL,
		0xA7FCD4E843B8B71EULL,
		0xB65BC9E8323148AEULL,
		0xFE0BC2C7BCDFC8BEULL,
		0xBA08CA7846F04BABULL,
		0x89253F2136E5A428ULL,
		0xE295442444838590ULL,
		0xEE284250819874CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA8EBBA5C5EDF804ULL,
		0x0D8C27D9E0ACF200ULL,
		0x61110EC85B4AA6B8ULL,
		0x36C78192986C46E8ULL,
		0x36C43B9A670874F8ULL,
		0x5E97298F57B03AD2ULL,
		0x00C90281031D1B40ULL,
		0xC67D13E0149DABACULL
	}};
	t = 1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6979CD9713B9171CULL,
		0x147B478FCD39408CULL,
		0x507374DB4F2069F6ULL,
		0x386E40396263A339ULL,
		0x0FE9024C73074705ULL,
		0xE93D6C26860A37D6ULL,
		0x78D3B16933ECD24BULL,
		0xAA3BA70155ABEA39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7F67EA4BBC7087FULL,
		0x2DE712F4BDBB9958ULL,
		0x923B139517B6D9DBULL,
		0x1F86FD6022F0820EULL,
		0x81B292964D925DF1ULL,
		0x9854CD1CBFECA7D9ULL,
		0x295EE5913783ACBAULL,
		0xCEFE7FD78B6BE57BULL
	}};
	t = -1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5957C8DBDDFA38A4ULL,
		0xA4A21E0B9376196EULL,
		0x5B7AD4ACFA2B4087ULL,
		0x1E8FEEB16A2F9056ULL,
		0x64313A448473885CULL,
		0x3D3E9620535F3049ULL,
		0xD64D0C5547525610ULL,
		0x711EB95E2CACDCA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5957C8DBDDFA38A4ULL,
		0xA4A21E0B9376196EULL,
		0x5B7AD4ACFA2B4087ULL,
		0x1E8FEEB16A2F9056ULL,
		0x64313A448473885CULL,
		0x3D3E9620535F3049ULL,
		0xD64D0C5547525610ULL,
		0x711EB95E2CACDCA6ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD5EBD3611F89BDD8ULL,
		0xB5E74BC9AA0933DBULL,
		0x0C8171D97DE1CA29ULL,
		0x7E6516F6E526566AULL,
		0xCEEE5A573656907CULL,
		0xA06985A3B37DB3B9ULL,
		0x0111EF855FBC2604ULL,
		0x3EF5F02D7D5C96E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E1837D5212DA995ULL,
		0x3423BB3D4D2A6467ULL,
		0x7F1D05EBF72F95D2ULL,
		0xED7E1A97E2534329ULL,
		0xDE895CB5775FBDD2ULL,
		0xD1D3E631B73EDF8DULL,
		0xD22816472A5F6228ULL,
		0x1331B12E85625DEFULL
	}};
	t = 1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF8644204244AC389ULL,
		0x3E3A1A3820A49C93ULL,
		0x8B802EEEA5183569ULL,
		0x2840B52027A7BF43ULL,
		0x3B9186B1D5A5C864ULL,
		0x63869A9E7B606FF4ULL,
		0x3812C161813FA64EULL,
		0x7CC3DCE3E0E537BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59C58C3FEFE6349CULL,
		0x33D420B36E3F5B6BULL,
		0x7C0F9DB1FB9045F7ULL,
		0xE90503E4EFD003E5ULL,
		0x8053BC01B8993DF1ULL,
		0xB1A8D5A6155F81FBULL,
		0x1019DFD34E5CF74BULL,
		0xB37B9D0C8295D839ULL
	}};
	t = -1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x16EC0EF8C25F6123ULL,
		0x8E8AEFF14BAE2087ULL,
		0xC6EC544453E5A7CCULL,
		0xA61B2695FAED5F52ULL,
		0x0FC78A30F5657276ULL,
		0x2DA7134FC98964EBULL,
		0x5AF1D719EB6E19B3ULL,
		0x56D73EFE79A19429ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0B063EAE725689ULL,
		0x50BFD9633EFBB4B6ULL,
		0xE327D36DD2DA9C44ULL,
		0x7A5A03D1D14C2C11ULL,
		0xC8B0195C8688E8C8ULL,
		0x54CD83CECE924AAEULL,
		0x5BCFCB474FE710A3ULL,
		0x1A1B2041790A8658ULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8F5F9A50F482B94CULL,
		0x04BAA8DFCABE3B9AULL,
		0x573465B901F89E01ULL,
		0xB3CD3A6432ED9734ULL,
		0xAD09BF61CE933E6AULL,
		0xB3A519B21A5E2CD2ULL,
		0x2E0F782240E77632ULL,
		0xBE19FEE66C44C9C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F5F9A50F482B94CULL,
		0x04BAA8DFCABE3B9AULL,
		0x573465B901F89E01ULL,
		0xB3CD3A6432ED9734ULL,
		0xAD09BF61CE933E6AULL,
		0xB3A519B21A5E2CD2ULL,
		0x2E0F782240E77632ULL,
		0xBE19FEE66C44C9C5ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDCBCA30411E2578FULL,
		0x9207A8A4F72A1C77ULL,
		0xB9F78A4C2D61AAB8ULL,
		0xFFCD9C2B153D726EULL,
		0x30FDE04B03737A35ULL,
		0x42CDF63E90F8AE55ULL,
		0x72E430D6E2BE5CEAULL,
		0x666D7ABD9D9B1FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06F73533DBABDF3AULL,
		0x0EE9C66CD0FBF091ULL,
		0x2614EE2666DE58F2ULL,
		0x7524AA4043824B00ULL,
		0x4B6D5D7B3D2F8654ULL,
		0x26C7C5AEE0C372EEULL,
		0xB6F7603790CE082EULL,
		0x522A6286194E6BB7ULL
	}};
	t = 1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x63833A57C21884CDULL,
		0x207F965DCE135F4AULL,
		0x74875CB9FB3A0AFAULL,
		0xD1C5AADCFBBC1ED6ULL,
		0x0E30D3DCF4AD4D00ULL,
		0x7B74D4E24BCAD1A2ULL,
		0x0C12754B2DC81C1EULL,
		0xBA7DA229160BA01DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54EC7422458992A4ULL,
		0xCEF76ABB30378615ULL,
		0x98CB269EE5C82B8DULL,
		0x7DBA2ACC962DA901ULL,
		0xC308D26BE8B35025ULL,
		0x798B2DB5E7C7ACFAULL,
		0x5F54EA65B9B233A0ULL,
		0x414A2EF9AAEFC7B2ULL
	}};
	t = 1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD92FF5A5FB390227ULL,
		0xCF7198F219A3007DULL,
		0xD99A5BF704DB1895ULL,
		0x20DA4DE6D0E62889ULL,
		0x3F7061FABFB62DECULL,
		0x10C1009E2C3CB03EULL,
		0x45B77E9DB864D3CBULL,
		0x7C6003F494655EB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x459905CA1686849DULL,
		0x3EB2F2EBD12E0117ULL,
		0xF534849BBE0A37E8ULL,
		0xB3675288BE7D6E6BULL,
		0x2F2AFBD0AE5426B5ULL,
		0x326CAE5B794210F3ULL,
		0x5E3BEE9A3EA56CB2ULL,
		0x22CF4E5AA75A8E42ULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x042BB572ABE206DFULL,
		0xF0646BF31B6D91E5ULL,
		0x7FA6BE573770EF7CULL,
		0x89A66BD80B70ECC2ULL,
		0x151B18A187A96F45ULL,
		0xCA1887F528B5C131ULL,
		0xF951FFF6BF2DD869ULL,
		0x540F57DF84FF1852ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x042BB572ABE206DFULL,
		0xF0646BF31B6D91E5ULL,
		0x7FA6BE573770EF7CULL,
		0x89A66BD80B70ECC2ULL,
		0x151B18A187A96F45ULL,
		0xCA1887F528B5C131ULL,
		0xF951FFF6BF2DD869ULL,
		0x540F57DF84FF1852ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x07F7BD6895F54041ULL,
		0x87044D7FD1231716ULL,
		0xBE5103270FF8F030ULL,
		0x3D060B156C07FEEDULL,
		0x44AAD0AFB2E38354ULL,
		0xED50EA9931DC9DC7ULL,
		0x942591EAC2D36FCAULL,
		0x59210DB78626887EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5CAE068FFAFD7D3ULL,
		0x5C2D2D8FF43B8D8BULL,
		0xD8519C27659C02A6ULL,
		0x82FFB45905E5935DULL,
		0xE59FF5FA1100ACC0ULL,
		0xC81284868DDC07D9ULL,
		0xAC899A71D69CE405ULL,
		0xC4356E7926E3A10EULL
	}};
	t = -1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC6D134D681B3268FULL,
		0xA024EE61E7FE591CULL,
		0x81502330FA944669ULL,
		0x335FE480CFEBF5D6ULL,
		0x4DE2E0B5B2A3F863ULL,
		0xC549EDD70A20206BULL,
		0xF30522E3B3AA624BULL,
		0x2FE968E151C349AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62D6253368DA0652ULL,
		0xDCA590EC8DF3F5C0ULL,
		0x17624D887E55A6A3ULL,
		0xA83FF0F39B7274A1ULL,
		0x32161648733EC5F0ULL,
		0x3D33C8549C8D75E8ULL,
		0x38B53A1458C9F33DULL,
		0x4CBD970791558C75ULL
	}};
	t = -1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAD86B4D5928DCDD2ULL,
		0x7D429348A19A181BULL,
		0x4BA767BF388A438CULL,
		0xFF4D0AC8D8292B18ULL,
		0xBC8529DCE9D1E462ULL,
		0xA9414EF07B554676ULL,
		0xAD992FC9BD163187ULL,
		0xACC126FD2B4EE4DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C235A6AAF01670ULL,
		0xCE5BC9CB4B9FDEFAULL,
		0xE28AF4A5076A8467ULL,
		0x668D69674F96DA6EULL,
		0x3FDE79DBD87B49DDULL,
		0x7A0D6805281C452CULL,
		0x88F0AE695247CDE9ULL,
		0x0890E3EFF8FF6C7EULL
	}};
	t = 1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8491D0B5B4D9C1FFULL,
		0xCA2807210672B54DULL,
		0xF81BE226FBF6D552ULL,
		0x4B254248C68C9051ULL,
		0x5C1A51E39F8B9F50ULL,
		0xBBE15B2D9F79B8A3ULL,
		0xD498CB49D96EDC63ULL,
		0x234E66018B6965C3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8491D0B5B4D9C1FFULL,
		0xCA2807210672B54DULL,
		0xF81BE226FBF6D552ULL,
		0x4B254248C68C9051ULL,
		0x5C1A51E39F8B9F50ULL,
		0xBBE15B2D9F79B8A3ULL,
		0xD498CB49D96EDC63ULL,
		0x234E66018B6965C3ULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x00B4B151144096F1ULL,
		0xF197BD1C9FF34B63ULL,
		0x2DB94CDE9C191E15ULL,
		0xBFB2529745DB781CULL,
		0xD257C8DD23FD5A9BULL,
		0x1F40779B539E76BDULL,
		0xB7B7772917782B72ULL,
		0x21FE17E9B85FA6E9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DAD01F13FF72FA1ULL,
		0x7E19D38B6DB451C2ULL,
		0x73129A71FA7A7170ULL,
		0x25795C2C499CFAEEULL,
		0x8DB3C6B97E8EE633ULL,
		0xFF0B05D8226D1F3FULL,
		0xCD5BADEA672684FBULL,
		0x8A86C2963EFEB210ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF2F65929543F0822ULL,
		0x09C1405C9DF7795FULL,
		0xBBEAC9CCB73839F2ULL,
		0x6ACD653E2BA3C20EULL,
		0xC2D72D705F7086FCULL,
		0xAB29B6FAF5C821C2ULL,
		0x8478AD1F913B3F3DULL,
		0x9B878356F42AE5E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91CA6DF1118DFB2BULL,
		0xB3C773D444DE17C6ULL,
		0x5187EDF3F12C18F4ULL,
		0xDEE67A419FF4EB5DULL,
		0x6724649B5D523615ULL,
		0x236A83D9519519A8ULL,
		0x0AFAB3F5A908FB41ULL,
		0x7590FF9157EEEF1FULL
	}};
	t = 1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x540496F3601F4ABEULL,
		0x691706CBD71043E1ULL,
		0x56E465249F2F19BFULL,
		0x41895AB53A36C6FFULL,
		0x83D0AD6FEBAF2D10ULL,
		0x20E30A152D884ABBULL,
		0xAB184A31934F6D19ULL,
		0x5FF3AB7E2C87AD03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF58744FB6D6DA68CULL,
		0x2A2979844D1ECE4CULL,
		0x7AC1CADFBCCAF630ULL,
		0x03F1C888B781F635ULL,
		0xAE15496D00857D3EULL,
		0x0545B6D5D94BCF00ULL,
		0x346802949CFA87ABULL,
		0xE7A545EDD9EB7AA5ULL
	}};
	t = -1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCBF5416E9F056FCAULL,
		0x93673090D0016305ULL,
		0x3CA36027CEB01B85ULL,
		0xDBDBD88396AA4B01ULL,
		0x292FBE0B6E810C09ULL,
		0x4DE14D79DB1B818DULL,
		0x4BCCFD05FAB11144ULL,
		0x2A943653146F71B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBF5416E9F056FCAULL,
		0x93673090D0016305ULL,
		0x3CA36027CEB01B85ULL,
		0xDBDBD88396AA4B01ULL,
		0x292FBE0B6E810C09ULL,
		0x4DE14D79DB1B818DULL,
		0x4BCCFD05FAB11144ULL,
		0x2A943653146F71B7ULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x51695137A542ACCCULL,
		0xD88EE4F5A7C2A691ULL,
		0x22E13579A1C8E15EULL,
		0xE25AA3849F59FEE0ULL,
		0x9AD70879AC16EDE5ULL,
		0x1EEC6A0CE8BB5C71ULL,
		0xD1501F981B58DEDBULL,
		0xF6A7CC63C3B01CF8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB894894E0C16DD3CULL,
		0x6792AF116CE7B620ULL,
		0x1793B59584992656ULL,
		0xA2FD4C0B920B0CA5ULL,
		0x2A0EC876F7B5EE09ULL,
		0xBD74C573FF38E6CFULL,
		0x9F785603B7F15C78ULL,
		0x2FC7A2C8E849B567ULL
	}};
	t = 1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF069D9EFCD8ED510ULL,
		0x125F781A2E98641AULL,
		0x404FD99E30A8EC91ULL,
		0xCFCFD1090A4CB513ULL,
		0xE129AA0E0C9D45A4ULL,
		0x22A3CFF4A35B5F11ULL,
		0x54C64F5E04125F29ULL,
		0xB221127ADC22FF57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD725C7EEDEA25DEAULL,
		0x2DA8D2708CD75EB9ULL,
		0x57244C44209570D9ULL,
		0xD0426D4F92B6F161ULL,
		0x021ED726C30B119EULL,
		0x2B1CE31572842A58ULL,
		0x7127D80B0F9F026CULL,
		0x075D6A68E3441C19ULL
	}};
	t = 1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2ACF8E69998FFFDAULL,
		0x3AADC7E57DC0333DULL,
		0xE0F6FC3F0500941BULL,
		0x3765EE61DDDB1C65ULL,
		0x4A3C999B16F003C8ULL,
		0xF08AFCE98E87F808ULL,
		0x1C05474C9D94DA41ULL,
		0x62AC0335EAC75487ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92FAA069BFEEFC9FULL,
		0x0F80268D08748B86ULL,
		0xF1A0F9CE671F0AA0ULL,
		0xA4431E6FF1851DB3ULL,
		0x7380DB65795D0FBDULL,
		0xBA0D04B8392396E6ULL,
		0x5A38D913BCB4FB39ULL,
		0x65FA556200B9796DULL
	}};
	t = -1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x034570C394AEA822ULL,
		0xAD2B95FE62A99864ULL,
		0x61ED0D854CD1B492ULL,
		0x48DB4B6CC0EFD408ULL,
		0xEE41452A5F5909DCULL,
		0xE33081699F4BE83CULL,
		0xFE8C211CD2B6A391ULL,
		0x7D72F24866E86D21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x034570C394AEA822ULL,
		0xAD2B95FE62A99864ULL,
		0x61ED0D854CD1B492ULL,
		0x48DB4B6CC0EFD408ULL,
		0xEE41452A5F5909DCULL,
		0xE33081699F4BE83CULL,
		0xFE8C211CD2B6A391ULL,
		0x7D72F24866E86D21ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x59752C6DFA9459B9ULL,
		0x2616E4E4A0BDEB0BULL,
		0x5669BB2674EC29F0ULL,
		0x1326E1B7DDC615B9ULL,
		0x21C4A936EDE10C05ULL,
		0x91A80CD50885A5CEULL,
		0x2C8E2408B8EA33D9ULL,
		0x13C87E0C287EE117ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CBB48514FD251F2ULL,
		0x015AD8C94EF8041BULL,
		0x314A2C3FAADEB1FAULL,
		0xE4DD824E1CC14B8DULL,
		0x35C2650F03700824ULL,
		0xE4E22E709D47C31FULL,
		0x3F023005848E4283ULL,
		0x1EFF7D075948FD31ULL
	}};
	t = -1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x57CFA32CB97343B0ULL,
		0xE09133D4B839CB58ULL,
		0xC379ABFA0340BBB2ULL,
		0x7906FC1E5F290B9FULL,
		0xF4081E2679ED50E5ULL,
		0x1C8C57B6FD5E7866ULL,
		0x25CD91E4DE5CD7EFULL,
		0x47C59DE11F8AA9A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD194E0E0A3F8F7ULL,
		0x3BA207E5C150DE3FULL,
		0x7AC7FE479E1BE46AULL,
		0x1BA4C4F5D8F2A67BULL,
		0x167D754E55A055A7ULL,
		0xFF2DDE29AF76B373ULL,
		0xA8A1261A0BEB1CC9ULL,
		0x1CDB2920E163BFF0ULL
	}};
	t = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xBA34FFD65CC77088ULL,
		0x03CED3A78ADE3C5CULL,
		0x0BA5866C0C6590F2ULL,
		0xFCA9845A1EDB39A7ULL,
		0xD181D425D7839DE9ULL,
		0xEE889ABD922E137CULL,
		0x1B0AC53B46E001BFULL,
		0x03BF34BDE9BC454AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA06FE500354CFD36ULL,
		0xA8C65AC21A9FF2ABULL,
		0x9B5EBF893932EE84ULL,
		0xC8B242D80D55359BULL,
		0xE90A7D280BF89AA6ULL,
		0xC1DEEFAF6A9E6179ULL,
		0x1FD7AF67E249DCB7ULL,
		0x0F51770A40CF6EB5ULL
	}};
	t = -1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0380716A83E1BCA8ULL,
		0x7CBE69E6B91730DDULL,
		0x63EEB37BF9D36747ULL,
		0xD19A9622FC602C01ULL,
		0x78929EBF49D2493FULL,
		0x6BF41F32A31D6B3CULL,
		0x65476C343AB036E7ULL,
		0xBFA2DE841984C115ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0380716A83E1BCA8ULL,
		0x7CBE69E6B91730DDULL,
		0x63EEB37BF9D36747ULL,
		0xD19A9622FC602C01ULL,
		0x78929EBF49D2493FULL,
		0x6BF41F32A31D6B3CULL,
		0x65476C343AB036E7ULL,
		0xBFA2DE841984C115ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAF7A9A75D2F2FEA6ULL,
		0x5560A2C9D0F60A6FULL,
		0x62FB22F2C833ECE8ULL,
		0x4FC85206386A9C1AULL,
		0xDE5DC5B1EB44E9C5ULL,
		0x23F2A87821DCFC0BULL,
		0xA5C0C40CB527AC01ULL,
		0x9AF1C73D522FE9D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFC8704AF9EAF88EULL,
		0xABBA57B6FEF4DEEEULL,
		0xC182A4F9F155DFF7ULL,
		0xFE1402E544410E1CULL,
		0x65782C73C80817A7ULL,
		0x5479B3BD5608D14BULL,
		0x404CB1E52949025DULL,
		0x6D957FC44EE2C4F8ULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xC2660014735D8C59ULL,
		0xD8992E6986FDA703ULL,
		0x2584C3E9631B354AULL,
		0xE9D33A6BC41F5F51ULL,
		0x58C097664862AF0EULL,
		0xF49244B67D4530C2ULL,
		0xCECDAB97A10764C4ULL,
		0x48B5BC749EC5F0EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1C2AB2E6CC34C0ULL,
		0x1E6910EF7B7F9956ULL,
		0x9C2E59816D163853ULL,
		0xC3CBD79C23417B55ULL,
		0x8BA532E3654BE267ULL,
		0x2FBEC525AF5AB77EULL,
		0x30ED958B71FD1002ULL,
		0x575ACC5C7291D4A0ULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xCEAB0547D55A8CD4ULL,
		0x3E3F2B924948512DULL,
		0x834B35E2E2F104D7ULL,
		0xFC42680C5674461BULL,
		0x47F2FA54819D3512ULL,
		0x65209F58B1ACF0B8ULL,
		0xF1E642BF0AB4B0CBULL,
		0x1A9592E10FBD6D14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x48C4BE9F17878510ULL,
		0xC0FA9ED66CB46F64ULL,
		0x8274BD6DCFBB1E9DULL,
		0x472E095E3D91039AULL,
		0x890C09C648871261ULL,
		0xE65EDE48D25F620EULL,
		0xA1245F68D37984CFULL,
		0x62036526F1146A35ULL
	}};
	t = -1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x632237EF67FAEDDFULL,
		0x39674438992D476AULL,
		0x64ED50219AF5D75BULL,
		0x6BA3FA1AD45CFAA2ULL,
		0x2533612975861C8EULL,
		0x0CCEF9F4D7F3626AULL,
		0xD0040C3DAE90816AULL,
		0x1A7048698C8A311CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x632237EF67FAEDDFULL,
		0x39674438992D476AULL,
		0x64ED50219AF5D75BULL,
		0x6BA3FA1AD45CFAA2ULL,
		0x2533612975861C8EULL,
		0x0CCEF9F4D7F3626AULL,
		0xD0040C3DAE90816AULL,
		0x1A7048698C8A311CULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x7FD42D94AB193D0EULL,
		0x0900E745ECDAFDCCULL,
		0xD575C550DC06AD4EULL,
		0x16D2CA96AE3FD38CULL,
		0x15BE22ED8EB68ECEULL,
		0x4B74895BF9407287ULL,
		0xD96F5DF83AAF54AFULL,
		0x846D5AD2FA1E49E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3126378C27AA771ULL,
		0xDEC2FA098DEFD45FULL,
		0x5D83C6548BEF0914ULL,
		0x48922B6D1C751AB2ULL,
		0x4F828A16D5302855ULL,
		0x3750B7422C1B2618ULL,
		0x05EE96F1952A0743ULL,
		0xE40D3002419524CAULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x301F4DF14DA6B551ULL,
		0x1D82F1C24380BC54ULL,
		0x0CEA09AFBA13CFF7ULL,
		0xC01DA2B31A5605BFULL,
		0x18ED818F379A400CULL,
		0x908E1F6DD58C299FULL,
		0x84AECACCF958BD06ULL,
		0xFD80A79F4CF67836ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46739E8EBF56CEF6ULL,
		0x8DEA9C482FB87DB0ULL,
		0x2B5AE19AF4611F28ULL,
		0x0CAD0968E934B4F3ULL,
		0xE48DAB7C9D31202CULL,
		0x4B89B55B0632EB28ULL,
		0x8A45DAC1AAA7E654ULL,
		0xCF952DEFBB95269BULL
	}};
	t = 1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x70AFA1E33B79A5C7ULL,
		0x7E0FB7A1104C6DEAULL,
		0x9D56371EB50177F5ULL,
		0x7421927E8BA65CE8ULL,
		0x19DEC036341EE93EULL,
		0x0A17B860F0824DE1ULL,
		0xD0BC0D795FA299D6ULL,
		0x23408D42A1BD5D6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A828627245BCC05ULL,
		0x09C7889C4EADFFF9ULL,
		0xFFDA03ECBAA13442ULL,
		0x88FA35B709AAE578ULL,
		0xA9088311B8921323ULL,
		0xF2D5E89C015B8A93ULL,
		0x72492DDF12042C6FULL,
		0xF2C6E2DE2F966C3EULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x47295F1F43B7F82FULL,
		0x9CB81993F411B530ULL,
		0x78C31356F5AF6842ULL,
		0x1525839042AD2F8EULL,
		0x3D5235F52F1B717BULL,
		0xF118F2FC32FC393AULL,
		0xFB67D6A6F008954DULL,
		0x1AA85EC218E61F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47295F1F43B7F82FULL,
		0x9CB81993F411B530ULL,
		0x78C31356F5AF6842ULL,
		0x1525839042AD2F8EULL,
		0x3D5235F52F1B717BULL,
		0xF118F2FC32FC393AULL,
		0xFB67D6A6F008954DULL,
		0x1AA85EC218E61F98ULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x41DC3EE9EC71EA6EULL,
		0x8C1438B5C4B292CBULL,
		0x53B6331CEF6A454DULL,
		0x72DA29F29CEE1C04ULL,
		0x7218900281C04D52ULL,
		0x678873A4220F4458ULL,
		0x4DF12BF8446DA75AULL,
		0x2C8BA07196A3D4A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94EC55F48C1BECE8ULL,
		0x7C5D157A31DBDF70ULL,
		0xE56563235383E287ULL,
		0x4819E4C9D63CDC7CULL,
		0x62049C1593EE85D3ULL,
		0xC0003A4C69E6EA46ULL,
		0xA1021514A43C8A0CULL,
		0x36967B355BB8473FULL
	}};
	t = -1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE5C53B04CBFACF4FULL,
		0xF7A99BF7D4ADFF3AULL,
		0xEA2FE2ED4EA6BD0DULL,
		0x7CC043BB527DBF37ULL,
		0xB90A7F2B7A18B4D6ULL,
		0x1FE6CF846092BF30ULL,
		0xB64F607B777FDE12ULL,
		0xBE0F38F9DFFDDDD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A3A948582780FFULL,
		0xA208FF00FDED04F8ULL,
		0xD3CEED4A811464ACULL,
		0x0280FAEE93D6EFFFULL,
		0x066979C8E5D2A689ULL,
		0xC455307944C6A1F2ULL,
		0xCBF4BFF59EF52183ULL,
		0xC7800ADABCEAE36DULL
	}};
	t = -1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE67961AB3601A2ECULL,
		0x42AAE4280A468730ULL,
		0x7168CFD891ADD051ULL,
		0x1DE10E1173EBDB8CULL,
		0xB3B7D47444C7FCA7ULL,
		0xE5F715F86467ECCEULL,
		0x5CCBB2D342ECF4BAULL,
		0x89E1D05574F60613ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4116BCCF23C9A137ULL,
		0xE86BE63DAFA8AF4AULL,
		0x316DA9BE54B31C77ULL,
		0x058E09B1F4B64D0CULL,
		0x02B3180E2D5C114EULL,
		0x5AB37E863753272CULL,
		0x48B44670DF0ED0FAULL,
		0x7458331DC1C7DE0FULL
	}};
	t = 1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xECD2A6EB98D29661ULL,
		0x72A5A6D05D78E535ULL,
		0xA33C7EF0F148A14EULL,
		0x2CF3AEEAD801F2B0ULL,
		0x47725FD5AFC489EAULL,
		0x62209D9EB99B6C34ULL,
		0x7C53F44939862638ULL,
		0xC08F5176D05CD3ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD2A6EB98D29661ULL,
		0x72A5A6D05D78E535ULL,
		0xA33C7EF0F148A14EULL,
		0x2CF3AEEAD801F2B0ULL,
		0x47725FD5AFC489EAULL,
		0x62209D9EB99B6C34ULL,
		0x7C53F44939862638ULL,
		0xC08F5176D05CD3ADULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xF2CF6F99414B79E4ULL,
		0xA5E650F9C1497F69ULL,
		0xC35621B2C3FD4038ULL,
		0x525FB05FD7D95C0EULL,
		0xD0E03BD2D6784331ULL,
		0x564B81BA51DCFA54ULL,
		0x24007A4FDEF308EFULL,
		0x72EC055B004C56C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB19D1DB230189D12ULL,
		0xEC56A6ABA91C0DBEULL,
		0x43865D7F11CF2EE7ULL,
		0x75579CE4BCC15DFFULL,
		0x32FFBD6BD7E70697ULL,
		0x0FB302DA6649A57FULL,
		0x72C4A7FA7DBA4C8FULL,
		0x2ABB36BB45E71539ULL
	}};
	t = 1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xFCCA3DC34229ED40ULL,
		0xA814006211A8E724ULL,
		0xC9099514869924A1ULL,
		0x35099259C07E141BULL,
		0xA0C0510D7FC12C2BULL,
		0x0131247081E1AF67ULL,
		0x851072E138BD3ACFULL,
		0x4864E9F276C65F4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71D19B5B0D0FCCF8ULL,
		0x7530337BBBF2CB00ULL,
		0x6301D092D196132AULL,
		0x9743F449AE793CAFULL,
		0x95ECB2B40474E8C4ULL,
		0x70FCC3E33B6F69F7ULL,
		0x7CEF2F65C594DC19ULL,
		0x58DDDB22B4FC9159ULL
	}};
	t = -1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4CE274EECD6680F6ULL,
		0x29D2E6A3AC884BF2ULL,
		0x10F79664C0A8B225ULL,
		0x6C8469A6B52E3D39ULL,
		0xFB80C4A667A2FC08ULL,
		0x8F284CBE4C7884FEULL,
		0x6D84AC1706EA03CAULL,
		0x01C2CB58BA27A78FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F59FC5E967A5CAEULL,
		0xD72E658695942FC7ULL,
		0xEDFEB85EAA6EF9FBULL,
		0x2ED29897AC28D2E7ULL,
		0x86553BB693031AFDULL,
		0x41A19064AC220C12ULL,
		0xE45734F70D027DC6ULL,
		0xD9EDB9F031304BCAULL
	}};
	t = -1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x37C454637F45B64DULL,
		0x8C9A33248D2286EBULL,
		0xDB88C4808B587D0EULL,
		0x526E0402453B341CULL,
		0xA03F4BCB00F67B24ULL,
		0xE471CE0560352214ULL,
		0xD663F0235999EDA7ULL,
		0xB99B78AF2714D63FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37C454637F45B64DULL,
		0x8C9A33248D2286EBULL,
		0xDB88C4808B587D0EULL,
		0x526E0402453B341CULL,
		0xA03F4BCB00F67B24ULL,
		0xE471CE0560352214ULL,
		0xD663F0235999EDA7ULL,
		0xB99B78AF2714D63FULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x607ADE14D598C04DULL,
		0xDDB9237020E41726ULL,
		0xCAF253B3ECF1103FULL,
		0x7DBF5CFE4A66C031ULL,
		0x22B095EA4A961675ULL,
		0x6B603C11CBA6E08FULL,
		0x97CB5ADE2FBFC16DULL,
		0x23FAD18CB7A8A182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF39C71E661F24E72ULL,
		0xA8E5B9FEB371C25EULL,
		0x596E96B25034397FULL,
		0x121217EB36F94B9AULL,
		0xCEF5B76F41CB9159ULL,
		0xF2571A1D8BFBF5BAULL,
		0xF2371F2596C8946BULL,
		0xE571CACDB591EE00ULL
	}};
	t = -1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA4BF7FC4CEAEBDE0ULL,
		0x6A1AF8553AC2504CULL,
		0x7CCEE3714ED7867BULL,
		0x7604D81C1D4D97DFULL,
		0x5B1C612F53F5BE1EULL,
		0x2E7B90983DA05B39ULL,
		0x374E53D09C368044ULL,
		0xEAACF47F765DA399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE7B230547227D0DULL,
		0xB72CC072992C3D85ULL,
		0xC5CCDBD291CD4BFBULL,
		0x73C0E1EF0D868BB7ULL,
		0xC84C04093713BC0AULL,
		0x187535C7E520D19CULL,
		0x798E624960A23D36ULL,
		0x0689A7E99CA8C1A9ULL
	}};
	t = 1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD4312074C3FA33A7ULL,
		0xD59BB0374D58CCADULL,
		0x8D807D169E54330FULL,
		0x029CBCADDE38CC21ULL,
		0x4B75A084DCB7603EULL,
		0x7D47FE2E3F90989AULL,
		0x0FA4DD48277FAA70ULL,
		0xCEE9EF305719D8BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74C8B40C965DFC64ULL,
		0xCFEC86452A6BBB8CULL,
		0x980D00AB8673B139ULL,
		0x3993A21441D550A0ULL,
		0x2CD2C756DE0185B8ULL,
		0x54C78D84A33B9B83ULL,
		0x9B87BEB908A77C7AULL,
		0x2150FA25119D9547ULL
	}};
	t = 1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x78F9434CA2E29EABULL,
		0xDD8A70044ACFC192ULL,
		0xDB1E8D771463B8EBULL,
		0xFBCFEDA4F597FD21ULL,
		0x5685D519DD465F15ULL,
		0x61DCBBBDE83FCAFCULL,
		0x063FC20600289A60ULL,
		0xDBC23B6B044465EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78F9434CA2E29EABULL,
		0xDD8A70044ACFC192ULL,
		0xDB1E8D771463B8EBULL,
		0xFBCFEDA4F597FD21ULL,
		0x5685D519DD465F15ULL,
		0x61DCBBBDE83FCAFCULL,
		0x063FC20600289A60ULL,
		0xDBC23B6B044465EEULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x99F12655C59114BAULL,
		0x41C374EB336F8F2BULL,
		0x018B2DAAC9877E9CULL,
		0xDABC683A0D83BAFEULL,
		0xE06A6E3AC4ACE5ABULL,
		0x43A953BF2DEA9AB9ULL,
		0xB6BF4C5967BB4DA8ULL,
		0x454ACC75F8C3A01CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A5914D901DBBEDULL,
		0x023138F1A8736C10ULL,
		0xB3BDBEF16211DAEFULL,
		0x08403E54520C9F7BULL,
		0x3AB5CA950F9B0BD6ULL,
		0x2EDB902440EC99EBULL,
		0x66E715F3A4A97BF7ULL,
		0x323B4EC297981956ULL
	}};
	t = 1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9554CFFEB3FE7F7BULL,
		0x9428C2AEAFF41012ULL,
		0x7D8E52784F176BD6ULL,
		0x653DDED39359B77FULL,
		0x9A8685CE97653F05ULL,
		0xBEDCA460B0990944ULL,
		0x9E9C800C3977818AULL,
		0x7F02F4B86AD0ACCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71C6C9085D78221EULL,
		0x49C718FDE8D7931AULL,
		0x8DCF619224EFED62ULL,
		0x3922FF9BB60DC609ULL,
		0x843777000A124938ULL,
		0x93305A429E66F3B2ULL,
		0x52154D6BD6D2F43DULL,
		0x5F4DB56DC3C26BDEULL
	}};
	t = 1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2FFD935471F9BB02ULL,
		0x4905798707953453ULL,
		0xD31D250A59C7CCCFULL,
		0xF49474E4AFEF9C99ULL,
		0x03AB9932AB13D631ULL,
		0x73E781D469E9180EULL,
		0x6348DA75461AE71EULL,
		0xC2F95224D6DC8958ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F2C3D77F267D920ULL,
		0x50D9087081343BEDULL,
		0x86748066D126A887ULL,
		0xD0C70C0A50EC93BAULL,
		0xB285461D334C61BFULL,
		0xE3BCC7B48B20A6EAULL,
		0x0FD5E920C6F39899ULL,
		0xA0C481A05CB9B6ADULL
	}};
	t = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9A09F5173D395112ULL,
		0x44023BE9A5CC368AULL,
		0xF88C0C60130F9084ULL,
		0xF1953F664076ACCBULL,
		0x512E61C492D60254ULL,
		0x3690F5C4AB6CC0BEULL,
		0xC525843E1AB07F6FULL,
		0x22AB7E0D8553EA78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A09F5173D395112ULL,
		0x44023BE9A5CC368AULL,
		0xF88C0C60130F9084ULL,
		0xF1953F664076ACCBULL,
		0x512E61C492D60254ULL,
		0x3690F5C4AB6CC0BEULL,
		0xC525843E1AB07F6FULL,
		0x22AB7E0D8553EA78ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE6409D2F8E84919EULL,
		0x2EB249D07E86C6ACULL,
		0x519B8D8DFCCBCC43ULL,
		0x8051DF16E8C1B407ULL,
		0x5D18818CE0D0F50DULL,
		0x686754F7DA645E86ULL,
		0x0103C7867D3343E1ULL,
		0xB241D4C53A67715FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E8AE6F6FE3369BDULL,
		0x905011E1123A4CC2ULL,
		0x18588184F9A932FBULL,
		0x26E23845BCA0F382ULL,
		0x7A77A535AAA76ED2ULL,
		0xC904436EE0D35C45ULL,
		0x94064DD9545FDA77ULL,
		0x10E13977426DA7B7ULL
	}};
	t = 1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5829DE26E951C577ULL,
		0x5F595CDE799AAB34ULL,
		0x6C95AE01272F3815ULL,
		0x7ECCD099999F16D7ULL,
		0x56A2B2558B245519ULL,
		0x3EEC76DF18542583ULL,
		0x918AFFEA8E6979EBULL,
		0x3862C932E7588265ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6801BFC4026170DDULL,
		0xB17580FD4393C5B6ULL,
		0xF13A9218A0B3B9F7ULL,
		0x3C4714A16204E24DULL,
		0x9F240FBCDF424218ULL,
		0x0BA02F061684B8AAULL,
		0x4EF55A7058544615ULL,
		0x3E66F7832733B730ULL
	}};
	t = -1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9C2A81CA2407D8DAULL,
		0xE94EE9F72A3024CBULL,
		0xC6494CEA3842586BULL,
		0xE4AFF5CBFFB9DD85ULL,
		0xC4ACDCABFB973C7BULL,
		0x36AA75B7CA03083FULL,
		0x806C6590601E6524ULL,
		0x1047A0F6C765E82DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C78977CC6F3EA6FULL,
		0xD717FE2F76BC1937ULL,
		0xD28CAC0A57A326E2ULL,
		0xD21EC1825A896B9AULL,
		0x8215B88AA4E770DBULL,
		0x9064D73CC0CB3661ULL,
		0xD934F4AC790BAB22ULL,
		0x213956C5D728F898ULL
	}};
	t = -1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA85BBC0965B19F1CULL,
		0xB85F8B767576A1A2ULL,
		0x2144EB4B2BD2E9E8ULL,
		0xCDAB8F10F5429BC6ULL,
		0x3062E0041DAAF236ULL,
		0xB89DCD77D240F93EULL,
		0x71052D112DE9A749ULL,
		0x0E67CF3399601CA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA85BBC0965B19F1CULL,
		0xB85F8B767576A1A2ULL,
		0x2144EB4B2BD2E9E8ULL,
		0xCDAB8F10F5429BC6ULL,
		0x3062E0041DAAF236ULL,
		0xB89DCD77D240F93EULL,
		0x71052D112DE9A749ULL,
		0x0E67CF3399601CA3ULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x151B44BC4677E139ULL,
		0x7041582E6F913097ULL,
		0xD82BF095ACB87038ULL,
		0xC4DF84F9B17D215CULL,
		0xE947FC27610EE75BULL,
		0x149CFBF373A91A19ULL,
		0x33795514D51F08CBULL,
		0xA51C940896A4647FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50A06318316B178BULL,
		0x24B0423E337CC4A0ULL,
		0xD264F52B20BDFDACULL,
		0x625268ACE5D51D7CULL,
		0x6CE9E63A905DE34BULL,
		0x75AB333905E17C9CULL,
		0x38EA2784DC256AB9ULL,
		0xDB83D4DB60F3B18FULL
	}};
	t = -1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x955EA37824DEFC29ULL,
		0xFF43A298909E5891ULL,
		0x6B840A523784B5D6ULL,
		0xC1A1F868A4A9FB02ULL,
		0xB0D306BE5377ADB9ULL,
		0xCAB3958F962860B4ULL,
		0x04E485EF17739A80ULL,
		0x05A6AC0E40FE0946ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE8518CABE4BC4DULL,
		0x66CD0A97D5F3D86EULL,
		0x2CAB7BF843D02709ULL,
		0xF315E6099AA41352ULL,
		0x699DE7846CAE9795ULL,
		0x5D1A286A6A97B59CULL,
		0x8090E01106FF34FAULL,
		0xF41C11806A653594ULL
	}};
	t = -1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xA1EA36E0728C80B3ULL,
		0x08A649ACAD85906AULL,
		0xCC79E8F72B358655ULL,
		0x8875F81F33924855ULL,
		0xB3B35D7728769B49ULL,
		0xA4540FFD25C71299ULL,
		0xCE1FF60AD7BAE32AULL,
		0x2829C625576C9760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC538C354985D0CULL,
		0x62F4E83BAA95EB0DULL,
		0x4155FF370F37CFCBULL,
		0xF322499036CF5F77ULL,
		0xF8C2F5FA8293F830ULL,
		0x819856DFDA95C464ULL,
		0xC7E4EFAB535B4ED9ULL,
		0x026C1432B7BB1BEBULL
	}};
	t = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x02126156A023DB92ULL,
		0x342B27D1E08749FDULL,
		0x356758A012F0B09BULL,
		0xB773C6933FEFD86AULL,
		0xE6B36F9E24C5249FULL,
		0x8A9758FE24F02F9CULL,
		0x801EAE9225A92FECULL,
		0xEA7EF875E4DFE9A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02126156A023DB92ULL,
		0x342B27D1E08749FDULL,
		0x356758A012F0B09BULL,
		0xB773C6933FEFD86AULL,
		0xE6B36F9E24C5249FULL,
		0x8A9758FE24F02F9CULL,
		0x801EAE9225A92FECULL,
		0xEA7EF875E4DFE9A1ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE4C7C1A13BEDAB89ULL,
		0x179E9FC73F8AC4BBULL,
		0x0E1CCB3B1A0D8DE0ULL,
		0x428A34027AE90C63ULL,
		0x28B8FDA8927F3C51ULL,
		0x1F4101B09DD02545ULL,
		0xDDB05393622D475AULL,
		0x8F37F7D9202ECA25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CF59CA99FDC340EULL,
		0x5DEB5135EA33D155ULL,
		0x46B202B56CE838D5ULL,
		0xC0A8B9950987058CULL,
		0xEA1CB74DF5CA17B3ULL,
		0xAAB3285D31D288DAULL,
		0x3103ACB67D955782ULL,
		0x839A0EB21EC00F6BULL
	}};
	t = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0F47B2D3016CE3C1ULL,
		0x128262550DA9C1ABULL,
		0x4D10DADBCC43B030ULL,
		0x0966748E29E4A018ULL,
		0x7408D0B61A69B48CULL,
		0x16FDF9D65D491415ULL,
		0x821E5D8B1681B0C6ULL,
		0x90FB9C4384740F83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9A133354F016DCULL,
		0xDB41588DD771F290ULL,
		0xA1EF385AACB74E23ULL,
		0x3C6DE3A82E24F8E0ULL,
		0xD6AD7B6302A021EBULL,
		0x47818073D80A7CF4ULL,
		0x87A477F097B2BBD8ULL,
		0x1BA0C310323FD23EULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8B90C267B39875C3ULL,
		0x961B659528B09888ULL,
		0x39BE345CC6B360D0ULL,
		0x19456B1510C01722ULL,
		0xAC88CF9891C521CBULL,
		0x1BEA20E10DD3EBD8ULL,
		0xA218AAC4A505352CULL,
		0xF2EB7B33916752BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D8228E06CD7EEEULL,
		0xB1841EA102D9BD19ULL,
		0x9CB82F5FDB0F868AULL,
		0x086428F78D6DBA33ULL,
		0xF16370882AD8A4A5ULL,
		0xCAB86B920117E4E1ULL,
		0x02A090E0FBCC31E9ULL,
		0x83CBE84676D98F41ULL
	}};
	t = 1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4916EC95FE23D08EULL,
		0x84D61AECC88500E1ULL,
		0x46C7989A9C100173ULL,
		0x64DD0F95FBDB906CULL,
		0x1DF753C7D6C83E6AULL,
		0xC54033CDEC559D40ULL,
		0xEC80CDB9099709F3ULL,
		0x919A861849A00C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4916EC95FE23D08EULL,
		0x84D61AECC88500E1ULL,
		0x46C7989A9C100173ULL,
		0x64DD0F95FBDB906CULL,
		0x1DF753C7D6C83E6AULL,
		0xC54033CDEC559D40ULL,
		0xEC80CDB9099709F3ULL,
		0x919A861849A00C02ULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xDE969C9E332663B7ULL,
		0x561D7FE9DA2799D8ULL,
		0xB56C2EB6CBFE39ADULL,
		0xA29138C6E50C0135ULL,
		0x3772B01F43A2F6B2ULL,
		0x018060E130327748ULL,
		0x76D9E03A4DEF156CULL,
		0xBFDEC74E3A88C140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A7F0271C433073ULL,
		0xE2561546747FD5D1ULL,
		0x5B441285B475208AULL,
		0xEC60C154BFDA1B5CULL,
		0xE6EFC7619D92C10BULL,
		0xB892543751C342BFULL,
		0xC8D2438A4C6F3470ULL,
		0x9A42E1BEA04B4554ULL
	}};
	t = 1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x9B8875881F4B456AULL,
		0x7FD781683E03CCD2ULL,
		0xF191F6849B1E454DULL,
		0x3DF2FFCA23B68D6EULL,
		0x8605245A8C84320CULL,
		0xB3EAEAA1A03B1F61ULL,
		0xA1CB401B6E3989C9ULL,
		0xCFD390DC1AFF16FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD9682E30B0311F1ULL,
		0x5FCE711494C78ABFULL,
		0x514D34A59ECDF7F3ULL,
		0xAE3FFD89D04F4F59ULL,
		0xC6627563B0DB2E38ULL,
		0x877AB414ED64C37EULL,
		0x71B8815A419D69F4ULL,
		0xA423C33E08396F3BULL
	}};
	t = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE6F447FA47E7D6B4ULL,
		0x66ACA3A8C9C71187ULL,
		0x998FD1DBC22ED44FULL,
		0x7928BC7F67FFBF3FULL,
		0x94A5BD91318EB0CEULL,
		0x58AAD62559B951C8ULL,
		0x3CCA77AB92221273ULL,
		0x4E3BD78B2D01A36DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA99BB81A854E18A3ULL,
		0x16F56736C9E3205DULL,
		0xDEB03221F8D20614ULL,
		0x3F75698F99D1E81AULL,
		0x29BF652DDFFBB925ULL,
		0xE39E77455B1CC02DULL,
		0x3DAF43CD1536BF73ULL,
		0xA82C734455DDA08AULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x12057B578250EC3FULL,
		0xC83F4F810EB5B47DULL,
		0xD025669F2E8A76D2ULL,
		0x7129A0AC081DBB0BULL,
		0x0D2DC9CECE80D6E0ULL,
		0x9EC6B6D367EE91E7ULL,
		0xDD1875FEE839AFF6ULL,
		0xCAC9CD209162F4B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12057B578250EC3FULL,
		0xC83F4F810EB5B47DULL,
		0xD025669F2E8A76D2ULL,
		0x7129A0AC081DBB0BULL,
		0x0D2DC9CECE80D6E0ULL,
		0x9EC6B6D367EE91E7ULL,
		0xDD1875FEE839AFF6ULL,
		0xCAC9CD209162F4B3ULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x31F773E990C27B94ULL,
		0x1193EB428095AF0FULL,
		0xDBB9CDD350F469B0ULL,
		0x329FD2D645A978BDULL,
		0x9B1B6906447E369CULL,
		0x87002FF887422B07ULL,
		0x4BBB23F19EB97CBFULL,
		0xBAD7D311D4717953ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2ED5612D7EE3562ULL,
		0x6BB581C44C7964F8ULL,
		0xC74AA243249343BCULL,
		0x14AD0D02774D2009ULL,
		0xD2200DD0B0CAC12DULL,
		0xB4DC9E5F0F4CFF4BULL,
		0x00D1D8B7A1A37DB5ULL,
		0xB7912C39F22951ECULL
	}};
	t = 1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x87389761D5EB759FULL,
		0xA54BB61B846F95ECULL,
		0x98FC21DEAA58A66CULL,
		0x631501676E5E77ADULL,
		0xDF1B660157B370D0ULL,
		0x75ABED1D9AB6552EULL,
		0x8CE9AF81E8E10BF5ULL,
		0x1443428A3E19D542ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x974F712372A45A7EULL,
		0x87764B16720A9F68ULL,
		0x1859EDC1247FFE41ULL,
		0x378E8BD91D6B9473ULL,
		0xDD03E75BA7FB9963ULL,
		0x7CCE3B25BAB376DDULL,
		0xE93A995D2E09FA88ULL,
		0x80F444F236A0C159ULL
	}};
	t = -1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x0271F7BBD8099414ULL,
		0xD756E662B6EC7AACULL,
		0xF9032CA2BCD0D6AAULL,
		0x16124A79CA482907ULL,
		0xE6B5EE4739AD7B6FULL,
		0x375FB678B96AF2A4ULL,
		0x4BDFA8F4D9846204ULL,
		0x9B3B3E18E823AD71ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF74DCB5BFE902E92ULL,
		0xDD57EA90BF697B66ULL,
		0xB367F14EE0C6C82AULL,
		0x815C981760B542A7ULL,
		0xDD07978B05909EFEULL,
		0xBCD76C2545CD4F43ULL,
		0x590C22AF33782F58ULL,
		0xF78359113F7C83DCULL
	}};
	t = -1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB668EFBE722B6BD0ULL,
		0x8282923B311AD8C1ULL,
		0xAFF7DCA19537BA7FULL,
		0x9EACF5A90D0C9191ULL,
		0x6730E9E05607BF79ULL,
		0x992FB27BF9278FBBULL,
		0x84846CC4F43084FCULL,
		0x1F6D72A11A0260B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB668EFBE722B6BD0ULL,
		0x8282923B311AD8C1ULL,
		0xAFF7DCA19537BA7FULL,
		0x9EACF5A90D0C9191ULL,
		0x6730E9E05607BF79ULL,
		0x992FB27BF9278FBBULL,
		0x84846CC4F43084FCULL,
		0x1F6D72A11A0260B0ULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x895AAF7FF32A7ADEULL,
		0x082617F04AD04769ULL,
		0xE411BC8377F069DFULL,
		0xA816023B7194120FULL,
		0x17530E2F1FA7AD94ULL,
		0x8A198C1B1BAE7243ULL,
		0x85BB51DE4BA0175FULL,
		0x496CC204735EE0A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04DE1F5AA77B79E8ULL,
		0x50F63F2A06654735ULL,
		0xBB23E05796F507A9ULL,
		0x04E44BD841D25986ULL,
		0x331003C50F912DACULL,
		0xC47E7720935A9762ULL,
		0x778EF4DD2A2D43B4ULL,
		0x02A4F05806246A1FULL
	}};
	t = 1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD50CE65FCB36D952ULL,
		0xEE7A60FECC14F22AULL,
		0xBFC64061E111D1E1ULL,
		0x1E27A9A964A697BBULL,
		0x03CF9876D202EA42ULL,
		0xE02379ECCA83FFE2ULL,
		0x18B7A3F5CAEC5FA5ULL,
		0x2CFD81E90E67BB1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4AB19CDAD8F806ULL,
		0xD2A31AA54915D692ULL,
		0xDDC039E9EEA14B68ULL,
		0xAD7362FA6C28A7F1ULL,
		0xDCA8BC9252E407F4ULL,
		0xD536EDC7FAA741B5ULL,
		0xBC36BD54256ED155ULL,
		0x0B9101F3D6EB64E2ULL
	}};
	t = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x802066F03CF1172BULL,
		0x1525A0E0E86DFE21ULL,
		0xD7A7AAE5A2C3E8ABULL,
		0xA5D0E104BC2BC6CAULL,
		0xB92D9FE95A81C11CULL,
		0x01E8536395269BDAULL,
		0xBC49CDB7A8A0A578ULL,
		0x4F717A624CE7F1C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6256089E565E2D4FULL,
		0x0F8B644444FBD528ULL,
		0x33CDFA7174C410F6ULL,
		0x91F8716224DC08ECULL,
		0x9E31116DE119843AULL,
		0xFABB5B25340AC59EULL,
		0x37610999ABC3AB55ULL,
		0x56C55F713EAC1C9BULL
	}};
	t = -1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x46E7B48F10453C3AULL,
		0x887A9FC57D3D983DULL,
		0x180242EE5F2D9BEDULL,
		0xD5359110ED0B0B0CULL,
		0x14F5A75E84839943ULL,
		0x67F60B2458E4547AULL,
		0xD1EC48C18961122CULL,
		0x16B889DB8321BCC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46E7B48F10453C3AULL,
		0x887A9FC57D3D983DULL,
		0x180242EE5F2D9BEDULL,
		0xD5359110ED0B0B0CULL,
		0x14F5A75E84839943ULL,
		0x67F60B2458E4547AULL,
		0xD1EC48C18961122CULL,
		0x16B889DB8321BCC7ULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x5E6FF64B92958BBEULL,
		0x6CEDE1DF6C00AE9DULL,
		0x2E9D0D145B4EAC25ULL,
		0x70DCF32A25697746ULL,
		0xA712574543BAA98FULL,
		0x9F8780055C16AD4EULL,
		0x4701FA5A1306F910ULL,
		0xEAECE130FF19C725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAB9F7B116BFE3C3ULL,
		0x67192ECA9548FC6CULL,
		0x776E7F2531E15C11ULL,
		0xBD675DB548034982ULL,
		0xA12AD47C365D86CCULL,
		0xD0ED1E0802B8E88CULL,
		0x99CDDBB7942482F9ULL,
		0xF8E6A96998E62D5CULL
	}};
	t = -1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x33AF7213188C0C62ULL,
		0xE05B09F73E0C7E97ULL,
		0x89DA335C6C57B592ULL,
		0x59588417E5DF36A6ULL,
		0x16B5A5E4D50054DAULL,
		0x4F438D362C8BC700ULL,
		0x8FDCDC86C8477DE8ULL,
		0x1C73CC38ADA5520CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x959B0F5AA74B6D55ULL,
		0xFC14CC7F4544B84CULL,
		0x661C6323AB6B69E6ULL,
		0x77C725099F171781ULL,
		0x6173626BC342114AULL,
		0xDC5327A5154E9667ULL,
		0x16A8C34EDC913468ULL,
		0xF3F1E6A6FCA0B3EFULL
	}};
	t = -1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x76A9CC34AC9AE893ULL,
		0x6E667340D9B80B5CULL,
		0x1960E43930B0EECBULL,
		0x99D9B8AF01C22F08ULL,
		0x5F42A096FA68EF45ULL,
		0x22FB29DA7252FEA3ULL,
		0x3BAFC0FB258AD386ULL,
		0xBFF6F669EA96B2CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE61CA1F1477EC268ULL,
		0x5C36E6CAB859CC46ULL,
		0x996F30DE1057223FULL,
		0xDDCF74329A357A48ULL,
		0xBBBCE079CD736906ULL,
		0xAA35CDCA31415DB8ULL,
		0xC6319E1836E396B5ULL,
		0xB772DC281D3A63A8ULL
	}};
	t = 1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x143DE89695C958C3ULL,
		0x0207EDC6FA967EA3ULL,
		0x4AAA1C6300DF5704ULL,
		0xECA671931794C1EBULL,
		0x5F26736379A11FFDULL,
		0xEE2E3B22EBD33E6CULL,
		0xD7BCEECC1CBD2791ULL,
		0x3770C416D2509DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x143DE89695C958C3ULL,
		0x0207EDC6FA967EA3ULL,
		0x4AAA1C6300DF5704ULL,
		0xECA671931794C1EBULL,
		0x5F26736379A11FFDULL,
		0xEE2E3B22EBD33E6CULL,
		0xD7BCEECC1CBD2791ULL,
		0x3770C416D2509DA1ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xEB3C25BC27749D60ULL,
		0xE2B44E4CE3985AF0ULL,
		0x327E1706295661CCULL,
		0x585EFA92C2F6B78BULL,
		0xBB9ECBA2B5927491ULL,
		0xD824803113D237ECULL,
		0x4F85CE0EF50C9D74ULL,
		0xB61E55D41AFE9038ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02A3490A9E63CF08ULL,
		0xB0C6BE586101BCACULL,
		0xB54A51BC87025B48ULL,
		0x436769DBB97AFBB1ULL,
		0xFCD573AD80C32573ULL,
		0xF9C5AE0F1BB85C75ULL,
		0x4D758BC71EA326DFULL,
		0x252EA8B5336BE067ULL
	}};
	t = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAAF51C0AACCB7D08ULL,
		0x967BCE8E5AA9429AULL,
		0xB1C83CF54747F779ULL,
		0xB9545B66954D7A63ULL,
		0xDBC1C7CBB3DB249EULL,
		0xAC606BF7765459ECULL,
		0xF638B54C146C6EBCULL,
		0xC66FFB199FABBF46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32395B6B75D18F50ULL,
		0xCE9AFEC0EE2703B7ULL,
		0xC2486CC4F65F1C45ULL,
		0xD852D58E233288C8ULL,
		0xC621384C14527802ULL,
		0xFA8035AA01D962A7ULL,
		0x6D59503B055D6617ULL,
		0xB135B24F8AE171FEULL
	}};
	t = 1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xD18BB045132CFEBFULL,
		0x8D60B202A7A09F01ULL,
		0xDACAF7646954B179ULL,
		0x0333399CADDF6CAAULL,
		0xF8A2C8E1ED69859AULL,
		0x0597CA5B0648E766ULL,
		0xD6534FBFEA25D164ULL,
		0x4CA707205F9E03E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F77D4C52E7626FULL,
		0x9D516AD310AF4461ULL,
		0x0E7EE3D99279A385ULL,
		0x4119B8FA9DD860EDULL,
		0xFD289A85494BBD5BULL,
		0x96ECDE80CD01DDECULL,
		0xC03CACB4B1326568ULL,
		0x35145E7BD2EA7F2BULL
	}};
	t = 1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x74BC462441BCC2A8ULL,
		0x4F8EA4A66E26B9FCULL,
		0xD91E3B8BB2B9684EULL,
		0x87C41635FE19983BULL,
		0x991EC42E8B154E1AULL,
		0x817F0DCFF59F7F8BULL,
		0x36B6FAFED8D2808DULL,
		0xAEDD6F36909C7608ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74BC462441BCC2A8ULL,
		0x4F8EA4A66E26B9FCULL,
		0xD91E3B8BB2B9684EULL,
		0x87C41635FE19983BULL,
		0x991EC42E8B154E1AULL,
		0x817F0DCFF59F7F8BULL,
		0x36B6FAFED8D2808DULL,
		0xAEDD6F36909C7608ULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x03850B2AE472EF36ULL,
		0x64D9D07C2F2BDEB3ULL,
		0xAA1169453F97B37EULL,
		0x4BE023C1145058D3ULL,
		0xEC505B2BD3FC3B71ULL,
		0xC7EFBB149CDFACBFULL,
		0x9B7D0DDE4D31E65AULL,
		0x9046E6B49B044779ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8850EE5839408014ULL,
		0x3AB3CE27221F09ADULL,
		0xE55F924BE251CFD8ULL,
		0xB3A7DB4AF82898ABULL,
		0x924C23E91F7AAB57ULL,
		0x46B01D9CA3DE47E2ULL,
		0x3B2FD1940F8320EAULL,
		0x051B329B3A8552CDULL
	}};
	t = 1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xE587D6A8F52D17A5ULL,
		0x945BCBCA7370397CULL,
		0x544DC5049D7A5B3BULL,
		0xC58B864B2C80897AULL,
		0x4184BF831D3A0EDBULL,
		0x0A47FE0E73B4B851ULL,
		0x09413BBDBC2E4E9EULL,
		0x2ED843B4978A2954ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF805FF4340918B8ULL,
		0xDB77734100D2A461ULL,
		0x0C36023D38C0D4D3ULL,
		0x298CAE1614005DD4ULL,
		0x2C1F48D88023D6D1ULL,
		0x578648061CECD0F4ULL,
		0xA9FA86C07F67E943ULL,
		0x2E6D2527611EE90BULL
	}};
	t = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x6D5ADFE2DB514D7EULL,
		0xFC1DF7D29AE7B381ULL,
		0x699AC54F6E0A2693ULL,
		0xF4F1404DC45A7631ULL,
		0xD0BAF645C0B62D59ULL,
		0xFA7F995761530938ULL,
		0x0CE7F01D33E8B613ULL,
		0x7CFD94D140C080A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5DB0137159DC16ULL,
		0x029849B38BEFCA10ULL,
		0xCE9B950C92883D8FULL,
		0x07BA23009C2F2D2CULL,
		0x20A79F85F9875398ULL,
		0x6AE2B0AC679CC68DULL,
		0x49790DB03A66D2D9ULL,
		0x4BC75CDAB0C512EAULL
	}};
	t = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4341DC0B554EC73FULL,
		0xCD22A45EFFBB2CE7ULL,
		0x1C3D97811350DDA8ULL,
		0x344AF1D2352F4C5AULL,
		0x713CD90B576DBED5ULL,
		0x3C99C3ADFA7699CAULL,
		0x835C38E2884A468CULL,
		0xCF6FC3E922BADA4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4341DC0B554EC73FULL,
		0xCD22A45EFFBB2CE7ULL,
		0x1C3D97811350DDA8ULL,
		0x344AF1D2352F4C5AULL,
		0x713CD90B576DBED5ULL,
		0x3C99C3ADFA7699CAULL,
		0x835C38E2884A468CULL,
		0xCF6FC3E922BADA4BULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x233E2601E9391FC0ULL,
		0x3C24D87FB5C6295BULL,
		0xFCE6542D114BEA24ULL,
		0x495A32F8DD377009ULL,
		0x3772DDE98641ACF2ULL,
		0x4EB7E46B2F8DAA2DULL,
		0x048C7F20C8FB2F84ULL,
		0x98B721F18885B760ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6C6A3EF2EE5D1ECULL,
		0xD03C099F56E7B596ULL,
		0x52DE161429F8D362ULL,
		0xA01BF64A4F6A3AEDULL,
		0x4591E861013CA53AULL,
		0x39946F9C0CF5F015ULL,
		0x53DEAA44421BD3DFULL,
		0xF3726D37C345FC96ULL
	}};
	t = -1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x70A3A352BB5AF3C3ULL,
		0x1D79864CA374937AULL,
		0x1AAD119628F02E30ULL,
		0x0FB3A087144BDBD5ULL,
		0xEB08ED679F30FF9EULL,
		0x071D07021E06FC13ULL,
		0xEE997223DE5C215EULL,
		0x0E4C3CF5EB030710ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7AD73A03F0AE7BAULL,
		0x4E5FA9476E4EFEC8ULL,
		0x56AC1D6B92191F4FULL,
		0xB7B651740478E36EULL,
		0xA735E8E0EFF39D86ULL,
		0xC61F58B5B17510F6ULL,
		0x683396153AA283EFULL,
		0xEC373732448E53F3ULL
	}};
	t = -1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x187BCAD1A3926F1BULL,
		0x496E7944E524D5D5ULL,
		0xC24D788F27A042C5ULL,
		0x02FFB33E36D3153DULL,
		0x3F03F5ED6360BE6DULL,
		0x4547E17C61EB36E8ULL,
		0xD89DBBF584564F5CULL,
		0x8CC8AB768AFBD5ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83B2D67674D7E3A0ULL,
		0x68CF27FDFC9BA86BULL,
		0xF1627DD7A36DF2A0ULL,
		0x48DA52231F206791ULL,
		0x695789A5A237D1EEULL,
		0x58199428C2063115ULL,
		0x09FD2D1AA7D901BFULL,
		0x16135C10CF4F588AULL
	}};
	t = 1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xB9CEE52C15F5D5E1ULL,
		0x4EF08F29EAF1AEA5ULL,
		0x2F08C0148A196DC9ULL,
		0x683D053DD9E83A27ULL,
		0x85C040CCC61843A7ULL,
		0x8ECFC0219033D4E8ULL,
		0x6441E036A2AA6EC1ULL,
		0x22745B45AC6B7AC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9CEE52C15F5D5E1ULL,
		0x4EF08F29EAF1AEA5ULL,
		0x2F08C0148A196DC9ULL,
		0x683D053DD9E83A27ULL,
		0x85C040CCC61843A7ULL,
		0x8ECFC0219033D4E8ULL,
		0x6441E036A2AA6EC1ULL,
		0x22745B45AC6B7AC5ULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xAF96FDDF18443A71ULL,
		0x1FC56C5CA928BC95ULL,
		0x10E8ACAA4456C91AULL,
		0x642F37038C13F0E8ULL,
		0x8DB895EE28DFBDE0ULL,
		0x7F6BDF102579B0A8ULL,
		0x1EC1F3473F234C7CULL,
		0xC8F5B6EE8C09BBA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF976EEF5D5FA201DULL,
		0x51056920327F312DULL,
		0x2057CF89B45ACF83ULL,
		0xDA03B382E05177D1ULL,
		0x322C3737895AEE64ULL,
		0x0C0A86D4CDA39BA6ULL,
		0xAF92D5A3AC4F1B69ULL,
		0xFF92576F73306489ULL
	}};
	t = -1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x4EC11557E71336D4ULL,
		0x94B603AE0FA79B13ULL,
		0x82222244C594F6DDULL,
		0x39614BAF67D8C939ULL,
		0x7A09766271D8EA83ULL,
		0x93F2540F1DA836DEULL,
		0x9F251F40F882546EULL,
		0x0250C6FF277D9F15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C15B8417F4426C0ULL,
		0x27D40D7888673363ULL,
		0x72787095CFB2D767ULL,
		0xA252622E594E277EULL,
		0x34ED89DC13C2C742ULL,
		0xB8668501244A6630ULL,
		0x152216DD1C0DBDF4ULL,
		0xAC600A7DCBAA94E8ULL
	}};
	t = -1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0xECDA372F2A823D8BULL,
		0x2CD04D5F9E7C66AEULL,
		0x7A11896D1E270FDCULL,
		0x76E84D3CAE46B21AULL,
		0xD7F9E5A2AF12822DULL,
		0x0193766DAC83901CULL,
		0x6E1877E363066C99ULL,
		0x2A298968CBD2489DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1871595C678A93ACULL,
		0x110FEDC77F2FCB96ULL,
		0x5FE6CC1928236263ULL,
		0x9339156B16374603ULL,
		0xEDEB93C7D484F942ULL,
		0xD80704BBC0BEB96FULL,
		0x2F78CF5BE4237430ULL,
		0x63A51DEBC36209B2ULL
	}};
	t = -1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x8380AA2F1E3FFD64ULL,
		0x3D0260A7C65D2770ULL,
		0x0E4C19B2E6EC3C7CULL,
		0x2F9FF60B3FEAF5EDULL,
		0xE29B7C74347AE5F4ULL,
		0x56B64F3926D6A842ULL,
		0x4AB4D07D88574A5DULL,
		0x1DFD2E10F9B87292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8380AA2F1E3FFD64ULL,
		0x3D0260A7C65D2770ULL,
		0x0E4C19B2E6EC3C7CULL,
		0x2F9FF60B3FEAF5EDULL,
		0xE29B7C74347AE5F4ULL,
		0x56B64F3926D6A842ULL,
		0x4AB4D07D88574A5DULL,
		0x1DFD2E10F9B87292ULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2D96E63D1AED3947ULL,
		0xEEAA76CB6DFF9012ULL,
		0x609F6EC1DDF984FBULL,
		0x343F4D27136B05BEULL,
		0x76FA6AA16950ABBBULL,
		0x9AA1044B8304EF3AULL,
		0xD27166B569729752ULL,
		0x980805ABF855F231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB10729E76E8D743ULL,
		0x85E21F83665E3308ULL,
		0x74072BF2EE1FF490ULL,
		0x6D62A1953ECBCC02ULL,
		0xFD50E6FC67512439ULL,
		0xF26E615D275B56F5ULL,
		0x17A4FCB07E6A0806ULL,
		0x8169DBD7AF95EE45ULL
	}};
	t = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x2384AEB696EEE4F5ULL,
		0xAF2555E1E4411012ULL,
		0x2D2E6EF5255ED1CAULL,
		0x6DFD241F8BA43CC3ULL,
		0xB34EE58903AC0D65ULL,
		0xE0214E1B10EDE6EBULL,
		0xB86F826346C164A6ULL,
		0xB48E6FF0B4C924B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5FE4D3D7E1BCA52ULL,
		0xAEDEBD91AC4D837BULL,
		0xCCFCEFCE892A9DA0ULL,
		0x5B9B24FBEA2DDC69ULL,
		0xAEEC173912BD9A4AULL,
		0xFB7993CF13B95800ULL,
		0x7CB6634E5AA1B319ULL,
		0xCF24EAD24DFA4DD3ULL
	}};
	t = -1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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
		0x69C04148C8039997ULL,
		0x3B580A025FD96741ULL,
		0xCBE6419E3F496935ULL,
		0x6033D18DB3FF7D65ULL,
		0x9F7F57E015FF3A6DULL,
		0xD7ED7EA35FE61534ULL,
		0x72383515F98FA05EULL,
		0xC8DA87D033CE267FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82FCB922AC84253AULL,
		0x8610463F43C508CEULL,
		0xC862C4E360405488ULL,
		0x06925A640FDF4875ULL,
		0x3161842C1D354FCFULL,
		0x8537E479A83B5B4EULL,
		0xDBEB30E358B053E1ULL,
		0x1570B1AFB3F1A484ULL
	}};
	t = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp(&k1, &k2);
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