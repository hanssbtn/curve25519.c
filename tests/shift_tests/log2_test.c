#include "../tests.h"

int32_t curve25519_key_log2_test(void) {
	printf("Key Log2 Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x5CAE948894383496ULL,
		0x6ED83660EA8CF254ULL,
		0xBA3174649CC8C072ULL,
		0x343966F217D899EDULL,
		0xEE088BE836E0D4E9ULL,
		0x47FB23F0903EB94BULL,
		0xA79161916E08343BULL,
		0x7CF75624AA7BC5D8ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x4000000000000000ULL
	}};
	int64_t la = 510;
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x4265E9DEE9BE3152ULL,
		0xC4CC9EE39D2F784BULL,
		0xFCC7C3E14DA3542AULL,
		0xFB38E36F8B93A517ULL,
		0x9044A7880A27B434ULL,
		0x56FF185587DECE49ULL,
		0x2342BE8A73526F07ULL,
		0x39CD9DED7669B284ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xF106AC8E27183FECULL,
		0xBF167651F6C36F64ULL,
		0x98B285CC829757C9ULL,
		0x7130B46BEE153663ULL,
		0x549A95C90188D5D8ULL,
		0x56446AE76B64EDFBULL,
		0xAA932A22F2ECCF5AULL,
		0x10675C7C59B4335DULL
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
		0x88ED33E637F3F3F5ULL,
		0x8DA20D58E0F50641ULL,
		0xB8A0360E707AB163ULL,
		0xD6FC2A66B818BA67ULL,
		0x4A0E0352E385F880ULL,
		0xCD3712DEE2670BF2ULL,
		0x2894E93A52C8772BULL,
		0xCE8BF89D452A1431ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1761F99FC28705DCULL,
		0x86B739168A0FA2EFULL,
		0x8797255EF4C59475ULL,
		0x5F47572B0BA65604ULL,
		0xDC20A7C031505FD0ULL,
		0x60E170BF660BD8DCULL,
		0x1AA07F614C480AC2ULL,
		0xCD35633BFA7E956FULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB02D08D5AD2CC41EULL,
		0xCE5D055F8C1DD83FULL,
		0xD44FD13762F5E5E4ULL,
		0x0F56746143EAEEB0ULL,
		0xEB648AB2DA980FFEULL,
		0xF584F937B4ECA8F4ULL,
		0x4814648B02EA7758ULL,
		0x2278DD48A345E9E9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x49D1FB18027448E6ULL,
		0xEEFEE64511FBD53BULL,
		0xA279C52D5842AF11ULL,
		0x16305FC9F57AFF61ULL,
		0x910C0D9156D8598FULL,
		0xF7BC2112FBDC0B51ULL,
		0xC687E3B615924565ULL,
		0x4E613A500AF37E0CULL
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
		0x056C7FEE4871FC71ULL,
		0xF49BA4E50CEC6290ULL,
		0xE75794A1B6C69AF3ULL,
		0x7479B75EBD5F318CULL,
		0x7B7B8FC89D837A87ULL,
		0x44032632D363B365ULL,
		0x386B143D045FB7A8ULL,
		0x511F1822A7AA9BAFULL
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
		0xC6E275932D103543ULL,
		0x78D32837870F74BFULL,
		0xD574FDB9BE54D52CULL,
		0x31DEB652E6E7C716ULL,
		0x2DDA20E08EE2499FULL,
		0x61FF854212AB99D1ULL,
		0x910081EB806648B3ULL,
		0xCB3FE6F428043CC0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x911A4205D2C3B1DCULL,
		0x058213AB52E5658BULL,
		0x9411C4C59775BB42ULL,
		0x5695D5666D957358ULL,
		0xF5B6D81EAF5B8E83ULL,
		0x9458DD3EE7A131E1ULL,
		0x9FAAA43FBA7F940AULL,
		0x5B8425DD0BEBD1FEULL
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
		0x843BBA80A345BCD3ULL,
		0xBC9283114C6D7F5FULL,
		0xE13633D420561560ULL,
		0x549AE7D97DF8369EULL,
		0xE5480D70FD2232F1ULL,
		0x357CF6E58F9F82C1ULL,
		0xE224D9756B8F4161ULL,
		0xF4C5CB5B81FB1DC5ULL
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
		0xEDD9CEECC9BAB44CULL,
		0xAA43069E034B92CBULL,
		0xBB5E3BB4A3D9EB73ULL,
		0xD0BACC10B58895DBULL,
		0xFDB5CC25C90CC71CULL,
		0x16676E0835A0FBD8ULL,
		0x874B20BD9605BEE1ULL,
		0xFAE763139C245D63ULL
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
		0xE1BF085EF0CB530FULL,
		0x3862F5541B746FA9ULL,
		0x50CEB32F10F97450ULL,
		0x7E52B623158641E3ULL,
		0x5924CC819028D3BEULL,
		0xA9D0EE2CF6BA9D73ULL,
		0x1840A754B9D19E29ULL,
		0xD58DE0F9027FAC44ULL
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
		0x41E614ED1B907E39ULL,
		0x4CD188676BCC5EC9ULL,
		0xAE53BFE455B4CA94ULL,
		0x6D21CADA0E028654ULL,
		0xD470CC5956ED5CBEULL,
		0x45D12960CF334898ULL,
		0xA66E04A6E6FB56DBULL,
		0xF3F8109A84FA4D72ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x43713B0C29D179BBULL,
		0x1A99FE7CAC32F0EEULL,
		0x938B91EA1616CF64ULL,
		0xE30A363286FC20CEULL,
		0xBA55A73B231585C5ULL,
		0x7422A441D84834A6ULL,
		0xC13B693246417F38ULL,
		0x0394E5DE7AA83C43ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC3CB13FB99E10E25ULL,
		0xDF4A8BCF306B0731ULL,
		0xE4EE2D2401418FC8ULL,
		0x0CBFEB599EA69E05ULL,
		0x7E897B46731F695EULL,
		0x93B6B6ABB2B64AADULL,
		0x37A537B136252FF7ULL,
		0x5C0B43A10B5468FEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9904020FEB1D73A2ULL,
		0x829E2DE46467152AULL,
		0x75AC511BD308C650ULL,
		0x049DCA3BF329DB30ULL,
		0x14D9D6FA5704E764ULL,
		0x156ED97A6531CE78ULL,
		0xAF5D39572438A9F0ULL,
		0x9EEE6B1BCA79AAE6ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF6F76DC65FC36370ULL,
		0x89C2A91B897C5AF4ULL,
		0xF6093841A3474B29ULL,
		0xB39FD05E81EFF468ULL,
		0x0600EBFB6ED68246ULL,
		0x340AA1311CC920BAULL,
		0xC9AE24A4595F6B98ULL,
		0x3CE3DA8ACF4C338FULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC708868550A90BE6ULL,
		0xD1E051AA01B63CD2ULL,
		0xE538AFB501187143ULL,
		0x01C176742F779947ULL,
		0xFF71BC0006676DA6ULL,
		0x49F80C123FB83202ULL,
		0xB4F4C9CFD9234E8DULL,
		0x38E6EA77D98C98FEULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x07F286B519F15EF2ULL,
		0x063DBCE92FA6CDAAULL,
		0xCA418B4C39068433ULL,
		0x5CFE8C3A542D4BFEULL,
		0x236B7FA9BB3F79D8ULL,
		0x706C801B82DFAB86ULL,
		0x6519E8C850925091ULL,
		0x33BB54525034EF2AULL
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
		0x993418A0A035B42DULL,
		0xAFBF81E0F4579F50ULL,
		0x06FA901B65B694E3ULL,
		0x092A4D2FBAACDAC3ULL,
		0x63D79A39D9AE0D8FULL,
		0x77F14B206AFDCD9DULL,
		0x36FA5FA58A2917B4ULL,
		0xA160E087AF8014D9ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB9F1D550D8749FF9ULL,
		0x4785F8CE0E34B449ULL,
		0xD127F5E65DECDCE1ULL,
		0x7D0DF9026AA90C2AULL,
		0xB9FDB535A444DF04ULL,
		0xD2C2DE335E6FD1D4ULL,
		0xC1E002128564BB19ULL,
		0x1F3804A2F8DA7150ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x555CBD35ACD85453ULL,
		0x847BD7E178B2360BULL,
		0x94575409F163F992ULL,
		0xCDE0552C796AD514ULL,
		0xFE27030E2F58D4A6ULL,
		0xC9781D715E6E0DB0ULL,
		0x41BF8AE905786C8CULL,
		0x252CC3A342997DB4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEF12610EDB0531E4ULL,
		0xA71E7D061202CD68ULL,
		0x51DA94353761176FULL,
		0xB3B2866743D01804ULL,
		0x035154036CD23D22ULL,
		0xE8E68ABD347E6AADULL,
		0x9F7515053988B83CULL,
		0xF797B67DB5B8C396ULL
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
		0x85FE8FB9F9D691BAULL,
		0x8D317336AFFBAFB1ULL,
		0xEB7646BC1FCD4875ULL,
		0x0972038F82CAB94AULL,
		0x75148D83106D13B8ULL,
		0x7BF60811DD7F0A90ULL,
		0xED97D884A1104C64ULL,
		0x9471F9A163FA842CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDD7AF5BC67361615ULL,
		0xFB845F243292E309ULL,
		0xBA9C85764AE3810CULL,
		0xA7CD084069C93077ULL,
		0xDDE2499377B2D5A4ULL,
		0x99502B662C88B23CULL,
		0x5D9054A49645B520ULL,
		0x6893CACD588C91C5ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE4FBFAE18AEBFDC7ULL,
		0x84CCED543EBE813DULL,
		0xE56C2DC7C73483B0ULL,
		0xBDEBB5AEA1C9E16FULL,
		0x570690D5C0626085ULL,
		0x142425CDDB321DD3ULL,
		0x8A5409BADAB689C3ULL,
		0x7C08AE966FB23F8CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A0EAFBB0F29DD7FULL,
		0xB4D1574FDB21C80DULL,
		0x0DDBB6EE43AD252DULL,
		0x210D56BCD18AD736ULL,
		0x4C572F232DDD5FABULL,
		0x632F7501978BD8AEULL,
		0x4937EFB243173B7DULL,
		0xB44E59BE83F52960ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2E2B7EDDF9548AB3ULL,
		0xC6D4DA53C94DE4DBULL,
		0x9CFF7BD600B65851ULL,
		0xED260661B217D00FULL,
		0x1CF966FB41E69837ULL,
		0xC5C87FA6B2036A97ULL,
		0xB9FDAF00DEB21EF0ULL,
		0xF68AF57CC8D06154ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5FE044920DF5BA0AULL,
		0x98E3C3D1C60C5AFFULL,
		0x79D33694A5814E8DULL,
		0x17F97AB9899499B8ULL,
		0x4107A727C5B06B4EULL,
		0x1630A4ED1DBABF68ULL,
		0xB41A76329E76EA1FULL,
		0x6B052E32F22EB7D0ULL
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
		0xBB588D75F0C229A8ULL,
		0xCACC6E1DC37C6892ULL,
		0xC8349E28C3271709ULL,
		0xA11C62DAD4EE2592ULL,
		0x66ABE000AC68AA40ULL,
		0x8AC61A0726CB9331ULL,
		0xF52C7442509DA343ULL,
		0xF2352908AA95BF85ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6058D9C3294973BEULL,
		0x0E4DD643F98F8F4CULL,
		0x5AF77693C6C3A2EEULL,
		0x90EE948D4853B7A8ULL,
		0x4601DA8F99415E81ULL,
		0x6F22D06A553E04A4ULL,
		0xD13E51D2E7074C72ULL,
		0x2DAFD55228223C17ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1095F176A1A89B48ULL,
		0xD945ADFFCC3E18D8ULL,
		0x0A527C944151BFA1ULL,
		0xFD455936E234DE30ULL,
		0x830270EAB8B882FFULL,
		0x8C07AC9A0BA332DFULL,
		0xD49D60AADB439072ULL,
		0xE489FAF9CDF9276AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2ABCAA286D0E1998ULL,
		0xFF818354AED4198EULL,
		0x212C22406495ECAFULL,
		0xEA5534846224D404ULL,
		0x05C9D0DF45AC78B7ULL,
		0x2502329E2523D052ULL,
		0xC65C80C46C006C87ULL,
		0xB67CBD9613FAF142ULL
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
		0x64F773402DFD08C8ULL,
		0xD30F1923EC29125DULL,
		0xFAEAFD12A8C3D930ULL,
		0x61556A7905573F49ULL,
		0x87DB13A3D18FA550ULL,
		0xFA60B03AD42E1D53ULL,
		0x4BC8E6AE5B12E86EULL,
		0x648171AF6F10F45DULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7AB8F61B3F5451B8ULL,
		0x99DF97647C3536F8ULL,
		0xD362014C651A6B7DULL,
		0x3A5BA99B31321CB6ULL,
		0xC16282AC0A731FEBULL,
		0x0DF370E9BCA437F7ULL,
		0x4142E3CD379259CFULL,
		0x21F430ECB6F3AE5CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB88DA5C7C828FD6FULL,
		0xE4C7ABDED35AA92EULL,
		0xBB1918B26EB0D246ULL,
		0xA43C898A58B26673ULL,
		0x725ACAE3780A77F1ULL,
		0x9B5C5DEAA34FAB9FULL,
		0x6B903684E3672AB1ULL,
		0x85D063B7DD7772D9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE413B59796967C84ULL,
		0xF99C00D0A93812CBULL,
		0x72B65DBBE2C115DAULL,
		0x68A93ED7A271C96EULL,
		0xD30182612E18E508ULL,
		0xB86514E615CF1908ULL,
		0xFA82924C400DA70DULL,
		0xADCF5D13EC484C71ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9D32FFAC49CFD04DULL,
		0x4F1F1A2A7DA34FD8ULL,
		0xA8C810E6CB08AA87ULL,
		0xEEFF66E6E8A6D2EAULL,
		0x4C3AE9E859B54313ULL,
		0x5A9387CFDBAD8E21ULL,
		0xEDA18410A5128537ULL,
		0x62A7C50CD0699769ULL
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
		0xA67C19BF3208E672ULL,
		0x71F5E54CF8FD54A0ULL,
		0x959F754E08485584ULL,
		0x422A4E9F47B7B8D6ULL,
		0x77E2FD160EF8E8DAULL,
		0xC00F769EE36E54A6ULL,
		0x5E4608ACD725D258ULL,
		0x8105D82EFE32273BULL
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
		0xDC168A2AA45632FFULL,
		0xD4EA196650743255ULL,
		0x87B330477089C0DCULL,
		0x9CAA434924DD3689ULL,
		0x67761FD631DDC82EULL,
		0x33A8E417C1F98196ULL,
		0x5869AF0A69DC0587ULL,
		0xC6729D67AE9FA72CULL
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
		0x887E9A15A816588DULL,
		0x7EF323BF872CD995ULL,
		0x525815204E585217ULL,
		0x1CB2E1FE473A1666ULL,
		0x37D708F97E5FF3B8ULL,
		0x5D24B76CAC7017D8ULL,
		0x1255A74177785562ULL,
		0x28DB2B8399080BB3ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA088A3815DFBE266ULL,
		0x894168014186AA9DULL,
		0xA1EE59CA49AFB7E6ULL,
		0x14CB5077828490EBULL,
		0xB3F43102C25C30D6ULL,
		0x2B2122433051E535ULL,
		0x41D5FD560841A2D3ULL,
		0x23F313171062C293ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x457E9B098BB9B93BULL,
		0x87BC1D3A58A88B20ULL,
		0xCB666A93CCC7EEC6ULL,
		0x4F083CEDABA453FDULL,
		0x03640E2BF244B95CULL,
		0x3635FA0EBAFAE47AULL,
		0xFC847B9610FA0AB5ULL,
		0xB8CFE15BABF73E27ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3789E26C06EE2829ULL,
		0x1E014DBD4C138C93ULL,
		0x667B2E76E659B46EULL,
		0xB6FA979BB6C227C4ULL,
		0x1A4ED0542DF6C7ADULL,
		0x5FFDD5D484A31C1EULL,
		0x29C2E926B65F1BB3ULL,
		0x667E634F61BF3FB2ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8EC12F7233F7E842ULL,
		0x444D8176861BF337ULL,
		0xC0DFCDC74A326940ULL,
		0x153E49045A5EDF25ULL,
		0xDECCE15C620F18C4ULL,
		0xB99783BD888054E1ULL,
		0x35765BA74E38C103ULL,
		0x3B83606C52B7EEA2ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8B3B16F8FB7746AULL,
		0xB7B440A714BF927EULL,
		0xD977862717917B0DULL,
		0x58FC9BB0F45B6398ULL,
		0x5097A94F7F9539A7ULL,
		0xCCC59C36B5809C1EULL,
		0x6250958836732C2CULL,
		0xC298A8C72C133BEDULL
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
		0xB6E3CE1234245251ULL,
		0xA932598BC2384894ULL,
		0x807CE4B3649A319AULL,
		0x12B838BE434A0D7DULL,
		0x87875F11E0A9B723ULL,
		0x24E2A978D18A4CE4ULL,
		0xA601FBBAB201E738ULL,
		0xC457086D6EE633F3ULL
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
		0x2F4BDF3E228E6F58ULL,
		0xA700E0F86F5D927BULL,
		0x03E4B0F04AEFD866ULL,
		0x8FD3771E7115C104ULL,
		0xB695B7FD4B4A0A4AULL,
		0x463F58B625430F68ULL,
		0x8FFD766C708B3ADDULL,
		0xA747C8B3B9AFF457ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4F355B767906465AULL,
		0x2B77F203F37F2F0AULL,
		0x9D6CB71707127DB4ULL,
		0xD1BAD980F64FE83FULL,
		0xDF1CBE2EC511C308ULL,
		0x5F56C7E3A7344AD4ULL,
		0xD0B7FEEE2AEA60F9ULL,
		0x53A70B5309764734ULL
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
		0xA0EA469688EA4FEAULL,
		0x514AAEFC6C1EB411ULL,
		0x6F0F036E5AF2EF29ULL,
		0xC6CC227F2AFA3C87ULL,
		0x32F9FEF0B3F3B32CULL,
		0x21BD2165D1B96563ULL,
		0x02987316CC2E1C09ULL,
		0x8B1A3F39A9524275ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF4D2110A2C4C4662ULL,
		0xE32C1514BF5241B1ULL,
		0x1884E92C8E466CC5ULL,
		0x3C47E1E86B7A3D72ULL,
		0x0CA9A7F6112E1839ULL,
		0xE3CD3B134DEA94E2ULL,
		0x9136FA9B9597472FULL,
		0xF76576B08A784365ULL
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
		0x616D94EC5DCC9CD5ULL,
		0x3294286E484E0853ULL,
		0xFAA88CB9AE20F019ULL,
		0x7CEA97F4E75C693AULL,
		0xC037E52DDF4CD5ACULL,
		0xB1D462B01110C017ULL,
		0x1B4B993EDE0563F0ULL,
		0xF81CAF1AB664B3C0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2BB2BCEED5B8BEB7ULL,
		0x8D0E61CAEDA52E21ULL,
		0x409F06404611BB20ULL,
		0x877725829BCEE4BAULL,
		0xADA6AE0815792D69ULL,
		0xC96D93229A815451ULL,
		0x0B12678DD177F044ULL,
		0xB355BF63433E9D46ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAC420BBB0033EEF5ULL,
		0xBC7F42700E8055C8ULL,
		0xA2BC3B313CB49DCDULL,
		0xE3BA1A9C3ADD1E19ULL,
		0xA01624BBC6417E00ULL,
		0x2E8243465E902B64ULL,
		0xF1864515033D5AA1ULL,
		0x2051CA165B5D5CBBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72E5EFA250AAAE9DULL,
		0xF141C6586DEFC1E1ULL,
		0x636BBAB0922973F1ULL,
		0x28C33BA377155401ULL,
		0x479FB0D5E135A11DULL,
		0x018154F9EE304E47ULL,
		0x556AF9A2A541851CULL,
		0x8639F37238667525ULL
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
		0xC6C428D527EA3ED3ULL,
		0x3CFC37DB6C5FD29EULL,
		0x02957490A5E470FBULL,
		0x540AA0B6A38745E5ULL,
		0x23D04B7A768025ECULL,
		0x5B00F9A605382ED2ULL,
		0xB165051F0BCA05AAULL,
		0x5C2E492E079CAF35ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x75C91D2F78B70C24ULL,
		0xCDAB2434FD6762DBULL,
		0x4BCF6234EEAEE640ULL,
		0x78A48D4833D25F6AULL,
		0x464B0F70DFCBDB56ULL,
		0x23F9F55871FF2566ULL,
		0x35AC40E8CC52731FULL,
		0x34FE5B3A54285467ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9B53B4A606CD76E0ULL,
		0x6C14BE67E725A4DBULL,
		0x94A5DDCDCC21A021ULL,
		0x329C9A5DBE5A9C20ULL,
		0x3F8C79069302D451ULL,
		0x810AC3881EEEF39EULL,
		0x54DA3C533B14940CULL,
		0x9CF00241828763D4ULL
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
		0x0E25C436CEE40390ULL,
		0xB4F7EEC5FE52B183ULL,
		0x897D92DA91A2FC71ULL,
		0x54560A2BB953E0C3ULL,
		0xB2CF935979A513FFULL,
		0x8E5EF4CFF7E3EFDDULL,
		0xB5562848827DFBBDULL,
		0x7E8635977370C0ABULL
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
		0x5C2B12AEC1BDD203ULL,
		0x2A9889256322EB13ULL,
		0xCB44DB89E2F90AEAULL,
		0x4C9E3384A0855342ULL,
		0x918DA80AF8E31367ULL,
		0x270572A36C4FE31DULL,
		0x6036D740DBB85F78ULL,
		0xB9839C6BEA50CD25ULL
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
		0x5B991BDC1C94C688ULL,
		0x315DC16AEFE7906EULL,
		0xD47E79222AC2C1DDULL,
		0x5E000C8473489C76ULL,
		0x8538CC7D1B1388A2ULL,
		0xA9E43250F4C8AA3CULL,
		0x370F5205B78BBFD1ULL,
		0x820DD4A07F7EE2EBULL
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
		0x4D6D27E5DF62F807ULL,
		0x3A51E9F41E6804C2ULL,
		0x391C6ADA9D568358ULL,
		0x1CD40E2A1C8C4ED7ULL,
		0x10CE862B64AEC3C0ULL,
		0x14E3530FB43100A4ULL,
		0xBD9962223D1B3872ULL,
		0xADAB0BB24E62FB6DULL
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
		0xB5A304B3B14ECA6AULL,
		0x3E1C4496BE8B7A7DULL,
		0x6413EF64049B9AA4ULL,
		0x16D36F9C7BBD6751ULL,
		0x3D1315CFC2200C6EULL,
		0x4B81DABCA4F8F6A6ULL,
		0xA780E5590A4722C8ULL,
		0xE2C7211E077132F4ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC43B9FB826C29A82ULL,
		0x0F06CACB0F5C7DCFULL,
		0x7D76D140F33D8682ULL,
		0xC3066839575FA629ULL,
		0x6C4EE16C55042A59ULL,
		0x8142AED13B2A571FULL,
		0x3E39B1B9CA864446ULL,
		0x5F637F6DD864EF27ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x62D3135CF7A72F3FULL,
		0xF77CC1997B8889A7ULL,
		0xF50E07A1C0593366ULL,
		0x455DA64448D912CAULL,
		0xAC3C7CEC50A2FCAFULL,
		0xA301E7CC19FB1CACULL,
		0xB8B3A384CC473ED3ULL,
		0xED8B6E7B9D4BCC31ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDA646C09E30021C3ULL,
		0x33F4B97115D41AA8ULL,
		0x10363AE74C1C217CULL,
		0xE6E37D47D5FA7643ULL,
		0x22B522AF424C311BULL,
		0xC7712A7FEE97750EULL,
		0x73CD192EFDE49C2FULL,
		0xA7F61E7FCFD59B6FULL
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
		0x06CA54AFC004B5CFULL,
		0x70EB739417A24DCFULL,
		0x7F64D4547E771FABULL,
		0x3F01F0C32880CB74ULL,
		0x2A959B6E0645231DULL,
		0x6230A45C062BC2F6ULL,
		0x6C6ECD130B253AD7ULL,
		0x9F6597F27EE7EF2FULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xADB81B10332DCDFEULL,
		0x35CA093D762BF1C1ULL,
		0x01DA8BF9E98663F3ULL,
		0xF1A15E50A85F5C52ULL,
		0x837CB8BB27D69858ULL,
		0x872FBD53F405E2CAULL,
		0x4A791F33711BA52BULL,
		0x1AE832180864CC46ULL
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
		0xCD77B11EBAFD9B93ULL,
		0x7A1E929928CB1AAEULL,
		0x3FAF002C1CCC8B7AULL,
		0x47E687E69E6F28D4ULL,
		0x21BA8C2B7AFC2880ULL,
		0xEE5220761DC8D273ULL,
		0x9E5AD0CD0A03E776ULL,
		0xF95982A5CFB2ACF7ULL
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
		0xD4CF2A1163C414EAULL,
		0x43F96EB1BA1B6292ULL,
		0xE5EB4F2D9BF15346ULL,
		0xB87ADFB47956536AULL,
		0x73F021CD11F6F40FULL,
		0xEEF7F5E84051A8F1ULL,
		0x626BDC80A3F21CFCULL,
		0x317E1A165C793B24ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xABF3114CF6D44FD3ULL,
		0x791886F56F4034EBULL,
		0x44683286FB7A0183ULL,
		0xDD6B7DD0F440A0BDULL,
		0x4241239C1F9E57B5ULL,
		0x38BA195BF3F6F9D8ULL,
		0xBF994CBC4C34E669ULL,
		0x22315D2A7CE157B3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x991652F57BBB02EEULL,
		0x2450314BD4219057ULL,
		0xADBB0433C4979692ULL,
		0x0BD0D033B5BFFE0CULL,
		0xE2AAF6589BCFAAC8ULL,
		0x8F7BA94C54EAEBAFULL,
		0x6A9EF95CABD67079ULL,
		0x70109F9F4A04990FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x51C4B66FDDB9433CULL,
		0xCEAA6F4A05C5CAFCULL,
		0x65760D4402D8CEDDULL,
		0xA2068188F2DB9A11ULL,
		0xEC5D20E5580D0AECULL,
		0xDCEE6D7890A3818EULL,
		0x14E231D8AE892E2FULL,
		0xEA4B228F8AF2952AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x03DAC0723982A72EULL,
		0x946307E08995B41AULL,
		0x1AD814D9192F7C25ULL,
		0x62880CC44C0C2246ULL,
		0x63A85A66AD68A678ULL,
		0xCC75C9DEC8453B71ULL,
		0x19A6479776267827ULL,
		0x828F57C73BD96D9CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x95F43579C46B42A5ULL,
		0xC186EDB979B6A998ULL,
		0x68EC690A8610AA84ULL,
		0x4BA664F4B84AB22DULL,
		0x22D1CDFFA1F6323AULL,
		0x8CBFE9348036BE9EULL,
		0x6BD24E38096D3411ULL,
		0xCC4AE5F10DEBFFBBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4C5E2668AC5F6311ULL,
		0x984827F8183335FDULL,
		0xFB1CB1E6C7E3604DULL,
		0x0011F2CE59287E14ULL,
		0xB12202084C94A4A8ULL,
		0x28C94ADE8381A940ULL,
		0x605576CC7B14F3ABULL,
		0xE19E3685BF030F8EULL
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
		0x0880BBC47E820694ULL,
		0x99F1BD27CD181B61ULL,
		0xB09DC8109C6FF3E3ULL,
		0x16146938187A42AAULL,
		0xC731A49705C5B3E2ULL,
		0xD15F6248ECF53429ULL,
		0xFEB84D4F577259A2ULL,
		0xD44D5C32A0D692B2ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA678AA3995212CA8ULL,
		0x1083D9594A844E9FULL,
		0x4571D719E6E3C213ULL,
		0x9572B3A37D94DC25ULL,
		0xDBF85B37D546B2BBULL,
		0x51829CF027BCF719ULL,
		0x2D4386578E656E71ULL,
		0x8FC0F52B10A34F5EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDEC138E3FDC9B612ULL,
		0xC7ACF0C2A59942FDULL,
		0xFE068FD214EACEC7ULL,
		0x1093D138577E3621ULL,
		0x4F3DB3C7526D0DBCULL,
		0x36ED438DE0093366ULL,
		0x63E111E6FF2EF0A0ULL,
		0xA87BEBD140FE958EULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x773D4A4A616EC976ULL,
		0x888B8EE8B3B7127CULL,
		0x3D6EAE1BD1350386ULL,
		0xC44709F485FE0653ULL,
		0x3E6EB68DC1C31855ULL,
		0x9140D9CFB9DFC693ULL,
		0xEFA2EAB24C8A9DCAULL,
		0x0632C91F472E02BBULL
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
		0xF889F6C6EC54E690ULL,
		0x1E5A11DE16C77612ULL,
		0xD48835A0511EE08BULL,
		0x84491144D20F80CFULL,
		0xE115B08889F9BACCULL,
		0xB8B219484864ACD6ULL,
		0xE15D4DE75E8ACD71ULL,
		0x8F6156251F2B6E2FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0C4628CB123E822CULL,
		0xAF9159EAF40B534AULL,
		0xE57179D487D12D2FULL,
		0xC23AAFF3FE15459DULL,
		0xD036C363F289599DULL,
		0x2D499D7A81E3F941ULL,
		0x290A6B64B84B99EDULL,
		0xA00D346EF6FA1E92ULL
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
		0x213D9952FFFEA415ULL,
		0x5D58CDCF45E7AD85ULL,
		0xEA25322F1DFA66C9ULL,
		0xEE2630E1004F2D16ULL,
		0xC96E3B46D1C6945CULL,
		0x80CD5157A87075D6ULL,
		0xD9B225C3AD395E69ULL,
		0xB1B2E34C755CDA94ULL
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
		0x882B58092EDF9F44ULL,
		0xE07E78E2044E4C92ULL,
		0x1F6596DD3EB9473DULL,
		0x9BB837FE16AC6D01ULL,
		0xBB2648D6EA4BEB3BULL,
		0x37FB958AD72F668DULL,
		0xF6E9599873A73625ULL,
		0x83D0FEF7BF9577F6ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC70D77589DC05E0BULL,
		0x43B910F5A1618D7DULL,
		0x7F116B71EB3B108AULL,
		0xC5F88D823625923DULL,
		0x4DE58BEBB3565C35ULL,
		0x681BB68C39ED27FBULL,
		0x745F5806C54601D3ULL,
		0x51A74FE892CC47B6ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3D3CAA009F28DDC5ULL,
		0x1341218E54512891ULL,
		0xD76FD7938D291CACULL,
		0x12F904CD9C9DD039ULL,
		0xD099FA8628D6A610ULL,
		0x26C90C5573965B4BULL,
		0x3253F6A466DE32D8ULL,
		0x586523A81ADE4C99ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xE226CB9822BA3823ULL,
		0x21598C2A6D396500ULL,
		0x836575B4CE06E9DBULL,
		0xDB5C05B914A3CB3DULL,
		0x0F61FF2A4D850B1DULL,
		0xB7A5BFB9F69F5C72ULL,
		0x635C882662483820ULL,
		0x03CC0DB3562232B3ULL
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
		0xA67F97EA08994B12ULL,
		0x53024AFFD0A83091ULL,
		0x803B35A76FD2571FULL,
		0xEC96A96D18752B92ULL,
		0x1F05B60132CBD720ULL,
		0x01485DD87441B9A4ULL,
		0xE27E6B0B7DB67D09ULL,
		0xBD6ADD5512501D0AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5FA6B3C16BEF901AULL,
		0x508D5E161E6ED161ULL,
		0xF157BCFC8B47628AULL,
		0xC8E8D79BCED99688ULL,
		0xDB08B6728E7E6D40ULL,
		0x57B48DE2CEA544F8ULL,
		0xA5827EEA31264993ULL,
		0x4FDAAA0D0F4A4FBFULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xAB5E0D2DC97C7D0CULL,
		0xC5E30BD4F2247C0CULL,
		0x0037492A79373DF4ULL,
		0x792D880ED7FDDF29ULL,
		0x5A41590252C2A9B6ULL,
		0x928F328B98CF2D09ULL,
		0x8F561301717E68F4ULL,
		0x0B3E16BB46E659E8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x47AE2C8556A4B0EBULL,
		0x3613E871E8BC3668ULL,
		0x1A18CADE413F012BULL,
		0xB5A4B56E17C83E07ULL,
		0x3401CA14E13E7EE8ULL,
		0x8B54D37752C54E2EULL,
		0x546EB42A5E98E142ULL,
		0xBF37A756B1F382E4ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3C046F2221892102ULL,
		0xED3ACEFC14724D39ULL,
		0x4DC31E2AF379D8C3ULL,
		0x8D97B45C4DE579EFULL,
		0xF6E85BC2C285195DULL,
		0xFB517F7287F81BFDULL,
		0x4B363FF6916EDE3FULL,
		0x74756E802B752616ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0EFB7BFC0E15435EULL,
		0x041C2C5ECEABFF4FULL,
		0xBA8EE4EF437DA68AULL,
		0xBE73F2E0F0BDF0BFULL,
		0x2F04065F3BFA9572ULL,
		0xF23744548831EAE3ULL,
		0x80B4977FBFF63B06ULL,
		0x302B46B398225CF6ULL
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
		0x5B588FE3F6F7A9EEULL,
		0xEFA1E8F1DAE10A73ULL,
		0xE416D276A9FF6106ULL,
		0x731666EFCE99962CULL,
		0xD19E796E314D310AULL,
		0x8348CFD141BB8687ULL,
		0x8E7BBBE4FCC21913ULL,
		0xE4EFC40765C6E5D9ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x82939750B4CBA9DAULL,
		0x765B591B64E82192ULL,
		0x85007028D859BCE1ULL,
		0x92CA0811325DF84CULL,
		0xA8ACECA9B4016DC5ULL,
		0x8B0F3894A025E325ULL,
		0x5BF4CBDB4DE45E97ULL,
		0x1ED6A16B042E303DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE9E5489442ACD075ULL,
		0x742C78D44271BB4EULL,
		0x5C07350606CF5683ULL,
		0x4B28140A446C87ACULL,
		0x83E37765B7310FFCULL,
		0x116861A0921AF9E1ULL,
		0xA8617F9E920D60A5ULL,
		0x9C695F8CF6B7A1C7ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1B997A8A80D841E0ULL,
		0x4641FEE775670B05ULL,
		0xB21FA420AF647FB6ULL,
		0x5CE70A86A2DD509AULL,
		0x44996F7132DA2622ULL,
		0xA9D90236B3FCF3BBULL,
		0xAE297DF3280FBBA5ULL,
		0x125B41E5FFA02172ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE31D48867AF5A30DULL,
		0xB2A0F017574D470FULL,
		0xCB309DC6FF034988ULL,
		0x301CA7DF799A1C84ULL,
		0xE9FC92875B47F5E9ULL,
		0x4D0767F9CCBCC8DAULL,
		0x9F67F22D57101415ULL,
		0xC740F32A7EE84A1CULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xEFD84EC892DA7E0FULL,
		0x442E311364DCC635ULL,
		0xC161500C41917653ULL,
		0x9F0A3BA0B81E368DULL,
		0x09F9604DBEEDA57AULL,
		0xF7E51C529CB7ABA9ULL,
		0x8846E940845DAF63ULL,
		0x2D1D125345BD9169ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4FF0E0F2854A7B17ULL,
		0x9A7D152FD4B1303AULL,
		0x2DEC5FAC2E1370DCULL,
		0x35DC396BE1D584E0ULL,
		0x6D0733112E95F3B4ULL,
		0x8D78BFEBA986DB0FULL,
		0x20967C11E3FD283CULL,
		0x77B004ACC23832F1ULL
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
		0x1279CE5518984BC9ULL,
		0xB4A86EE199EA6D32ULL,
		0xC95015E0F695F9BAULL,
		0xC91C48E122F338C6ULL,
		0xF0810CE1E531FC64ULL,
		0xBB8DE00517E8B04FULL,
		0x443119E3D021EA11ULL,
		0x744362FE8E5BC0E3ULL
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
		0x2292D0B075F498E8ULL,
		0xBB06CAB4A8CC66BBULL,
		0xC019E5E280CE7D76ULL,
		0x9FB14CF456F1F697ULL,
		0x4698E2ACB2C761D4ULL,
		0x217C77A169FEAC50ULL,
		0x706EBC72F6443304ULL,
		0xA6A49B9D91C0BCEDULL
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
		0x5AE834281BB4AFA2ULL,
		0x17426357758C1E20ULL,
		0xD51447C058252526ULL,
		0xB254E20B3EA855E3ULL,
		0xC66C384638001B1FULL,
		0xAEC447DD8DC381D1ULL,
		0x01E856340D637133ULL,
		0x2D97271DA5BA087BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2428AACC00C67F06ULL,
		0x29C34DD2B41FFB5FULL,
		0x197DFBA4432B12C1ULL,
		0xE222BBFB183983EBULL,
		0xEE61BDEEB9591440ULL,
		0xA284B68F6201FD0AULL,
		0xCD176047708AFD64ULL,
		0xE3AC20016D5116F9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x61230AB7CCD5DFE0ULL,
		0x8E69766CFCD51087ULL,
		0xE1CC78EA1E471D0AULL,
		0xCA215328E208B781ULL,
		0x19E647503D9F83F7ULL,
		0x9236B348737E41C9ULL,
		0x00E67F221F5DC224ULL,
		0xB85C3EDD775F9734ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x29E9A931748EF3DCULL,
		0x31E87DC8C136B3C8ULL,
		0xFA07430E72A5580CULL,
		0xF8626A43C9D05887ULL,
		0xF54DEB7BE2C9ADCDULL,
		0x74C7780BAD91D635ULL,
		0x654EFE9B7AF0C689ULL,
		0x414AB2A5689BAB55ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8682CB8E98A70EADULL,
		0xDA303E1EF1497C28ULL,
		0x1F05414668DD6672ULL,
		0x0E88612825D89933ULL,
		0x9F7A8122E513A63AULL,
		0x65CC27092A7A3DAEULL,
		0x79F35135EE1BF98EULL,
		0xA63E7BABF13B7646ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8FF2F44C3FFF494CULL,
		0x9D341033B65CF1E8ULL,
		0x10921BC1C4F3AB63ULL,
		0x08DC7F9198AF9BFDULL,
		0x205DA75D84E56C61ULL,
		0xEE165CEED75AEFC4ULL,
		0x829C9D033D5F4D33ULL,
		0x60E1C99F7EA23212ULL
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
		0xD7CBBF1996D67ADEULL,
		0xC2576220FBCF9861ULL,
		0x071BA77836A334B7ULL,
		0xA9C9117591A670B1ULL,
		0x937615347979E8A7ULL,
		0x81E7AFF515892EE2ULL,
		0x545F44A6E2F2CDFAULL,
		0xCD408B44CB2013FBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB54FB2719F24DE7EULL,
		0xF31943BFCD83006EULL,
		0x5C52BB5026E40F9AULL,
		0x56DC7E2E72E429EAULL,
		0x1E3E9AEAFCB110E4ULL,
		0xE4123886017FA52CULL,
		0xF81047E6297BB8EEULL,
		0x94CD3A5C5E8E6443ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x014DEE1F15D193E3ULL,
		0x1F5EF81AA089AC12ULL,
		0x6AC748D5A9D3B4F6ULL,
		0xCFEA5801E76F7B46ULL,
		0x533716EA0884D17FULL,
		0x0A05F11AA41B0039ULL,
		0xA7ADD2E8130257AAULL,
		0x948F3A2CA69D04EAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4859A80AA231FF33ULL,
		0x8D641455BAAC7DA8ULL,
		0xD8766B1B853A7F43ULL,
		0x72F1280ACE11DBFFULL,
		0x358D619B6BF791C7ULL,
		0xFF221F766C36787DULL,
		0xA510ECFAA735A345ULL,
		0x91A5F5D654221DB7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8AC054A04C0B87B4ULL,
		0x330927854CC57CB7ULL,
		0x195C65FEB9ED6BB2ULL,
		0xA64F41B5BB2B1D61ULL,
		0xA636EDB7090BB719ULL,
		0x118800BDEF62CA1BULL,
		0xDA94865DD350DED1ULL,
		0x6502B662C13BF357ULL
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
		0x8AE3A404AF2A3CD0ULL,
		0x9DFFADF320500BECULL,
		0xE2F48B3D5282B276ULL,
		0xDEA4A55B1DBCFFD8ULL,
		0x4F9F31B215E4C3CBULL,
		0x00F4A6C0A66DDC4AULL,
		0xBEE930F4034F33E5ULL,
		0xF30989820B1A388BULL
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
		0x3C85C8E6B2643FD2ULL,
		0x734B61EE16E4648CULL,
		0x9FBE98414BC5F7EAULL,
		0xEAD6E42C097F5D38ULL,
		0xD029A8A02EDCFE6AULL,
		0x91571B034451F2C4ULL,
		0xCDA8077813959708ULL,
		0xB6706756D3B8C5F9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x658CC7C5F1621145ULL,
		0x234F5B3ABA523D5EULL,
		0x765C5E45DB26E44FULL,
		0x75F748F8C7AC3BC9ULL,
		0x568434003462B3D8ULL,
		0x91A152B275DBF8A1ULL,
		0x735EF67BBBF4FCC7ULL,
		0x87EED39E99C75016ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x9D42491BF9844352ULL,
		0x541F095D944B05DAULL,
		0x72762E7E3071FCECULL,
		0x185E0E4D68A1FF59ULL,
		0xAD3133FECAD22695ULL,
		0xBE8731034D0BBD94ULL,
		0x06D28E67DFA94C3DULL,
		0x0EA5ED724AEFD433ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x65971C34EB494ABCULL,
		0x302C4B8244F6E0D8ULL,
		0x395DB470A0483274ULL,
		0xA6D11BA5D437DD21ULL,
		0x3BA982F4F4CB10CDULL,
		0x7F243AAA3B0B272AULL,
		0xDB6D0880A9DE6D0EULL,
		0x6294F83577F7E7BDULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x56BB564253B0AD6CULL,
		0x522F337BF533C343ULL,
		0xB83C8E6232ABCBBCULL,
		0x9BA25468ACE9FBFEULL,
		0x50F38304001C5995ULL,
		0x4340E334BADE7418ULL,
		0x3D6D07F513CB79F6ULL,
		0x5F6CFDAA2C6E291EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBF53816FF5A99F03ULL,
		0x26177955946EFBBCULL,
		0xEC907387AF4A7D11ULL,
		0x8D9852531B1E2F97ULL,
		0xEEA91FFEA91157A4ULL,
		0x38CD37AC40B206C5ULL,
		0xFD20FAE23CC70FC1ULL,
		0xE62FAA2F7ADD497AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xFE93FCBA3E045C6DULL,
		0x91299E6309D31804ULL,
		0xA9CA064DA51A432CULL,
		0x544B634193921E88ULL,
		0x3D18CA96C7EF554BULL,
		0xA26CE493359379B3ULL,
		0x1611BF6BF726E226ULL,
		0x44A9331E3ED186B8ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xAEC8578D71C72BBFULL,
		0xF560D3B99A841D89ULL,
		0xF277C269AC935147ULL,
		0xB6A1CEA13B32B14FULL,
		0xC86205E2FB2595ABULL,
		0x56AF5EE9153C4C12ULL,
		0xEC3B07743D6DE006ULL,
		0x196347CC3FEA9248ULL
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
		0x4A3F59B55F4337B5ULL,
		0xF66B1731F0FC05EFULL,
		0x39FBB43915CFD353ULL,
		0x8E896F606D8F055EULL,
		0x07E8AD01BED24A8CULL,
		0x951977D96F93F1D9ULL,
		0xDE0D94CA5EC54980ULL,
		0x70C37C423DFA1A7AULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA5A9B38B37ADFBD7ULL,
		0x97A58D35D35FFD47ULL,
		0x608689F540F23804ULL,
		0x6AE71CEA6B6DD395ULL,
		0xFABF2A758069B1DEULL,
		0x51E20371380B935EULL,
		0x2718FC77019D5BCAULL,
		0x3E84E1D694EC1C70ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1F8DAB813A608154ULL,
		0x243E79EB94BF2826ULL,
		0x90B21E13D6D5EF94ULL,
		0x999C12FECC7E702BULL,
		0x42DACD358381BDD4ULL,
		0x74AF774BCE78561FULL,
		0x6CA71E8145A0E257ULL,
		0xDFFE7D93778CEDA9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7AC54812558D26E1ULL,
		0x225373CF21991D1EULL,
		0x635A899FE1E25192ULL,
		0x96603FE26814B877ULL,
		0x14E308E932174633ULL,
		0xD4AF82C8A007C19FULL,
		0x5064DD7D73B8F167ULL,
		0xEEF18DE7C0CE462DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAB122CE6180FF48EULL,
		0xE5109347EAEBE9DAULL,
		0x6D9CA3E6F9758AD9ULL,
		0x6DD902BF8BEA5099ULL,
		0xCD16FFB45F5909D6ULL,
		0x64418479EC16C82FULL,
		0x3CA242ED24AC81DBULL,
		0xEE2D0CBE46D44DADULL
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
		0x52C880567BEFF417ULL,
		0xA445AAE69F4B00AAULL,
		0x02CE491D8A5FB976ULL,
		0x08429669BB044B94ULL,
		0xB17DCE49A7F3236DULL,
		0xD90473D7B205D3B4ULL,
		0x57D42A1B80299C53ULL,
		0x7528A85C47DFB737ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3339178149B2625FULL,
		0x7253D24363D4CCAAULL,
		0xD3C240674E551901ULL,
		0x594FEC4BBC737D0BULL,
		0xF2DEAACD3F6FA675ULL,
		0xF60C2F82251154C9ULL,
		0x973B033F563FA44FULL,
		0x5DA786A5D94D1E3FULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA9BDEC9B332BAAA6ULL,
		0xFA74C232CDECD60BULL,
		0x909177548E215A4BULL,
		0x2E48F387FBEE00D1ULL,
		0xFFB99D435E69F2C2ULL,
		0x63B03117891D6793ULL,
		0x992BE598C7072CB8ULL,
		0x30ADC7E867637AC6ULL
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
		0x6AEAB4C68C830414ULL,
		0x4D1DB93A672028BDULL,
		0xD24951D8C56D8D3DULL,
		0x240C100DCEFF5D70ULL,
		0x08980FDFF481F5B6ULL,
		0xC0D64026179FC4EEULL,
		0x19DB2E05617C7AB0ULL,
		0x52D7DBCF861F16E2ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xDEBEDB5C047D226DULL,
		0x19CA9876ADB5A75AULL,
		0xBCAE1C861DF4A343ULL,
		0xE3B1DB0541A2E45FULL,
		0xE4E3F9EA9DA8FE02ULL,
		0xDB43D8DB60E3574CULL,
		0x31F5256ADE97B492ULL,
		0x0B51BB445B184FF0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x18ED72DE7969D492ULL,
		0x5256A1A05AF7AEA8ULL,
		0x13B89DED905E6E82ULL,
		0x638CE0508CE1E414ULL,
		0x97BC261FA779CF77ULL,
		0x60A57A6A4BF3A274ULL,
		0x2F28D2784B28554FULL,
		0x4036977D9C886758ULL
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
		0xAABFE9B7F42E4616ULL,
		0x52CA6E60CD6FAF65ULL,
		0x2583EC2380C3FE3FULL,
		0x7973F9BDE69057E5ULL,
		0x02A85025C119EE6DULL,
		0x4E17E45B42C8D96CULL,
		0x6F68582867201A8FULL,
		0xAB43AA863173532CULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x02242364A37C980AULL,
		0x666078A5F84CCA98ULL,
		0xD037BDAF23D6AE61ULL,
		0x728EEBD1501A4806ULL,
		0xA174054227191E3EULL,
		0x5BB8D9CDAB9312CAULL,
		0x7DBD68441B490841ULL,
		0x032F9A4FC9A0B2E2ULL
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
		0x6270DAF73759C546ULL,
		0xAA340EB43C71721AULL,
		0x3E7E74A8D99B5283ULL,
		0x82D6BFD57CF432C3ULL,
		0xCEF7B29CC37444C2ULL,
		0x2E6CC4E3F54F5A7AULL,
		0x7A9A7C363CE57AF6ULL,
		0x9496ADE9F54EA868ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x0A610344B22A4DD9ULL,
		0xB752A69578F3E97EULL,
		0xEE56EEFDF95AB720ULL,
		0xEE4F85669F7B2C99ULL,
		0x1551EE9AF48C3A51ULL,
		0x6F7E2A4F583119DBULL,
		0xA68680CF37DE36F6ULL,
		0x031E7FEA6BFD159DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEFE601FCFA2B3F95ULL,
		0xF1B781C39A5852E8ULL,
		0x5EA2F2FDB993C4E6ULL,
		0xD586C879ED7D507BULL,
		0xF1AD12676A361680ULL,
		0x98686DE445E21A77ULL,
		0x99B47AB2AEA5FBD2ULL,
		0xB42CBF8D1BFC0D35ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CF1D97C950E3DBCULL,
		0xE3608BF19E863C0EULL,
		0xEC5AED15A8916CA4ULL,
		0x1DB90507DA4A8C31ULL,
		0xA84C4810DA2859D4ULL,
		0xC588E1BE9E2F5008ULL,
		0x1AAE8A9C8904C8D8ULL,
		0xDB086F835AE2F531ULL
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
		0xD1EBB194FBC1CEFDULL,
		0x463D308BEEDA00FFULL,
		0x99BB62E2365825EFULL,
		0x2042CB6E88B64DA5ULL,
		0x317A6CFF4D3A0A27ULL,
		0x8A21A37243EDD472ULL,
		0x458F7407520751AEULL,
		0x94D01A7EA0FA8CE3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBD158A562E0D7EA4ULL,
		0x4A746ABB5C403B78ULL,
		0x6AF350895B88567BULL,
		0x7002A23FEE41B556ULL,
		0x65E419CDF3A0BD6CULL,
		0xA65C359DB297A25AULL,
		0x24F1B3182199ACE3ULL,
		0x4C05BE96383EC77CULL
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
		0xEDDDC3479DA25F64ULL,
		0x413BDFBC03E2D007ULL,
		0x1C153D19B773813AULL,
		0x099D238090BF305EULL,
		0x89F24B704CD70B35ULL,
		0x648A9246DC338C43ULL,
		0x32DA530042471D69ULL,
		0x90121F4F70DE06D4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x076458354D06D985ULL,
		0xD56031E717297B8DULL,
		0x13C94B1FCAD98BC4ULL,
		0xC9B6A072952903ADULL,
		0x1EA412B282085FE7ULL,
		0x71DB94FB73F97538ULL,
		0x359A9F7D238D7798ULL,
		0x26425B7A1CA021DCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB5CE2B0FB84F9C5DULL,
		0x3DEE209AE6F67F0AULL,
		0xDF9AF5D733F03B4DULL,
		0xC470AA97CFDBC2C0ULL,
		0xE48E6C027EEA041EULL,
		0xD004BA2958DAF481ULL,
		0xFE70A7F92893268DULL,
		0xC408938D73E60DE7ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x36796E02BEA74D1EULL,
		0x36E8819C54358A97ULL,
		0x52BE0C63C285B493ULL,
		0x0D7408443CE0BBA8ULL,
		0x2D11EF6394407607ULL,
		0x34415195C82C0051ULL,
		0x7DB1AF5548B71C30ULL,
		0x3594DAC81829EFEBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0B705C4D7AF69F10ULL,
		0xCA874BF8ACB9C49DULL,
		0x2768FC8F104D4A63ULL,
		0x7B05FD896F794156ULL,
		0x528C6245B08671F2ULL,
		0xF91506294419F152ULL,
		0x707323254E0FD1FCULL,
		0xE80BC3E51BC5C8E8ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x33C6D37180880EEDULL,
		0xF978D9302386F74EULL,
		0xE0772B631390F3FAULL,
		0x3D32B77592CC139CULL,
		0xA4BA878BF0FC2219ULL,
		0x4AD0996618D060BBULL,
		0xCC54F9C06CE12F1AULL,
		0x171EC07E1E1B119FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x28B3BD9F080F0604ULL,
		0x47A093BA083FF42CULL,
		0x738F4BF84878FA90ULL,
		0xD7F4D98701E253A0ULL,
		0xD76EAE5AB6075D3FULL,
		0x28062A40228C9CCDULL,
		0x35936DAA67AC78B5ULL,
		0xF87AD90BF59093B0ULL
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
		0x3873896B432DD428ULL,
		0xA356B3D1E6C17A1AULL,
		0xF062A6FAF9AE5AA4ULL,
		0xADB46A1DF0382CBFULL,
		0x2351FAADB5939334ULL,
		0xFF38DD6E4AE850C0ULL,
		0x19E3AAEFBC1E4669ULL,
		0xAF733E8DD01AD81BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1FC049623E209E85ULL,
		0x9AFDD4A73D1BBB64ULL,
		0x21E40438201DAF17ULL,
		0x65AC41A1BB3F63CBULL,
		0x442EC5AA2AAB0C07ULL,
		0xF32D39E16F88398FULL,
		0x0112808B61430430ULL,
		0x8EA0F07885F80041ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE3C731C280919ABAULL,
		0x243C661A56BA12ADULL,
		0xCF9D0C58C4895FFDULL,
		0xB9472E3A40572C8FULL,
		0x1CFC61C033BE53FBULL,
		0x3604EFB7B2B47ACEULL,
		0xDC58E417D80307D8ULL,
		0x3F91067781F9B4F1ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCF6B3FB211654776ULL,
		0xE6721F6E3DC9943CULL,
		0xFC2D9A6065EF8FA3ULL,
		0x247598BB6A431AADULL,
		0x128B92EE9D45AC99ULL,
		0xB422A00E802FCABCULL,
		0x2A4C5119B064B320ULL,
		0x5EFC88C93B948F43ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x66E06F8EDD5885D7ULL,
		0x540DBE5E43DFB37EULL,
		0xE29087D9429BD726ULL,
		0x37270490ADF138E5ULL,
		0x00FFC17DF0979B05ULL,
		0xDCDD593BE759A0C8ULL,
		0x1B395D2B0B73BEF8ULL,
		0x6E6E8867982C7C77ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3C9DB17469B52479ULL,
		0xB44F4B53CA3A9851ULL,
		0xBA3116FFE5E78AC0ULL,
		0x2DBCD9F1A2C062B8ULL,
		0xD892DC4423F5AAA4ULL,
		0x38F187E3D8263F5CULL,
		0xAAC3263B9DE25950ULL,
		0x2EBEE807B3E46DAFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD623E83075023EF7ULL,
		0x7AC0F61D41580BE1ULL,
		0x4543E5E07F5FEFADULL,
		0xBCB4D59D39A14885ULL,
		0xDAE6CA1DFE992D03ULL,
		0x92B115FC4729F551ULL,
		0x7BBD12E37B5F977CULL,
		0xE71DCF1B260A55FAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF5AB547DD40D5D8BULL,
		0xD79E89939753C7A7ULL,
		0x3901850E6B91362CULL,
		0x42829E1694D2FA6BULL,
		0x27E5FF6359F38CB9ULL,
		0xFAE31BDA8624A7BFULL,
		0x2FCC73F865556370ULL,
		0xCE2D4A8D9A199B06ULL
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
		0xDDA3D970911A5851ULL,
		0x8261FEEF2E3C5340ULL,
		0x9C1E711F7F2E67BDULL,
		0x525B66DB1A1CBF70ULL,
		0xBC16E51634E55412ULL,
		0xFC6B1F836FEB36DDULL,
		0x0AB886489EDB4C09ULL,
		0xB5476EEA350A04CEULL
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
		0xFCD2C70749F98DDAULL,
		0x95E7313C027668C6ULL,
		0x2C8B94F7D37E8E9CULL,
		0x11987B9E8008C3EAULL,
		0x014FD5F27AD88E52ULL,
		0x5A9CF281D5D1AE0DULL,
		0x1574D7A8C5D41CCAULL,
		0xA9E83AEEC30322D9ULL
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
		0xAB0A5D4F291F49BFULL,
		0xCF65BF866838E1A0ULL,
		0xC3AB3A91FDDCA533ULL,
		0x73275E0B76B61118ULL,
		0x4511B6E0E5E7A69FULL,
		0x4797FE8AFA7DEC89ULL,
		0xF7EC204E4A5629AEULL,
		0xC10BBBE04E503A8AULL
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
		0x874E590AB5053977ULL,
		0x023679DC733A3E37ULL,
		0xDB6408157FDDAFF0ULL,
		0xA81EFA2FE26ECE2BULL,
		0xF145C9726B7F2C2BULL,
		0x1851B8B96D099E0EULL,
		0x6F5A7E04B3584BCEULL,
		0xD4151D1D1144A027ULL
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
		0x451A5F8251C7EDDEULL,
		0x0703AAFE41A986BDULL,
		0x3B423B37A6EDE108ULL,
		0x72F7B3DBA5978A86ULL,
		0x655D7F96E7B24DEFULL,
		0x35FA44FF9628BDDBULL,
		0x186C97842CF6F26CULL,
		0x95D9B82634C44329ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBACC850B6402EF81ULL,
		0xBBCF1CAD24C9511EULL,
		0xBB6F7AA69F2AA9D3ULL,
		0x041A425D4F8E0750ULL,
		0xAA84A127723D0129ULL,
		0x65FC3FD05E0D5776ULL,
		0x3267063CE0CFD71FULL,
		0xA047BF516E244238ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x522EEFDE86D24103ULL,
		0xFBD2E20BA0B72E56ULL,
		0xBC0CD98E8B3A4D1AULL,
		0x518BC94F0DF12F91ULL,
		0xB80D7055A95EDB11ULL,
		0xE8F1B5B3F6D51701ULL,
		0xCF53C88218C9C2D3ULL,
		0xF7AAB72B301DA45CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBDDF25AEACD89C59ULL,
		0x2BF78BE9005AC17CULL,
		0xC2263D785D4E691EULL,
		0x386DFFD80C1FEF13ULL,
		0x18ACECE6B5530F14ULL,
		0x0981C5DB35F62DCEULL,
		0xC03E7AC7BE52C4A8ULL,
		0x8C6A137211413D4CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7830E98FD39FC2F0ULL,
		0xB81D0DA505D8CE82ULL,
		0x63D4524FAFD21A23ULL,
		0x1965E05DF54243F8ULL,
		0x3B9BA333AE4AC685ULL,
		0xDAE78A60E4D8BA6CULL,
		0xA2919501DAFD6DF2ULL,
		0xD895FFFB540818D9ULL
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
		0x24ABF95C4F11CB54ULL,
		0x22CEB0DE006B7C48ULL,
		0x7AFC84001B3083EDULL,
		0x1F491E0AB8BCD479ULL,
		0xA0B0190468A71033ULL,
		0xD50DC6F354F0E727ULL,
		0xA253E82F5BFE2258ULL,
		0xA287AEA790BE8ABAULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7D2A8419CD391BB6ULL,
		0xB6F50A8C1B04D0C5ULL,
		0x17CF34D92CF3E514ULL,
		0x52C452390F98DEC7ULL,
		0x0ED482F68DC4BDCEULL,
		0x76B550E1C25FABCCULL,
		0x43266AB774F16F40ULL,
		0x4FF16E48CC24420EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x21A30DFB6AF6BD3FULL,
		0xF637769A0C906273ULL,
		0x90CE0227B71E7956ULL,
		0xE91CE1E0175E9A9BULL,
		0x6CEC6BFCE52583CEULL,
		0x87E5FE092D3525DAULL,
		0x65839D0301AB6532ULL,
		0xC5D6856B9224C1F9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x88B1988B4F8F145BULL,
		0x6FFF01208EDFB788ULL,
		0xA76D25F9A477011DULL,
		0x8FC0A06F9C5443BBULL,
		0xEE957FEB67963543ULL,
		0x7684FDF8C39D5723ULL,
		0x21D2CDA9C4288D8EULL,
		0x959B72575A2A47B2ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8918CE8D1867402BULL,
		0xA0D0870F06AC1F09ULL,
		0xE7DF7D2341404E2BULL,
		0xD296D9A6DA4C12A9ULL,
		0x17228F1A39F40AC6ULL,
		0x07AB66D1AF2DB9B4ULL,
		0x5C25A68442419BBAULL,
		0xAAB848FB7E7E81C0ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xC8B4647678DAD9CDULL,
		0x7D1AE987536B23DEULL,
		0x6A9FC0FAFD5D81D9ULL,
		0xB15FB5DC10A973E9ULL,
		0x83F263B170A39ED9ULL,
		0x40CC300A4D8F63A2ULL,
		0xCDAFAA1EE024D618ULL,
		0x02F26B2EEE4A768AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3A512B1BEB68C847ULL,
		0x5161ABF6E7D94D97ULL,
		0xD9A821EE5074C06FULL,
		0x27459DCFD2E0852DULL,
		0xAE69303662FE2FDBULL,
		0xF975CC3BCA1D19D7ULL,
		0x84C186F4F39DE91FULL,
		0xC44C4462132BFF54ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x345BDC90709F6B5EULL,
		0x11025C3629FCC64BULL,
		0x0E72FF5277B43D48ULL,
		0x0B325F5D7BD3EC52ULL,
		0xD102FCD3C786121DULL,
		0x04B93BE28E7E3A7BULL,
		0x8D5202FA88C9D8EFULL,
		0xE6729AC4724CF31EULL
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
		0x10B182FE84DF7434ULL,
		0xEB7B58A29F36F1B1ULL,
		0xF432E4BC5D8FC3EBULL,
		0xEBFAA84CCA856CC9ULL,
		0x85FB97104E168B4FULL,
		0x23B5BD90F4A8E253ULL,
		0xE21608458F44D0EEULL,
		0xC36D42C2CD5D61B8ULL
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
		0x202F537ED50A0965ULL,
		0xF9B36CF1378CCEEEULL,
		0xE43B11EF487DD9C9ULL,
		0x4F1AC4BAFACA823CULL,
		0xB3B854D92B8997D5ULL,
		0x312646240AF79667ULL,
		0x9C739910AE2B8D4AULL,
		0xBFB0479D6622256FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90DA1446766979EBULL,
		0x6748F6680D5D7EAEULL,
		0x2E30728ADFC07BB5ULL,
		0x4E20C2A8CC6FC37FULL,
		0xE26E2B4ABF1B2A95ULL,
		0xABD79FDA5C112897ULL,
		0x57B18A28A0BB7BD6ULL,
		0xC298EF8C1FF07785ULL
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
		0x5CCABC756590FACAULL,
		0x13D1B182614F3844ULL,
		0x7E1AE56FF54D14A5ULL,
		0xFBBA767C563826B4ULL,
		0xA54CB4B0354EB891ULL,
		0xDAF7C64F1947564AULL,
		0xEAC6B029473FA17FULL,
		0xB5362D5A9929144FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3022350D061915F0ULL,
		0xC627D0EF7F2AA4DFULL,
		0x62B58C56CB1273DCULL,
		0x7E92D68FD6ACD882ULL,
		0xEAF02DA999403A60ULL,
		0x045887136B336328ULL,
		0xDF88F39C570494D7ULL,
		0xC89B005C9D07BC1AULL
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
		0xA821ABB90112F1FBULL,
		0xA03A232C8075C1F7ULL,
		0x6829823A4DD3B2F8ULL,
		0x63D55DD63B5EC403ULL,
		0x783357E91946A1B2ULL,
		0x0B17F1CC1FB688DDULL,
		0x8FB732D0A8CD6C54ULL,
		0xCC256E5E26CDFA4FULL
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
		0xA82A29E5ADF8F5DBULL,
		0xA3E1D464F5FCC132ULL,
		0x008F5FDB6ECAB6D7ULL,
		0xAC665AB39038EEBCULL,
		0x06AFF40B893395A9ULL,
		0x6262C1805D250014ULL,
		0xB609C7E02FE3EEC2ULL,
		0xB123F0A033DFB905ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB00D2260DC8B0781ULL,
		0x6BC408B3A9D4370AULL,
		0xE0588D2304B8D73AULL,
		0x9C12452C0752EFD6ULL,
		0x4772609A3BAD4A47ULL,
		0xFBCE8FF9F3B5B39EULL,
		0x30DA82DCD8C12061ULL,
		0x1EF921A0D86E1632ULL
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
		0x16FBFA5A8320DA09ULL,
		0xFEFC18049ABB81CCULL,
		0x5665FE7DD474CE38ULL,
		0x411102276C8EE9B2ULL,
		0xA756A6B305579C45ULL,
		0x85A55893D77A2B7FULL,
		0x8DC7F6D54B42DA93ULL,
		0xB7FA55488924EC4CULL
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
		0x0E351D2F5F7658C9ULL,
		0xC2C4B5D8FB83C54EULL,
		0xBF50DBB94F4F3165ULL,
		0xC62EA8102B8D1D39ULL,
		0x547BD86218359DB6ULL,
		0xD3E253039A7F3F5DULL,
		0xB034D38F3209E8F7ULL,
		0x568615BE8FC9932CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC56ECB2E03C311E3ULL,
		0x384986B91F841F43ULL,
		0x90C044DA39F4DFD0ULL,
		0xEF2D29FB6BEB0144ULL,
		0xB81E079011A94E24ULL,
		0xDE38917B9B8564E0ULL,
		0x3CBCE4A998518DD3ULL,
		0x63244F3C79705BF1ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x7DE3EF7748AB88AFULL,
		0xFAE2427BBE758524ULL,
		0x4E6A7C93792D47FAULL,
		0x77770C33F0A06B4DULL,
		0xE298AA4F3A27036EULL,
		0x77D696B2B649E466ULL,
		0xBDDC49B33FCA6A2AULL,
		0x08943FDAA98D7A20ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x68CDB475D85975EAULL,
		0x5FD5DB67E5A0AD84ULL,
		0x10E6020FCA381677ULL,
		0x7A41CC71854EEEA1ULL,
		0x39665802ECE1A7E7ULL,
		0x36517D2853E464C7ULL,
		0xB8137F5152547F13ULL,
		0xCED490C71066D8E3ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF64BC094AE541B48ULL,
		0x3477FAEA29F02AA4ULL,
		0x94A1B4F045C7DAF3ULL,
		0x5CCD77007B8E2C28ULL,
		0xE0FC992E0547F01FULL,
		0x800566D2203EA0B7ULL,
		0xA7A9526474B58110ULL,
		0xE40F396F9029080CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB2440A496D9E84B2ULL,
		0x7EF9691A057AAE84ULL,
		0xF30EEEA75FCD3199ULL,
		0xFC77F5F484BD3FEBULL,
		0xDE32811062B60461ULL,
		0xDB551661E6F92715ULL,
		0x40029C3706CD6456ULL,
		0x49FA1DCE889069B1ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9930A632440FF743ULL,
		0x6820B1A7BAB874F2ULL,
		0xE617C8435250ACC8ULL,
		0x4C8152E082076EF9ULL,
		0x76805C11C5B47B9CULL,
		0x06AA0AAD52CC09DAULL,
		0xF756D450EAF0132CULL,
		0x763C438024ED8BF7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x11388EA127D18AE8ULL,
		0xEAC5292695A11FD3ULL,
		0xDE1725F8B0E41B1FULL,
		0x0A1FF101A53B7E01ULL,
		0x36E23B64C8A4B0D9ULL,
		0x98391AF8485FBFACULL,
		0xE33B1993A86A300BULL,
		0x4E48883DB9EE8E14ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF977D203AC862AD1ULL,
		0x59FB0ABC7155EC86ULL,
		0x85F3AC357833CA77ULL,
		0x6C6A5241A0B23C09ULL,
		0xE26F26733EFE2F70ULL,
		0x20D54B62FEDFA56FULL,
		0x89438E51FB973B0AULL,
		0x9B041A3849EEF0B2ULL
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
		0x2CD97DFEED745217ULL,
		0x7B435C2F7A07BE78ULL,
		0xB2698F4AE755222EULL,
		0xD8F9ECB6B22A3D00ULL,
		0x976741FF77ADEC78ULL,
		0xC152FB761BE779D4ULL,
		0x00AD9CB876C82B5CULL,
		0x914EEA06DFFA8505ULL
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
		0xD6423B2D03B82F79ULL,
		0x27F2B8966FB35FFFULL,
		0x1107C0AF366F2CD3ULL,
		0xCE157765CE3EA12BULL,
		0x7DDAA4486D4D3B1AULL,
		0x1B2D963CD1E2E074ULL,
		0x93860BB3A9B8E50EULL,
		0xAEA131D48A5F1D03ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE3068B264628826BULL,
		0x683CF55EAF5E0B96ULL,
		0xE2157EFE9407F0B6ULL,
		0x07A72C9EB3B58129ULL,
		0xBEF81381CBE8EF19ULL,
		0xD5560EA54532AC4EULL,
		0x6C21EB2046E5B656ULL,
		0x0AC773CF2D76C962ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x3C9A772DF11B076FULL,
		0xB979B89924DC43ACULL,
		0xF5CDEF2ABA796193ULL,
		0x23C202C65B5A6E4FULL,
		0xC12590D0EBE65001ULL,
		0x7F931A53E93C471FULL,
		0xC3AB01592341B01AULL,
		0x0F8B0E785E1C8EC7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7894D6E2BE2A8725ULL,
		0xD2F73A8E6A313B20ULL,
		0x1D6D744B4A60C270ULL,
		0x51DBFE4F5250BB49ULL,
		0x9C3FFF849A888C8FULL,
		0xB4C5483E4C174023ULL,
		0xBF4C54B480CC01EFULL,
		0xB2329754D56574F7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x714E07F2C2D76081ULL,
		0xDCACC0972698CA72ULL,
		0x20182F151D605619ULL,
		0x783A4DCA6E26DD1CULL,
		0xC5CC421C76F09E08ULL,
		0x57B0D5487211FE8CULL,
		0x44FD70F87F4373DFULL,
		0x72BDF06F05234BF9ULL
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
		0x5196B0EC8800A704ULL,
		0xA50E647254D4338CULL,
		0x8AE7E448AE656811ULL,
		0x1943B4C7B6ADE1A8ULL,
		0xEB3718B132C603C0ULL,
		0xB1C3C22ABF05B386ULL,
		0xC6E222B623C762FCULL,
		0x819E0C3B4B6F197FULL
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
		0x17414D4128ADC981ULL,
		0x6E3C78C912B11BB1ULL,
		0x16C6F85069F5115DULL,
		0x0D27FC823C5513C2ULL,
		0xED05FF82DBA0CBB0ULL,
		0xB40082227754DA2DULL,
		0x5511464221D1DCF4ULL,
		0x6AF2CA73E845F413ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD31CBA2F14F2759AULL,
		0x5971BD391D6577F0ULL,
		0x40A30DF5AB1A12FAULL,
		0x99B6CD1C544D57B2ULL,
		0x456CA6C14FE763A6ULL,
		0xA0AB6954970693A0ULL,
		0x8A9071962982847DULL,
		0x2EC51B37879BCBF2ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC41148E8F4FC80FFULL,
		0x21775BCCFF69C54EULL,
		0xDFDB11B7A37142A4ULL,
		0x8AAA0E7B71296B99ULL,
		0x5FB5981CB5B898F5ULL,
		0x989B69FE98C589DCULL,
		0x4F8D0E8A7B6433DAULL,
		0x11BE708015110D7EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x76395B3C7C116C60ULL,
		0x4DA4CE56C731421FULL,
		0x05A92186E45B65C8ULL,
		0x940CFF03E497C857ULL,
		0x0D7F70884BC8AF74ULL,
		0x485D21A2A84C66FDULL,
		0xBB81D0A65C6C09ACULL,
		0x23D04F66419DB0BAULL
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
		0x9BDA801FD74B28C9ULL,
		0x15B43802153B5A3DULL,
		0x9E975BBAFA12310BULL,
		0x26E6E58CBBD9F831ULL,
		0xEB87BD49D3C57458ULL,
		0x322A7EE5A91DC49AULL,
		0xE263FC7FD9356298ULL,
		0x66453B832D88D518ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xA791649B651ECBC3ULL,
		0x2A4A11ECA9DD5860ULL,
		0x4D3DEBE94B2344B3ULL,
		0x74B1EC0851D920AAULL,
		0x50A4830208CA46ACULL,
		0x364686CEE2EA0110ULL,
		0x60A232F7203E7C08ULL,
		0x0AECD0E25B3CBB56ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBE0D2545A19BEC80ULL,
		0x7DB1E10536032610ULL,
		0x05EB4C4B85468D90ULL,
		0x75399DF106F630DAULL,
		0xC3A67901F8A3E3F5ULL,
		0xE677DF88917F2D95ULL,
		0xD49028BF1805213DULL,
		0xCB359F5E747F9CCBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x975DAD1C5C208260ULL,
		0xF5B7AB33BD62EC79ULL,
		0x0AE9A493E7614A4CULL,
		0xA2F871DA0201413BULL,
		0x166478370C7390ADULL,
		0x70579CF1E427C16EULL,
		0x782BED2D9BB4B73DULL,
		0xAE632E37E31AF577ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD56817836690433EULL,
		0xDB83377F1892083AULL,
		0x5DBF4DDAFD37F2B3ULL,
		0x242921884BB852DEULL,
		0x3854DB73089F3A23ULL,
		0x180CC0E64D76110CULL,
		0xADCCD1C7BF7CBB59ULL,
		0x865CD4621BB41CDCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD9C5EE3AB4020388ULL,
		0xCC9934C756B1977FULL,
		0xFB150553E4F2044AULL,
		0xBD3FC52BB20E1294ULL,
		0xCFC5899E4D0EE69FULL,
		0xF0E79E981456B947ULL,
		0x1DB3DEF2EF1BE51EULL,
		0xB195F15A15882C03ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3C5AEAF8506857DEULL,
		0xA16AD5C71C4E9879ULL,
		0xA921AB0752D8FBD7ULL,
		0xD878A2C76CD09BB2ULL,
		0xBE2E76A4A58A8AD2ULL,
		0x3CA4E8C465441973ULL,
		0x376BDF2C153E3C50ULL,
		0x9A677427C455E581ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF5BFABE48122DB5FULL,
		0x77489EF3719E7ADDULL,
		0x821DEA0AD2742434ULL,
		0xAABD277F2B9A88D0ULL,
		0xF52F3AB6F5151EB3ULL,
		0x30B4F5482BA9DC8FULL,
		0x9FAC1641D2575DE4ULL,
		0x50F29CA770C5FD3EULL
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
		0xA489EAFCB59A504FULL,
		0x9B0ED5074C46CBD7ULL,
		0xD9723D4B933C80E5ULL,
		0xA501EFFAE5F4D407ULL,
		0x51B9C61AEB802C6CULL,
		0x9DADE76A3F6E69E5ULL,
		0x95435F17E3BDE962ULL,
		0x8D175DFF909AA27AULL
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
	la = 502;
	k1 = (curve25519_key_t){.key64 = {
		0x53E235536E11F300ULL,
		0xE8FBA6289F742FEFULL,
		0xB1FCDA15BAF3109BULL,
		0xC384CADEBBBEDC1FULL,
		0xA1B644D59F2754F8ULL,
		0xA0B5CF728B243C38ULL,
		0x3D38A58FC2676BB2ULL,
		0x0068A0564BC92C4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL
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
		0x5E496A08AE711A32ULL,
		0xBC75F3BAC9216763ULL,
		0x907E597FCED67BFCULL,
		0x5124638C1B1D0058ULL,
		0xBA2721A2794DF44CULL,
		0xB667C49E005F8D6BULL,
		0x7514BF43312135A2ULL,
		0x848FC2701BB23482ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3B3D154239818D9CULL,
		0x3214390153966824ULL,
		0x964CFFB48A3CF51EULL,
		0x5FA18C8F07419C0BULL,
		0xDDEA8B3604300D0AULL,
		0x74FD5B499EA6D0AEULL,
		0x0B63664395F64CE1ULL,
		0x50B214492A7D4399ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x740B15AAACEEA978ULL,
		0xA88055CBDDB8E9FCULL,
		0x2478C7F156C5C417ULL,
		0xAABF63F7B2575F94ULL,
		0x1CD07EA73FD7A155ULL,
		0xF2DE8999E7B0A66AULL,
		0x1439AE9F8F7E12CCULL,
		0x1C7AE703353AB0CAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3863B3E9EC84D762ULL,
		0x1A5749C314A423B4ULL,
		0x45693794B139DA81ULL,
		0x9B2C5074319FD191ULL,
		0x2CF87681B94D188EULL,
		0x8B5CBE40AEBB3557ULL,
		0xD2561570851DE695ULL,
		0x9325ADC5EB8CF9D4ULL
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
		0xD5B7AD7A880BA186ULL,
		0xC55E48C0F73AD36FULL,
		0x43475176B4C45D65ULL,
		0x25BC04F85C1F263DULL,
		0x2FE318CD1FF21529ULL,
		0xDB22736A36FB83C9ULL,
		0x0E68542A5F3EEFD8ULL,
		0xF2695D5097A3D23AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5BFA40F1C67F79E0ULL,
		0x6E6678DB2905B00BULL,
		0x966AD2AE2C3C5321ULL,
		0x9AD7AEB67CE0CE17ULL,
		0x4433FB01A000F85DULL,
		0x51EDCA16B10D91EAULL,
		0xC5818C344B75B561ULL,
		0x65D90B6328135A30ULL
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
		0x9A76112B495660BDULL,
		0x5DD22929798CC23DULL,
		0x7D517D1DD7E4ECC3ULL,
		0x75563326D76A9BE6ULL,
		0xBEE6357917A30F40ULL,
		0xBC39998760B6B01EULL,
		0x2D4CA4E0B34F5DC3ULL,
		0xECA08C85F66C0DFAULL
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
		0xE1551FB740C4B25BULL,
		0x4C49E870DF0856B9ULL,
		0x3339B86E9B4C99C2ULL,
		0x80010D8B2426A643ULL,
		0x13A5FE2B351E1704ULL,
		0xB80702D85D688372ULL,
		0x5488D511B844F903ULL,
		0xA7A900535CF9D41CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0AAF442BBE428F0CULL,
		0x1A1E9D8641E69F82ULL,
		0xE1414B4636C676D3ULL,
		0xCF3A74B84DC47656ULL,
		0xA3AF6FCB30F748BBULL,
		0x9E439E3C459DF998ULL,
		0x1DCF4360CF3E657BULL,
		0xB250DA9860891A55ULL
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
		0xCABEBCC9FEA462CCULL,
		0x1C5895459D06E840ULL,
		0x8794891203449BECULL,
		0x6139716C66D7C310ULL,
		0x69540D6A3B978ECDULL,
		0x7CB0F0C39BAD76FBULL,
		0x50EF45867D95BA4BULL,
		0x9A261418A7E67BDEULL
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
		0xCE383E3E853C6DE2ULL,
		0x421CA79CA9F33BD6ULL,
		0x73DBB68A275AE4CDULL,
		0x7EC8913D17F07D79ULL,
		0x0A8DD62C775E18DAULL,
		0x0CE124AB6561C3BBULL,
		0x905A9AEB0A3B4FE2ULL,
		0xDA7716C9A60BB8D5ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1269091242731BADULL,
		0x2715C70370E46026ULL,
		0x8F50C2D5869735A3ULL,
		0x4B1B0815E40A4B54ULL,
		0xB526E3CC685981AFULL,
		0x5B5C73CD933AC834ULL,
		0x9CB0BCE1F8E83BA5ULL,
		0x4556A4DABD064052ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xE1937F54FDA9C863ULL,
		0x83A253FD97C1BAEBULL,
		0xCAB8245887A839E6ULL,
		0xE90345C584A9F697ULL,
		0x78C4139D8D0537BBULL,
		0x04569693E1046BA5ULL,
		0xD204D50BCBA2E83FULL,
		0x0A2D0B61B534353CULL
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
		0x835682E5C79DF4A3ULL,
		0x42A7A825DA6E3B53ULL,
		0xB6532C03DE317F82ULL,
		0x60365A44C9D132BBULL,
		0x743F97A3BCB6ED8FULL,
		0xA642B9FF48F25FAAULL,
		0x76EC4180DE01877FULL,
		0xB0B8B8E69A3B58E7ULL
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
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0x9335EC5626268424ULL,
		0x6B487580A13D1A51ULL,
		0xD744DE98B87F23B7ULL,
		0xE43E4E205DDC36E4ULL,
		0x6A0B9B88586DC07CULL,
		0x7185C88575BBD7F1ULL,
		0x5DBF2FD01FD16304ULL,
		0x009EDAED0BBB5578ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xA26EF792B4E9D283ULL,
		0x048ECBF1B44B071FULL,
		0x71940ED1516053FFULL,
		0x1A473D7186EB1197ULL,
		0xEFA2058E4D30A5F3ULL,
		0x24E1A0BFFB2FC1EFULL,
		0x42C917D31AD28F7AULL,
		0x0BAC3AB09AA86E1BULL
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
		0xC45C3CC56523F42DULL,
		0x734A19CBFA2227AFULL,
		0x8C7BF2A22B02635FULL,
		0x91145DD2BAD11C55ULL,
		0xBDBEC6733ABCEE2EULL,
		0x06E35319F7D4D756ULL,
		0xABB6DC9C724755A5ULL,
		0xDA1EAE25F3B98DD7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE653BDF0EF7573E3ULL,
		0x35E6E28E83EAAB4FULL,
		0x7AF3CE3ABCBFF173ULL,
		0x963007AD3A33C4FEULL,
		0xBBF1DF2F457B55ADULL,
		0xBA67C373640BBBD6ULL,
		0xE24B9206CB7C6C69ULL,
		0x92FD87482B6F4139ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x82032F8B1512AFC5ULL,
		0x10CF568A89EEC281ULL,
		0x65404AFD289737DAULL,
		0x2046C44C43BF7175ULL,
		0x82F01219FDB21011ULL,
		0xA3EF18D9E6EF193DULL,
		0xA6553716076C0D2EULL,
		0x591A6913A1BDEAEEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8821865A65E644D7ULL,
		0x515749C76EE7AF0FULL,
		0x671C1696632F407AULL,
		0x4882EA6AF8DB124DULL,
		0x2937652D9468C231ULL,
		0xB779177ACE0C6E3BULL,
		0x24029B2A55A16905ULL,
		0xD2698296B225B793ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6C246B5D01CBBD15ULL,
		0xE088EDD1A1E93987ULL,
		0xD4454EAD0DA77E6BULL,
		0xCD42DC5B3ADEDB91ULL,
		0x208E6D5700E584E6ULL,
		0x28075FD707D49B37ULL,
		0x36E0E95495CECFA7ULL,
		0x25588D92A518AFB9ULL
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
		0xB5743CB1EBCB8984ULL,
		0x0564B0BC06CAB9F5ULL,
		0xE81B63719197DEEBULL,
		0x45867245C86FC1E2ULL,
		0x183916A54DAF73C7ULL,
		0x187325F3CB2DD05BULL,
		0x24D354F54E9C3D7CULL,
		0x850D7E8F4B3CDC5BULL
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
		0xAC47C4AC5E067758ULL,
		0x0672F174A4937E0DULL,
		0x8EC9AEE7959A4B27ULL,
		0x33B10BD802CA97A6ULL,
		0x5A1693B1901B6EDCULL,
		0xD4A41441B919BA77ULL,
		0x994E07FB64D5CF2FULL,
		0x935F0230B3CCBCB3ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xE15FFB8387C22073ULL,
		0x9A1423004A94273EULL,
		0xE980936BCC791F78ULL,
		0x5821A1EFB6733264ULL,
		0x86E70A18033BE84EULL,
		0xB26AEE3CB277D9A4ULL,
		0xA21D04C646C432E4ULL,
		0x1DBCA1C303EC2974ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFB3FA6BD60AC1B92ULL,
		0x222E85E2FE2747C0ULL,
		0xE0C7EF5AAC400CD1ULL,
		0x38304DA6FCEF81E2ULL,
		0xC201B7E682CD06F1ULL,
		0x11A1406A20DF6515ULL,
		0x5EFAF4C620A241E9ULL,
		0x84BA305E373EFC3BULL
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
		0x4B4C694A48CC0CC6ULL,
		0x0483C7819A3866F9ULL,
		0x62A1FF1CED90105CULL,
		0x65EEF298BCCB9B98ULL,
		0xA7AC4441748A0E82ULL,
		0xAAB17B5500E6D0B2ULL,
		0x636213A36DFF3DF9ULL,
		0xEE782FD24F6BDA2EULL
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
		0x55131F0AAC24CFB0ULL,
		0x9A3C15D16042D424ULL,
		0x5248F7D0C3FA7929ULL,
		0x60968DC63BD77418ULL,
		0xF4055C854252392FULL,
		0x1B7370688683A31AULL,
		0xC5E147DFCBD85A43ULL,
		0xAB590BA850452A54ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6F180EB454273175ULL,
		0x123B68F651BD2544ULL,
		0x4086F2C07A2B1FDAULL,
		0x7FA149EB6CC374DDULL,
		0xE6B0B7D51F1048A2ULL,
		0x43C1715A04DD9092ULL,
		0xF8AB2E6878E36260ULL,
		0x541045492C6CB8C3ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x59DF8537B10B2AE9ULL,
		0x307BCF15A10DBFD4ULL,
		0x248A9F05BE479B35ULL,
		0xCA57D537CBE3E5E3ULL,
		0xEE06D0AC5899C40DULL,
		0x3634D971D7A24314ULL,
		0xC5783EEF5E2FAD6BULL,
		0x383555F91601962DULL
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
		0x7CE09BD72B4DAC11ULL,
		0x47947D122F1FB67AULL,
		0x8B69273DF4EA79FCULL,
		0x542D2FF1A1CD6CB2ULL,
		0x6DED1C310C506F3DULL,
		0x6C9712B02A0CE4DDULL,
		0x8F0A7A127ED50F29ULL,
		0xD74B21173218E5C1ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4103C43AAD46F74FULL,
		0x25E9A6ABE24E50F7ULL,
		0xD1F382352881D221ULL,
		0xBE8241F0F12388C3ULL,
		0x1FC1940DFAC61911ULL,
		0x09F52C76CB5FAE66ULL,
		0x5DD33A12659F259DULL,
		0x10DC43B9C9B13DA1ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x970E6532AACB6820ULL,
		0xAD5C254970EC43EDULL,
		0x7140F6963DB79498ULL,
		0xD2E68402DC371565ULL,
		0x63E1F3A6708A9050ULL,
		0x65748330EAAECEC0ULL,
		0x77A10AD69F484945ULL,
		0x0C444F135B24BC63ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD77677EF26AF779AULL,
		0x5A8760EA60C36568ULL,
		0x699216839E47D3CEULL,
		0x32B561836AA83DA1ULL,
		0x614FBC3A6D8ECAD0ULL,
		0xF3E3FA2453F421D2ULL,
		0x8A6BFDCD3E9B7819ULL,
		0xB04A292A69A03414ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x91A4312E335AC230ULL,
		0xF6BAFB7FC73E8B95ULL,
		0x9D2FBFE55CDEC636ULL,
		0x917C34A55839FF5DULL,
		0x05F4186EE8D0D31FULL,
		0x0E8F8F4B0D9D811FULL,
		0x45C06D901941EC23ULL,
		0x53125FEDFFDDF7A0ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x07314F7FFD15A4C3ULL,
		0xC47DCF430C0D6EBFULL,
		0xF63916B869D1926BULL,
		0x7332BB69543BF986ULL,
		0x601B8789184B4C10ULL,
		0xF9E661CA8026C35BULL,
		0x2C02FD320A98EE9DULL,
		0x07DBBBC003A2D661ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x94DDB4FD9D04C8DAULL,
		0x1D126E8B8F729C96ULL,
		0xB4FBF4BAF20A4940ULL,
		0x875133CB1CCB3DB2ULL,
		0x531A3AE744C70D11ULL,
		0x68E703DA39C547E3ULL,
		0xF80213DA9F49E382ULL,
		0x37E23B6883A587D9ULL
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
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0xC38834E20ECC95F7ULL,
		0x0983B7E44E9165B8ULL,
		0x37BB165C54C5CBC3ULL,
		0xA0F27F4F6B1A18C6ULL,
		0x37A89DC50EF35057ULL,
		0x63294FA19BC82434ULL,
		0x69121F3251273461ULL,
		0x009280EA7A137F61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x71BB0484D8D056BAULL,
		0xC63C6A99C5CECA3FULL,
		0x991839E004AE77FDULL,
		0x941FF66EB34733C0ULL,
		0x598EE24D1D695A6BULL,
		0x16FC44B9FF489D3CULL,
		0x339FAFF0311A7E4DULL,
		0x7CCFE924FF076EBAULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x981007125A93B7B9ULL,
		0xDA915687FA2653AEULL,
		0x5CEBFF42DB2E1845ULL,
		0x26C02EE01C83DA96ULL,
		0x59CC6EDBBDB2E25BULL,
		0x38AB3874E09828AAULL,
		0xC954CDE831001B4FULL,
		0x1AE3BE2E7823CE65ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5879F0F6B527C135ULL,
		0xDCBAE8F68ED3D557ULL,
		0x47D3D70C65E90453ULL,
		0xA2C6060F0B20AECBULL,
		0x474B3EC698602EF9ULL,
		0x1860F1CD2CA9A0C3ULL,
		0xCCFEE30310473938ULL,
		0x72BD539EA78D283AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1A8D343EF1482EE6ULL,
		0xCE26F8B8B6D49772ULL,
		0x4FAC45F2A2C9B366ULL,
		0x3A3E9592D89FB10AULL,
		0xF1FA8999A81E8663ULL,
		0xC9999F5AEF22C5D9ULL,
		0xB5E64AC0D0D73675ULL,
		0x425709C1C32CAA44ULL
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
		0xF9D74BF96F5EC124ULL,
		0x0A04A7AEA1FCBB7DULL,
		0x231EE02C61777398ULL,
		0x11C52F38846D6886ULL,
		0xEC487ABC7790870CULL,
		0x63732BF382B8B0F3ULL,
		0xA3D386932F3DC177ULL,
		0xDAC30C09005934F2ULL
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
		0x3C13AAD2C71CA33DULL,
		0xECC6D73D33ECAE9DULL,
		0x550511AD7C1A2EA1ULL,
		0x1A53E957B190D9F0ULL,
		0xBA87BFCF4E89F69AULL,
		0x09CC927849B6BE44ULL,
		0x6F9EB4099A1B5150ULL,
		0xD224FBE2A012AC37ULL
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
		0x1A993F52EF54DDAFULL,
		0x4EA54D0820652AE6ULL,
		0xEDDC52D75425ADBCULL,
		0x8D21AEED9BBADC5BULL,
		0x5FD87C856E05FABCULL,
		0xF9200BAA25C3AC92ULL,
		0x7F86AB9F1EFD472DULL,
		0x6CBA4704E2C3F140ULL
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
		0x9F6FD670A3367BDAULL,
		0xD69419657B3FBE62ULL,
		0x7D577666DC1400ACULL,
		0x1B3B56E8C6E7AFE0ULL,
		0xEC30CC5AAB4148DFULL,
		0x336195A663C8759DULL,
		0x8DCB1AD9A2B9E5B0ULL,
		0xD19409EBAD04A900ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1097A50E3B1D55FAULL,
		0x264F6B1C503DACA6ULL,
		0x05F604B5ECA6FABCULL,
		0x24DC3F963DBEFFC1ULL,
		0x209252959E1E2568ULL,
		0xB82E8BB855F27EC3ULL,
		0x4288C4B9DB09C685ULL,
		0x17D5F79E2E2D8370ULL
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
		0x3D7B3CC0E47BC551ULL,
		0xEBA8AA5A4D1AFA75ULL,
		0xADAD845F2A6D6FB0ULL,
		0x0812CBBA5C7A6219ULL,
		0x6DABAB3CE20AF984ULL,
		0x6A473162C38F0AA8ULL,
		0xE76F70ACA3F81507ULL,
		0xEA273878E486F228ULL
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
		0x24953C64F20BB5DCULL,
		0x0CE3A8EFD9FF1E87ULL,
		0x8A9DC3AEB3C610F4ULL,
		0xD5446793EBFA8214ULL,
		0x033FD56A39687D64ULL,
		0x30753625C8594273ULL,
		0x4D1BF88C0AD79D6FULL,
		0xDE188A0722092B25ULL
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
		0xC1FCFFE892EBD3A0ULL,
		0x7517735443422610ULL,
		0xAFFDA251AE23F9C9ULL,
		0x36B24DA7772CCACFULL,
		0xCAF9723EB4C66058ULL,
		0x4CE0C22DD1AE68B0ULL,
		0x5614F604824E8FCBULL,
		0xB3A23A8CAD5969EDULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB6A31B747C2883E0ULL,
		0x9CD80FA9F6366DBFULL,
		0xDBB9B4A67F974611ULL,
		0xFF3C29CBA0350745ULL,
		0x7721D2F935E43F7AULL,
		0xC7D6072AD1D2242BULL,
		0x3EA22E189BB04AF3ULL,
		0x3179F49F68C653B1ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0C0F6AB52D931533ULL,
		0x4E460E56A823CA7BULL,
		0x6E4941256C080FC2ULL,
		0x04EF5E55897FDB3BULL,
		0xA44961EF5724BD30ULL,
		0xA97DEBF21B97F2D2ULL,
		0xFB8D6F6C796C479BULL,
		0x2C4465B411D49D50ULL
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
		0xBB1A31272947E0BFULL,
		0x6590A1A543511999ULL,
		0xE68764737605E6D9ULL,
		0x26C71CD3E7914939ULL,
		0x947BBFB43CDEAA0EULL,
		0x0FF8F32D31EDF551ULL,
		0xAFCCB965665328B6ULL,
		0xADEDEAD2EA9087D7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8715D313D10F1F05ULL,
		0x9B4FF700820F2BD2ULL,
		0xE9381387DB430784ULL,
		0xB82A9C1C8C9D8729ULL,
		0x758A56D6776F19F5ULL,
		0x85FF29F7AC187DA1ULL,
		0x3B0F993BDD639864ULL,
		0xAF0FE613437889ADULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE2F0745EF907F438ULL,
		0x3635DA6C4A11C93BULL,
		0x37C67A526C662D5CULL,
		0x02B6CF77EAF3627AULL,
		0x8BB5BB28553E53B2ULL,
		0x87ACA772699232E1ULL,
		0xB10E9CA8CAEC5979ULL,
		0xF225B23CD5E59F49ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x59A476BFC2FC3A0EULL,
		0x1516A8ABBC3431D5ULL,
		0x2E30001D0BE5C177ULL,
		0xDB1CFB8C5D20ECC0ULL,
		0x212CECBDC321B52BULL,
		0xF3337086C1053E5FULL,
		0x9FDF24B7AC8E6534ULL,
		0x51E599CB0F118615ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1BEEF927C521F1D1ULL,
		0x2ABF741A8E6E5C03ULL,
		0x8223E7F3CE67C3CBULL,
		0xB339370B14660C74ULL,
		0x25D53D79FAE93296ULL,
		0xEA2449FBF8936134ULL,
		0xACC7DAF9D4A0E6B7ULL,
		0x5DD074531CA650D7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA22314F630CCAC2FULL,
		0xF86B838730E71CBBULL,
		0xCD94BDF393AB48FFULL,
		0xFACC64E4D35934C3ULL,
		0x6997DED206367C01ULL,
		0x45CF23D90A35B672ULL,
		0x9A7C828EB8A29A45ULL,
		0xF387CB7E9968EF23ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3621C546CA457A3AULL,
		0xB267DC95B0609326ULL,
		0xD7C1160B239F84CCULL,
		0xCA6BE0D16FBEC369ULL,
		0x273C42B95E1ABB7DULL,
		0xE394C2E23D89C71FULL,
		0x320548630A98E654ULL,
		0x6372CA5066226680ULL
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
		0x9E6519B2FDF24DABULL,
		0x68803C668A6061B2ULL,
		0xEB13E5DDC0FFB27CULL,
		0x3F40232CDEB8A282ULL,
		0xC0CFECB6E1C16BBAULL,
		0x959AC01FF12B0D77ULL,
		0x612329633FD9B935ULL,
		0xAB3095E879E38849ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEA4AB8242ECC1F32ULL,
		0xF9834E15498C19D4ULL,
		0x94346BFE7F05BB7DULL,
		0x5806D572D6939527ULL,
		0x4A914AA2A22C42F9ULL,
		0x3AE1997423A5346AULL,
		0x1C33320CECEB2AFDULL,
		0xE4969810A093FEF5ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x062C31DAF00B99EFULL,
		0xA77B09564EF9352EULL,
		0x6326810F74B1FFC9ULL,
		0xBE840695F6F2D59EULL,
		0x0A7F7799F2D91317ULL,
		0x2EB51C4F9D55F395ULL,
		0x621E608640785EE8ULL,
		0xCE472A4441E2E56DULL
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
		0x39D0D3E04CD3E0DDULL,
		0xAF44A5EFF89E7CA2ULL,
		0x54A8E61120595BF4ULL,
		0x732DB123B5364800ULL,
		0xC9DDB98C8233CE1FULL,
		0x71E95580991E3C31ULL,
		0xF200C18CA72884BBULL,
		0xD3493E4082A4456BULL
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
		0x3F2F726140396F2EULL,
		0xE59441CC6233E68FULL,
		0x485A0263994EDD81ULL,
		0xA4342F0C2946E673ULL,
		0x84B360F4862C75B5ULL,
		0xA4B900ADFF4E370BULL,
		0xFB33371099EDC09BULL,
		0xC43CD3CBA4B85724ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC5C8FFAD9DF2C10DULL,
		0x70BF162C4F073B51ULL,
		0x8BCFB9EDEA209F21ULL,
		0x932E2BD75D3FA3CCULL,
		0xDC80E67950D00C4FULL,
		0x76988E4C27BCBD6AULL,
		0x955FE5BBC57F069BULL,
		0xB3F152D92D076926ULL
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
		0x8508A070A03A7032ULL,
		0x89C2B0F271A00FB9ULL,
		0xB99E3CC16FC539D4ULL,
		0x5A62B6C1886B12ECULL,
		0xE1437CF850F510DFULL,
		0xAE2A31B0BA8B8570ULL,
		0x793AA6CA17B9E127ULL,
		0xE76A1E06F9D731B7ULL
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
		0xE04ACA2D275019B5ULL,
		0xF545A694071F234DULL,
		0xCB019FBBCAD9D93FULL,
		0x3BC2ADB5281BA0F6ULL,
		0x0B9B4AAF8B3B7B97ULL,
		0x460D8DA071DB9F4EULL,
		0xF543BF515465E869ULL,
		0x8CC59D2DD786DD44ULL
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
		0x16899DCDF404F9AEULL,
		0x849EDEC98CF99DE2ULL,
		0x42D5F55220CE93D5ULL,
		0xD50FAF6D0C408C4BULL,
		0x9765D50C925E7622ULL,
		0x0B80ACE266A273EBULL,
		0xD8324D478517F250ULL,
		0xD00610A88A61E63FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x24B31E5454DFCE26ULL,
		0xEFB502C614D249A1ULL,
		0xCE0467738CDBD84EULL,
		0xE9DD18AEA8DE6687ULL,
		0x3C1084F5BF6E44AEULL,
		0x6CB3B8A1293E47A2ULL,
		0x5793BDF74E2FC1D6ULL,
		0xDC12BF2735915B07ULL
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
		0x057AEDB93EA831BFULL,
		0x666000CAAB075A86ULL,
		0x8D7D5AEE0AEE6C17ULL,
		0x7D5017C72E76078EULL,
		0x63C6549F18190BFBULL,
		0xF87616B0656FC0D3ULL,
		0xAB6221A50907BE5FULL,
		0x7FD23A6C2EA00989ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFAAD9648E4A2CCD5ULL,
		0xC2433C49E21F369DULL,
		0xA93F8F5220AF1C93ULL,
		0x1CBC8CAD5CFF9FEBULL,
		0xF54FF6265859909AULL,
		0xDDD899A794065C48ULL,
		0x5EF74B42B8FFD500ULL,
		0x9121721E9423143DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA428F1D6ACFCE6CFULL,
		0xAA0FCF6C5A397726ULL,
		0x9C7CBEA9B55F8083ULL,
		0x5E97F44021433419ULL,
		0x8E71B435DA13183DULL,
		0xD4E57A3EAFDAD09EULL,
		0xB8FDE715B5022FE8ULL,
		0x73733BE9C3BF24C4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC99711B00E8C5F62ULL,
		0xC183B724F6939497ULL,
		0x10FB1D0C67941BD1ULL,
		0xB08C8411EEF9E1ECULL,
		0xBE158454B7D6E47AULL,
		0x2CAA51CEA81F2E22ULL,
		0xB3C13BFAB3712888ULL,
		0xF061535076AA7C78ULL
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
		0xFCCCDCDFEB19D00EULL,
		0x323D7698D4B39088ULL,
		0x9712E6878721FA34ULL,
		0x20624347284218ABULL,
		0xD6527D8467287BD3ULL,
		0x52905BDEA19DFAEFULL,
		0x3C3D3A90C9923DD8ULL,
		0xB30036408E998B0BULL
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
		0x54C258DF995A69ADULL,
		0x32CC2CB4CA316786ULL,
		0x291BD7B504868EC5ULL,
		0xB4FA2C03FE935543ULL,
		0x61749DF7EE652E24ULL,
		0xB90E1EEC160BA5E8ULL,
		0xA5EC7EFC426C3F04ULL,
		0xF7A0CA6BA4E36E6FULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x15C0DC843A0583E4ULL,
		0xD3790E1B307B1D45ULL,
		0x73B9527793454C0BULL,
		0x46587563B586A126ULL,
		0x22E9F598C3399658ULL,
		0x4FD61F356615E480ULL,
		0xF1AB773240880749ULL,
		0x64A0D8B5B9F006D6ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xBBBF65F441DA6A77ULL,
		0x4660E4C18A8055FEULL,
		0xCB9B716357FB2933ULL,
		0xE4474E8FD1F9ED39ULL,
		0xB2A37906F2927B01ULL,
		0x24287F8DC7669A0DULL,
		0x02AEF36F1191D0A4ULL,
		0x1229B83CD2EED9EFULL
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
		0xC1F8791A10274DF0ULL,
		0x7F14BB477C97A8F5ULL,
		0x7199DCE440D80BCFULL,
		0x8C6BCF59ABA416FDULL,
		0x57B39139FE6C5C79ULL,
		0xB9FEB6CD7684AFEAULL,
		0x049608C9CA16125FULL,
		0xA586AF065133E304ULL
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
		0xA3680983197E5A88ULL,
		0xAF96FB538DA38C34ULL,
		0xA2898369690B3CA1ULL,
		0x0516AFB7EF44A333ULL,
		0x46DD593B429C4AA4ULL,
		0x919E83124CB6929EULL,
		0xBC939F9E833DC308ULL,
		0xB4C424820CA1BC40ULL
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
		0x0021549728630180ULL,
		0xDE435C31B3224901ULL,
		0x79427B407B654097ULL,
		0x68DF24222FC176E4ULL,
		0x50AA7C21A3B4E8C1ULL,
		0xDBDB118998D87D8CULL,
		0x11697B243916FABAULL,
		0xAB28EA59A57AF8BCULL
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
		0xA0F66B5C2A592E1CULL,
		0xE7BC442DB4DF0333ULL,
		0x357E504A2B0F22F9ULL,
		0xE4EA48C80BEDB1F0ULL,
		0x8624D031EFAA40EBULL,
		0x84473C218FB6CE7FULL,
		0xBF993510D343D64CULL,
		0x3F1C830E9BA96363ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x488F26CE73014507ULL,
		0xF4041D0C99297648ULL,
		0x7BF041AEB8430F83ULL,
		0xC31CDE5543F1DFBFULL,
		0xF8BE1953C1909CD4ULL,
		0x02C69B581D676D20ULL,
		0x20B7C11C6BE8D195ULL,
		0xC05243B5684F250DULL
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
		0x386957478A712BF5ULL,
		0x10338E0E2FDE5858ULL,
		0x9A80A0B6AA9F53E0ULL,
		0x94A360CC53468ADBULL,
		0x83BF120B7BAEDB2EULL,
		0x6E196BD1F943744CULL,
		0xC354C6A87A0CBB05ULL,
		0x876649707AC3A248ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1B5109416BE85313ULL,
		0x3422374E05EDFB01ULL,
		0xD1DAE162F1295934ULL,
		0xBF5609EEAD6C68D2ULL,
		0x5E47B1F3FB48DB53ULL,
		0xC20BB9B64F27AC62ULL,
		0x971FB1FE1AE80D6BULL,
		0x17CE20EF666EC2EAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCFB6E8DA60927605ULL,
		0x3288AACB40AA13D2ULL,
		0xA24508AED2579166ULL,
		0x784E9A6C190FAB09ULL,
		0x73CF0E19EF5AB0E0ULL,
		0x07E5F1337F630565ULL,
		0x712BC12A59480932ULL,
		0x947E1EFE8E69F20CULL
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
		0x19A8360246D32057ULL,
		0xBD32C736E2600B00ULL,
		0xB0B0C91ACA6B98A2ULL,
		0x62B9ADCD89DE01C1ULL,
		0x37454987F51450A2ULL,
		0x596924497D4CE2AFULL,
		0x9D15D1D942C61C9CULL,
		0xFD4B27545B67982BULL
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
		0x1ED40BC7C9B50708ULL,
		0x73FA9A6A2C249D2DULL,
		0x346FFF6B0FF96FF8ULL,
		0xE0681B2DE14DB648ULL,
		0x8AEC550C20CBDCABULL,
		0xC60CBAB0A141495BULL,
		0x6BFE1B1E99FA819DULL,
		0x9C0467330015C7D9ULL
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
		0x2774153AB80C06A0ULL,
		0x16F6057E95DFCA14ULL,
		0x1D0B135AFD3D992EULL,
		0x885F58BD43FF7309ULL,
		0xCE6FA052B5144D94ULL,
		0x710A107F235ED294ULL,
		0xC8F838A5561DD8F2ULL,
		0x91844199FA01BA33ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x298889AF2C941CB1ULL,
		0x2A7C494D970DAC0BULL,
		0x449E6EAFD8F803CFULL,
		0x8BF826A786C2D43BULL,
		0x272D8CC8DE476A22ULL,
		0x1EEC11AA72AF105CULL,
		0xED4CE3EDA3669CF3ULL,
		0xA62270E2A8560888ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCC2450C7159F29C7ULL,
		0xEB69664571A3FA64ULL,
		0x3BF40D4BF33C341FULL,
		0x92EF75A029EE3ABCULL,
		0xC0B281843907CB00ULL,
		0x14AEB0729FC198E3ULL,
		0x5C437B9CBF937B57ULL,
		0x9B9E8B674278F07EULL
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
		0xC79A00FCD943A453ULL,
		0x117991762D6895E4ULL,
		0xA884F8CDDDE4DCF9ULL,
		0x13F8A546EFCC389DULL,
		0x3940D5854788EB59ULL,
		0x0C99CD2AFA7F35DEULL,
		0x85287A05AB1C966EULL,
		0xA866E7672C314399ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x71CAD1891A1E77BAULL,
		0x60842D3D8D7C0680ULL,
		0x4A6A08641E559498ULL,
		0x64033C256F20B832ULL,
		0xDC28BF0B07E9F1E4ULL,
		0x0B12647EE3546D76ULL,
		0x60BA881C4300F8DEULL,
		0x3AC53F01658FFC0CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7CAA198ABCCE3F7DULL,
		0x3ECD4B872D62E45FULL,
		0xC58C4DB81F41B764ULL,
		0xF8EA4607FD66B364ULL,
		0xFB3184BDBFEBCCEBULL,
		0x9082E4BD7EC4C04EULL,
		0x2AE36E3B59593C6FULL,
		0x6610233F2A973F38ULL
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
		0xF169F6642C1E7005ULL,
		0x89C1038A86C69BB2ULL,
		0xE72714AA18ADF4ECULL,
		0xDF4F57A374DE65FBULL,
		0xF83C8350F80C13F8ULL,
		0x8E3773893B0D77DAULL,
		0xAA0CA821DAED1E05ULL,
		0x9E4EDA74C8590A3AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2256E21B4041BFCCULL,
		0x1BE2A2351270EB78ULL,
		0xF44D0ED3FE57E835ULL,
		0x70D7AE3EF15057F3ULL,
		0x92B7C060983AE1A9ULL,
		0x692A6380BF3E3DD1ULL,
		0xB63256B608D4F764ULL,
		0xB6CF2B23B6744FBDULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDDAFFC673B7ECB8EULL,
		0xEF515BF3DC63DC82ULL,
		0x521EEC3A0EE57D60ULL,
		0x1134AAC86E24326FULL,
		0xB4B1DCAE8D84327CULL,
		0x4E9D931841529BFFULL,
		0x0346E99E5C55B88DULL,
		0x55345E65C267F323ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB3CCBB2CCDF6ACBAULL,
		0xDE23ADAB16E8ED95ULL,
		0x5667E37C48FC29A9ULL,
		0xC6271708DD8D70C3ULL,
		0x801179B16B9E736AULL,
		0x18D975CC78BCEA1EULL,
		0x614E9FFAD7BD7143ULL,
		0x885C2B043F07C199ULL
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
		0x5894B8C29007079BULL,
		0xBBDD89CBEE737F7AULL,
		0xB6F99A076F420C31ULL,
		0xB275D6171CFFE49CULL,
		0x2D8F9194428468C7ULL,
		0x06DF7F86D0FF4EC7ULL,
		0x7C330A6AF2BAD574ULL,
		0xCE73C1AF6033D97EULL
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
		0x7E9178897BE0E85DULL,
		0x9B1DB90723C72F4EULL,
		0x8CDF23590E91535FULL,
		0x99D75AE357804DBEULL,
		0xB698A07B52B1DB91ULL,
		0x0E699644FBB86124ULL,
		0x512EE9AE101133F2ULL,
		0xB199EC4F41C12361ULL
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
		0xE6577551C2DB810DULL,
		0x1BDB1D0240A57BFBULL,
		0x95E9C663255BD7CEULL,
		0xB3B47A25964A05D8ULL,
		0x3CF16742383C93F3ULL,
		0x111F65CA90D02BB1ULL,
		0x25910BB053D48A23ULL,
		0xCB42B54BBC00F580ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x342734B3E388375FULL,
		0x31FCD128A54E8111ULL,
		0x5CAFFD9ED5940474ULL,
		0x5FB7A47BBE2025CFULL,
		0x74E74942E61EE5BDULL,
		0xE107236A30DD0938ULL,
		0x691D6486A761422FULL,
		0xB094FF3B4D8041F9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3FEBE824FC8EE041ULL,
		0xD640CC421EC10D1DULL,
		0x85525898CAD3EE47ULL,
		0xC96DB2FA5A7AB8A9ULL,
		0xB928884E56A3988DULL,
		0x81BE6A4674526A8AULL,
		0xF9FB7315B3C355F6ULL,
		0x778CF24F2347706CULL
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
		0x50F24F4E3C8DD3EDULL,
		0x6C6AD0AE14EB819FULL,
		0x8D54D40C1130B2FBULL,
		0x4FBB018047E1A423ULL,
		0x0E44133F57FC6BD2ULL,
		0x07B9972D58511305ULL,
		0x4236F6B6E40B4DEFULL,
		0xED3BC01C45649263ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xD163A68DD7FF9FEEULL,
		0x5F8721D51CAFFB80ULL,
		0x02FC3C327E2CF44AULL,
		0x7F9DF2837DEED423ULL,
		0xE7315209D60FFF90ULL,
		0xBE090021EC6C8E3CULL,
		0x601CFAAE92944C7BULL,
		0x058EA1877ECAE9F0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x428CADEB3CAB6FBFULL,
		0xB1B8063F1DAFC32AULL,
		0x29A8312F363BC90EULL,
		0x7AEE4FCA2BFCFBBBULL,
		0x835782D28B8D7A5BULL,
		0x4B440A4EFAB44BC1ULL,
		0x10F12D55184EA084ULL,
		0x64A495F05E91BF46ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8BD10EEDFCE830AAULL,
		0x8568E5E37CCF4EEFULL,
		0x0EEFCF1C70347B8BULL,
		0x614E53B289D4378BULL,
		0x1AF6FD92112D8AD1ULL,
		0x8BE5705F057FC2ABULL,
		0xFC93C2DC763974CFULL,
		0x7F539C5D545FA9A3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDF7BED96258D6CA6ULL,
		0x78E5EF4D9F411017ULL,
		0x6BAB13C910067CDBULL,
		0x7D4C5EB4E9366FA7ULL,
		0xDFFDBE2361B45CD5ULL,
		0x3252B6060AD7F840ULL,
		0x1332E5E961EAEF6EULL,
		0x6B0F6C7BE221E201ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF7412B47173EB6F0ULL,
		0x8AC5F80FB898E0C8ULL,
		0x3E906AB62390016AULL,
		0x5B0A79B60394717AULL,
		0x7365CEEA7ABEFF3DULL,
		0xFB291A16D497C5D3ULL,
		0x43122F659C036A96ULL,
		0x4EA6015D63C42424ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB08448A73962E349ULL,
		0xA2024C435030B1C2ULL,
		0x290A122618D61C23ULL,
		0x36E3D4EF662CBDCFULL,
		0x8CF21116CE753FEAULL,
		0xEFC9F2930347AFCCULL,
		0x90E9CA3DC10E7939ULL,
		0x9910F4ABB977215BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB82A1AEEE5B15BAEULL,
		0xC5028704594082ECULL,
		0x041CCEBEDB129F4FULL,
		0x21D894E9935D61B1ULL,
		0xD7AD50E9BC819A2EULL,
		0x428344ABBADEC31AULL,
		0x9F418CE8843D6332ULL,
		0x4ABA72871A503880ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF8CCF014DF5D87F6ULL,
		0xCD59DA3260E2F827ULL,
		0xAE4CB891A33A4B03ULL,
		0x47CC643052F9262FULL,
		0xA8D24820CEC09388ULL,
		0x1838939E7281292BULL,
		0x61249BE4F91DCBE7ULL,
		0x6256B75059F59B5DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6DB86D6F36284E89ULL,
		0xA2C0073004349ABCULL,
		0x1671B8D3E12756B7ULL,
		0x817212BA13622E34ULL,
		0x77FE8047A162CB00ULL,
		0x3BA634ECAF8BC51AULL,
		0x31D9E7AEB9B8AAD5ULL,
		0x41343CF39EF5BE28ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0E6CAC72F2542105ULL,
		0x567773C6892A48B2ULL,
		0x4E95E4CEF7679EDCULL,
		0x1E96975B5B740C3BULL,
		0xF9D97A25A460097EULL,
		0x82CF85507656CF77ULL,
		0x5A60410D96E3776AULL,
		0x6642555BC4DB89A8ULL
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
		0x1789DCF6C5BCB3BDULL,
		0x3E0B80CBB7AEDC01ULL,
		0x06801388219B23D2ULL,
		0x4ADBDEF976336BA6ULL,
		0x9CAFCFD44303D98CULL,
		0xB065E3EAB1DA6B29ULL,
		0x6C6CC2F5E1E1EF4CULL,
		0xE4ED181F40974AA9ULL
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
		0x5FE931176EE1DDDFULL,
		0x87D37BEDA7DD224EULL,
		0x7376C37CF35A7329ULL,
		0x92C236237E7238B8ULL,
		0x3309994762A1440CULL,
		0x93955EE30E795321ULL,
		0x98C0CAA30A337212ULL,
		0xB0918FDA744A23B7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB99D12D14504AECDULL,
		0x97D875B2F680E052ULL,
		0x21C94AF5F8973979ULL,
		0x91239229188621BCULL,
		0x21C953E607756E0FULL,
		0x6AFC98B397089FE0ULL,
		0x3D9A5B52E3694375ULL,
		0xA8F17ECF11FDBD8DULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD207369D701C2CDEULL,
		0x70C79143EFC973D6ULL,
		0x73A9560C90E16AC2ULL,
		0xDF66C81F9722FDD4ULL,
		0x04440866FC081F71ULL,
		0xDA94B92C6905BDBFULL,
		0x0370AE6933BC61B7ULL,
		0x324343D66014217CULL
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
		0x5F8DC33EA696AB72ULL,
		0xB7920C4483A24B28ULL,
		0x1DC05A63C8F2F085ULL,
		0x8F20C5C84DDA4EBBULL,
		0xEA79FDDFC82E5E89ULL,
		0xF4C857026E780D49ULL,
		0xB489CAF898336C5DULL,
		0xDA846AFA840546BBULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC2EBA45C6571547AULL,
		0xCA4AECA0111D5933ULL,
		0xE758061DAA263400ULL,
		0x35D8A0E0E5D77C27ULL,
		0xA9694F0ADB37194DULL,
		0x15D33A7320DEB739ULL,
		0x52C171ADABB46AD5ULL,
		0x421204D69A8C5AB5ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDE75097DEF0A4B5BULL,
		0x5C3E554B3318CE7EULL,
		0xC141D8C98D7E91C5ULL,
		0x7E6B25DC47F9913EULL,
		0x64C11E87596E1B69ULL,
		0xA709731655EB9C03ULL,
		0x2B9B2B965C455CC5ULL,
		0x9A5D67BC31FEDDB4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x489B06134E7D6D51ULL,
		0x29DF6EF277D77A73ULL,
		0x2D447EBE8FDD8296ULL,
		0xE9D838F41125A6F4ULL,
		0xDC9C3EF8F1797BC3ULL,
		0x82BCAD2951AD4038ULL,
		0xC53F11B57F081EC6ULL,
		0x205FD6BE545C0B5CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBDA840BD1B96EB67ULL,
		0xB6B253F0586B706AULL,
		0x42D991DD7C6C4F07ULL,
		0x31DE365BD4AAE12FULL,
		0x7DA2CEF9526904B3ULL,
		0x067E0607C0DC07E1ULL,
		0xD1FFF3BC90EAB077ULL,
		0x55C52453E3282002ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2044D579E995C74EULL,
		0x32A30E86E9EBF164ULL,
		0x8E293289C44BAF57ULL,
		0xE1FDC5A0657D4241ULL,
		0x06EAE7A22B5E0C4BULL,
		0x6E2F46540ED68631ULL,
		0xE241533CF9563F6AULL,
		0xAAC57C9B263C4229ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9C0980B105DDEF2BULL,
		0x97C11C427FF3732EULL,
		0x88BAE5FEB555A46EULL,
		0x5F50B64423D8C14DULL,
		0x6E43DEE83703738CULL,
		0x2F27E977B46A7960ULL,
		0x8FAF430D6A151C7EULL,
		0x7923490DAE163A3EULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xC654724D90958F29ULL,
		0xE0CE510E3A42D34DULL,
		0x4FF88FBADCE9C606ULL,
		0x015CD9E024EA9766ULL,
		0xE3CFDCD5C02CC1EBULL,
		0x42AF4A8C352CC541ULL,
		0x297B116514CA6C21ULL,
		0x0241C38B735604C6ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x4AC6DD8372088596ULL,
		0xFE87CB215B3EDF40ULL,
		0x5F7BBAEB0CA44559ULL,
		0x184953A928A159F3ULL,
		0x2A8AF00B54E50B24ULL,
		0x77C020D0400A0BBDULL,
		0x3F1BA2999136340CULL,
		0x07434CB360F00EA0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0A6FC136EA08C6E9ULL,
		0xB36D0F72FD38D618ULL,
		0x1F38A14D4765303CULL,
		0xEED1BC99372D2B0CULL,
		0xB8A6BC67FFB5846BULL,
		0x3541B6CCE0848381ULL,
		0x1F121BBFDDC372AEULL,
		0x4F0BFA93D0B60A7BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x744F1169F1AD7B58ULL,
		0xF37B2DFD8A183B24ULL,
		0xF18022C6586490C9ULL,
		0xFC46F6BC22E3B19DULL,
		0xEB1C021FCCF9561EULL,
		0x70CF52A316B9E6A9ULL,
		0x15C3836881D95C1FULL,
		0xB39C4583613176C3ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE1FF90F5548059E0ULL,
		0xCF49C5DD47269B62ULL,
		0x0C54D446636E526DULL,
		0x28EE026DAC60BD4CULL,
		0xF67B74BA54282F36ULL,
		0xFF94C5D840B6F91BULL,
		0xFF45271E3F1CD84DULL,
		0xB462B44720C844F4ULL
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
		0xD83EBF3CD0C184AEULL,
		0xA963555DF592C947ULL,
		0x47B841629F499E5BULL,
		0xED9298EC353061D4ULL,
		0xE5B43E5980765A30ULL,
		0xB76EC1543FC38ADEULL,
		0xBCB0E14D9B1E2134ULL,
		0xE874C125D7308CFFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCDB118F83BA960E3ULL,
		0x4D078B5EF0BE3752ULL,
		0xD79A85F6C552D6FEULL,
		0x66FF7F8356C0B659ULL,
		0x2967651D1E8F2905ULL,
		0x7D689BEFAD9C1E35ULL,
		0x15B4FCADB4F560D3ULL,
		0x8B8D83552CC27061ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x21D9F205930A746EULL,
		0xE3234F4514A7303CULL,
		0xD631E05B44AA3A13ULL,
		0xFFAB689B7DF7FACAULL,
		0xCDEF5C89A36E94B0ULL,
		0x040B019580FCA331ULL,
		0x0796C8BC9D6F87D2ULL,
		0x8C79C107E739972AULL
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
		0x230BC7F04E421CD5ULL,
		0xE87E9F9AFB188EE0ULL,
		0xC44EB44853AA6E7DULL,
		0xDBD1B7095CE6B07AULL,
		0x035F9D49BC313BA8ULL,
		0x43A153FEE1523CC0ULL,
		0xDEF11DA493A0FD20ULL,
		0x571C22586C2F033FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9E20802564B6FDBEULL,
		0x61A9EB23B4F5AF00ULL,
		0xF0C3829B8163F758ULL,
		0x61BA80E7BAA59528ULL,
		0xDEABBBE58883299FULL,
		0xFC283CD0AE1C5DA4ULL,
		0x7B567BF5BB998D05ULL,
		0xE85E672B7DDAE2EAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1B96932A886872A5ULL,
		0x1831D3EEE3BCE017ULL,
		0x72B61658129CB4C5ULL,
		0x979D3C0187D9C638ULL,
		0x93468B79E7CB0115ULL,
		0xCADA13AEDCDBF82BULL,
		0x4052C91A864BF863ULL,
		0xF73822E961A32D33ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA9DCBCA2CC03D89CULL,
		0x6B005A400EB438D5ULL,
		0x6D1A63AF3D9557C9ULL,
		0x1887F6F24C09FE5EULL,
		0xCF4764C51B71B364ULL,
		0x43015EF648DEED66ULL,
		0xBE763E2E931A2B8AULL,
		0xD88A826BC89980BEULL
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
		0x8AF0A18715695963ULL,
		0xCC0348D24C9969D3ULL,
		0xA4DB8E70E8A3A595ULL,
		0x4FC57D4E4E441933ULL,
		0x223307A77ABE0A5EULL,
		0x76C51B40D4838EEEULL,
		0x86331831D03A0125ULL,
		0xA2208EEC07FA89F8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE5A579999C974316ULL,
		0xC9E9689B9B51CF1EULL,
		0xB2F3AC887C38F443ULL,
		0x282A09EFB95A5966ULL,
		0x326E9A45916E256CULL,
		0xB3E96184F7392331ULL,
		0xAC9682975ED82035ULL,
		0x982361A7DC5CC8B4ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEC2AEBD85EB83563ULL,
		0x6A21AF8163E66A0FULL,
		0xDC383F3FA58CFF77ULL,
		0xBDE0EDBA09ABA57AULL,
		0x09A9DAB4D1D7018EULL,
		0x9B0E7881276221E9ULL,
		0x282E8F4191ADA16EULL,
		0x6DBEEDAB3A5D86F4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF7136176CC96D843ULL,
		0x8F4913478A472FA8ULL,
		0x4975EF31D499D747ULL,
		0x10C2F5949616B807ULL,
		0x429EA03B2BCC313BULL,
		0x722AEAACC91082AAULL,
		0x23F63E4E60A998EAULL,
		0x2F14F9FCDBF727D2ULL
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
		0x69B380E611232F78ULL,
		0x50B71AFF23BA98ADULL,
		0x35654B9D80F27B3EULL,
		0x4B879CD66C4C25E3ULL,
		0xB0E154B04D8DE7E2ULL,
		0x098744E43F848598ULL,
		0x2E98011852068DF3ULL,
		0xCECEA98AA7848CABULL
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
		0xE4DD193A98BD4B6DULL,
		0xA7783876F02E08C9ULL,
		0x723B5E4892C92724ULL,
		0x4206554E1F6F864FULL,
		0xBCDF70DAB2D313C5ULL,
		0x7D4DD945E7DA2BFAULL,
		0xFEF804EDA87C9853ULL,
		0x4C0F4B6B4F33213CULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xDE2B7AD9CF68BCA1ULL,
		0x771BA1EFD7DACA88ULL,
		0x90679F1E29AABDE6ULL,
		0x5C879C5EBA2BA27EULL,
		0xE1279D4EA468CFA2ULL,
		0x1A053D52B01F2E09ULL,
		0x45B446B3CE6503A9ULL,
		0x29F468FD12554293ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8F20682745B6D24FULL,
		0xB3C38B67EDA0835FULL,
		0x7BCA163A69F9FFAFULL,
		0x1FA93E3FBD98049BULL,
		0xBC732032DBE296B7ULL,
		0xFF03C62FC9579852ULL,
		0x87D1482B254137D9ULL,
		0xFACB8FC0A4A542C3ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD3F2502119D9AF12ULL,
		0xD44DDC10C74B71BFULL,
		0x9A215A8A9A1DE280ULL,
		0x5C9213438112C5EBULL,
		0x6BFA25EDC99D4369ULL,
		0x9699CFE0766CFB74ULL,
		0xF5BB2E2F31A0E1D0ULL,
		0xC1029E0C99DEF60FULL
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
		0x7F9C7BDC32BB084AULL,
		0x1EEF5FFAEA5DEBD2ULL,
		0xB24B9EBB31DE1A55ULL,
		0x0ACBF29EDA6BED6DULL,
		0xAE032E0D2A47BBE1ULL,
		0xC7B1664411CBFF83ULL,
		0xCD69881980408379ULL,
		0xC49A70B947BF536DULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB736DDDE06CC9328ULL,
		0x6FF971FC64C3EEBFULL,
		0xD2AFF982061FB8BCULL,
		0xBDA694FE0CF3194AULL,
		0x8BFF950E7A985E24ULL,
		0x51D7C39AC9EFC1A1ULL,
		0x14970A9B65E3063FULL,
		0x1E2019C101D8A253ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8FF1CDE6314DE0C1ULL,
		0x7C12F31C82ED3585ULL,
		0x44CAD02D3BB1693AULL,
		0xC49988942DA8B401ULL,
		0x7E2EC38DD5E54F0EULL,
		0xA9458C9A05EBD04AULL,
		0x4264A0B9272B860FULL,
		0x37BEFAA47DF16C11ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x12679E5B0B6591C2ULL,
		0x23BC991C4C7E0401ULL,
		0xBDDCD9F500196B1CULL,
		0x63BD338A0A9A9CCBULL,
		0xE72DE1936238E07AULL,
		0xCD4752A1DF83718AULL,
		0x48FCC72860C82E06ULL,
		0x36DD24160890EE21ULL
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
		0x1E376719C6C07324ULL,
		0x7A2F95B134AFBFBEULL,
		0x137377E5B50567DCULL,
		0x394EDFAA8301DF28ULL,
		0x0A2935D3C971ABF6ULL,
		0x3268FEBB1C100C56ULL,
		0xD60E444209D45DF7ULL,
		0x84D9BA7256A95D3EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x061A67CFAA3DF535ULL,
		0xE015EEC35A4F0053ULL,
		0x3D048C8B8D24DA5CULL,
		0xE1315714CC4B6833ULL,
		0x9B07E71FC42561DAULL,
		0xF12666259C8575DCULL,
		0xFBFE0CBBB04E779DULL,
		0x33B986440F283EE4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC1C9B108E40F0F0AULL,
		0x1A95D2544FDF327EULL,
		0x40071871481004C8ULL,
		0x06D63602E2E8C2EDULL,
		0xDBB9102F42530649ULL,
		0x86F3BD62361A511BULL,
		0x611C2A3E51FC3962ULL,
		0xDBC5A1D21C327CD7ULL
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
		0x5FD43D6A6AF2CFCDULL,
		0x71CAC6652D94FB2EULL,
		0xC527F02A2A6ADB5CULL,
		0xC6218773BB389969ULL,
		0xBC8BDE5D6B272E0EULL,
		0x3985484919847F9AULL,
		0x0082A4573E4B1772ULL,
		0x28BC55D9AEEE7922ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCE95725A786CC42EULL,
		0x8BCCB3AAD44E9FD2ULL,
		0x35608FBA3A3A75ACULL,
		0x64E27C0B385BE643ULL,
		0x7EC0F2E4A4F85FD0ULL,
		0x59AF6525B9CCB61DULL,
		0x3C9EA9DB95A0E77DULL,
		0x7D38A14825A08678ULL
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
		0xCBF931A8274F8CBBULL,
		0x87EDDC65927E3ACDULL,
		0x915CE29A11B9EB2EULL,
		0x4FB15ECEA2091069ULL,
		0x123DBAA76C394049ULL,
		0x064A0104D6472EE9ULL,
		0xE9BBC5277AB9413CULL,
		0x78248B573D1C2A32ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x917B2C06C116BEF5ULL,
		0xB6340E7B8A4B2292ULL,
		0x959FADE2D46289E6ULL,
		0x1406FF27409FDAA5ULL,
		0xE52FC3E972D9F242ULL,
		0x608C90B7A0D9BF34ULL,
		0xB4C65FC1706819EDULL,
		0x20F2EEDB0DBF335AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2B407DC01F23C3B5ULL,
		0xC012072A93E1D109ULL,
		0x098482B9CF1AE195ULL,
		0x435FB19A28B3C505ULL,
		0xBDED686DCB731A3BULL,
		0x73F76B2D69FDA818ULL,
		0xE0E63023E0B0CF0FULL,
		0xDB8EE9C06E013ABEULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9C5347E16E18BFABULL,
		0x7D90060BC9273350ULL,
		0x0E0098D7DCE633F3ULL,
		0xB8D03C257EE75E2CULL,
		0x541C20FD31F53754ULL,
		0x1E248BDA500C06DCULL,
		0xA0D96CF37E1EC767ULL,
		0x597814DB52C6F3F7ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x80B2D3D352460F77ULL,
		0xD1B2E0C5CB4DB383ULL,
		0x6AAFAAA6AD44BF80ULL,
		0x806CAE053AB36B0CULL,
		0xEBC6B2EB36BB6AFEULL,
		0xA30F5C6E44318D01ULL,
		0x6CDC10B458BBE585ULL,
		0x3D6AB94C7FF73DEEULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9BDC24CCABF44BAFULL,
		0xC4659D0DB4CBE535ULL,
		0x3EC202EBE7D8EBB3ULL,
		0xC6C014552C7B729EULL,
		0xD76EA58C9FFD11B0ULL,
		0x37C2FD02B9C6F91EULL,
		0x58280757A4F75504ULL,
		0x6149AD7AC00C80BFULL
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
		0xD7890D110C550F34ULL,
		0x40707AC075C3A388ULL,
		0x60A071AC2B2A42ACULL,
		0xFC3326632C957531ULL,
		0x0BE876E708E2E399ULL,
		0xEF5400315A25CAD2ULL,
		0x2441C6AE6647C808ULL,
		0xA84BA300F8EAEC8DULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x55DA175CED8F0269ULL,
		0x3044CBA8C0B0A6F2ULL,
		0x5304E9F0D22AE798ULL,
		0x2EAB4A323FB348DBULL,
		0x0B529E7D30946F7FULL,
		0x9993314C62E68F6DULL,
		0x329691C6CFB2E675ULL,
		0x20F265D702E8D0ADULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2F712F11B62402B0ULL,
		0xDA2ED8846DB7C936ULL,
		0xABC415F280297869ULL,
		0xF7942D90E6089CB9ULL,
		0xE3EC4562DDD6AA02ULL,
		0x4F5E749E427C326CULL,
		0xBA642CEEDF8CB301ULL,
		0x3B367936F1C85229ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2D26DCE2D1F2B487ULL,
		0xBB1E0C84D3AA91DCULL,
		0xB875C6A6E4E0068EULL,
		0x48848D058ADE8896ULL,
		0x34724338D1FA699DULL,
		0x904538BB8AD2779EULL,
		0xCBFAC42C50DD177AULL,
		0xE968B91BD02C4367ULL
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
		0x227AB04413935E3CULL,
		0x717BFCDCCE85A7ECULL,
		0x276BE237EC8733FBULL,
		0x48D69427E3DADD64ULL,
		0x2236C6FA9C440486ULL,
		0xF9B98394A7DB103EULL,
		0xADC857C1A07D4AAEULL,
		0xD32029B3E7DA68A2ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7A54D7D9B0C763AAULL,
		0x5A0B3C707CB89959ULL,
		0x872082E29015F6FEULL,
		0x0999A8E9DACC4894ULL,
		0xEEB0F42B12BD5478ULL,
		0x935FE5650AFE588FULL,
		0x60199B791EEE1387ULL,
		0x24F13E31D4D02902ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAA44351B04FDA9FBULL,
		0xC9DC906ED0A0435AULL,
		0x3BC19E20366F01D7ULL,
		0x5A91E8BB387AF99FULL,
		0x3092FE896397F1EAULL,
		0x1356632F1077E4E7ULL,
		0x9FF03DC95F51F4EEULL,
		0xD92138C8EECFC560ULL
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
		0x6020D24D053084B7ULL,
		0x65A31ECF8671A4ADULL,
		0x64CC389165D347E2ULL,
		0x62B6A6D8C374B02FULL,
		0xDA68329DEBCE5583ULL,
		0x65A1B18A4407246CULL,
		0x485448D10A017273ULL,
		0x349D32FDC5FEAE17ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF91E36CFF27FB23AULL,
		0xC4E928D6389DBBAAULL,
		0x06C00DAE539BCBBFULL,
		0xE29E16F8B223359BULL,
		0x349E6B928683A9F7ULL,
		0xDE5233EA4FDD2952ULL,
		0x52A13F899347C589ULL,
		0x396FC68D1D4E3659ULL
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
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0x6EDC463C745C1294ULL,
		0xDC77A2F81F507B45ULL,
		0xB8B4F2D0B4127954ULL,
		0x87DE23DA714954F3ULL,
		0xB115A8EE65BF7748ULL,
		0xED5FDF9DD22054FDULL,
		0xADA920C98DFFD53DULL,
		0x00DBD1DEE480D9A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
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
		0x50E60E8F1BDB60B6ULL,
		0x93E8995B3ED213D5ULL,
		0xEA58A535EC05F33AULL,
		0xF7C05C1FF9DC0BE8ULL,
		0x243B1369E70AA72AULL,
		0xB5D300DE51BF30A9ULL,
		0x8B727EC98580769AULL,
		0x409544AD7CE7BDA5ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x59EC66D6BC0A5948ULL,
		0x76AD5444FAAF2743ULL,
		0xD6AC17D386807738ULL,
		0x6C5069C5C3EA6162ULL,
		0xCCFB55E1D6E7D0E8ULL,
		0x92270344EB55CCCFULL,
		0x9C0B618EA5628DAEULL,
		0x0799AF8FCFC7E1ADULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD8813D3850C04A63ULL,
		0x8ED0469BE21B66AEULL,
		0xD68AFC3BB011086EULL,
		0x277D8058CB727F38ULL,
		0xCC6290204B01552AULL,
		0xDF3FD9AE799B305CULL,
		0x3ACC5C398762061BULL,
		0x73651FA472B70B9EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x872753A65FDE0753ULL,
		0x61DA399527ADF8C5ULL,
		0x046E4B7BC4BFFE67ULL,
		0x17DE5201F5D06413ULL,
		0x182E280C2264EF5FULL,
		0xE546BFA660BEBC0FULL,
		0x1254E8DE91BC993FULL,
		0xEC71D7EBEF05AD60ULL
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
		0x9AC702F8FD5CA569ULL,
		0x97BCAC986A7E7ABEULL,
		0xDD6FFF44DD21FEC6ULL,
		0x498EECD98DEFA50EULL,
		0xD4C39585D8016447ULL,
		0xD1735612F6735B21ULL,
		0xDFEAC3A489A8C727ULL,
		0x5662931478369AC4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE1069F85944DC7F0ULL,
		0xD5C65BAC2BAC4A90ULL,
		0xDF77599B0BC957B2ULL,
		0x76D9D89C8ED15E92ULL,
		0x2729E29AE4CF2B57ULL,
		0xC9C6F637E2723375ULL,
		0xF6F0EFEB08739A62ULL,
		0x22A296A14EAA4EB0ULL
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
		0x419D915CF3F7E8AFULL,
		0x3A13255B1F3CDF14ULL,
		0xA311584E1C3A3B90ULL,
		0xFB430BE8F6928B19ULL,
		0xBF64CD14BC2E6EE7ULL,
		0x204D1B2C443FFA45ULL,
		0xD20821600D71469CULL,
		0xA7F1AD38A0B6A573ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x57D67F55F822B5DFULL,
		0x9409CBF39F813F96ULL,
		0xFBDB0C480024FFFAULL,
		0x107828DCB9A65DCBULL,
		0x3E6E48AB72EE2DEFULL,
		0x448A3A4A23467D1DULL,
		0xF51941D40E8D5FA2ULL,
		0xBEFAD5899D8CA4E2ULL
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
		0xDA067E78379579EEULL,
		0x9768633B1E7ECC9DULL,
		0x3354B6D923FB1792ULL,
		0xA6CC99C44593E034ULL,
		0xA8947B09622E5B61ULL,
		0x4897149B2F3AFF4FULL,
		0x3EF1D72302B60C0AULL,
		0xBBF5409DCA800F4FULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0060FCE44BC38386ULL,
		0x536C3641A58587F3ULL,
		0x343F7D497DCF445DULL,
		0x3BC3260B7B3FDEE6ULL,
		0x483815553BEDE4DCULL,
		0xABCFBF54C8E33AB5ULL,
		0x39545640AB83CDB8ULL,
		0x5A7531C95B116363ULL
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
		0x47A0F2768C661120ULL,
		0x6DEC57F4907D73C6ULL,
		0x3E82DD18A72F73EBULL,
		0x260F337EC02EE135ULL,
		0x248123EEDE1551E3ULL,
		0x1D1F73279FDDEA2AULL,
		0x9FC5B73A062F4F06ULL,
		0xBC0C220D14540392ULL
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
		0xA1DDF49B0923CA14ULL,
		0x12E36ECC6C16E3D1ULL,
		0x80FB5E75E8779952ULL,
		0xE8EB3BF02617B65DULL,
		0xD9BA361B47395666ULL,
		0xED6715782545AB44ULL,
		0x32EB4E1D2A4885B3ULL,
		0x9B227F2A2C7BB2BCULL
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
		0x7859F0A5DB28C570ULL,
		0xC808CF46FD2E43D3ULL,
		0x6EE933C030DEE592ULL,
		0xAB9B9458428D15ACULL,
		0x74EC25A2EA32F885ULL,
		0x1E0910D1C35B6EF7ULL,
		0x3EEDF86B010187DAULL,
		0x2A80664A294C5F5DULL
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
		0xF76295A4D27AEDD8ULL,
		0x50AC0D22C3BCB931ULL,
		0xB0006B86820916C1ULL,
		0x6885B77682785BC1ULL,
		0x64B9EE71CC0841FFULL,
		0xD56941A1217E3B98ULL,
		0xECECFA3BDDCF9F71ULL,
		0x768485D8F3E24B5DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF88F474732BCCC98ULL,
		0xEE6B8B02FDB1A7ADULL,
		0xEA3896D45273FF7EULL,
		0x341594CFE7A3A016ULL,
		0x04A7950E8CF87F1BULL,
		0xD01283184FAF6499ULL,
		0xCF17438B8D624117ULL,
		0xBA35E1B3B263643DULL
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
		0x0FC0CE223792D871ULL,
		0x96F3E3ABB83BCF07ULL,
		0xE719B0958111DE3DULL,
		0x8333A3DCAA2EAE26ULL,
		0x55D1C981CC404399ULL,
		0xA152E62F06FD1410ULL,
		0x738892AA774F9153ULL,
		0xDF1594B3D7252D60ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC06BF010D18D8162ULL,
		0x15EA480B9DB92E42ULL,
		0x52B56DF0DB013897ULL,
		0xA6335854D1C2E106ULL,
		0xD7AC09DE43F163AFULL,
		0xD988326349088D29ULL,
		0xA26AC656CAE714D8ULL,
		0x32A486278E9713E8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x58DA9A43C7BA4BCCULL,
		0x9D1313A49FFF30BBULL,
		0x6C539C4C0489288CULL,
		0xF4A4B31B7017D114ULL,
		0x45C1F3A252597393ULL,
		0xF09A18B380D9BB38ULL,
		0x3DDDFC151B3D2783ULL,
		0xE0F9812452024EE7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEAD7701E6875B655ULL,
		0x9A7EC9E64C1FA3A4ULL,
		0x0FF4E428B8FADFABULL,
		0x6754A147C9185AC4ULL,
		0x523E169A01F8F2C4ULL,
		0xD416FD4A9E92884EULL,
		0x9C00C0F7DE7CFF8AULL,
		0xFDF8596E2A3CF463ULL
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
		0x98A91983F5F01F0FULL,
		0x2EF8F09797B6ACCBULL,
		0x149C55C57D4B5CBAULL,
		0x60AFF1C2E9D7624DULL,
		0x0AAECBB3C2AE1ECBULL,
		0x7794968FA9460E04ULL,
		0xF132B5FB71C02A4BULL,
		0xC873C46F00402983ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBD7A778953EF8FD8ULL,
		0x765126E920FC600EULL,
		0xD7B87097538FD8A9ULL,
		0xCE294473A802828DULL,
		0x11BF4C95DCE5C493ULL,
		0x5358F3BD4E7A0800ULL,
		0x144F523D75610FA0ULL,
		0x92A4779178DFAE59ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1A831652B68D28CEULL,
		0x55D687C1266C10DDULL,
		0x3C54057074323A94ULL,
		0x22567CC5E45D105BULL,
		0x6885DCF76EE47931ULL,
		0x98E676549AAAA17CULL,
		0xDC1ABA8F4445EC93ULL,
		0x480BDB1038BB773DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7521DBE9BA2EAF26ULL,
		0xEBC5EEA24520D793ULL,
		0xB963F179CEE602B1ULL,
		0x66EE0420C9D52ACDULL,
		0x86168562EF0BA264ULL,
		0x4044C2F8BAC276E0ULL,
		0x24532B54DAD9DCADULL,
		0x5326579385FFAC0BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x19792018DDDFEE8AULL,
		0x4ABAF131F9D31E12ULL,
		0x9C7CD871A8407183ULL,
		0xB698AAEBFD71269EULL,
		0x2F9A1A73C894403EULL,
		0x65D7381BB8132334ULL,
		0x4BEFA0C508478AAEULL,
		0xDB96BAE5BBB0A464ULL
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
		0xF62B1D64E96FF262ULL,
		0x9E1FA308CA85ACC7ULL,
		0x32F09EA4A17BDB8BULL,
		0xF7DB78E5C583DC35ULL,
		0x9EB5A8DB82DF27DEULL,
		0x76D3F1A0C65E6A20ULL,
		0x6E00B64EE94E15E5ULL,
		0xEE847F1B6120D3D2ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9127513F5CEE2D31ULL,
		0xCADD724B75C44268ULL,
		0x4EED64BB45946CACULL,
		0x0E2D2D7785FDEAEDULL,
		0x81987F4D41CF5D7AULL,
		0x359E8CD720BCC60DULL,
		0x7F0860C87A0F1E7BULL,
		0x6AE23B86764234E0ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x14EB8D1DD2E00E6CULL,
		0xFDABFE3509B92EFBULL,
		0xCB777E86562EC353ULL,
		0xAFA1E2D0807CF013ULL,
		0xF0EE259B4A0489CFULL,
		0xDFB7A194AEFFE7E8ULL,
		0x7556B41E80267EFBULL,
		0x3A4628310E03C198ULL
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
		0x0F51173B5D61C4B7ULL,
		0xF7436FF747C91F0CULL,
		0x8AD2A4F3F013B877ULL,
		0x29C8DB9945F54AFBULL,
		0xA65BBD8FD605328AULL,
		0x4F8DD00B33B312ADULL,
		0x0151865A30B5BE73ULL,
		0x95FE3C1DAFA6D4D0ULL
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
		0x10FB6311735EF00AULL,
		0x4D798B0B0A9149D7ULL,
		0xA8B9BB66A7A7F7A9ULL,
		0x89DC637295B50B0EULL,
		0x53A99F631E72D62DULL,
		0x2B9211D47D30C27FULL,
		0x492BC52F3D3133CCULL,
		0xA7C530A7E109C883ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x748363B08F2A0674ULL,
		0x454B2C3DF6B527B4ULL,
		0x48F99C74D6BBADBEULL,
		0xC16723F98031136CULL,
		0xDA5268D42DE89D67ULL,
		0x716015142A3D3824ULL,
		0x94C2814DC929B1A9ULL,
		0x12DD817B40995E54ULL
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
		0x50BFA720363A5F1AULL,
		0x8A6CBA93CDB46ACEULL,
		0x4832003297C7F723ULL,
		0xF51F563DD9846A95ULL,
		0xCD2CD8D797961AACULL,
		0x85BC7CB08F7A9192ULL,
		0x0A19D026221502C1ULL,
		0xB8E37385BF0B45F6ULL
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
	la = 503;
	k1 = (curve25519_key_t){.key64 = {
		0xDA370E648E649B3AULL,
		0x98ECC8E80458DD5FULL,
		0x3D10F3148DFD0502ULL,
		0x2E0AC41E175BD105ULL,
		0x2CDA1ED7669BE472ULL,
		0xDA50FE293183C1B6ULL,
		0x86E46C1341AECE42ULL,
		0x0097A89D0BFD4157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0080000000000000ULL
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
		0x113241304F9EC390ULL,
		0x8FE528A300394DBCULL,
		0xAF55336FEFBB89D8ULL,
		0xABFDAD5B20803482ULL,
		0xD33EEB11D25EFD50ULL,
		0xD78F37BF5493DE2AULL,
		0x8495EC79A10765BDULL,
		0xDB1B67BF9A92DF0BULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x79D8CEB5757C470CULL,
		0x5845848F5F8DA132ULL,
		0x5E9788CA3F879CFEULL,
		0x229BCA0CA3E84113ULL,
		0x201F699259601C41ULL,
		0x333B4AFFAC25609DULL,
		0xCEA9BF1CC53CCACEULL,
		0x1A55D3A37052E503ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x8AF6A09CE1238459ULL,
		0x55B17BF2B680722AULL,
		0x3D46A4FA518255A2ULL,
		0x11A4758812493E21ULL,
		0xEDE3B2EDBB2C98F8ULL,
		0x39802F9DB042D7B0ULL,
		0x375D15D234592CDAULL,
		0x0F9B21353E311221ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE6D3EEE3DC88DA00ULL,
		0xB639BFC5AA7E0CEBULL,
		0xFC5EC8988B7FCE45ULL,
		0xF81A8CD9A4F96145ULL,
		0x7CA2FA992D8C7110ULL,
		0x12A70E759B191DEBULL,
		0x7F1373BBCAF50178ULL,
		0xFF91DC5B6544EE7CULL
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
		0x4FB7C4263121D5A3ULL,
		0xE7B7E7C28833210DULL,
		0xE9CE80512E37B57DULL,
		0x19975CD5D8298023ULL,
		0xF5D013730606FD63ULL,
		0x287F3700476CE0B1ULL,
		0xA79F660382804D6CULL,
		0xA36D0CD2A97413D9ULL
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
		0xA5B03F9ECB6E34DFULL,
		0x4ABC50BE65FE7A9AULL,
		0xC114F86A8C5606DCULL,
		0x60F6B2453E22CEF8ULL,
		0xD0BCB9FF0D86C215ULL,
		0x191405BB7EEB5201ULL,
		0xF0EBBC46E9D0D631ULL,
		0x9403EABEDF301200ULL
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
		0xA92E9ACB09FBDE45ULL,
		0xEBF2CCEDA2B3E257ULL,
		0xA7131BB21BF18065ULL,
		0x0F6F6EDD0D69AF83ULL,
		0x420125E6BC3A7783ULL,
		0x3F47365093BCA319ULL,
		0x82C0FF8D479C86C9ULL,
		0xD8AC6FF4893E5EAFULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x5D4C3FF0BA1B76DAULL,
		0x3F8AFD358C727136ULL,
		0x99D8F329834952B5ULL,
		0xAC8B219F78D3E2B6ULL,
		0x804C9D2B1323C73BULL,
		0x16F4CA8084A924CAULL,
		0x54522F783F398EE6ULL,
		0x35D226292D6BD5E7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x30AFD1AF77588683ULL,
		0x2E13EB55865828D6ULL,
		0x1FE067A1B9B1AB77ULL,
		0xDEF1678C65282074ULL,
		0x4735EB0582601F25ULL,
		0x9860D2ADD2133F1AULL,
		0xFB36DBFDC7D57F5AULL,
		0x9F97B7B79C495E1FULL
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
		0x5303A48585879CEFULL,
		0x822179D29267596EULL,
		0xA344AC94FA15DFAFULL,
		0x04648B5682B6F789ULL,
		0x8D693608AFD86564ULL,
		0xCFC3A293D6F52B26ULL,
		0x53AB38BB2F559609ULL,
		0x9CE3B4344E222C9EULL
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
		0xC6017FAE6C94C895ULL,
		0xD424BB39BB64AAC3ULL,
		0x67A5D2A09E5E7D88ULL,
		0x07DCDDD43F7BC1F0ULL,
		0xE8424E632A7DAD14ULL,
		0x0E1D0DD7882DE8FCULL,
		0x1FB219CFA57E317AULL,
		0xD2F048A34CFDE3B4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x99BECEFE90D85137ULL,
		0x05F1A185C26C10B6ULL,
		0x6BFFFE9CE14C5245ULL,
		0x9A65F323684A74A0ULL,
		0x1C2A5F3DD082B239ULL,
		0xE08A7890129862E8ULL,
		0x0AAE62244CC5F797ULL,
		0x28C0B52B1BC06DFAULL
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
		0x759C9AA1AB4F7905ULL,
		0xE1514529EB819D02ULL,
		0x238FA6533FDF1A5BULL,
		0x44B686846AE7FDEDULL,
		0x861F20C7140F63DCULL,
		0xC940DCA6E292F534ULL,
		0xA46E2413BE3198FBULL,
		0x2C8D2A875257260EULL
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
		0xC15CF787B2348739ULL,
		0x1A8685CDED9A73BDULL,
		0x64949372FA484BF7ULL,
		0x45D4BBB7A456C413ULL,
		0x3C21ABB788246B36ULL,
		0xDC0B18368A79095DULL,
		0x34A8069AC1318295ULL,
		0xB8EF357045B12AB3ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xF1E53B23493A97FDULL,
		0x574533D637129B0DULL,
		0x4F95DA4FA52AD8E9ULL,
		0x9BD60C20FA34C67FULL,
		0x078276A4E9619833ULL,
		0x811267C397AD3AB2ULL,
		0x2955C0DB62DC5DA0ULL,
		0x1E1205F4FF82B82EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB75FF1795AB73684ULL,
		0x5A029A653600B280ULL,
		0xCDF829073B598213ULL,
		0xDCE7281A1A56F1F0ULL,
		0x3CED1CD2FECCC14AULL,
		0xB04FFCD02CB2B210ULL,
		0xC399E90C6F3093D6ULL,
		0xE0AF83D868DBF337ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xFCC635EF22091203ULL,
		0xBC1F7701BB9FCE1CULL,
		0x61285ADD81300BCEULL,
		0xBA8066F84CBEF50CULL,
		0x3293B3114A911B2BULL,
		0x1D5116CB991D01FCULL,
		0x75BB15DDCBD16762ULL,
		0xECF62FAD59202456ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x72AC2BE38157F956ULL,
		0x631285BF6E161ED1ULL,
		0xBA942DCE44895660ULL,
		0x732C5AE2CA0EF5BFULL,
		0x1608FE573A6D5DF3ULL,
		0xD7B73CD1A50539AEULL,
		0x2ACDE654439FF8BAULL,
		0x6A440D33D175ACCFULL
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
		0x53C0AAB7CE695DDAULL,
		0x71EB65F6337F475AULL,
		0x6EAEB346B59FA000ULL,
		0xD61C95EA78323046ULL,
		0x11B6460E71194E57ULL,
		0x9887205A8B211261ULL,
		0x401C807582CB736FULL,
		0xBCCF82EB0C046A6FULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x984505D900E5B444ULL,
		0xEF9A00700CCDDDD1ULL,
		0x1C7652F640828E6FULL,
		0x5270A55803AEB025ULL,
		0x22929BCDB444FD32ULL,
		0x04CDB243BF39AF96ULL,
		0xB48BDED7F8CE3C0BULL,
		0x6D16CA230A3E0F84ULL
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
		0xC3B1244F1BFDCFBDULL,
		0xB2388E1DD94F9529ULL,
		0x3F5758082FD82C7CULL,
		0xBCC08D97F9C76B0BULL,
		0x86A0101B58B57F7DULL,
		0x0C3F8F030A381C7CULL,
		0x28632A35ADD8EBD9ULL,
		0xB3382372CF3B7A33ULL
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
	la = 502;
	k1 = (curve25519_key_t){.key64 = {
		0x167B70177283F366ULL,
		0x5A7F16FBE4059C92ULL,
		0x0174E308D6A98AEDULL,
		0x38A9AE561ED24906ULL,
		0xEED0200FA4E5CAFCULL,
		0x1053C7002D2F1F78ULL,
		0x0E23AB7A351E19D8ULL,
		0x006DAEB9000EB068ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x74498622D663C8D4ULL,
		0xE5F661543C4EE285ULL,
		0xC7CE73A5EE5D567AULL,
		0x3A3E66D90D2E6612ULL,
		0x3AA821CA2A1F99E4ULL,
		0x81CA2CC63C29D18EULL,
		0xD63C6F4CCE4C4B36ULL,
		0xB8BC0F0992875C2FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCC0952D0A664F965ULL,
		0x675816B344730EFFULL,
		0xEAE4A53C4F5E6A7CULL,
		0x7BA132AB0A0B427DULL,
		0x4C48F343448DA63CULL,
		0x5D33F2AE5427684FULL,
		0xEDB059D870409A6DULL,
		0xEDC54675C7C2C454ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC6CB014F1EE685DBULL,
		0x92AB0A4D3845EA24ULL,
		0xB5C12BA27113108FULL,
		0x59739E81948735C1ULL,
		0x8B7C60F657091B62ULL,
		0x05EA6757A334E3E4ULL,
		0x7CEFC13F2F430BDBULL,
		0x4466CF180007965CULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB53A0D543923BDFEULL,
		0x08AF9FE982FE8215ULL,
		0xA9821E8C93CE3F81ULL,
		0xB8F411F6449A1C5FULL,
		0x91D965B139EA1B1AULL,
		0x4504035BE98DBA3EULL,
		0xC4851119327F7A93ULL,
		0x2261C1C7ACF589CEULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0C67B049464773C3ULL,
		0x2C4281326B096544ULL,
		0x18FC01C18E2561F7ULL,
		0x609DD7F2CA0B3602ULL,
		0xA9D1EA4AA9F9710BULL,
		0xB3B37DEE2E895477ULL,
		0xC9DCAFEE75D6C067ULL,
		0x1FA3C087AB9503EAULL
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
		0xB2B0D326A1241CEAULL,
		0xFE96B7FD9B2532DAULL,
		0x1B8FCE776F1B57A3ULL,
		0xE872DE2C18AE62FBULL,
		0x9F0B77C2E3AD2A41ULL,
		0xF9A8C2290D18A2F1ULL,
		0x1A6039A56A488973ULL,
		0xCCF9AF5827454379ULL
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
		0x6ACC7C4FDD825D60ULL,
		0xB6080AB4D1994B77ULL,
		0xF23F6FE08F4BCDB3ULL,
		0x4A70F27B7965C33FULL,
		0x752B069A8E05E989ULL,
		0x8F9ECA849F2C1C68ULL,
		0x703EDB1FA1928CEDULL,
		0xCF427F51AA76185AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x124EF4F095D504EBULL,
		0xFDD39290669CC53EULL,
		0xEB4BF0C734D38303ULL,
		0xBB0F07558A93E44CULL,
		0x4AA9DDE7993A7784ULL,
		0xA559D32B1A4ABDCCULL,
		0x90EA06BC40DB57B6ULL,
		0x7C4826B6E3089D2CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF8648BE227F387FCULL,
		0x4357635D2C2F84F7ULL,
		0x50C2DDE3D18B188BULL,
		0x07A9E2ECB2F59314ULL,
		0x8BA6DB1BC0483F0FULL,
		0x0F7DC3CF443D4529ULL,
		0x54D757CA751EA324ULL,
		0x825F68140EAF817DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4E96224165C06D7DULL,
		0x1DE0A798B138FB59ULL,
		0xFF78B960006FAF16ULL,
		0xB97692EBFC33643EULL,
		0x5DD6B052A73E65D6ULL,
		0x1EA2FBD207F2B4DFULL,
		0xF3DB2D54D153E8E6ULL,
		0xB02AD9D21E0ED52BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF00E3A14D18B3FBEULL,
		0xF10EE9EE15078F9DULL,
		0xBF503051A731B942ULL,
		0x486D8CF1A5CAFA80ULL,
		0x428984309820C9B0ULL,
		0xEC3D002BC1D8698AULL,
		0x81865870E8FFD210ULL,
		0x501BBAF8AAA4A484ULL
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
		0xEF6014F5A10D80ABULL,
		0x1BE938A24568FCA4ULL,
		0x72557E3888AF4647ULL,
		0xF47C6A3EF6E37BFBULL,
		0xA2A19EC47C24FB7BULL,
		0xFAB1FD7649808191ULL,
		0xEF845EB5135C6692ULL,
		0xD5B85228D25EBCB7ULL
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
		0x5D3275F184DD943CULL,
		0x959FC79592767528ULL,
		0xF74187A09A2140C8ULL,
		0xDA1D270163135F2BULL,
		0x6F84F1FBBFCE9662ULL,
		0xC08295DF8D99CD7CULL,
		0xA24525BF6DF63D00ULL,
		0xC5E892FBBC0AF73FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x37359D4989DFD80DULL,
		0x0575C4F2B42C0E94ULL,
		0x288500432F0FE6EEULL,
		0x51935AF2F9987FC0ULL,
		0xD72C79206435AA95ULL,
		0x254F54D6B47119B1ULL,
		0x1DB3FB7FCE7B6F9EULL,
		0xF3E182713FFE15C0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBA4237B779C42DCBULL,
		0x4407F10C6E8C873FULL,
		0x5C563B33CE5F7F02ULL,
		0xAB9C294460F5A1C4ULL,
		0x8250D4582175752BULL,
		0x72CB16E0BA8D1353ULL,
		0x79ACAE1FA17C6841ULL,
		0xAD6B8AFC62B5A7FFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6EB8D2782C053CCCULL,
		0xB443200528A0670AULL,
		0x2696053CAFD54EB8ULL,
		0xA3073E8E149E3636ULL,
		0x6680C430657D9614ULL,
		0xA313DEB0EC9FB902ULL,
		0x6AAA0ABF35DBF93EULL,
		0xFF30ED20B7F52B81ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF753435D2B96392CULL,
		0x4A0D3E9F71ED02D6ULL,
		0x57ABDA3FF7EAB266ULL,
		0x61D19F55E5291563ULL,
		0x23898B69339B8DCDULL,
		0x647450E9604CF9D0ULL,
		0x12EA064701FBD94BULL,
		0x6FF69B449C37B97CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA77D75DB89E383C2ULL,
		0xC21357A9FCDA301AULL,
		0x4BCC86889F797250ULL,
		0x40323E5DFC480802ULL,
		0xA4BF5518EBDA1475ULL,
		0xC0C6FEAF5BB6BD08ULL,
		0xF6885DA1563332ACULL,
		0xFC1085A8AF92384BULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x903F49D41AA68B79ULL,
		0x07E61AAD8E160615ULL,
		0xCEC720830AD70792ULL,
		0x0A1CB4FC8250B62AULL,
		0x7A36DAC76546EB25ULL,
		0x59E2A5C451138180ULL,
		0x85D0B2A319D22D91ULL,
		0x0CF92464A77B0A8EULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xD6BF53E5DF1FC30EULL,
		0xDF92866F7F144A65ULL,
		0x1B67835307D1E36BULL,
		0xC166DEACD774DD35ULL,
		0x0392A4AD0EF94AA0ULL,
		0x1AB8F5E20597A8EBULL,
		0x5CBCA4472E292381ULL,
		0x03E97843AE895248ULL
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
		0x9F68B60101ECA12DULL,
		0xBB6C435FE40A89C8ULL,
		0x73342E6812AD8D19ULL,
		0x8DC3CCE899C84DEBULL,
		0x5AF23F0CE4FA54C9ULL,
		0x36C1DA53DC9C67AEULL,
		0x85AF081E1E6D97B4ULL,
		0x6FCFDE069D0B723EULL
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
		0xB0682A54BD355378ULL,
		0x5058D6F0A97AA008ULL,
		0x7F2FE54FFC4B9AE0ULL,
		0xB712E50273B63051ULL,
		0xF5C20EE472673506ULL,
		0x7C59093AEA783D0EULL,
		0x5E54044035C51CCEULL,
		0xC87AA2D5AEF76384ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5ED10FA1A2D1E882ULL,
		0xBBEF3716328DE506ULL,
		0x4F8AA0A64B85EACDULL,
		0xEEF52AEEA28A1216ULL,
		0x3F7E5A6B808ADB19ULL,
		0x4B1C8FF14DC95942ULL,
		0x2003EA8956E9E43FULL,
		0x8B928B13A1BB6221ULL
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
		0xE9BF944D674FF625ULL,
		0xD1A352203F0A1809ULL,
		0x778208DBDFDA82A9ULL,
		0xE45E6E55708C4BC0ULL,
		0xB42F9D0B7E395A03ULL,
		0x629156AAC877522BULL,
		0x45C7A222440661B1ULL,
		0xE85E8AC2231C58DBULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x23702EA8D51F3874ULL,
		0x926EAFB4693A833DULL,
		0xC83BB35A97873C99ULL,
		0x867C0C284B739A26ULL,
		0xE131C40706500C8DULL,
		0x629C7F8B18A74754ULL,
		0x43FAAB1C78238EACULL,
		0x12FB01327ED49136ULL
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
		0x528ACE2F3952F987ULL,
		0xA43EF2E341865AB7ULL,
		0x612C71E3239C23A6ULL,
		0x23B83E1C0C124C0DULL,
		0x6D1DBD4BD2C59B78ULL,
		0x8CB569C85CCEE241ULL,
		0x11389F3062869055ULL,
		0xEE4CE691F8962156ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xAD92407FBE2376F7ULL,
		0x47AF1CF5D2697EB8ULL,
		0xE2944B82D1A925B5ULL,
		0x6634A94DF0497F4EULL,
		0x490FDE21B5269C59ULL,
		0xBBECF9CDC50490B6ULL,
		0x3DD06E2CC7CF7981ULL,
		0xC22FC66703C5F8C1ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4D4B58ABED894D92ULL,
		0xFBA01914954B1882ULL,
		0xAF62E6D0F9CD3B13ULL,
		0xEAE691D8BE6E79ACULL,
		0xCD4E5F071A680A01ULL,
		0x9E8E6420E00C30F4ULL,
		0x74C00451592F7D71ULL,
		0x6A171C453EE79CBAULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x46D932DF2765508BULL,
		0xC13D337E4A82B55CULL,
		0xFFD86DFA4E5DC041ULL,
		0x1F35F95D3F71698CULL,
		0xFAE0A5E6038C2D1EULL,
		0x585EB0B2E3AAE2D9ULL,
		0x1F374F380DFEC634ULL,
		0x0B369EB8244AED44ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x9BB2E78682AC77F5ULL,
		0x555BC14D055BB647ULL,
		0x80F93EFFA1E11AF6ULL,
		0x652FDAA9A2982627ULL,
		0xC259014F4A11CEBDULL,
		0x628FE4DA6C7F92E2ULL,
		0x77C7D71047358AD9ULL,
		0x14D6C9A7F2F3E653ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB759CE4EB3002B3DULL,
		0xF4B34D171CD2CD6EULL,
		0xCF351A634F6E1DB9ULL,
		0x46BFD76CD222A83CULL,
		0x0777E8D514F61577ULL,
		0x06074D861ECC8F41ULL,
		0x0864FEBC0AE3E8EBULL,
		0x13A2D3C47F467E09ULL
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
		0x1836C3582ECB0B2BULL,
		0x31A69DC2D905043BULL,
		0x43865F3423FDD8AEULL,
		0xB8B992550D576452ULL,
		0x9C88EBDE7A94E07CULL,
		0x3BF16734E4427542ULL,
		0xA7396505DBC95B4BULL,
		0xCB6778E48743F276ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x212FD12D407B6283ULL,
		0xC80168F2740D2DD4ULL,
		0xE6941EC714428CFEULL,
		0x20AF6E30E7D810BAULL,
		0x44314365400607CEULL,
		0x6E2F7C3B317497CEULL,
		0x344BD95FF5B86D51ULL,
		0x27637A7463ECFF37ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFC68F0F74ED365C5ULL,
		0xE2F5B935BCB270BCULL,
		0xFE3CE4B7265E4B56ULL,
		0xE865C8C8A25B7C78ULL,
		0x25963E908336E294ULL,
		0x9F7CA18AD434C3BEULL,
		0xE04A8D131436FC94ULL,
		0x32F77DBE697FC75BULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF60F13C341EAE8B6ULL,
		0xD9F864099C966DE1ULL,
		0xF7B8A3BAD2E5095EULL,
		0x1F1CAA88686DA982ULL,
		0x572BEFE4A5B8E628ULL,
		0x5092B8BDB900DD0FULL,
		0x4EEF7EB29BCFE0F0ULL,
		0x3A43399F6693AD16ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3607BC7F81A3B2B7ULL,
		0x4F01D086950EE839ULL,
		0x6B3E4275A82BB43BULL,
		0x6C5CE6E481F85EA7ULL,
		0xEB0E866B56A32394ULL,
		0x72281CF24D1AB134ULL,
		0xA1BE97819CA04005ULL,
		0x2782FF21BD374EC4ULL
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
		0xCC4C79923646FFA0ULL,
		0x4863ACC94040F890ULL,
		0x1D14524ED28D8BCAULL,
		0x14C7BDCCF0CE0C3CULL,
		0x703AF296C9EC6582ULL,
		0xD0F617532320496AULL,
		0xAB0406B401A6F167ULL,
		0xF56D78FF0066AC1CULL
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
		0xC567236251B37474ULL,
		0x5BDB8A454ECAEFCCULL,
		0xD7A20157743E98CAULL,
		0x3F098F7CBB15C557ULL,
		0x28E66E238ABE638DULL,
		0x4313E9979F7562D0ULL,
		0xBFCA6333BF8726B7ULL,
		0x1C8CF1F08932069CULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xEA52FC8149D58EEBULL,
		0x5B38B59EE27FC431ULL,
		0x492A55A984EF03A5ULL,
		0x8A7B4E0D49175454ULL,
		0xE2AFC3C15935D604ULL,
		0x8A32201A567F49EBULL,
		0x64C7EDF0F7F6294FULL,
		0x31A93368146F48AFULL
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
		0x26AB412B0CF83944ULL,
		0xBB4736B45F1DC356ULL,
		0xCD02EA33462F2AE4ULL,
		0xA3FC6786D7691AD4ULL,
		0x1305858AE7E5CAA8ULL,
		0xEBD8A02D1E75CF7CULL,
		0x9E664F2C30E642DDULL,
		0x6FB1C6663DA21C9EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB345E493A9C7A02FULL,
		0xE27E15F5DE644120ULL,
		0x5899E1BB3EEB6A23ULL,
		0x630D621A7F2DB434ULL,
		0xD21E4DB18094176AULL,
		0xD43BFA6090F2CBC4ULL,
		0xDA6C84BE0D6D062AULL,
		0x29CBCEF8E7151171ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x52CA33D8258F384CULL,
		0x337539C1640EB415ULL,
		0xB82776E0D9D7CA65ULL,
		0x83738AECD996C0B7ULL,
		0x58D64DD66EDCDFEBULL,
		0x5811BA5A2192B953ULL,
		0xD62D165B77829FB6ULL,
		0xC1FC3A574088C9A8ULL
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
		0x7340F606A7912408ULL,
		0x12440CFA529AAC07ULL,
		0x4251CD943936DB1BULL,
		0x92BF70803A25429DULL,
		0x3D154932F3D24A92ULL,
		0xACBD699D3DF3FC61ULL,
		0x4A03D04394AE2269ULL,
		0x979E904C9996C4E6ULL
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
		0xBCAD153E563F059BULL,
		0xD9EBDD9B8AF5F359ULL,
		0x0871C204B9B9917BULL,
		0xE68D0E9EB3959F1DULL,
		0xA474087FEBFB1CE9ULL,
		0x500CE2334A2E3968ULL,
		0x10EE788145B12A39ULL,
		0x8EC7AA34E820894FULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x44AAB04544D5C491ULL,
		0xD90EAECC9AA46F5EULL,
		0xEBB623967A193C54ULL,
		0x565F6F6976A9C6C0ULL,
		0x6AE39B179020A5A6ULL,
		0x754DC9E0EB01B2E2ULL,
		0x20D3D8DB0EC74D2EULL,
		0x07270BD33F189472ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xAC849131AB2FD810ULL,
		0x52530E34A2E3A18FULL,
		0xC9C4B738617FD834ULL,
		0x4B5AF2CABC500245ULL,
		0x4634F6D2C6AD8796ULL,
		0x33D5A028CB9C82EDULL,
		0x8C07B2B9D12BDF3EULL,
		0x7F56872389EA6DB2ULL
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
		0x0D846F82ADFE2745ULL,
		0x357A4051E88A0AA4ULL,
		0x40532EFE2BBAC68BULL,
		0x0FA807282971A1E5ULL,
		0x1812276779E3AFFCULL,
		0x52CBC0BD48BB6102ULL,
		0x4F36766002B56207ULL,
		0x73EB8BC541A7D742ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCE646EAB54AA1213ULL,
		0xCC2B1E067C60B570ULL,
		0x88C2EA346BD7E531ULL,
		0xCCF2C67ADF50065FULL,
		0x931CD3BA9D21FC09ULL,
		0xBB4B8B7AD078F78EULL,
		0xF421EA19E9976466ULL,
		0x69D7F8AAC8A910FEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBD1129428C2F22B1ULL,
		0x00F99B7D3E1716F6ULL,
		0xABCE54674EE65326ULL,
		0x54F42A96B50BD9A7ULL,
		0xD76CB41322A2ACAFULL,
		0x6048C0C47C2C05B0ULL,
		0x4E1074D608361872ULL,
		0xCBBD0402959C525BULL
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
		0x338F483F09AA9CE1ULL,
		0x3FFDA1AEE05D2C8EULL,
		0x3B2FD6C88A8CDDDFULL,
		0x083587E05AF2F746ULL,
		0xA3A4D287E2B15B96ULL,
		0xD1A00ACA0ED6FF9DULL,
		0x9F7BEBFA774BB932ULL,
		0xDD34BC14C8F2D8BBULL
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
		0x575BAA69928A30D3ULL,
		0xA28071A77C7062F1ULL,
		0xF7F9469F51C033AEULL,
		0x79E3CFA8D55DC856ULL,
		0xEA0A1F35C96DA566ULL,
		0x834B77493844F6C8ULL,
		0x5AA51B1BB4E5A40BULL,
		0xFBB075A7C8737351ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x44770DCB88203263ULL,
		0x4CBBD01686F97CAAULL,
		0x14BA03676DE1C87BULL,
		0x01579D18B9338EF5ULL,
		0x9B30EB9AC181A01BULL,
		0x6CD07468AE8DA422ULL,
		0xD5D73126CA8F99AEULL,
		0x3E96E74EF57800C4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6B496A0D49D662BFULL,
		0x67F11AB4D6F0BD31ULL,
		0x804D40A74EC59D5CULL,
		0x74765706F0161D9EULL,
		0xE499396891598849ULL,
		0xBB9240AD2C678808ULL,
		0x66C8B050F5981CC5ULL,
		0xE56858B5F9C8E3E0ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xF03E1AF536AA4971ULL,
		0x3F6896AAF5940668ULL,
		0x0C615735964B7280ULL,
		0x70CAC4665BE9478EULL,
		0xBE11E2721B2B94DFULL,
		0xC99931F1C757EF05ULL,
		0xB1D6BAF4EEF6FFCCULL,
		0x14CD817195BC06E7ULL
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
		0x2C37B3A3C07D49C1ULL,
		0x5E245E317890F52DULL,
		0xC528EF72C9372D4AULL,
		0x0DB804DB47BB532AULL,
		0xF64CAB770ED7FEE0ULL,
		0x215E0075603184EFULL,
		0xAD928FEBDF41B6E5ULL,
		0x2E0647545C3D5D5EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDCC899907B7F13FEULL,
		0xC472F7B43B558C18ULL,
		0xDA8025E2AE1F6B0EULL,
		0x1B7D87D3B5ADB3A7ULL,
		0x60771BA71AA3DF44ULL,
		0xB119BC89F7F11B7FULL,
		0x25374B0224999BB2ULL,
		0x9EAF19A095F91075ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCA66A58505808DB2ULL,
		0x1D44C1FA65E31CCFULL,
		0x6C2D296B4EDA8F9DULL,
		0x8731E31B31C32773ULL,
		0x5FE282178CC16DEBULL,
		0x324BA164DF8CF44AULL,
		0xDFDB84FC228E8B5CULL,
		0x636B2D704EAE254FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9FBE66ED9D75D2FAULL,
		0x208DF3642CEAE63BULL,
		0x0880B51B56953FE0ULL,
		0x363803E8660E40D6ULL,
		0xDB12EB97A99298D9ULL,
		0xC0B95A8BE5E13A9BULL,
		0xD3800FE2F04ED413ULL,
		0xAAA6FBD81DA3E33CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x081526DBE969E545ULL,
		0xA6FFDDDDDAC6A731ULL,
		0x9C8BF7E8ADC1285AULL,
		0x593AD593692AE8FFULL,
		0x0DB96D4395508B02ULL,
		0x496627326A3A48D6ULL,
		0x5E275BDE229588BEULL,
		0x41CB8E8FA8874E8EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x62523E8C7AB40726ULL,
		0x142F5F895A259E18ULL,
		0xD639CD35C837980FULL,
		0xA4FD826F90AB780FULL,
		0xD22E31DE7794353DULL,
		0x9FEA701096F5A3D9ULL,
		0x788C599726740738ULL,
		0x91BE5C41C138F660ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC4B02E4F75ED4B2DULL,
		0xF10F9E008F33E3C9ULL,
		0x8CEE28E3BA989E07ULL,
		0xFD6E2231E3382022ULL,
		0x7871D26D120F46A3ULL,
		0x3BF3AF2E9C1A749BULL,
		0xE0D9160FA48281A0ULL,
		0xAD37713545A94889ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCA6D9D6B8BD63B5BULL,
		0x92C403D785B763E4ULL,
		0xF09AA6140D0056D0ULL,
		0xD374DA440205D1E4ULL,
		0xFEA2A73BE2D8B768ULL,
		0x30DBBBBCF7841EF5ULL,
		0xDE6E60EC4E8D15DAULL,
		0x566014A9F5DA44ACULL
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
	la = 502;
	k1 = (curve25519_key_t){.key64 = {
		0x2ECC72423283D169ULL,
		0xD4371BD8509E55DCULL,
		0xAD294108DF9382F6ULL,
		0xD6C396A9A5911C4FULL,
		0x667285AB7C79B98AULL,
		0x319A69704F705FB9ULL,
		0x7FB72858407B3CBFULL,
		0x0067F03FAD756BE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0040000000000000ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x48FF557A313AB06FULL,
		0x9378BFA089EEED88ULL,
		0x73AD25C67F37CEBBULL,
		0x452559B0D6A4C0E3ULL,
		0x94B3CC61DDD52193ULL,
		0x70AE4B0AC16ACF21ULL,
		0x71FEA7D61B140C93ULL,
		0xE5A967EAFB6CE3BFULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xA6DED3DB883A5765ULL,
		0x215E79C6E0A8A785ULL,
		0x0EF339954EEFF0D0ULL,
		0x1DA0A71259B7BDDAULL,
		0x24590767CF569AB2ULL,
		0x64B9F7690B15BA6EULL,
		0x6AD99116B46ECDDAULL,
		0x113B5C03D41F4C9DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x201DE4DBF6A26157ULL,
		0x5B91DBA0033F5DC2ULL,
		0xED5747A6B2EBB576ULL,
		0xDAD6F93E122E7A9AULL,
		0x6EFCB63DD2581927ULL,
		0xACB003EE034B6ECDULL,
		0x255976CF5C5B6BA5ULL,
		0x82F8D982F1D14417ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x62F41A860DC4FE9EULL,
		0x72AF639848EC4167ULL,
		0x880AAC549C4A7149ULL,
		0x079F8D879EA7DC58ULL,
		0xA0E0C55126754A03ULL,
		0xF88FBE685CC93C28ULL,
		0x44EC3B6B1D7CA6A8ULL,
		0x4A74CB17E9BE320FULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x138B22C7B0BC6C39ULL,
		0x6EC9C302187D5F61ULL,
		0x52AF5DC7745CC6A2ULL,
		0x9A3DEF6A38FC4C07ULL,
		0x3BD21E590D7E4F5DULL,
		0x733C9CBF2BF35DF3ULL,
		0xAB1846F483AA816FULL,
		0x15F5BF23C6BD4142ULL
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
		0xA9A5B629C3FF9E4BULL,
		0x5BF4D7E4798C54ECULL,
		0xC0610958A5690ED4ULL,
		0xBE11F2DF7FE41A79ULL,
		0x1A0BDDF8BDB7E8B0ULL,
		0xB3FD8C69AD59EE9FULL,
		0x81934830933D4F1BULL,
		0x3FECD0708764BE7BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD8A20DD44F32228FULL,
		0x800A3292310C0102ULL,
		0x01DBE1E1C02163FDULL,
		0x8033AD696CFD2E36ULL,
		0x8E0210FCF0819BE6ULL,
		0xE2ABF5E64CB515E2ULL,
		0xBEF64DD2385E7ABFULL,
		0x8CCFE0E28D799107ULL
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
		0xFF378F7B6C1E9BEBULL,
		0xDF5A676C32BC32B1ULL,
		0x8E89F4563F853F1EULL,
		0x8811004A816E040DULL,
		0x08341BA728666307ULL,
		0xDB1382839474F667ULL,
		0x6CE458C3B89BD825ULL,
		0xA799C35E2CE8FBDBULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xA7C592BE4F28C0BAULL,
		0x03181D5F0C05A752ULL,
		0x2905A2E68BBC28DCULL,
		0x8C77537FD6818C63ULL,
		0x5EF247E0CD07C047ULL,
		0xB89C4C0C141C01F0ULL,
		0x261E088248961410ULL,
		0x51AB7B126EA1A1DBULL
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
		0x625CB70B91A721DDULL,
		0x1F613CAE3FC47E44ULL,
		0x940A27757CAACF21ULL,
		0x0C618017394EC250ULL,
		0xCC6CB63739ED980BULL,
		0xCC4A7081CFB1865BULL,
		0xBE36D257412C44A6ULL,
		0xE87422293BD5E3DFULL
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
		0xAE6F5B561D351973ULL,
		0xB3A5F251E172B25AULL,
		0xFA88FEF66836B376ULL,
		0x1F0F4EABB8DA53D3ULL,
		0x85DDA07CD9C8EF17ULL,
		0xF993D57D6CA5373CULL,
		0x85F78489A44C2FCBULL,
		0x7F60CDD2F91293E9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4ADE3BED6FCD2C71ULL,
		0x244EBC1D8A47EA9CULL,
		0x19F9ED57F4C9228CULL,
		0xDE44112E37778DA7ULL,
		0x0359558322FB7532ULL,
		0xD9C9FBCD0F76028BULL,
		0x2E31A8959F75CDDBULL,
		0xF405C0D9AEA2E15AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8214F86FD4CD3E0AULL,
		0x85AA9F30CC80A270ULL,
		0xE509420CC83002F0ULL,
		0x2B55FDB09F28C192ULL,
		0x4F6A5FA78401E87EULL,
		0xDCFA81E777596E31ULL,
		0xD593B47B2F3FB826ULL,
		0xB9C09C057F4C638BULL
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
		0x92483EF76A09E828ULL,
		0xF715F3AEBA43ED38ULL,
		0xA75AF9641AF068D2ULL,
		0xAB14F7C666790FDDULL,
		0x0E22F56549199BC0ULL,
		0x37EAAF0C82AC0BDBULL,
		0xE7C286B4A225829EULL,
		0x9B5134F3FC80359FULL
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
		0x3D164D6E0C3372F3ULL,
		0x7FB817008DD7D6FBULL,
		0x447E8CED009A3C52ULL,
		0xB112F81F4BB33B1BULL,
		0xB5046B31CB977BB4ULL,
		0x65D2294B6856A36EULL,
		0xC765D0314FD7C5D1ULL,
		0x492619A23FA75280ULL
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
		0x97F616919B86EC01ULL,
		0x08FE9323DE06093AULL,
		0x715755FD3BB1E4F9ULL,
		0xD839588DA131D768ULL,
		0x8C9774A211965B60ULL,
		0xF7115F98E20AC155ULL,
		0x91AE3DF2F7D50A9EULL,
		0xFB6A0EB431236C4AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5F8E8C2CBF0150C1ULL,
		0xEEFC448595CE330BULL,
		0xF1793C2563444A83ULL,
		0x2E6F2D7953B6A5CCULL,
		0x904E84B7C610E925ULL,
		0x6FF2C8B5B2AF885EULL,
		0x28F6DD7858FBCBEEULL,
		0x9ADA7E1BEF9DD1E0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x95AE9B4A4763F03DULL,
		0x2D990C8199D0D58FULL,
		0xDF74FE2149CA7134ULL,
		0x9D86D35D2AB0AC87ULL,
		0x5A0C0D605C9BEC41ULL,
		0x975132E1D367AE5FULL,
		0x18C7216E8055FDDDULL,
		0xB48F7322C97BBF01ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x61EE9142949C9AD5ULL,
		0x11DA7B4B669B2990ULL,
		0x6DE7344411918CC1ULL,
		0xB3F300B3CFC0BDDEULL,
		0x4BA0CC1EABFF2821ULL,
		0x6CE9041975908C11ULL,
		0xEAE81C341603E48CULL,
		0x2B302643C233A2E9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBACECFAC3B59DAAEULL,
		0xF41C29798C9A34C8ULL,
		0x2CC5310B503EB90AULL,
		0xC849A3577A38FC00ULL,
		0xD486A8D91F8CA3DBULL,
		0x3A7821A90F23A98BULL,
		0x85A7198AF50D21ADULL,
		0xC456D91310152111ULL
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
		0x58D625E578A88A40ULL,
		0x5CD556D6FC3F784AULL,
		0x4EB57E90C6A77A28ULL,
		0x81F78F96805D6731ULL,
		0x208824F329F4B7B4ULL,
		0xA4152C4CD55E8BE2ULL,
		0x262E2F9E392519CBULL,
		0x6B1D83C218619F90ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9768EB911A05E8AFULL,
		0xD0416C091ACBB57AULL,
		0x651590FA27ED8BA9ULL,
		0x6A710974CDDDC38AULL,
		0x2CC877E1E1693C88ULL,
		0xCDD3279956FCF4DFULL,
		0x10BC55F8023C68B0ULL,
		0xF9A2C2F690F034C9ULL
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
		0xBEC333DB52CBACB0ULL,
		0x07568DD7A17050EAULL,
		0x34B330E37D81D693ULL,
		0x99DC9586A02BD23BULL,
		0xC94D7B06794B0BCDULL,
		0xB8AA91B0E0FB839BULL,
		0xF8B064C753D83F3CULL,
		0xFFC88352F094F851ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x06BBF6E923726BC0ULL,
		0x2C58550927AA645DULL,
		0x019BFC9F278EC37DULL,
		0x4D105EAF617EDD43ULL,
		0x2176C196D73EE40FULL,
		0x5BEC0F4AFC5C06CCULL,
		0x8147E4C5B8CFF19EULL,
		0x0F586E2F50E3664DULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x0E001ED3A0FF5766ULL,
		0x5624FB716FED6BE7ULL,
		0x7D6E766F5BB8A920ULL,
		0xCB013D3174B59480ULL,
		0x6935B37C7B2EEE7BULL,
		0x9204CD1B0AFBC774ULL,
		0x1E7E5D14D089D200ULL,
		0x0ECC9FA70E6C6AB4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF58FCB8B6E0AFC51ULL,
		0x6123D83DCA3FD6A4ULL,
		0xD2F2F0CC47ABF471ULL,
		0x3CC5ED921A5D282FULL,
		0xB9AED805A7CF7324ULL,
		0x9DC6B08D2BEE1B95ULL,
		0x76DC68620957B812ULL,
		0xA03B2139D86DCA48ULL
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
		0xE4A1946C6D5B2A50ULL,
		0xDB585B80920E9418ULL,
		0xF49BE7FFE47DF14CULL,
		0xD8B3A00E01DF22C5ULL,
		0xD61CBBF3AEE10FEDULL,
		0xAE1D6AE0239BC5C7ULL,
		0x7EE9BDBB1246A2B5ULL,
		0x98E8706F5D68F4E6ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDF27A01B81C8CFCFULL,
		0x7E99644D282915E3ULL,
		0x7B560161291AF60EULL,
		0x8FDB6C2CF29A9862ULL,
		0xBDAA6BE0AF221D18ULL,
		0x83ED1DBBFB6B8177ULL,
		0xECF9BF4A3B154EC1ULL,
		0x502EB6F9D5E42E73ULL
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
		0x93F36B457B84D943ULL,
		0xA45286DDAB363C07ULL,
		0x4B38B34DA21DF7F6ULL,
		0xAEDE314538D2D25EULL,
		0xEE34B7B2B97B220BULL,
		0xCD33220C7859CD29ULL,
		0x19636023DDAD8823ULL,
		0x9D76C7D418808A61ULL
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
		0xEA7E1B3057110E98ULL,
		0xC8E8C29AEFBC20BCULL,
		0x65780716D4C7850BULL,
		0x0E0ED0957F24F7FFULL,
		0xE48BC827C318E215ULL,
		0xEF413AAD4C90B9ACULL,
		0x28735746696BD394ULL,
		0x9A130DC998804394ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x754168969A6ECAD5ULL,
		0x79498F10355675E7ULL,
		0xC22563DA13B32976ULL,
		0xBA1722749E051621ULL,
		0x007BB2C7054E735AULL,
		0x9D85521AEE0A11F1ULL,
		0xC4B704B01F4EF4F0ULL,
		0x6B49FC9B8CD1161EULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x44A1FE4031577188ULL,
		0x52DC5556AB6B3923ULL,
		0xDE1D3A1A56A6F2A9ULL,
		0xE818CCB6EC91680CULL,
		0xE3BFD80C4BBB364FULL,
		0x665DDBF35C4B3A89ULL,
		0x60C378F3AEC175FDULL,
		0x1DCBA85315D4AD85ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE1F8AF73B7CED16BULL,
		0xDF9C3B89D2EAD467ULL,
		0x79370E7354F81D37ULL,
		0x8D8718695C1F9C91ULL,
		0x0416A6BFD140DD13ULL,
		0x447D0FFE739E4E9AULL,
		0xFBE958B4A332BA76ULL,
		0xDF7FB089F2A4D1DFULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x417B41B2D2EF7234ULL,
		0x100874188B1D822BULL,
		0x41125E40AF6528D2ULL,
		0x5F72EEC79CD4F8B1ULL,
		0x9C37C9FBF8AA1E79ULL,
		0xAD11FB7CDBB9CEF0ULL,
		0x974768B8AC933E94ULL,
		0x594155B8EE18D500ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x1EE60A6D694F5016ULL,
		0xA397A0D3EA4EE56DULL,
		0x803F135065CC270FULL,
		0xDF603EF259DD633AULL,
		0xAED451BF1462F673ULL,
		0x00558C58919CE9F9ULL,
		0x4BEC17D9155CBA6DULL,
		0x0D828DAE4C7FC468ULL
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
		0x1DEA8BB3721CF8D7ULL,
		0x4C6BFDFCE1E82CBEULL,
		0xC51D05DD8EBDC830ULL,
		0xCF1991F8B619F437ULL,
		0xA319D740DB001DDCULL,
		0x747017DCDA647604ULL,
		0x63119333C93CD50FULL,
		0x8D08209F2440FD23ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBD572BAB9FB6014BULL,
		0x918FCC71BC4AE724ULL,
		0xCEDF7E77AF95932BULL,
		0x611678A64623CBBFULL,
		0xC99BA4D97B3A2C30ULL,
		0xB6984C79E2F12F24ULL,
		0x17C29F2DDDA01028ULL,
		0x495F89838B38F921ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72FF79CF4107341BULL,
		0x3B41F64DFF741C07ULL,
		0xE1161149058762F6ULL,
		0x00222DB01AF42BAEULL,
		0x71B18DFA9593445DULL,
		0x04F3BAC938ADF885ULL,
		0x8EC0874F23849751ULL,
		0xB58B992280C05559ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD2503ADC221FACABULL,
		0x23D2E9A4497B28C4ULL,
		0x6AE24DB8B55940EDULL,
		0x299143E042F14B88ULL,
		0x22994B30E33FE769ULL,
		0x52B17A0C6F19633CULL,
		0x73EBA1632D4B74F9ULL,
		0x83A6B09B2551C414ULL
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
		0x344D5F05D180BC09ULL,
		0xAE6479713B1782EEULL,
		0x9315EACBA74A2AECULL,
		0x20385F66B4188006ULL,
		0xE091C0A8EC087A94ULL,
		0x5A9D8992CD85475BULL,
		0xF86B18C66EDBF84CULL,
		0xC4151C7E2A381232ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x24E52634E2082961ULL,
		0x2ACCB2C0B1B78C9BULL,
		0x7C8DE2EA01D5CD2CULL,
		0xCFB2038590E405D2ULL,
		0x27882A8CC7368525ULL,
		0x9DD1B648BD8C7FA2ULL,
		0xE6722CF0F8F5C8D0ULL,
		0xDD7F778DBA0BF283ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x2D7427276BE07B97ULL,
		0xCAB1B5BEB68C191DULL,
		0xBBB02A4DBF721AB7ULL,
		0x6F18BD16E6286564ULL,
		0x416FF319DCEDCB87ULL,
		0x98F9A277C8F95905ULL,
		0x385EE0025130AB4AULL,
		0x08AC6518EAA63677ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE1188AAB4DDFBADEULL,
		0x3E65D7D691BF55C4ULL,
		0x3C6C6D20A48EE178ULL,
		0x83423BEE91A080D8ULL,
		0x2AF007DB43F56AC3ULL,
		0xAA17FEA2A2F617E3ULL,
		0x7E9305E2D844BB06ULL,
		0x54A68FEAE1D4F039ULL
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
		0xBDE15206A6A020C8ULL,
		0x9D201C8E858BD4FAULL,
		0x4B41F1D6C4253859ULL,
		0x94A2B39317729D87ULL,
		0x491C303607AFCBFCULL,
		0x3C4CCC42F8B4B103ULL,
		0x2DFF00C110CE1AE6ULL,
		0xF89CD8FA70DCD5E5ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x99A2B2120C1C5534ULL,
		0xA3A336E155CD3AF2ULL,
		0x2F9C11956273A1FAULL,
		0xE7FDA2CB5A2F1DA4ULL,
		0xCD2E650649492575ULL,
		0x68F7A8DEAEBCD295ULL,
		0x777DC5B4EDBAFDD4ULL,
		0xE498772DF72967B4ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3A4D4D59DE5962F5ULL,
		0xBB7AA7B9476F0F93ULL,
		0x6105F17CC206BFABULL,
		0xE028A820F97EC04CULL,
		0x96A2E4277E915687ULL,
		0x4D3425B819619207ULL,
		0x09CBC2853E05E795ULL,
		0x7AC8ECC06739BB4BULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x3D5A68607A1A5ED7ULL,
		0xBE6156BF238AA31EULL,
		0xBD071D7EB026F8B7ULL,
		0x6B1463C31ADD8A7EULL,
		0x86C64A53485F667CULL,
		0x2F7AEC15186803B8ULL,
		0xC96DD55F0A08F845ULL,
		0x3892A92699BFE1D2ULL
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
		0x894DFC8561EF071BULL,
		0x11676B0F52420C03ULL,
		0xE988C3E63525547FULL,
		0xB617968D29740FBFULL,
		0x8DB7E3521969A039ULL,
		0xA3EBF3BAE5EB0CFDULL,
		0x2B97130296367FF0ULL,
		0xAB6A05F90DCDEDBEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x30504241B5E98794ULL,
		0x3C65D8D021BE8BBCULL,
		0x0A9C4ED1A0A9CC4CULL,
		0x1A893AAF50DE3C46ULL,
		0x8048C24428B7E7ADULL,
		0x7ECDDFEEB32E95A1ULL,
		0xE30C4B4810017467ULL,
		0xA216C069A268A5CDULL
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
		0x692D89BF72F565F0ULL,
		0xE7F1F5D1175E4845ULL,
		0x4E3660FB7C93E6C7ULL,
		0xB3ED07DF80E9E721ULL,
		0x8E5C496CF583A9BFULL,
		0x051A1D360D7630AFULL,
		0xE2F9B2FC40774061ULL,
		0x93AA38EB3627BB85ULL
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
		0x5A5FF2AB37B0C636ULL,
		0x3F321E7CD951FBC7ULL,
		0x4582D0A2271E45A4ULL,
		0x78D4AC748C5700D1ULL,
		0x44CA4B6765768B77ULL,
		0x38F3C8417FADD417ULL,
		0xFC6E717A8F20D5F2ULL,
		0x7A4F0546299CE154ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC55CF610DB8AF8CAULL,
		0x0CB5D740F3FB39CEULL,
		0xA1DC6C814ABF4EB1ULL,
		0x016F0FBA8FCA599DULL,
		0xEDBE230676B3FA97ULL,
		0xB08CCCAED74C820EULL,
		0x4415CD87C212D114ULL,
		0x275F92FBCA26ED06ULL
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
		0xAE69D72762685D5EULL,
		0xA93CA0D4D1635FEDULL,
		0x661F98FCD1317EDDULL,
		0x668ED15B043AEE1FULL,
		0x5F36D008286A3F2CULL,
		0xB8520179B4B90851ULL,
		0x7BA9BBC626DB4482ULL,
		0x0CAF99BF4B48DCA1ULL
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
		0x9973705B45377048ULL,
		0xAAD574AFE4019485ULL,
		0x51BE8436C03B8528ULL,
		0xBC0FFCD55596CC29ULL,
		0x895A7A62108BF514ULL,
		0x30C57AFC4D0C71F4ULL,
		0x6FD4B93B752B6D32ULL,
		0x2992B4EE7F7B0897ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2442D778BD869C42ULL,
		0xA4FFE8964850E7A8ULL,
		0x6283DB8D117332CCULL,
		0xFF95BC7E733DC674ULL,
		0xBCA9F2A39D3F3085ULL,
		0xCC8C64BEE727AD8EULL,
		0x3DC5EF316666A732ULL,
		0x9C7F0E328D32668EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x52FF0ACB8EE1FFBAULL,
		0x2D8182EFC75F0218ULL,
		0x0870D33B4E948322ULL,
		0xA7FFADCD1C762BFEULL,
		0xECFAA8EAFE0E4270ULL,
		0x3189BF7F7749A2E6ULL,
		0xE55C86AFFABDC70FULL,
		0x3E87CC5C4327B196ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2B8DF6493C339649ULL,
		0xB574319E2609B482ULL,
		0x3508D275093A7C14ULL,
		0xFD287362EA1395D5ULL,
		0xC05FAD2D5597F726ULL,
		0x024231037AF7E359ULL,
		0x84237870D44EDE1BULL,
		0x6654B7FBA4DA7251ULL
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
		0x1A5C5B400745E602ULL,
		0x83F431C64A5B0FC2ULL,
		0x7000A70FC81A60EFULL,
		0x5D27AAF62E9D42CFULL,
		0x391076ACE5DE888AULL,
		0xF11F47D6AB138E67ULL,
		0xAB8B80F7B7113D72ULL,
		0xBEC112100B200357ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x73FF72139C7D39EEULL,
		0x8EB8425FCED7C2D7ULL,
		0x9D0F8D4CD08E31C4ULL,
		0x2399EF9C7BBEB904ULL,
		0x1C44E9DF7E41371EULL,
		0x2CBC8BFFBB091AE4ULL,
		0xCDBB1DDEE5803ED5ULL,
		0x1A8692AE462FD6EBULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC8286FDFFAAA8B29ULL,
		0x27276C630B1561B6ULL,
		0xDC871633E018A012ULL,
		0x35F68CF3D8433042ULL,
		0x5B56BADC5AF028E0ULL,
		0x6BEC6DD0A0AD9FACULL,
		0xC9D4DFA732BF2E23ULL,
		0x52EBD77058898D15ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4BC41990B68A6FF9ULL,
		0x4A175234A871856BULL,
		0x6BE6817244002A60ULL,
		0x4CEE716C66699149ULL,
		0x6A0C6BB37C150793ULL,
		0x160E68377AC321C9ULL,
		0x24AACCFB65ED0FB2ULL,
		0x7A8738E79B649ADDULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA8FF2910F041B8A8ULL,
		0xCCEE412BEFD3DA77ULL,
		0xDBF1FF379B60E260ULL,
		0x50FA574EC21A8F21ULL,
		0x728A8DD2DBBECBC8ULL,
		0x28601C57D09CB462ULL,
		0xC0947A98430A3001ULL,
		0xD285CF1B6D826339ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCB787241A6B46F60ULL,
		0x27E9E3DB059EF1C2ULL,
		0x0F2372DC8E9C5A87ULL,
		0x1C212EC70A087E37ULL,
		0x49967239E7FD41ACULL,
		0x83436BC6D3594843ULL,
		0x99DA1B66136E21C7ULL,
		0xD96F58994B57B834ULL
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
		0x251CEC57CD5A3AB4ULL,
		0xAF727CF6CC0A9092ULL,
		0x60980D6B3905E42FULL,
		0xB21F547541C0D2ACULL,
		0x7E544AEB1692CE0AULL,
		0x41BF7F2115A93E03ULL,
		0xDD948C89D4997258ULL,
		0x93A653BCD05B636CULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7147A5C164298575ULL,
		0xF9B143BB45010572ULL,
		0x65D6BAF3450D5E0EULL,
		0xEE0ECF4B809F1D4FULL,
		0x99F681C7CBA4919CULL,
		0x8DB188EC98A2A297ULL,
		0x2B6ADE86720EFC35ULL,
		0x3FD3F5844F393CE8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7E5FA829558A09E8ULL,
		0x1B4DCD5BF2B44453ULL,
		0x3CE8B7D3CB10D9E6ULL,
		0x8BDAD982640C0EFFULL,
		0x2BA5FE56BA62E51DULL,
		0xDEAE5FCBD5B736B6ULL,
		0x42FDBBBC4CFAFA17ULL,
		0xB8E1F536F6FDC358ULL
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
		0x9A8FFBD168CDAC91ULL,
		0x98C8D89B00FEAB6FULL,
		0x0028DD944BE259D6ULL,
		0xEC838B90E8A0B697ULL,
		0x130C7D4481B5769AULL,
		0x24F19D08137A0286ULL,
		0xED09533889F8EFC8ULL,
		0xC2CEA39FBD06B89CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7EBC3F7082EE6E0BULL,
		0x681FE8FA3A0493B1ULL,
		0xB49AF61646A757AFULL,
		0xBB86FDE40FDBB95CULL,
		0x88D77F26A7DBD270ULL,
		0x21E0A3A3341E0671ULL,
		0xC87E26C8C027E7C0ULL,
		0x8C3B5E915C79C49EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA2F3469C0C9D2DB7ULL,
		0xF79E8F1053EEFA21ULL,
		0x952A7C24CAF4F3F1ULL,
		0xFAAB75931405E8A3ULL,
		0x4967BDA692F0AB1AULL,
		0x2DDE5C93F128422FULL,
		0x39DD10A3C04617B5ULL,
		0x28AAD3262516BA3EULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB3E8ACA8350C2660ULL,
		0x79CE303C262C6DCEULL,
		0x8FFA35A8343E1B5BULL,
		0x84BBA8ED16B3C352ULL,
		0x6CAD1E317556D417ULL,
		0x9E414B32E1E6AF7FULL,
		0x72FEA4D7720450DBULL,
		0x57A107E6430D60BAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC1A991C0CFA1F6EDULL,
		0xAED8817310466A15ULL,
		0x255155C00F3BE9A3ULL,
		0xF447D95BB7EBB328ULL,
		0xACD8566A050736C7ULL,
		0x326BA5F679A87F39ULL,
		0x8E9C6372DE51DF46ULL,
		0xAEB84FA3CB8269EAULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE6ADD2ABC1E643C7ULL,
		0x85B437B37A4E7A03ULL,
		0x1483B83F6002C048ULL,
		0x7B4F9D1294223CFEULL,
		0x7540950FB0407D0BULL,
		0x1D040628B13B06C1ULL,
		0x9CA17DF93D22004EULL,
		0x36086AFA59D22E87ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA42014A8B09F57C4ULL,
		0x7B9FE153AD992A4BULL,
		0x082128E13C7292BBULL,
		0x9290D0E33370A029ULL,
		0xB682A68D53D37400ULL,
		0xA02B3315662D1AEDULL,
		0x0346623442FAF5CDULL,
		0x25334FD23F3C56EBULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xB0582C4052E09CABULL,
		0x9D4390ED35358590ULL,
		0x07F2A969147D61ECULL,
		0x4FC18A91FADD1708ULL,
		0xF5C2386D40B70CBAULL,
		0xED30160DD670963DULL,
		0x2F7F2A23B17F1F0EULL,
		0x1A8D4207F5FE3CB3ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6444B944CDA3889EULL,
		0x261C2E9A1B8ADE92ULL,
		0xECF4E19B49A9728FULL,
		0xF91080E326FE9591ULL,
		0xE3F1406897292002ULL,
		0xABB311DA857BA320ULL,
		0xE68F50039C5C1B55ULL,
		0x8F50DA87A9AF1371ULL
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
		0xC2B6E532B6F45793ULL,
		0xB4D0446B1021078EULL,
		0x5F2D36938FAD236DULL,
		0xCD97066B7B9D4446ULL,
		0x965E75FC2AF905EAULL,
		0x516EAADC2EC32DEFULL,
		0x05C4604AB5E4E427ULL,
		0x6145BE3F9CC75CDDULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF44C2027A4E85876ULL,
		0x8F8A9124D73A377AULL,
		0xCC2D64AE68E7DA69ULL,
		0xC34640641F4E972EULL,
		0xE680428B3D31065AULL,
		0xC0296B813DDFA602ULL,
		0x723922EF352CF7E1ULL,
		0x4AC0ECBA9D26A67FULL
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
		0x5B83D085ECF8110AULL,
		0x2D80F89F14AD9A08ULL,
		0x8E6D6091086259C1ULL,
		0x2A5166A91A99944EULL,
		0xF62A7FABEB2E3E84ULL,
		0x7ECD2308D46DD2B9ULL,
		0xAA3BA747A927E5BBULL,
		0xB66316924B802917ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4A22AB27FE78FDB0ULL,
		0x3AD60B9C5CBC710EULL,
		0x4AB0C55717298F94ULL,
		0x69F3C53316BD0BCCULL,
		0x380185F59B9D5827ULL,
		0xCB051CC967774FCFULL,
		0xD9899383247E08CBULL,
		0xF9628EDF0EED4246ULL
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
		0xBCA838BEFE94C876ULL,
		0x40D14B1B04544ED5ULL,
		0x6239FD0C5B9CDAB4ULL,
		0xC2846CBE879B1F53ULL,
		0x37F222204A65E247ULL,
		0x2C96F7DF8C808883ULL,
		0x5910DBDFDF8245A0ULL,
		0x5E43B7CE6DFDE7F6ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xCB592EA7C50190FEULL,
		0x82ACF47CFBD562F2ULL,
		0xBD8993C5D57FE23DULL,
		0xC2047DB841CF5CFBULL,
		0x580D96A879F8B788ULL,
		0x78D9838B7FC75D25ULL,
		0x7DDE2AC0391BF0C2ULL,
		0x029D5185217C167BULL
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
		0x5B2171000E842BEDULL,
		0x094F1C0E68088180ULL,
		0x145733346ACE27B1ULL,
		0x6C0AED9BDB71843EULL,
		0x6B67EA5CE42E4801ULL,
		0x47191C4205FBC4E1ULL,
		0x89CF5C2382CA344BULL,
		0x86EA7F8A2BEE29C8ULL
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
		0xCBA7AAECF4D9CADEULL,
		0xBA1E05F631D01D88ULL,
		0xBE366CF311BD0F05ULL,
		0x59C417F6EE03CEEAULL,
		0xF5A30B940C27A256ULL,
		0x503081808DA97DBBULL,
		0x4B9FA9A286F8B357ULL,
		0xED9BCE52158534ABULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA5DA4D8D7AE856D3ULL,
		0xB1DE8267BBE958B2ULL,
		0xEEE8B3A892FF601DULL,
		0x2ACBEEB53A1FA052ULL,
		0x0204232BCB73EBA5ULL,
		0xFED06C62CB9FAFDCULL,
		0x7CBAEDDE66E61D1FULL,
		0x336892F17A4775F6ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB938C11395B84C63ULL,
		0xB3DF33AE0978F86AULL,
		0x9C88C7A64C042B75ULL,
		0x873107F09DA4CD39ULL,
		0xA22E49B6CFD14E67ULL,
		0xFAA52D6C85F0C30CULL,
		0x103DB55E087F57B1ULL,
		0x454F38A071EC05E7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6CD868C28473CA9BULL,
		0xE1A7D941265C6D80ULL,
		0x382ABCBE0C6C898DULL,
		0x02E55A0430FAB2AAULL,
		0x786E6DBCDB9513C2ULL,
		0x0E80EB5125B57CC0ULL,
		0x1F7983CFC050DF80ULL,
		0x7357C46329A51801ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x31153C3F38DF5B44ULL,
		0xE2CD77029C64A24AULL,
		0x56536EC879EF3E19ULL,
		0xE0B64E7BB1A19B11ULL,
		0x57FBB741E4880B5DULL,
		0x8347505BAAD76352ULL,
		0x33D0E9B4A13DA318ULL,
		0x66CAC57FF6D38CB3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x922F6886AAF68F7BULL,
		0x12C567117B8E3690ULL,
		0x355378B895D6CBD1ULL,
		0x68ACE8181C140FFEULL,
		0x7A37E64E7D34063AULL,
		0x626950B77C8A532DULL,
		0xC4AC74A868346615ULL,
		0x51913F9A7FB87FD9ULL
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
		0xB020BAC4186B4655ULL,
		0xE8A7F0A711C15ACBULL,
		0xBA9A719BF08AF84CULL,
		0xEAAD85E103E1FB77ULL,
		0x83B1D9BB38ACFD30ULL,
		0x031865794C846AF7ULL,
		0x90C97C4A49EFBF4EULL,
		0x69CA375D27FC1C89ULL
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
		0x365196877F825C17ULL,
		0x39B96AB11CE24FFAULL,
		0x73BBFF8AB6203D3FULL,
		0x9761B182DB8236DFULL,
		0x6F44D98EC858DE6DULL,
		0x361D754E1C4BEC62ULL,
		0x406B2F1C1A7C9CCDULL,
		0xF2044F8286EE4796ULL
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
		0xAD294B770C0B705AULL,
		0x28FF05B5C5A9913BULL,
		0xE883E92ABBC72C3EULL,
		0x54CD9F77A7974493ULL,
		0x2C7A400435606E89ULL,
		0xC823FA9F511915F5ULL,
		0x8180725B02C0B55AULL,
		0xFE3996C6202DD716ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x8C205AA4F912F33BULL,
		0x3DC95107B58747AFULL,
		0x2F1E872CF8EF916AULL,
		0x1A05DF0A1549AED1ULL,
		0x9D078F9F886753B1ULL,
		0x9BDCC9223A7CD91DULL,
		0x4430781E66D7C002ULL,
		0x0CA2C8512A0DDE72ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFA1447B964431E1AULL,
		0x74844C1CA25FB810ULL,
		0xB75BA31816DE153DULL,
		0x239137A1F183706BULL,
		0xBB4E1C2B0F82F501ULL,
		0x3494D7D99D3F876FULL,
		0xE55294A24FB2F8FEULL,
		0x2DDAEEBAC11E618AULL
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
		0x11C05253C71AE313ULL,
		0xFA99763DA11AE51CULL,
		0x02037B9484DF6B3CULL,
		0xD76CD7A4C957EC77ULL,
		0x0566114626E097F7ULL,
		0xB0948B6E86F7132CULL,
		0x58663A9296BF3F1AULL,
		0x9B80BA21E5ADED0EULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x502CF5EC2CE8549BULL,
		0xB10AC47F425FE087ULL,
		0xB3047E772B0017E2ULL,
		0xB0114C16FC28F00DULL,
		0x8744FFC3A161A815ULL,
		0xAAAC178DCF6A1764ULL,
		0x0636337F35227B56ULL,
		0x48B951488B0F03C0ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xA1CD7D9E635AFBB4ULL,
		0xE258EE3ED64D7A10ULL,
		0xFAB706C734C268A3ULL,
		0x6F7A32745D5EF257ULL,
		0x2C16EB5C4596A559ULL,
		0x25B34DE2FB50410DULL,
		0x82CA64172977DF2DULL,
		0x08AB64B3E3587BE5ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3544F5C87E961ADEULL,
		0x5B6CD007754C273EULL,
		0x211330451DD4A337ULL,
		0xF948E5CFD1DD5950ULL,
		0x614A37A9A29C6FADULL,
		0xFB45EF1C716A311CULL,
		0xBB5C350929D9CCC0ULL,
		0x40E811EBDCFD812AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE9817ED2995CC62DULL,
		0xAF4E38890CFB9AB2ULL,
		0x36F670C0A4AEB917ULL,
		0x5F3B33E2976E24F6ULL,
		0xE9D207320F161879ULL,
		0xCD96A486DB1673E3ULL,
		0x553833C57F6F8729ULL,
		0xE37B26794BFDFFA7ULL
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
		0x701E6F508D0E7F50ULL,
		0x9C0CD24D70848D16ULL,
		0xC502899478BF257BULL,
		0xB57B1F048DFD1D61ULL,
		0xF4BB4D7DD60E760AULL,
		0xF2A024349C8F524AULL,
		0x48CB5019CA1D849AULL,
		0xB469B810E810B8A4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xEE3C5D21315215BCULL,
		0x79E6650725F08C97ULL,
		0x9C2E93B53AE9704BULL,
		0xA6190ADB861DC444ULL,
		0x019A8847B030EA20ULL,
		0xDBDC5DBD634519B6ULL,
		0xF22C162402AF45A4ULL,
		0x3D640E91360267D2ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDC0B40227BDF72B1ULL,
		0x64630237242339FFULL,
		0x383D4806E0B7BC72ULL,
		0x6ADB2D879AB3C1ECULL,
		0xA841394247BA7E0AULL,
		0xD7E50727EFD77744ULL,
		0x489053AF08195DEEULL,
		0x7A56A7E44143F187ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBB85EEF4B98E3BE5ULL,
		0xAD352F520683D574ULL,
		0x092ACC6A292BBBCDULL,
		0x9EF994BA56216646ULL,
		0xAA8F995243054003ULL,
		0xB691B6148ADA308EULL,
		0x5BA397D70D54A11EULL,
		0x5DFCC25FE6AB232FULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5FB6975B2F1E78CCULL,
		0x2D0572F059678BFBULL,
		0xEA24305C53E22C9BULL,
		0x1D00CF79F5467726ULL,
		0x2F2F15B09572D817ULL,
		0x29BD074B873EADEBULL,
		0xF7EA66581860DBB9ULL,
		0x7384422BC1D9CE6AULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8730B223BA6B1B63ULL,
		0x26079C90CAFA21F3ULL,
		0x81B87B512D63A008ULL,
		0x4858FB1234A9F6D8ULL,
		0x461E5E27539CC8DEULL,
		0x800544E8ACAB0AB0ULL,
		0x6C03FB2A8BDB4ACEULL,
		0x204BBC856E4A8263ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB8DB49E413998DBFULL,
		0x286E911BF63F1E01ULL,
		0x350D0EA5F15F185EULL,
		0x536D32968CA50C19ULL,
		0x37A8B5B137042954ULL,
		0x4528BB06D59F465AULL,
		0xBC3CC80F4DE1386AULL,
		0xF9FE784436206918ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xD4F4EB888AAE17E0ULL,
		0x7A30BFE46C47C54DULL,
		0x2F0FFFDBAA7B587DULL,
		0xF740243A2F8B7486ULL,
		0x7FEF761DB47C09BEULL,
		0x4143BFEAE4C7F2E9ULL,
		0xDC7AFE32434AC5F8ULL,
		0x0B990540B68517ABULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xABB629CD2B03667DULL,
		0x16C1A0397C30304BULL,
		0x51F7A466AF70A631ULL,
		0x46674819207984A8ULL,
		0x7BDCDF8E29699B94ULL,
		0x45015C0555272B21ULL,
		0x870B0822EE0BC398ULL,
		0x91C27C2A26E1FD02ULL
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
		0x83B8E7873BB11C0AULL,
		0x70CE2A09C3D89181ULL,
		0x415A435DDB11C099ULL,
		0xD06B850BF542BC17ULL,
		0xA2C0F0E0837FD1F4ULL,
		0xA97ACEC37E22AF05ULL,
		0xC81FF0A2AD285476ULL,
		0xA0634FFC2EED543FULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x9F2D25852761A4B3ULL,
		0xB97A6FD58E234CE7ULL,
		0xBE5CD431F38316E5ULL,
		0xFD511657B20A85D7ULL,
		0xC1AD2026611E8CFCULL,
		0x7DA278C15AC43D3BULL,
		0x807F5594AD99B140ULL,
		0x1C442784C23D852EULL
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
		0x4BB705ECA12577A7ULL,
		0xF06C130F1CDE0073ULL,
		0xB8F94F1D5CD51CDBULL,
		0x732F56522614E8C1ULL,
		0xAB595EF68ACC7177ULL,
		0x036FA147C2E494A5ULL,
		0x12D4C320226DDDE8ULL,
		0x33618DF75771975DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x07D3548FF5311920ULL,
		0x2EBAA7B8A89BA719ULL,
		0x00AA4B3C97FA6628ULL,
		0x20B8E021B7D4AFC0ULL,
		0x6D3C37A63B5B9271ULL,
		0xA751FD9423457EF1ULL,
		0x9E650A66DCB374B6ULL,
		0x6DF3EDB2D3558AA4ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x95BFAFE5107E6911ULL,
		0x66AEFEC215A09663ULL,
		0x904CF6A5452C0D84ULL,
		0x59EA0B3CCAF8BF4EULL,
		0xCD31EA528B04736AULL,
		0xC88727E46DF9D71DULL,
		0x0C0CF6FEC557F168ULL,
		0x7FF6328FE675FDF8ULL
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
		0x70FFF5002BC6EC98ULL,
		0xAAD30D57B8C87342ULL,
		0x62855089B8680C47ULL,
		0x729C7931FC41ABE7ULL,
		0xF65ACF51087EDD05ULL,
		0x3925A02822F95C04ULL,
		0x8CC127BF41B18DC1ULL,
		0x9B1330A2C4507793ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x42FC376EEDDC1C36ULL,
		0xD5B785B7F1ED0AF6ULL,
		0x6564DB25F292CB90ULL,
		0xB0D27568A6B2D108ULL,
		0x25D2E5414E66EB24ULL,
		0x2A5CC21AA2980EA9ULL,
		0x26C305931E77536CULL,
		0x108675B9838D9689ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x70F44365B3A22948ULL,
		0xD1EF2CB73FDC9A19ULL,
		0x254049FE1391B768ULL,
		0x4CCC45C6E861FA30ULL,
		0xDE0F762C79DA488AULL,
		0xF2376246CAA75B1BULL,
		0x2A8857ACC6EF7EB4ULL,
		0x45E3F27F0BB12FCCULL
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
		0x06F4197946B113BDULL,
		0xFCD60BD253DD102CULL,
		0x7F3E4B6CFAA21C2FULL,
		0x2E6BAE5FA9B4CE21ULL,
		0xC0E63F44C228ABFFULL,
		0x12D101A324008248ULL,
		0xA1AC3748D48921A3ULL,
		0xE42783589D83C355ULL
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
		0x4E87AE759654AB91ULL,
		0xD7913F43E869CB05ULL,
		0x31A4B5F6404FA4E9ULL,
		0x9233FA410AB5350BULL,
		0x6238C9A83F2ED907ULL,
		0xAD274D7B2F085166ULL,
		0x2B0613977E27421FULL,
		0xD8B256530C4ED332ULL
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
		0x88101201D4AFAED7ULL,
		0x430720DE987F1201ULL,
		0xC9FE9EC38934869FULL,
		0x248F2D130282DE9FULL,
		0x7C599E249A203044ULL,
		0x6816B3D6DA479DD8ULL,
		0x6F7712B09ADAE3A6ULL,
		0x95CD626248EAFA19ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6AD501EDBAFD7516ULL,
		0x6631C23C5AF7B334ULL,
		0x12C2606D5D18379CULL,
		0x8420C8EE986BB6D5ULL,
		0x4B38F5A6F2DC88F6ULL,
		0x4E551E2046E07508ULL,
		0x7E7392A543E95FE5ULL,
		0x28A3492C437BAA74ULL
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
		0x731622DF3E198FB7ULL,
		0x357E5E6C73FD256FULL,
		0xE59DB4362FE4D796ULL,
		0x8B47AC002E34E039ULL,
		0x8BCDC9FD5341285DULL,
		0x6572E3BFEB23A0BCULL,
		0xA27AE554527AFF2AULL,
		0xFB943BA0F75D727CULL
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
		0xF3D32BBF2E55D414ULL,
		0xE6AE0B176A3E720EULL,
		0xD1D8FAC0BC059F71ULL,
		0x25BFFC872B58D053ULL,
		0x2DC6F581414A8C02ULL,
		0x1F37557692D09AF6ULL,
		0x3F0C4CF239AD643AULL,
		0x636F633583E24EA5ULL
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
		0xD534B409206BCCB8ULL,
		0xE0BA22B4AE5B1A34ULL,
		0x05290208647EA249ULL,
		0x4560972347D2B384ULL,
		0xC637DEAB16A92596ULL,
		0xB59C583131FD43E1ULL,
		0xBC07A2A063BC6C5DULL,
		0xA6C19FB167024AC7ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xC89E13CE379134B5ULL,
		0xFFF61847A0221CE4ULL,
		0x793C6643793F5C88ULL,
		0x02036F30E2FEAAF7ULL,
		0x363B0686FBB96954ULL,
		0x1194BB0DFE544AFDULL,
		0x7FBB2D5E85EBA106ULL,
		0x1946C9B18CF3F609ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4FB6D656E8C44D54ULL,
		0xBFBFA47240AA1E1AULL,
		0xFAAD8D8E75658E53ULL,
		0x4243E1777EF9AEB4ULL,
		0x9E477EA4A9F4C3C9ULL,
		0x7C1A8F9571548E6EULL,
		0xE3BA20757EEC123AULL,
		0x198F6713C32E596EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC91AA70CD49DB648ULL,
		0x8DC7B29FB90217FBULL,
		0x85EE0347FDC4CB19ULL,
		0xEFF6563138FF0237ULL,
		0x893753EEF9FBD032ULL,
		0xDAE36D9C18795360ULL,
		0x7F9FF8F376BCD70EULL,
		0xAD18BEA5F2A2FC7AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x621B909EC0A3996AULL,
		0x47D621036AA307FEULL,
		0x14DBE4881A0164A4ULL,
		0x08AAEF53C728F808ULL,
		0x65686999CAEBE9DAULL,
		0x77E5FC3902A1852BULL,
		0xE8614F384A763C6AULL,
		0xF5FDDE21E371523FULL
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
		0xDD6CDBC71290761FULL,
		0x45397C3C89BCD6CDULL,
		0x553385C8DBF71C34ULL,
		0x6CAD480D7976B92EULL,
		0x50C78701E3D34934ULL,
		0x5BED26A4F93C03C6ULL,
		0xB9F7B25573748C1BULL,
		0x024D0CD9E5927F7AULL
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
		0x5AC6F3AB3157A7F5ULL,
		0x08685EECAE83F901ULL,
		0x8A46A81B2F3E6EC0ULL,
		0x6A3F25BF7B14F473ULL,
		0x2497B8EA51DB5F61ULL,
		0x6AB98C805A2B30C9ULL,
		0xF2B498D061A04461ULL,
		0xC94B1A9858FD74ACULL
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
		0xEE814C62320A7CA1ULL,
		0xFADF3E8C0D27D57EULL,
		0x2D57662DB998D98CULL,
		0x0F442FE979A40D41ULL,
		0x41FA79EE58870260ULL,
		0xAE8224F5286F2583ULL,
		0xC55942B243F98F52ULL,
		0x377EAF7C8EEAF179ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x93C638F0598E037AULL,
		0x292C4DB48CF9F235ULL,
		0xCE56093CC1458190ULL,
		0x68B1884A4C93F3E1ULL,
		0xF75C1582C9D507DBULL,
		0xE6108084B73ABCC9ULL,
		0x0731004A2DFDD496ULL,
		0x54E71AC7757849A4ULL
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
		0xC6AB51780B974810ULL,
		0x240AF1A74953EF36ULL,
		0x8D8F477D3A5D38BFULL,
		0xF8D45A1B8756523EULL,
		0x66CB25552CF8534EULL,
		0xFE9A48716BCAE695ULL,
		0x7312B058C1E1441EULL,
		0xC7597A0C53D86B38ULL
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
		0x2237C466938C9962ULL,
		0x9F3094F5AE6ADB72ULL,
		0xF07C8EC463F10B57ULL,
		0x0E65C47BB1D4F288ULL,
		0xC1B5364294EDACFBULL,
		0x7C98EDAAB1C2583EULL,
		0xD279E67151B06B6CULL,
		0x73C2A5CAC97A986BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9A0E29C4A7DF234BULL,
		0x85C72A54D268064FULL,
		0x3EA64DB16CDC2DACULL,
		0x2A8C81D70FE294B7ULL,
		0x6823C28604AC4839ULL,
		0xD7BBD4FCC2852F6BULL,
		0x918846E92EE1FA55ULL,
		0xE6A71126A600AF5CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9377B736B33C88C5ULL,
		0xF4442E782E8911F8ULL,
		0x7A822173D76EDA53ULL,
		0xE66514903322EB72ULL,
		0x4274C4F6E241DE48ULL,
		0xD00D3601CECD3F38ULL,
		0x7BEBA18661BD03D1ULL,
		0xF9B829A2B9772C8DULL
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
		0xAA01822A7632F6B9ULL,
		0xF45741D499B0607DULL,
		0xD5B6BA2535D54BC2ULL,
		0x146BE274037E9B7FULL,
		0x66CEA89AEBE86569ULL,
		0xC0DACF974C18B060ULL,
		0x4538E2558685210AULL,
		0x14A5C44C12DEE100ULL
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
		0x90C8BB507CB02411ULL,
		0x017E531596DC0837ULL,
		0x50612FA04E272E8DULL,
		0x4760C98B6E092996ULL,
		0x8CACC678176A4DA5ULL,
		0x5400FBE7B84CC487ULL,
		0x44BEA0FB0E79419EULL,
		0x97F9E8B8435BE461ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBF7B0456B63CFBBEULL,
		0x256B7515313D322AULL,
		0x1F045AFB4EF5A4E3ULL,
		0xC90310599DE29BD4ULL,
		0xF8A4C772FE1E08A8ULL,
		0x72476E9B19087AC3ULL,
		0xBA94F961C3C7287CULL,
		0x95A2AFDD67CA2009ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xAD530E73CAEE9929ULL,
		0x488378A66331FC0BULL,
		0x191392FB7CA8B3FBULL,
		0x3CD2FDBAC859E16FULL,
		0xB8A1889FACABC1AFULL,
		0xB850ECA72F2CD362ULL,
		0xE9D314567BEACE1AULL,
		0x3460A12469D9D5A9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC00196D9A252FF91ULL,
		0x9CD7076246AB10E5ULL,
		0x9D5CBCCDA14F1F8FULL,
		0xF6E5A3C70141A019ULL,
		0x7204E9FA44995F4AULL,
		0x34FAF57C214200B9ULL,
		0xAA398B1013DDBC8AULL,
		0x4D807E62E86911DAULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB25669FC2F021F44ULL,
		0xC49ABAC25165B0A4ULL,
		0x97429B265292CAB1ULL,
		0x587F3AC98A2FE5A5ULL,
		0x607D7BC58220C956ULL,
		0x64CD15A7672D585DULL,
		0xAE4ADE73605008D2ULL,
		0x5DDF878A86EF35CAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x522A744A58117327ULL,
		0x7ECCF40B1BAD9733ULL,
		0x7F52F65836D45B70ULL,
		0xCF82548188F30285ULL,
		0x930053E635F81842ULL,
		0xB1093C67C0F3C2C2ULL,
		0xE1555C976674F2BBULL,
		0xE2A424636CB4DCABULL
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
		0x136431DFBD6E0BE1ULL,
		0xF3EB66E2C06E1980ULL,
		0x2670168F8F6C03A2ULL,
		0xB9FA905D52CE0019ULL,
		0x82BF5042140F3C74ULL,
		0xACF146BBE07D1DF4ULL,
		0x34F0D171D6171452ULL,
		0x63A657151C118ECFULL
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
		0xC4112B7188659653ULL,
		0xD715C44EC56B6211ULL,
		0x723D4BC15A1A211BULL,
		0xC57084EA71C029C9ULL,
		0x6C922908EEF21914ULL,
		0x13F4A8A08D76A551ULL,
		0x36C43291A803BB05ULL,
		0xE60B16C2CAFD3728ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB593DAA9A9D89EFBULL,
		0x3BB9A9B3D7E39ADBULL,
		0x9C3AF8D48AA61392ULL,
		0x41EAB6B1968BC03BULL,
		0xA04EC94153F446B9ULL,
		0xD46BD1BD32910FADULL,
		0x5891442216721E49ULL,
		0x76E57D7CDC2B81D7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xCEE49D6D3F546C49ULL,
		0xB6C513BCCED734FFULL,
		0x979AEB7F0F989D38ULL,
		0x57D4EC8409475BC8ULL,
		0xB0241B47FC0C4327ULL,
		0x543ABA224A3C18B5ULL,
		0x0555B5FE684D0B62ULL,
		0x664803A3B5B865A3ULL
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
		0x4C9B0A8B4149F55EULL,
		0x6A37B8BA5FAE1BFCULL,
		0x439EDE9D923014AAULL,
		0x9A1C8C4B3036A6BDULL,
		0x6452959423B6A6CAULL,
		0x4781B5E451EE047BULL,
		0xF9F69CEEF382D63FULL,
		0xAA86301BBCAFE50AULL
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
		0x9EEBA0F4141A1954ULL,
		0xA1E539E2EDF64093ULL,
		0x943026BA5B6350DAULL,
		0x4783B72E5346A33CULL,
		0xEF72F595A2F8128EULL,
		0xD0B0DAE9593B3F7DULL,
		0x9B4722900DB533F1ULL,
		0xF1B4B6BC712337A8ULL
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
		0x97DA6D5DD057C639ULL,
		0x076E1193F77DA01CULL,
		0xD6330E3C488D40D2ULL,
		0xB72D84DE0D213129ULL,
		0x4DA554DF6CD248C8ULL,
		0x8D79D45CB70C7B5EULL,
		0xD4D3AB2F8424DA2EULL,
		0x5C4CDADAAF9DE9A6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF606B8BA073F803AULL,
		0x09BCC064B9816B26ULL,
		0xBF8B48519E3D5774ULL,
		0x0D9A1D3336E9053EULL,
		0x02BE19483095E434ULL,
		0x93B2ED06FD416DF0ULL,
		0x5D3FA060662E5B61ULL,
		0xBF1CA45AEE1B6D70ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA46C67F3AD1D0E21ULL,
		0xCBA05DBEF4807A87ULL,
		0xDC0B76D81FDD2DD7ULL,
		0x5041EE878F41255DULL,
		0x8C247744094AE297ULL,
		0x60484069A06FDF21ULL,
		0x7D47C3F462F936D2ULL,
		0xE9950F62B538094EULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD0643CA299BB727FULL,
		0x735E0008EE91285FULL,
		0x85C0F0A4261066D7ULL,
		0xAB0FFD88F05D1F7BULL,
		0x98EB912E377C2CA3ULL,
		0x9C18DD7716E1FC03ULL,
		0xA5138EB79ABFF84AULL,
		0x548446D8BD7A176DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x96B86EED53938F36ULL,
		0x43CF9F0FDCBCA3E2ULL,
		0xADC3CD45F594611FULL,
		0x1F6980066637F109ULL,
		0x884977B64C703A49ULL,
		0x46E7A9E3A67A3460ULL,
		0xA3E2079B4137E034ULL,
		0xFA148D85BD107F44ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xA791A9745716A906ULL,
		0xA5A6C8F674F888A6ULL,
		0x9879720384192EA8ULL,
		0x5DEB51B8EC2962F3ULL,
		0x25C34EB7F8852BA8ULL,
		0x2E8926BFB0D8D74EULL,
		0x66ECD2E748209CEBULL,
		0x022B076E6E8A6A65ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1DDE1FC07B55C4E7ULL,
		0xE74C40D8D65B30BBULL,
		0xDCF2AE9C3797415BULL,
		0xF3DAF49D015E68C0ULL,
		0xC79A2E915CB440CCULL,
		0x380BF4D210094238ULL,
		0xB76067977BFDC76BULL,
		0x3B836E272ADD9660ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5DFA40EB5D9C0AADULL,
		0xB9A15BC81CC24137ULL,
		0x1B46F42FEA4578C0ULL,
		0x7AF77882B5E7902AULL,
		0x484EF24758295031ULL,
		0xCF9CACDB70B79C07ULL,
		0xAC08D3EF218C1814ULL,
		0xF975937907ACF8A6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF3ED6632F689F28AULL,
		0x9D9DE52020984D36ULL,
		0xC2D23E354C6EEA5BULL,
		0x22E5A7EF0EF672CAULL,
		0x0269106225153745ULL,
		0x0BFBF0C2B2B52D17ULL,
		0x21FA6DC5816CDCD4ULL,
		0xC1D7A15C2BF2BFCDULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3474CE10007E3059ULL,
		0xE1343FA7746F3A61ULL,
		0xD6C5242591E6901BULL,
		0x36A4D51BCED65C26ULL,
		0x97C660E584E22F26ULL,
		0xF9B4EF04B92A4E9CULL,
		0xDE7638095A2D0C18ULL,
		0x46476500BC1E4492ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF1997E3CBEA0C924ULL,
		0x6CB75E043215A21DULL,
		0x6C80B8ED15D000DEULL,
		0xA6F872E59EE28D96ULL,
		0xA9D7D1B4C896C64BULL,
		0x6CD05E7682E74DE8ULL,
		0xA3610B4D9556BB92ULL,
		0x35D52FB1B0AB280FULL
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
		0xB574B60156438952ULL,
		0x1F5AE6F4CD9616F9ULL,
		0xB1CA33E210141839ULL,
		0xAC132ADC7DE8F25FULL,
		0x49EE4E91B90754DFULL,
		0xD42984BDF4BFA1EFULL,
		0x04E0E417A144DC33ULL,
		0x497DACAE3A7E0718ULL
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
		0x348AA4A6C3647F17ULL,
		0x1867272D733DE7E9ULL,
		0x5F1977D38DA7A556ULL,
		0xED3B5140A0F7DDB7ULL,
		0x6E3CFE9EB96C7610ULL,
		0x6B663596D3733B8DULL,
		0xA80FED24764F0982ULL,
		0xF37F1CD13F4ABAE8ULL
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
		0x857A1B2E7E45ACA0ULL,
		0x54CA014B482D217CULL,
		0x6424FA96B63F7BE0ULL,
		0x1F3ADCD25A2978ECULL,
		0x804080FB334F643FULL,
		0x20DDF1976A18D363ULL,
		0x62E4AC8039649BC9ULL,
		0xB36BF4AE9DE032FDULL
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
		0x0E14DE5A0BA04E1DULL,
		0xA3316A4326BBFC22ULL,
		0x243D18A188C082D4ULL,
		0xAAAA6A4FABC1E160ULL,
		0xA884AFBD55333E31ULL,
		0xCB1D694CA05253FCULL,
		0x57D0C4B3945B02B1ULL,
		0xD54F8C8645C72CCAULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x76D901A613D4B4F3ULL,
		0xB572F0E54C838B2EULL,
		0x850A29481EF6E71DULL,
		0x885F9E7F62D3AEC5ULL,
		0x18376B54ECB0480CULL,
		0x69C9B4E3A55B7B8AULL,
		0xCAF2C8C7DB1AF2E5ULL,
		0x1A8E29776CE13E6AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF2E3EF1A545AB81CULL,
		0xAD58B94D952E1FA1ULL,
		0xFF75FE7E4289971DULL,
		0xE19BF4603367F120ULL,
		0x10BF20D43568BC91ULL,
		0x08915AB89CAB392FULL,
		0x29657CC38A56C052ULL,
		0x59DD6973C884786BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x13312EAEB673E47CULL,
		0x8AA2CEAB0D83139CULL,
		0x224F0F09E5C4AC95ULL,
		0x28DFD0D445AD0748ULL,
		0xC14D913E5D933B58ULL,
		0x12A02F6F25FD5ED4ULL,
		0xF0236802FA5CAE5AULL,
		0x5C8BFC5ABC04A416ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x8C739CB72C3D2AFBULL,
		0x3BCA10047FD1737DULL,
		0xD1F38FC8542F6243ULL,
		0xF2DDA82DC2C85F5DULL,
		0x591C750E889B94C2ULL,
		0x3A935E1264CA3301ULL,
		0x036E3BAAC110A3F4ULL,
		0x0D999B865C8339DFULL
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
		0xAAC99BA2DEE2FB9FULL,
		0xC4D70BF819D873C4ULL,
		0x053DCC0C1DF73761ULL,
		0x73A40645C2A0D7E6ULL,
		0xBD73000DB8FBF304ULL,
		0x1A571D58EFD6BFA0ULL,
		0x3B4D956B223BF57EULL,
		0xB572662736415121ULL
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
		0x016B620F8D53F620ULL,
		0x7E46139F2990A15DULL,
		0x8A8166192EEBF9B1ULL,
		0xEADB1921F9E85D6DULL,
		0x86486F80BB3632ECULL,
		0x65CC3D0D8B049840ULL,
		0xB13BC69C1717DA40ULL,
		0xCF3151DD90EB5232ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x09C916E0D68E84E5ULL,
		0xA0A1680B05681FA2ULL,
		0x3A12A9A1377B4F5FULL,
		0xE6DE88B10198A575ULL,
		0xB4146C5CCA683447ULL,
		0xF1C5CDFE184AA9E4ULL,
		0x976FB30C8530F512ULL,
		0x126F799FB2879CABULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x06FF5EC37126B504ULL,
		0x4B389BBB5E741AE2ULL,
		0xAD54DA3929FFE739ULL,
		0x5704DCB9513938D7ULL,
		0x826FC356B254A5A7ULL,
		0xBF2B67307B5DDFAAULL,
		0x95A5BFFD25776AEBULL,
		0x4E3724CB6AAEECB3ULL
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
		0x2B4FFF9601A44E2EULL,
		0x6A713E869BEC5747ULL,
		0x739249A0B49976CFULL,
		0x0F15D60E9946BACAULL,
		0xEF71AAA14AD17CBEULL,
		0xE9B79EBA7F764A60ULL,
		0x78B7D3E81F3C6725ULL,
		0x70E27BBCBAB3EFD8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6D98A990F9A2479FULL,
		0xF83D124788A86F20ULL,
		0x0E15977AB8564943ULL,
		0xD94786BBA941A28AULL,
		0x84D2747F1E5A699CULL,
		0x5468958BB1D1C326ULL,
		0xB465E36FAE63E1DCULL,
		0x86A0EDEA3CF70AB1ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD7367D0C3C8568C8ULL,
		0x38E9507533E75FC9ULL,
		0x8354CF5DC74C34EFULL,
		0x7630C6DCEFEDF954ULL,
		0x19EC6DDBD8987B43ULL,
		0x38A694E8C35DB08EULL,
		0x63B0314404BCDF7BULL,
		0x23FAE4466B5B04CEULL
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
		0x5E3DCC098BB23B16ULL,
		0x3664398561EC08AAULL,
		0xAE8F201CC9645930ULL,
		0x8F2DCEFD4D344D07ULL,
		0x669AE41F12C65470ULL,
		0x2846DACFF6C4602FULL,
		0x1B56E3D6895B0F43ULL,
		0xE6085D4D60827BD4ULL
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
		0xE4812F931F09D7D4ULL,
		0x8D4A9AA8E587B503ULL,
		0x312CA33679EB009FULL,
		0x8DDAB9AF408B89FBULL,
		0x6097F3406D892BDDULL,
		0x08F41E9888FE42D9ULL,
		0xE9FFD1486F15438DULL,
		0xC9C935F3C0527E97ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x876D922CED7CAFEBULL,
		0x26281E199F82A53AULL,
		0x1E4E50008857489EULL,
		0x23890F18B6B30F26ULL,
		0x90E804E32D091281ULL,
		0xF7739BA767C635D8ULL,
		0xF3510701A0586221ULL,
		0x2765CA7E2ED4CD6DULL
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
		0xF406E319FFA015FCULL,
		0x421937E1FCED122DULL,
		0x01830D92AD95F0EAULL,
		0xFDAFFE80F0D2B94AULL,
		0x08C8051E811FF6D6ULL,
		0xCFC510A13ABC0A17ULL,
		0xADE8CB89771CEF0FULL,
		0xAC9AE5C76BDEEF78ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x1AF207C03DF6322AULL,
		0xA6406A7403308AF3ULL,
		0x80BEFAA1258426C7ULL,
		0xC649DD52494D52F7ULL,
		0xAD64CA944A840036ULL,
		0xD72EB0377E14BF22ULL,
		0x753233E0C2697467ULL,
		0x31F110B0299CF1B3ULL
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
		0x5EA44794DAC61ADFULL,
		0x8A95A10F020B4374ULL,
		0x3C65B5F2A1D8B5A6ULL,
		0x8293B42FD8F5AC9CULL,
		0xEDC13D51621DDA70ULL,
		0xE3C22D2FE01194E4ULL,
		0xFF16DE16DA6F600FULL,
		0xD283AB75CA551925ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF159DEE465099861ULL,
		0x16F9CB21267C2E72ULL,
		0x089327F8F1CE4357ULL,
		0x8541C4CF101C8448ULL,
		0xB174874D642AD0ADULL,
		0x95DAAF8196D7C534ULL,
		0xC94ECF6ABCD6CE9DULL,
		0x915B893B14BB6B7DULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xD55A4BA40B0AB7F9ULL,
		0x0B40E28B72F22D50ULL,
		0xF64F6AF47238139EULL,
		0x7727CCAE7D4F8706ULL,
		0xE861C22A86D34DC1ULL,
		0x2415111418AFEB84ULL,
		0x270BCCFB57B7B093ULL,
		0x0AF6E0A1422B51B9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF93CBB9BD6521E56ULL,
		0xDBF3BD0634A0FE56ULL,
		0x00CB28DE8024B87BULL,
		0x562ADED532A337FDULL,
		0xD165C001F14168FFULL,
		0x33116C6ECA81A710ULL,
		0xF18894A1A52830C8ULL,
		0xF06D6DD10FDC3560ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBE7F338F0C63436CULL,
		0x039610B7894F33E5ULL,
		0xA7B18198291A05B9ULL,
		0xAB07852B3D0BD98DULL,
		0x0757904B31565A10ULL,
		0x6CFE4548EEA5A475ULL,
		0xA5D248AC0A0DEB59ULL,
		0xA4BFA9BF21118DA0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD7B3838A8C9502D1ULL,
		0xE8B5E98F2C811D2BULL,
		0xAF69CE29373BE4F7ULL,
		0xB37D23C2786B42DEULL,
		0x4DF6E33093079F8AULL,
		0xBB6653136F25196EULL,
		0x112D2559F612D995ULL,
		0xD07D3166A78E9508ULL
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
		0x05AED4B87BDC94BCULL,
		0x04F55EE90C4E1DC7ULL,
		0x5B611E3C6FE9404BULL,
		0xEFB11ED6706C5C67ULL,
		0x9AAE6779BAB6C8E0ULL,
		0x4F58C83AE0F43EF4ULL,
		0xB583B58DE2D9290BULL,
		0xA0608712EF0ABEC8ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x07345187B2B4A606ULL,
		0xAE5C24A8BEE35178ULL,
		0x3F1D9532296A01BEULL,
		0x702C6A4570BA07C8ULL,
		0x6E0A6B014F990534ULL,
		0x7E2A19874E931025ULL,
		0x7EFA1D1C14E9E211ULL,
		0x7466F2028C2B27FAULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2F0B906FEB7AD83DULL,
		0x55F7C7AC270808EDULL,
		0x8BF005F5839199FDULL,
		0xCA8863600F48EC57ULL,
		0x765EF1367A7CEA05ULL,
		0x62E9418C6663AC80ULL,
		0xF124B839D9EC635FULL,
		0xF8A67DC7AD928701ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0FCAEEC902D0D208ULL,
		0x40D0AD73CBD34AC0ULL,
		0x83344017AB0C0E5CULL,
		0x8F0898E3BB3E20B9ULL,
		0x27B4D6F7ABACA12EULL,
		0x97AEB996AC3EDA4CULL,
		0x33BB12C25C638DBFULL,
		0xFA9CD881BC502A0DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x78BB17C96AD5358BULL,
		0xC8E57F3FCA18E12BULL,
		0x9D91FC499DF730EAULL,
		0xD1409EDE3C354E7CULL,
		0xC2D7CB3897A044BAULL,
		0x8CF69DB44F2F4CA6ULL,
		0x186A74FCCEAF3FDCULL,
		0xCFDB30BFA9F018D3ULL
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
		0x487E89A1C0A3D382ULL,
		0x8D3AF493BB8132CEULL,
		0xE93AA56B7D88B17FULL,
		0x1F7BF5A231D055CBULL,
		0x039D9270120918D2ULL,
		0x945A1FAE7CA359AAULL,
		0x5A32DF35B6AD824BULL,
		0xB44FDE4DB305FF06ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x188B9BDC434F7E67ULL,
		0xE0A3F5C8938A88F2ULL,
		0x0375F8892E4A0BD0ULL,
		0xC22D5FA7E0B0A9A5ULL,
		0x718F3F2B3386C2C1ULL,
		0x8DB7E4C9CB3A3B88ULL,
		0x36242131147CB80BULL,
		0x30CA651259E72CA9ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xB6BEF6EC96ABF458ULL,
		0x4B89C1E29494DECBULL,
		0xE38D972951C39A42ULL,
		0xEBE6DFDBD255E490ULL,
		0x31176D5D9031D9E8ULL,
		0x0B499ABD3912114AULL,
		0xE9A8F3EEF32DEDA8ULL,
		0x3DBDAA0B541DBF40ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x33281CC83F3A20F9ULL,
		0x84EA868B558A80A2ULL,
		0x1E5375E92BD8AB52ULL,
		0x62B2F6CC010D0A55ULL,
		0x43AD25D7727FD40FULL,
		0x9373BAA859104BA7ULL,
		0x3F38788544ADD6A4ULL,
		0x49DB3A873EFABBC2ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x40FD394CD9C16C60ULL,
		0xDB2F22809CECBF77ULL,
		0xB2E674742E3FADC2ULL,
		0xF40918B2674F4993ULL,
		0xEEA77373D39EA158ULL,
		0x072E28DEF93F0C07ULL,
		0xA42AC46DDFFC2C90ULL,
		0x093F993AD74B20B7ULL
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
		0xB4E325E36D825B7DULL,
		0xCD87AAFABE6B875DULL,
		0x964C510435917496ULL,
		0x142F4052EC555965ULL,
		0x2AFEABFE7A4FFD88ULL,
		0xDF3E243D45F8E14EULL,
		0xB3EAF78D7DFF4C19ULL,
		0xB8D657A1F04E84D6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF44F66549D10E2BBULL,
		0x75DEA14D3A8B4282ULL,
		0xE935BA3AF36B54C4ULL,
		0x10929ED902EFCB98ULL,
		0xD04CDFE4D62AAFA5ULL,
		0xF0A63446A84724F3ULL,
		0x02A630DA227E4B44ULL,
		0xC9EEACF63719062DULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x4DC8D6A9D4182868ULL,
		0xA5F3035D4E215DDFULL,
		0x18D54B147D3E03F9ULL,
		0x9DA04B20443B8D78ULL,
		0x6061D97601C005A4ULL,
		0xB53625AB8FA02B6AULL,
		0x88FEC3F8C25DA0CAULL,
		0x1469C768B72DD3DEULL
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
		0x43F0379F064F78E5ULL,
		0x7907E9E2797D7397ULL,
		0xC1C9ECE2567F1D78ULL,
		0x265F7861FF97CDE2ULL,
		0x1EAEA50F6AEB3CF5ULL,
		0xBC4223A32524934FULL,
		0x94F1629864E7F223ULL,
		0xD45C52285FDEA905ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1EFCDA0E30F318ECULL,
		0x0365B1045B5C1B7DULL,
		0x26FD8D2E88B0B7FCULL,
		0x848AB33FD22C0A91ULL,
		0x58DC70EAABC4E194ULL,
		0x52055C8451468245ULL,
		0xF822FB9581D73EBDULL,
		0x66CFBDD656B18A8EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD4DE810F22B09179ULL,
		0x49FDDF6AD791AC92ULL,
		0xBC332A36DB735299ULL,
		0x1BF15527A9E9D882ULL,
		0xD632C691C2EA37B3ULL,
		0xB23F1495A0DF1FE0ULL,
		0x98DDBB7D054C078CULL,
		0x269100FCEA28CDBDULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x486858652A38E64AULL,
		0x2D0B80D3648F56BFULL,
		0x3F795A7035F3A2CFULL,
		0x8D977282C81BD9E5ULL,
		0x51546B6D1738D040ULL,
		0x6627E249B4EB44B4ULL,
		0x2F666CDC33DFF935ULL,
		0x71F0C5926AC1CA2CULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x77A7A9429D462929ULL,
		0x52239E6494894450ULL,
		0x6C06844D311A30B1ULL,
		0xE5446C5E53556FA6ULL,
		0xF236AE95FCA19D1EULL,
		0xAC563F4876EA7593ULL,
		0xD695D786BAB46503ULL,
		0x0CA48F8BEA56C402ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x213D28A33A0291FDULL,
		0xFCD49E14FB4CB538ULL,
		0x6435681C0EC6770EULL,
		0x189CCCDC954C5A9FULL,
		0xF7FBD2CD872A745AULL,
		0xFDC5EBC951273789ULL,
		0xC8A08DA90A0166C0ULL,
		0x508B51ECC803720BULL
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
		0x4A1B401E682F3015ULL,
		0xDB58E68E53604150ULL,
		0xE0905292F9AD4298ULL,
		0x2551E91E0787238DULL,
		0x2FC164133DA539BAULL,
		0xD9B1A6539DDF4461ULL,
		0x80D646FC6C542307ULL,
		0xED11AC17F2367AC0ULL
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
		0xD4D750F630C1529CULL,
		0x1DC882625ACA025EULL,
		0x029DC280E572C131ULL,
		0x060136F9DF9114C9ULL,
		0xB39C51FEA76C4522ULL,
		0x9B8D1852E31E0779ULL,
		0x8B0B7472FA31A975ULL,
		0xC6711612D46906CEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xED6F57D263F37D85ULL,
		0x7A428725110AE144ULL,
		0x00B5D9E44E425EB2ULL,
		0x6948367D2768FE8CULL,
		0xBA0389EF303D9564ULL,
		0x64A266340D6E3ADFULL,
		0x3504B05733381943ULL,
		0xE1AE8BFB07A915B1ULL
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
		0x28E399A3E990778AULL,
		0x65AFEF99135DA634ULL,
		0xC133F1C73754B3CBULL,
		0xF2D1BB40A3F58E0EULL,
		0x641A9B59582947FEULL,
		0xE1F88B25FC860BB7ULL,
		0xA2621B36DAFEC26AULL,
		0xCA0BFC2E9070FA69ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4EEF41F2BDA0F6EAULL,
		0x6E5B35CFF15C493EULL,
		0x8ACB59FE89D2E49CULL,
		0x3CB96A04EF3EE3CEULL,
		0x7222B3FA2C7FD277ULL,
		0xCC7BD90E8C2D6AF5ULL,
		0xAE9CC16A144A462AULL,
		0x86D41F3C2682DF37ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xBFB994BD8ECA3C6BULL,
		0x9B86C1DF479CB368ULL,
		0xF446D293FCEFC31FULL,
		0xD8DD47DCA1AC5C05ULL,
		0xFFDEC079DB7537A5ULL,
		0x11113B040154DDF1ULL,
		0xAE1BA4BAB03B6505ULL,
		0x61665DDC9BECFF2AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC59DDC7C83EC706EULL,
		0x57F9F0FC6835205DULL,
		0x77EE1B56B7170D20ULL,
		0x9E59F80D5C0C111CULL,
		0xF17E45ABA1B81DE7ULL,
		0xE34B7F41B78470B7ULL,
		0x0DA3B030BA13A798ULL,
		0x83CFD75A747647B0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3F88B7455AA8976BULL,
		0x95798B528C65EEF9ULL,
		0xEA48516194873745ULL,
		0xF8C915010980C8B4ULL,
		0xBFAD10B4317C1B1BULL,
		0xDB4AC7244907EF48ULL,
		0x7562F61C722C275EULL,
		0x7E2F64621183AF6EULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x73D5D231514814FCULL,
		0x2D7BE8FFBAC1A76CULL,
		0xA44D7905C5C7D49FULL,
		0x033857DB45BE0A2DULL,
		0x020506EA0F8257E9ULL,
		0x8C15AA291A11FF1BULL,
		0x8607308B9544FB21ULL,
		0x5BC08D97CDA6B0CFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDA9B41359BACED0CULL,
		0x8DDCAF1AE9F49705ULL,
		0x5C0BF04440CBD0D5ULL,
		0x60FC6086041BDE89ULL,
		0xE2B698B107B962AAULL,
		0xAC69C6FC886CEDE9ULL,
		0xBF35206AB8975AB9ULL,
		0xD82EC548A670423EULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x900FB0D95C065505ULL,
		0x91E62B9E3E2B5EDBULL,
		0xB7CDF960AB77B41BULL,
		0x34D2FCEEC596A55CULL,
		0xBC77D416BEDBA67EULL,
		0x94ED4B5F5BA84223ULL,
		0x950C351572B5A2A2ULL,
		0x32EF6D3ECE641D4AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x44A246BB40B1DC14ULL,
		0xB3E175B903E946ABULL,
		0xD8B91D3E0A2CF2B4ULL,
		0xE08A9EF9B9248FECULL,
		0xDEFD3741CCBEB7E4ULL,
		0x3EC407AD67DAA7ECULL,
		0xF985008349D3A5E6ULL,
		0xF9970EE4B85BA88CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6CF818A9FE4CE6D3ULL,
		0xD64842A40A32E458ULL,
		0xAF9280E04A905C76ULL,
		0x7609CE7DC42C03D2ULL,
		0xA6A8A9CCE7FC396CULL,
		0xB9B01077CF3D7621ULL,
		0x8143A6370C0928EAULL,
		0xAA07DF0D091EBC63ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xEBB1ACA4DCF65DE9ULL,
		0x56BBF48061A5CC39ULL,
		0x0EC3010964A97501ULL,
		0x3AE1768C3665BF91ULL,
		0xF50F1B1C38018BFEULL,
		0x83B41F0AB7010D8CULL,
		0xE3EE13D117D1D491ULL,
		0x70A977DD1199BAF1ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9D7C6E664F607C4EULL,
		0x694ADFED590E2F91ULL,
		0x3F109F5C11639375ULL,
		0xC7F6B1B549D108A9ULL,
		0xE095F4394468D0FCULL,
		0x473FA956C3C25ADCULL,
		0xEA5C75107396572FULL,
		0x803F650537E0D224ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBB6F75FE636829DULL,
		0xE6BD119132327950ULL,
		0x6622A9CA9DB47009ULL,
		0x0C23033FDEAAD0FCULL,
		0x33F50A992401DAAFULL,
		0x438764CC432B7F08ULL,
		0xF88D8274400AAA8EULL,
		0xE8D74ED8D90C724DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x48A940084ADF92B7ULL,
		0xC57EC2E744B5724EULL,
		0xCF85FAC4F9898098ULL,
		0xF6332E9D42A7CD26ULL,
		0x3C7B92167BFB37AEULL,
		0x3B0318947B549AB2ULL,
		0xE020189CA4BDD5D5ULL,
		0x877C847A11FBDA25ULL
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
		0xEE8C0BC78E187C33ULL,
		0x5973DE425A1EC923ULL,
		0xAF9B61EFD2AADF0EULL,
		0xE01AF0C6F255DA08ULL,
		0x4A3EC7EDD322CE26ULL,
		0x7BCF2346DAA6FCC1ULL,
		0x8A9ADDF2B1033FF7ULL,
		0x6AC58617E5A65257ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xB12217662FDBB250ULL,
		0xE95D6CA3860CF386ULL,
		0x2200874EE68F7799ULL,
		0x5EF0CB36CC02B22CULL,
		0x217B6AB169B5CC6EULL,
		0x88377B087C9EBDBFULL,
		0x5C23304D9367CF47ULL,
		0x59AA6DE1B127F758ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0D05AB5A85A40917ULL,
		0xABF9ADFB2D5161C5ULL,
		0x1C9DEF8360C6D812ULL,
		0xD69664E4CDB8E3D7ULL,
		0x8557DDA8901482E1ULL,
		0xC04FB26A8C1BC9C1ULL,
		0x7FC651A99E040C06ULL,
		0xE830D3AB8333E170ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEDE30D8A871890D3ULL,
		0x012EB146A5AC634DULL,
		0x6081CA0719898342ULL,
		0x007AB7D44D6D2844ULL,
		0x1AC1C6C2ADCAACFFULL,
		0x4B6637877D69017EULL,
		0x63E147AB09AB7BE1ULL,
		0xCA9C23670F195350ULL
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
		0x023200089061AFE5ULL,
		0xD9311E36D9297EF5ULL,
		0x8FC39A6382969D71ULL,
		0x13A07C2CF93EBAE4ULL,
		0x1E690CCE95B5761FULL,
		0x9268A88B7ADAC28AULL,
		0xEB39ACF684203786ULL,
		0xADDEAC5A70082BF0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9DC930626EFBA125ULL,
		0xBCB6974F73D74F7DULL,
		0x467EAEC10F35BECDULL,
		0xA6BD928C1EC8693BULL,
		0x35BC5DE807F02FFAULL,
		0xFEFADD6C571BA3C8ULL,
		0x8B63B435F3BB64BDULL,
		0x8329BAE460301C1EULL
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
		0x23D83A4AD19BEA78ULL,
		0x5647C9F9F6445CDCULL,
		0x00336286E3F29ECBULL,
		0xD581346C6562A0E5ULL,
		0x5D7B15F98030390EULL,
		0x6C4BBCC5669C1260ULL,
		0x6550B06A4777E29EULL,
		0x30B2A2AF4C5E8462ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xE46D722F401C17DAULL,
		0x09875B27DC0F2343ULL,
		0xE3A260086EEC0BB7ULL,
		0x12FBFE518B828C89ULL,
		0xDD8275AF69357258ULL,
		0x935316E77923B096ULL,
		0x78A68F3EA2A3D350ULL,
		0x07B3F3FFCC98ACA6ULL
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
		0xAD7857536E7BFEDEULL,
		0x364AB3E49BEF79D0ULL,
		0xE97E1D11978C54A2ULL,
		0xF6B982F0837E48E9ULL,
		0x3D0AF86FCE3AD415ULL,
		0xE3F213C7D88E74EDULL,
		0x5509137B69E5E752ULL,
		0x884CDA92F8894F58ULL
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
		0x86A7207249179FD8ULL,
		0x4D3E0FE7E64497E0ULL,
		0x496AFC0A6D7DF1E2ULL,
		0x3F7EFB54B0DA70DFULL,
		0xB4E59F8A31D566D5ULL,
		0xD3E52FE069C49615ULL,
		0xDDE70EB6E48C8319ULL,
		0xD50F5F9B0847409AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xE61F83D4E2FEA3B9ULL,
		0xE5F998333FF353F0ULL,
		0x0FA61EFBA92D1B66ULL,
		0x49BAF9B7722712FFULL,
		0x32B025EAACD4DD00ULL,
		0x4060D0DE9BA97E60ULL,
		0x1F74C37222D82B2BULL,
		0x639BB3D8B8439A45ULL
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
		0xB9537F6A7E323C27ULL,
		0x329D5AE3A6CF8895ULL,
		0x675875C655D8D831ULL,
		0x864DA3BF313E7389ULL,
		0x76BCA40AF6C37AB6ULL,
		0x006763F8D5E0670AULL,
		0x3785F5BA74DE4F07ULL,
		0x5A68F458A07418BCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4BDBBD546E3630FULL,
		0x4D079F7E9BEF0C5DULL,
		0xF69225113D7EEBCBULL,
		0x80BE7054981A25A9ULL,
		0x62BD76DD1E9F2708ULL,
		0x8E33511DE72B4837ULL,
		0x561F89B790032D17ULL,
		0xDBD95C7D6BAFDE3CULL
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
		0x41FA91D3681A36FCULL,
		0x37794DA7C14519F8ULL,
		0xCD1C28552665B179ULL,
		0xA84A01A50D72F341ULL,
		0xD2F04862A942C395ULL,
		0xD04A38385EC7A490ULL,
		0x03F8C9BB36FE5585ULL,
		0xC760F21DA150B283ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x63B3BDEE0C532AAAULL,
		0x7B7AF0E4A07DDF27ULL,
		0xC514B6F9ADFC33A9ULL,
		0x3B4481A2F12A7123ULL,
		0x121B88A335EA6F48ULL,
		0x40764A97D392C1D3ULL,
		0x83DFE2E3B62E0959ULL,
		0x0FD3923D9EBB541DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x59F1EFA9EFB527DDULL,
		0xC5B3AB111931F2F3ULL,
		0xD761E12FE5DD19C0ULL,
		0xCC5A0AC6CD0896DBULL,
		0x5AA0B34503D6E345ULL,
		0x16A62EC45A98F7DFULL,
		0xFD27479BA84ABC97ULL,
		0x7097168076E86C4FULL
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
		0x8024E8B50F8B4FD6ULL,
		0x6670AC5108F1CAA6ULL,
		0x73EC7BE04070A706ULL,
		0x4262725C49335032ULL,
		0xE3DE718474CC588CULL,
		0x4D91048D8959798EULL,
		0xDDB56B1ABD06196EULL,
		0x8AC1B75F842CFD2DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x717066FC44AE7DEBULL,
		0x85C37BC43718BC86ULL,
		0x3D6B8BB8010E25F0ULL,
		0xDCDF7BACFE493798ULL,
		0x0AFCA2E3A24509D1ULL,
		0x1C0CEAA3797B2CD6ULL,
		0x89CC6E0FC545D6ADULL,
		0x9F6392B029B0C440ULL
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
		0xB52139ACEFBDE7E9ULL,
		0xBD5127CB74DA5A75ULL,
		0xDCD9BAF539EFC0E2ULL,
		0x5073CA0CD72235D6ULL,
		0xF023A3C1A7E859EEULL,
		0x21E198ECFFE60AF9ULL,
		0x093C1D61AF6DBEAAULL,
		0x52374561D5B1BC98ULL
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
		0xA3E8DDC6FBD5657BULL,
		0x19CC27F1B44AFEFEULL,
		0x089F29D7711CC800ULL,
		0x1F7764D3D3847DB0ULL,
		0x80C14EB7C1CAFCB0ULL,
		0xAFD78F92F32C0A08ULL,
		0x337E779F4F8E11A6ULL,
		0xE09E7B4884D603D9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x5820FE2368705E64ULL,
		0xA666217574AB7B72ULL,
		0x873754B000EFF968ULL,
		0x55C76FDD06A49686ULL,
		0xEC0A4BA23D8420E7ULL,
		0xFA096BD71B3F38ADULL,
		0x0F60729417CE0BCCULL,
		0x70C9DD8FFC4BF614ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9CBAAD6E1F60D2D9ULL,
		0xE31DDDCC71E08A2BULL,
		0x5D1D98A855E457CCULL,
		0x714A97DFF000C9B2ULL,
		0xE836A0CD892634B9ULL,
		0x7C2DD53EFE150336ULL,
		0x767DE6CDF847B617ULL,
		0x65E4A747EE600F85ULL
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
		0x9608F0C6E490F036ULL,
		0x6C4C89A31BB45D9BULL,
		0x1EA5D0B4505F70C1ULL,
		0x5C3AE9E6DF05BC5BULL,
		0x5ED35EC0C9E4FA06ULL,
		0xE05EC705E383B728ULL,
		0x438B9503D7463491ULL,
		0xDF3999FAC39971FDULL
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
		0x9E556599B00D1D52ULL,
		0xC59A2CC4CC131844ULL,
		0x180285EE28171644ULL,
		0x69F5DAFC93BD0AF2ULL,
		0xB8A2009E6BAAAE76ULL,
		0x77C1E0ECD40987D8ULL,
		0xE5C559FFCB53D276ULL,
		0x34F179FA19A4EF37ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xBE335E04F4E2B2F3ULL,
		0x6605EC960BA169AAULL,
		0x30ADAB4533C0DF4EULL,
		0xDA49B3CA77995635ULL,
		0xE2BC9E52CBC950DEULL,
		0x4061ADAB7DE35B66ULL,
		0x2DBE3841FECAD8B6ULL,
		0x3C7B73F435BC2528ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xCA329A21545689FEULL,
		0xF8FF471BAE1F9209ULL,
		0x0CEEB8ED3C12FE3FULL,
		0x6B7ED72BE7E0D146ULL,
		0x28179F41A63FE439ULL,
		0x76B6E0C8C5CD9E32ULL,
		0x2860DF598E7CEA6DULL,
		0x0D445D2021E1A5CFULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x7ADA6CE35C7A7621ULL,
		0x19822FA347448536ULL,
		0xFCD259D2054B6F0EULL,
		0x80FB701EEE034DAAULL,
		0x7563C78894FAE3FBULL,
		0x4DB98B142B35ABBEULL,
		0xB4BF32598C77FC00ULL,
		0x39C85CC9C27B5D0BULL
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
		0x562081D8EEB50EF4ULL,
		0xDCDEECDFAAE77E2DULL,
		0x87CA2BECB98C6DC6ULL,
		0x0D44B244D7F040F9ULL,
		0x8344025775AFCD77ULL,
		0x039D2D67B9571F0BULL,
		0xAD2FA0C21DCD247AULL,
		0x9AAA86D3ABD79014ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6FDBDD4098587D1EULL,
		0xC47991927873BA91ULL,
		0x70B91890E67A43C3ULL,
		0x40005252020845B5ULL,
		0xA820C90337931EEBULL,
		0x70DB2AC34482AC13ULL,
		0xF812EF25F5663CD0ULL,
		0x65722D2E019E3C30ULL
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
		0x981C1E0D7DC75DBFULL,
		0xE877B61F5B4C511CULL,
		0x92FE806A9FA3B704ULL,
		0x7AF5B1E1381EB86AULL,
		0xD2210FD56BE82462ULL,
		0xF67843CD113A38E5ULL,
		0xC02D903C41AA9125ULL,
		0x4197AF37F09C27B7ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xFB002B92E259436FULL,
		0xDFA9F0A9202D6E77ULL,
		0x3C7B4FECEFC08B8EULL,
		0x6EAE73BC6B7E3491ULL,
		0xD2F31A84C229392DULL,
		0xB0581A9159D42C6EULL,
		0x26CCAF71C21DB1F1ULL,
		0x261CD6D2E395CE36ULL
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
		0x05F8D7E41A04A5FFULL,
		0x868D61996B832530ULL,
		0x2B51C0DAE984E2E2ULL,
		0x70CBD923A8834088ULL,
		0xFEA6F9938295F149ULL,
		0xCC3C5848453F07EEULL,
		0x6FB6A17D199ABD60ULL,
		0xBAD7E94B7B6C2F53ULL
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
		0xF6BEFA2265887EBAULL,
		0x0A4AF53E3D7BE405ULL,
		0xEE32CFDA070C2EE7ULL,
		0xF287939556F4114FULL,
		0xF7CE07C99397E12AULL,
		0x51C19AA35A1666A7ULL,
		0x9EB2110531E08E1AULL,
		0xE594934139B0BA33ULL
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
		0x9849388E4F9163C3ULL,
		0x5C39CC161E525FD1ULL,
		0x57D1DF8A582DE7F6ULL,
		0x098B84807845783EULL,
		0x3A871C7D6D9C8D68ULL,
		0xC9F741F6531276C4ULL,
		0xAED5FABB6879D368ULL,
		0xDC9209C148B42E4AULL
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
		0x79DDAFB81FF8EDFCULL,
		0x065E5606D970D661ULL,
		0x00996B5258D53FD5ULL,
		0x08EA2AA9F43F81DCULL,
		0x33CC95E298020ACEULL,
		0x0BB2C09EC5497033ULL,
		0x6F8CA6DA325A86C5ULL,
		0xD58DEE7F7B14051FULL
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
		0x15AD32457198B60EULL,
		0xB17E678BA2655033ULL,
		0x0A65988760E8CA2FULL,
		0xCA261A0AB172784DULL,
		0xAA895E3659D0EA3DULL,
		0xEAE7BDBB3A6C166CULL,
		0x530127B1A003EFD5ULL,
		0xDA0F39875999E121ULL
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
		0x70194072E55A5F91ULL,
		0x59907DA01C0B436AULL,
		0xB373EF84A60345C1ULL,
		0x8E2A5E2FAD883CBFULL,
		0x307FBB93C34FD189ULL,
		0x99CDBB699ABCD502ULL,
		0xFEE37FD7998E0914ULL,
		0x7264D118D29129B3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x41B2CBD038968B9DULL,
		0xC7CE721059B7F48FULL,
		0x97B32887ABA42044ULL,
		0x9F469B877DC17A40ULL,
		0x51C2FD0C6466D58CULL,
		0x573CDD15EA28BC14ULL,
		0xAADEBBEA869BE4FBULL,
		0x430BE5292D8C8000ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB221D9EE97C1E4EFULL,
		0x1C786B28AAC24BAAULL,
		0xB3BE3DE3EFD2C7AEULL,
		0x7BBB0DF88717EC53ULL,
		0xD54205701A3A2F64ULL,
		0x58D1B6E58B4539A3ULL,
		0xC16F7AE1B6066B7FULL,
		0xE266684E1449767AULL
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
		0x3A38201B59F92462ULL,
		0xD088B41B163D98EAULL,
		0xF7B7A7248B750F34ULL,
		0x9540909C43703D98ULL,
		0x6B965A26D601BC67ULL,
		0xC85B3BBB7E3E01E1ULL,
		0x305E0E00E07252BBULL,
		0x88DD8BDF3D18C0B9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8D5113E8E6A56DB6ULL,
		0x02741F7624CFC138ULL,
		0x42EC8DCAD38970D0ULL,
		0x186E76CF9E2795C6ULL,
		0xF24FEABC07011AD8ULL,
		0x9811A5C7F663A07AULL,
		0xC7081979457CFC24ULL,
		0xB57D2EB477012DF6ULL
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
		0x8BE5FE64BD4BC0E9ULL,
		0x19367BC59E05D7F8ULL,
		0x892F12C3D06D7D19ULL,
		0x5C00EB9E32825AE1ULL,
		0x2CB14FC312FEED9FULL,
		0xB8597F40B7DF619EULL,
		0xE3DC513E77310C66ULL,
		0xCEE3F8322241CD4AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x97CD66C89D220B38ULL,
		0x34B4DCB5481B5EF0ULL,
		0x1F058E4A7165CF75ULL,
		0xA98187F2E59CB28EULL,
		0x2FB7C8C80F3A2E80ULL,
		0x652B2309ADE1FB4CULL,
		0xBFFCCA4E4E01FEABULL,
		0x55598C6152328FD0ULL
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
		0x15EA45FB972D00E1ULL,
		0x0C136A20F73B5448ULL,
		0x771B109CB23B8C8DULL,
		0xEA2D5F5EA684A8C1ULL,
		0x45CCC400E0C54C4EULL,
		0xC41EF01198683E47ULL,
		0x67DD976CE691C5E5ULL,
		0x7C1947C41426518CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBBD7FCA186529B62ULL,
		0x717E2C6F25B127C6ULL,
		0x75734C24EFD8248BULL,
		0x3573ABA1628D6AB1ULL,
		0x0D12F78DE3DC5186ULL,
		0xE43AA840011F2DB9ULL,
		0xEB88067064543052ULL,
		0x82B89E1E0D302415ULL
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
	la = 504;
	k1 = (curve25519_key_t){.key64 = {
		0xBCB698183E159D19ULL,
		0x3308D167C08D1942ULL,
		0x37BD23A1729E8EB1ULL,
		0x30414DDB094483EDULL,
		0x1B31ED0EFF9AA832ULL,
		0xC2C6683C58B4805EULL,
		0xDAAD16F07061C33DULL,
		0x01B1EDC47730F443ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x18E3AD90BB977CEFULL,
		0xB860958F7E58F002ULL,
		0xFA08BAAD8ACDF14EULL,
		0xED91850AD5EC2660ULL,
		0xF8BAD8338902E6B1ULL,
		0xA0406C23E5F22391ULL,
		0xCD486CB014FFC707ULL,
		0x1AF2F337F463BB4BULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x6D12BD077A9AE200ULL,
		0x4FC0FE7EAB5EC248ULL,
		0xD53A5490E4A0B0DAULL,
		0xD2E4F2497B9D9A99ULL,
		0xA0748B9C4C621EF9ULL,
		0x4A93C7B7FA3B1478ULL,
		0x5E0291BD2D8863ABULL,
		0x05EA9ECBD1C33BFBULL
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
		0xD537B71BD36A31F9ULL,
		0xF6592F8AEDBF23DEULL,
		0x9BA7F0E058DEC4D0ULL,
		0xE48A58DB7FAEE7B6ULL,
		0x9AF6C55CEB305168ULL,
		0x59BDBE752E991FB0ULL,
		0xAF0D1E6E7ADC4A81ULL,
		0xF7CEBBA3A09B6B38ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x267EBD431E7D534FULL,
		0x7580939714487FE8ULL,
		0x29263D114C2FBB65ULL,
		0x39AF8A24CFA28CD9ULL,
		0x3CC4D7E58CE1294CULL,
		0xDB0E4B4D325775F5ULL,
		0xF6F0CA21CDF5F937ULL,
		0xE4FAA7FECF5AF982ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0D88B87FD2E2379FULL,
		0x5E4AB37F1E58B2B0ULL,
		0xE07732164EA37DD4ULL,
		0x072C5AC0F0004A9BULL,
		0x37BBFAC308B101AFULL,
		0xC62B2081C7367091ULL,
		0x7D3129B8FAD341D5ULL,
		0xDE9D790266B1C557ULL
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
		0xA9025ECD687672C6ULL,
		0xBBACFC199110021AULL,
		0x2453A3E153CB1B1DULL,
		0x7C0A8C38A5C2AB27ULL,
		0xAFE1AB764A2C6110ULL,
		0x0FB02E3294EB2464ULL,
		0x962A54BF40FCEE12ULL,
		0xA060C7B8A0AA5575ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x22045F76113549CFULL,
		0xBA76DEBBD3BB5D79ULL,
		0xE5D60521087E6B39ULL,
		0xCAE8EB4263BA2CC3ULL,
		0xD1C44837F43EF2A5ULL,
		0x009B095103541D56ULL,
		0x12AA47734502E1CBULL,
		0x264F637BBDE76A43ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x56DC040A585ECEACULL,
		0x7BE7C04711252F03ULL,
		0x1622C6199638F08CULL,
		0xE5C3FC494BC37CF9ULL,
		0xEECBD4E4FB094B59ULL,
		0xA27D52D8D80E5B43ULL,
		0x1D9FEC10555B64D6ULL,
		0x2F3936385EAD53EBULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3EDD37D7ADB980D3ULL,
		0xE5B125A1A0BB71B8ULL,
		0xBB47F056862333C6ULL,
		0xEBE663137970BC16ULL,
		0xBED8444C98B5B0EAULL,
		0x293A8E1DB0AE3009ULL,
		0x03B52DFC0C325DCAULL,
		0xEBB9A9C64C66C981ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0xDBA0135A421D7162ULL,
		0x9A88035D9BDBFBF2ULL,
		0xE3417416DE57BC45ULL,
		0x62E9EBEEE8AE47C1ULL,
		0xF69767412891B79CULL,
		0x3E33013283E00FD2ULL,
		0x5D2DE9F81824D11DULL,
		0x17CC1239AAE73D91ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x9DEDEA017CD1B6E4ULL,
		0xA2495AFB213A96D7ULL,
		0xE175F02EC1A089A2ULL,
		0x2BD0CC314F2560DCULL,
		0x54912789F0C925DEULL,
		0x5D9DB4D70B8DB1A1ULL,
		0x119D6F0C6446E10AULL,
		0x573BC22F25AD64D5ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x429FD89A07CA8278ULL,
		0xDA4CF0B589963ADDULL,
		0x5F6F7BD2D0C4E291ULL,
		0x15454D1161949A49ULL,
		0xD86038B18F176472ULL,
		0xCA47F0167AC8962DULL,
		0x0BAFA34CD886700CULL,
		0x168FE0ECFB3BFB67ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x758A59116583752CULL,
		0x1D2233145F8F3F60ULL,
		0xF27D42DD4D2E28E7ULL,
		0x6A68864F6C830E5EULL,
		0x4E7B6A2D6860FDE3ULL,
		0xF515B11F35614056ULL,
		0x41C515F9303F9566ULL,
		0x23EFCAC9162319F8ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x62F198C9D9F2563BULL,
		0x6613D638A0AF7EA4ULL,
		0xDD31E933333FA94DULL,
		0x1427E15CBEDFB30DULL,
		0x3C86DC65358FE634ULL,
		0x59357E0F0DDF481FULL,
		0x05623228C10F676EULL,
		0x59F9C39BF3201C92ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x93BCB289E1C59843ULL,
		0xBAC785E8B0C88696ULL,
		0x128B2826F1B1DCBAULL,
		0x6F7D2A13E64E8682ULL,
		0x0E17574E5089ED6DULL,
		0xA1CA290001A8765EULL,
		0x4BDF375421FA474AULL,
		0xAB561DAD89D534D9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3D712C7D3A756ADDULL,
		0xC3584B9B69C08AA3ULL,
		0x338245322CF2F6F8ULL,
		0xB7AA28AE6757B32FULL,
		0xF2CE0F2957C48D95ULL,
		0xE0D6B03D8835DFF4ULL,
		0x94241EFB3D31367DULL,
		0xEC0D6A6B14B7DF6DULL
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
		0xE8D72557EFAEC899ULL,
		0xC9FB893D14DDFCD7ULL,
		0x6D7EB1A01C786876ULL,
		0x8C095BE2292C2D1EULL,
		0xFC69FFE35E01FB52ULL,
		0xD45986637755C7A2ULL,
		0x6FA3FB98707D6E39ULL,
		0x6C67580A11AC2792ULL
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
		0xEA8649D7652B216AULL,
		0x34D05DBB873EED9DULL,
		0x786540831A41387BULL,
		0xDE4DF2A29B1FEBD5ULL,
		0x8819EFF1CE754AFBULL,
		0x23A2E557F2D92AE0ULL,
		0xAAD2763704D289F7ULL,
		0xEE14A77A6D4E3561ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x65866E72F3F5433FULL,
		0x8998E055B61E46D5ULL,
		0x8F701A6C97B763D2ULL,
		0x7F73FAFBEBE550A7ULL,
		0x9A4322A21BD5975CULL,
		0x4B56DC6608DC5ECEULL,
		0xBE81F5E7CDA3DEA5ULL,
		0xFB231CF6F410EA3EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x72CD46B2C6D90B28ULL,
		0xAE44E1649D21F885ULL,
		0x7BC98B39458A6F1CULL,
		0x79B8B6EA87DE865CULL,
		0xABB3D18B39F3A8A8ULL,
		0x572F39D7E827ACC7ULL,
		0x8861D0CCE7EEBE07ULL,
		0xE92DFFC3F8B7E327ULL
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
		0xE47CCB0AB51E025AULL,
		0xECCA1E22CB121DD9ULL,
		0x124A36C7B52E7A33ULL,
		0x601C9C2F41E1DD94ULL,
		0xF543111BED0D37D4ULL,
		0x84C81F5CF514127DULL,
		0x1235DC3E8A460E1AULL,
		0x693C8740B0ED9C79ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xF6C07EC5778A90E0ULL,
		0x537311408F6AB874ULL,
		0x5CFBA666C7625AF3ULL,
		0xD0B7DC2101B3EB7BULL,
		0x42744CCD81C527ECULL,
		0x9B85C6B7A39CBEADULL,
		0x5E16512EDCFD0DF0ULL,
		0x3751ECB33C97A692ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x77EDFED5A64C0B28ULL,
		0xC16EBFD90BE0F98FULL,
		0x849ACF8F88B8882DULL,
		0x0376FC966BE4849AULL,
		0x919045F2F2480AFBULL,
		0x690E68AA2D038C0AULL,
		0xFEDE4A5DEF2478A1ULL,
		0xCD288C309788FFD1ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x0E65773F527967A6ULL,
		0x980FD7100492D424ULL,
		0xBDAFF4C85F71AE97ULL,
		0x70BF8FA535103970ULL,
		0x238D998D52BEC375ULL,
		0x26FA293D88331E92ULL,
		0xB77EED5CA6A910AFULL,
		0x314BD779971A3192ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x6E98E766CC95825BULL,
		0xB4D63D2DC2DE8BE0ULL,
		0xFBD13D39C8361BF0ULL,
		0x5674E8E8FA88CA03ULL,
		0x7E12EF810AD2A55AULL,
		0x6F70CB7ABB8DAC45ULL,
		0xDE03FC067FDC5412ULL,
		0x4D3179F27C3322C3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x256930C008534BF9ULL,
		0x16D00DE5699FDF50ULL,
		0xEB901CA5257BAEC8ULL,
		0xF1DE59F0753F94BAULL,
		0x554FA7EE3D4E72C7ULL,
		0x3318C789B6E3B651ULL,
		0xDDF205454E990E1BULL,
		0x599814D1883169D0ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x81062DC3FF23E168ULL,
		0xAD88E290B432B486ULL,
		0x29ECB82F1215B849ULL,
		0x810EA461FFA8250EULL,
		0x599A32188D143420ULL,
		0xF72363080AFCB226ULL,
		0x55607FA5C1FF3582ULL,
		0xB4B9C1C6F468623BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF7B67CC367FD4019ULL,
		0x693D43B129EB7289ULL,
		0x76E954D52B35B74BULL,
		0xEFC5B994AB88F5D7ULL,
		0xB07B6854C87611E3ULL,
		0x8FCB6C054D0A8AAEULL,
		0xCD2B014F2276E905ULL,
		0x4776DE8D7A5B0B13ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC1EF51BD61FDF918ULL,
		0x179CE99F837E7099ULL,
		0xE8F59ED1C3E16E11ULL,
		0xA5EC52803DA165F9ULL,
		0xB71F836D73757A5AULL,
		0xAE156460117163D8ULL,
		0xE79210FA7F1C7BBDULL,
		0x3F39B71014D1178DULL
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
		0xDA409A08945B66C6ULL,
		0xB8FECC1F22BD7B35ULL,
		0x0029CE77F1EB7FBEULL,
		0xD736B96D1169DDCCULL,
		0x40188A6AC324C3DDULL,
		0xBDDCDD68082A8D43ULL,
		0x442207BA4676BBF0ULL,
		0xEF71F978ADFE85F7ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x0133C6B4D6720EB0ULL,
		0x13C82EDF0C8DFE33ULL,
		0x38B6DC1C0DDCE260ULL,
		0xBCDC2355D6B7C545ULL,
		0x33FA982D65289A0BULL,
		0x9E7689E86ED133B9ULL,
		0x09E9E57C57BBE8F9ULL,
		0x5CF0E055160C14C3ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x958EA7DE86C262F3ULL,
		0x923C7602690C62CBULL,
		0xE27A778717D03F04ULL,
		0x63A64A77ABC8B676ULL,
		0x24F3151770DB87F5ULL,
		0x630CAA134AB6C6FDULL,
		0x257A2BF585D7B016ULL,
		0x49BCD3EB71FB1923ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8863BBD8D076AFDDULL,
		0xD165852F3BFB2B14ULL,
		0x62A53459BB4851ACULL,
		0x7D63111DA429C0DFULL,
		0x21A6A1C9F74334C1ULL,
		0x3417A03F7BF5364CULL,
		0x8690922B97B10515ULL,
		0xD42B824190BD9321ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xDB02F076331C63DEULL,
		0xF949AA55D37341D7ULL,
		0xAA54C8F6D51288F4ULL,
		0x5C93759FF5D6FAEAULL,
		0xEFAAFF79440F461FULL,
		0x02B4794D4DF02AD9ULL,
		0x99E2252DACC61D82ULL,
		0x839D1C069B6E06BBULL
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
		0xDF0EFBFC188C1FF9ULL,
		0xFF7AF4C2CE1CA8CBULL,
		0xB644CCA5C6C4AEA9ULL,
		0xD0EB5FD2CE8D4D7CULL,
		0x691B9C970F6B8A38ULL,
		0x997A1FD56CFAB774ULL,
		0x9B789F8B7797550AULL,
		0x7BC6ED0B69E4741BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5F0F3C7ABB9F3B09ULL,
		0x559EEDBAE9FD7EF5ULL,
		0x7A394DDDF6972F9CULL,
		0x5CA3EE6DFCED88EEULL,
		0x6BE9C1BE0216EC46ULL,
		0xDCA7AEE123F84D13ULL,
		0xD8BD6D82D8098183ULL,
		0xFB23DE12FAC9AAF6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE8E946CE7CCCACD1ULL,
		0x4B3E15FCF054F5A9ULL,
		0xF782DE271A31E2C6ULL,
		0xBE97025955457D79ULL,
		0x475863924B18EA16ULL,
		0xD622CD811484DC61ULL,
		0xE0A99462E7309BD7ULL,
		0xD14DC2891A68E892ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x5F22722ED417698CULL,
		0x2715DD4AD2844A8AULL,
		0xAA80422921D75D26ULL,
		0x720E3879BDA4C50DULL,
		0xC260EFD3B8BE9FA8ULL,
		0x6E587C666F4B917FULL,
		0xD320BAF3493FB9E8ULL,
		0x132904C83AB85D75ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD346CC75BC070C11ULL,
		0x7237E178714B35A2ULL,
		0x62698E130C92AC0AULL,
		0x73F9DEA02F193EB2ULL,
		0xE7316FDD5703936CULL,
		0xE956CE20A4A4F95AULL,
		0x56D9775E29878BC0ULL,
		0x34CFEF5381A26E1AULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x408FEA6F827F8384ULL,
		0xCBBF1AF5FC464DA4ULL,
		0x7535B537638B9FE6ULL,
		0x6D6EC2F5DAE42D16ULL,
		0x4F6D8E18F4FF9879ULL,
		0x4F12560525BA6230ULL,
		0x922E488B721E2C02ULL,
		0x3817446B7F263BCAULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x40492A41111C80D6ULL,
		0xF42DDBD238A4CE90ULL,
		0x439156D130E9919EULL,
		0x1F8EE59FDDF6A1F7ULL,
		0x1142B64FAA415C0DULL,
		0x6375FED5EE3CE4ADULL,
		0x02FF7723CDB9AC07ULL,
		0x1C9A688A9050794CULL
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
		0xE88630517016A253ULL,
		0xAEDCD7AB2207BD2EULL,
		0xC59300F996527AB7ULL,
		0x3186ED35B8CC1B71ULL,
		0x3A895E1CB6959833ULL,
		0x8AD2F39874E29A99ULL,
		0x289A77C51DDC90ABULL,
		0x726463699717E853ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9E8EE69298817B4BULL,
		0xBC96D6BCDE66773BULL,
		0x4F197058B5F00316ULL,
		0x1896C0F63F2DC51DULL,
		0x04188F27940F0DCCULL,
		0x1CFD941DA1800CDCULL,
		0xFF6B2874CFE57694ULL,
		0xA4B425042B6DEF17ULL
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
		0x1B03D2234F610208ULL,
		0x19023AE7AF0A0D63ULL,
		0x93C168E7C53EED5BULL,
		0x85D3A3B10A2AADEFULL,
		0xCC6F9F239EC2AE52ULL,
		0xA158C9FB6F6CAA77ULL,
		0x8FBB8B53D62ADCD5ULL,
		0xE5BBB3AEEC3EB24BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA63B81A99F120A70ULL,
		0xD374D1C6857C634BULL,
		0x009189DF129D0A65ULL,
		0x86BEBDB5CC211C38ULL,
		0x5B90E66A2A1F3971ULL,
		0xB4EA2D64097B6D53ULL,
		0x8C4B40707EFD0BFFULL,
		0xBF4314868BD34618ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2CB13E2EB79EBCDAULL,
		0xEA2E04DB72A54F1AULL,
		0xADD7B5E237EA846DULL,
		0x480D27A6B5D9BA4EULL,
		0xC800E08588C3428AULL,
		0x9D8AC4244C3CB8EAULL,
		0xCE06DC8504126883ULL,
		0x7C2EEEF5DF1EDD2AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA6B43C9C94A69755ULL,
		0xAB1A9B079D1FF155ULL,
		0x28076DE6E5EE8533ULL,
		0xE9B8BB1D86201E22ULL,
		0x002B5A36743F93D4ULL,
		0x214ED982D281634FULL,
		0x4FB3897D198627BAULL,
		0xC1F55D5396F46BFCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA70F57860FF43442ULL,
		0xFFC4C84F4247EDB5ULL,
		0x0034E1EAD07A1C2BULL,
		0xC60156930BC717CAULL,
		0x15D41132FDC14127ULL,
		0xCDFD7A80BE6DEE80ULL,
		0x04D2A494C0660642ULL,
		0xE8F1E53DD048CC66ULL
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
		0xF338B32C76D9B5F3ULL,
		0xA3A655927DBC6CB1ULL,
		0xDDA1EA51C95ABCC3ULL,
		0x6C9236E056ACA754ULL,
		0xB1370D8701AC752DULL,
		0x324CABFBDF0DF6F4ULL,
		0x3796B772714CBC52ULL,
		0xD07E0951BAEC6C55ULL
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
		0xD568C57D3AF80DD6ULL,
		0xED1D02CCEDEA49F4ULL,
		0x0DFD4E76D94C105AULL,
		0x9E57151322F85708ULL,
		0x584328E4CD58F013ULL,
		0x074C6094B3E6BD2DULL,
		0x1E419922566D03AAULL,
		0xFC34A9C95DA23D10ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x29B4BE756E558966ULL,
		0x85A6D1DBEDE36478ULL,
		0x06BF8005F64B026BULL,
		0x784F14424D86A072ULL,
		0x6C6E32BC5D90FBB7ULL,
		0x4B45351EF4F2250AULL,
		0xCC8940F6BF46C486ULL,
		0xBFF5FF895513BB63ULL
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
		0x95DA8AB63A3F6977ULL,
		0x89330A131E51FE60ULL,
		0x4B00BBD4224EC2D4ULL,
		0x1E2CA8ACD926B9ECULL,
		0xC34F3DB0B44BB582ULL,
		0x0B1B07B53D752C43ULL,
		0x554BD88E02B23D23ULL,
		0x650FB307C6CC6E93ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE16C2D9BE6D5CDAULL,
		0xA4DF6D2F00AF8AF7ULL,
		0x15651B3DE3B912B5ULL,
		0x26BA26EB151EEA91ULL,
		0x806CE8DB079BAFCDULL,
		0x7F928ED7F1AE8FDDULL,
		0x5A70C242A993EC84ULL,
		0xFA9EB6D6412482C7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEE42DCF9946E1540ULL,
		0x867D9226E08DAEE6ULL,
		0xCB48AEE616794890ULL,
		0xFFAC3588DC38F6F2ULL,
		0xC2251D3CB8CE3CECULL,
		0x079DCE3B7DD84FA8ULL,
		0x2561C0507DF58DE6ULL,
		0xD4A372C456AAC29EULL
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
		0xFD1592A6B28EB973ULL,
		0x4A794CA4832FF30AULL,
		0xB046D01C726E76A1ULL,
		0x0728C95CC5798425ULL,
		0x846DC06454022E78ULL,
		0xDBC7B0B4BE4789E9ULL,
		0xC44AC6592D2ED82DULL,
		0xCF9289B46F6B0D66ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x16AB094B4A56B238ULL,
		0x9A30F76E770A0A46ULL,
		0xED133D489DFE65B0ULL,
		0xFE14A24FABFA5292ULL,
		0x33963C151E2C1F63ULL,
		0xBB6DFE97EF977E4BULL,
		0x0E10C99919E4BAFFULL,
		0x5E54C1105B2D02AEULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF6E157CEEE0C225BULL,
		0x95C3FFAE45EA9244ULL,
		0xDD8800808D4DBCE6ULL,
		0xF299F7FFF4944A64ULL,
		0x669B98929AD52B59ULL,
		0x5FA46B87DF071F44ULL,
		0x8DE11C5DC68B9102ULL,
		0x7AE241FD0E2F165FULL
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
		0xBE2B7E260EFB9E10ULL,
		0xAAE060FE088B969BULL,
		0xDDAFB1654D126236ULL,
		0xD243BD590C5AA4E2ULL,
		0xD77AA887B0BB3BE9ULL,
		0xE61FC28A30A6E575ULL,
		0xE210AE35CC4443CAULL,
		0x41AE94B251046973ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7222FE238848D2A6ULL,
		0x9397FEA7AE8ED959ULL,
		0xD4CCB97B0C08E449ULL,
		0xC8F1DA9474B38D75ULL,
		0xD87C3681A4AB24A2ULL,
		0x337501D55E39CDD3ULL,
		0xBC4D3B52CBA50E0DULL,
		0x8DED45F5DCEB60E9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xC4C527137558227EULL,
		0x919DC2E60B35BA5AULL,
		0x92C13DBCB30135A8ULL,
		0xAF9CF4B21A0872C6ULL,
		0xD8C22FDD393BE375ULL,
		0x4002663F1C22341AULL,
		0xBFBD99E2FDD3D821ULL,
		0x62A2A2678867EE18ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xC0EF2BC8DD6B84A4ULL,
		0x674A23B2722A0ABAULL,
		0xE2217ED185F26DA8ULL,
		0x7DB6B0E260658997ULL,
		0x9B8642EE45234C87ULL,
		0x9B2A24B6F30F581BULL,
		0x4A9A091BA9D05BDDULL,
		0x3E53E69B1C8F5F81ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4EF488CEE6ABCE65ULL,
		0x00D2424A790F8165ULL,
		0xD1586BCA5347C0C9ULL,
		0xFE4634D083024CD2ULL,
		0x30AE8A35580E77E6ULL,
		0x34430AF370365A2AULL,
		0x24C789F3D85B6024ULL,
		0xBED93938F190A3EFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4B9EBDADE8901D1ULL,
		0x1184D508A18DBE62ULL,
		0x2D316F88F1A2C3D2ULL,
		0xF05E78A691B6251AULL,
		0xCE423AA0A60E658DULL,
		0x3BE3867C8F98CBEAULL,
		0x9A0DF89E07CF95F1ULL,
		0xB5630866329CFBD3ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD7EB8A3645D8E581ULL,
		0xD1D3ABEBA406CD0AULL,
		0x9EB627333F36FA05ULL,
		0xBBFC2281DE9FD89FULL,
		0x90F0461012C2C5B2ULL,
		0xCA8D8D54F9A64D3CULL,
		0xC183BBDAD6818F17ULL,
		0x28FFE1B8A9B3D3F4ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x601F686DDC1484B3ULL,
		0x903D00B792DD5752ULL,
		0x1364172AA2F36A8DULL,
		0xA8DC9B4DF82768F1ULL,
		0x7E7D3938DE02B77DULL,
		0x3464F71D5FA809DCULL,
		0x1ACDCE6BDD0B2BB9ULL,
		0x05552D52F5E4162DULL
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
		0xB9D0AC16BCF83AABULL,
		0xE02EB0958677E990ULL,
		0x7ABED329E89E0C84ULL,
		0xB34A412E885C40D9ULL,
		0xECCB3DD2E4089FA9ULL,
		0xC486A346EA170AC2ULL,
		0x1ADCB7303DC02A2DULL,
		0xB5B010D9D54DFE54ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x03CFFF6A9C4983D9ULL,
		0x11ACC869FCF64406ULL,
		0xA04CA01503BEF18DULL,
		0xA7776FF9C8048E6BULL,
		0x4D08C962BC17568DULL,
		0x2824B0EE1AA0D3D6ULL,
		0x56BDB8D254FFB0F4ULL,
		0x3C044092B69F8F3CULL
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
		0x73D56291496E07E6ULL,
		0xADA4AC061CF13038ULL,
		0x0BF4F07998292A15ULL,
		0x4C2539CDE1F5EAF9ULL,
		0xE8A12916091561A4ULL,
		0x95141927F8021F98ULL,
		0xCE03330BE1BC919CULL,
		0xCB7475AE4E5635A6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1707DAF1F8C0503DULL,
		0xB4D26806BFFBC44BULL,
		0xC64BBE51A72E5E56ULL,
		0x2EC95D02B7701DB6ULL,
		0xEBDEB868E0FE454DULL,
		0x1A1D84C093ABB0B3ULL,
		0x5DB513180A17116AULL,
		0xFE94B855BE76618AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x698C631E77C0E08EULL,
		0xA1DD9D9164FA4A71ULL,
		0xE2463A2863C38400ULL,
		0x3FC5A997581CD954ULL,
		0x3A1E16E480BDADC3ULL,
		0x4E1E90241B072438ULL,
		0x4D910E6AA38C7F59ULL,
		0x7245F1763435DEB5ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x2681018152529297ULL,
		0xD845DBF8177BFB5DULL,
		0x6F8A22D79DC5DB82ULL,
		0x58EA14AE9E6A24C2ULL,
		0x4C731A7521BC4C11ULL,
		0x65CEA4EEEA9C49DFULL,
		0x5A67C9F203514D3CULL,
		0xBEBD67A626ECA15EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB62AD22BDCD561B9ULL,
		0xB700D2511FA208DFULL,
		0x4517F11FDF4FCC07ULL,
		0xBFBA6B1DF35515B8ULL,
		0xFD8E008F73E6A627ULL,
		0x6A47816A5B31D051ULL,
		0x1499767DAF7BAE80ULL,
		0xECC41826536591F8ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xD77D92A831CB0151ULL,
		0x9957E4392D7B6444ULL,
		0xDC2F36B7A4688240ULL,
		0x98922FE130226BD7ULL,
		0xBB68EB1167C5F330ULL,
		0x47BBDEB66D81B738ULL,
		0xF8913900AE185FF2ULL,
		0xB89D6AAEDA0668F0ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2859942A842D7E95ULL,
		0x23143C6152E752B9ULL,
		0x119BC3170C4DFDE2ULL,
		0x23F978AEB3D5D2C9ULL,
		0x3A973C44BAC0E094ULL,
		0x779C98224BCB91A2ULL,
		0xEA8226031CDEE279ULL,
		0x207AC9754F25608BULL
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
		0x6AF15478550BAF9AULL,
		0x1A2BC561F5653BF1ULL,
		0xD1C679A2F9202D9BULL,
		0xBAB4D1913EB8B82CULL,
		0x323F33FEFAEEC440ULL,
		0xD12FF204AC7F3874ULL,
		0xECD55186EA746F4DULL,
		0xB4E67DE15FE80422ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2B3D8EFA955668DBULL,
		0xFACB2BD8468742BEULL,
		0x58BF351D95EC9E2BULL,
		0xF1CDA0036A26B309ULL,
		0x09ED87804C7AB1E9ULL,
		0x1A75C7FCCFFD64FAULL,
		0x73302DEF784F8B60ULL,
		0x4B7D3FA08AA1EAA6ULL
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
		0x8190A83A93283A32ULL,
		0xE7A6D1F36B0AE7CBULL,
		0x93FB0B84C754026CULL,
		0x9434C3B444E03BE5ULL,
		0x6698D4C79CFC89D7ULL,
		0x40CD1567B15E271EULL,
		0x79B08B4DA3A44A04ULL,
		0xF2407D1AB43F250AULL
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
		0x1718CF03D1B26A6AULL,
		0x53ED2B52547046D1ULL,
		0x538F37521D40A6D1ULL,
		0xB9B9E4B91BC5B888ULL,
		0x293664C547B54B72ULL,
		0xF58974F04CF25838ULL,
		0x1A369B282ABCE1F7ULL,
		0xEB4A3528EFCDB87DULL
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
		0x76BA05654EE8A16FULL,
		0x8B7813EABA7980DDULL,
		0x9EC41043A57444C3ULL,
		0xD1FA20252FDEFF51ULL,
		0x24B2EAB25C909AF6ULL,
		0x7EA4865627E5CA23ULL,
		0x1774FC631367C137ULL,
		0x40894AD1892BB1B0ULL
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
		0xEDA27C20D32880B2ULL,
		0x7900794EFB57F5FEULL,
		0xAA5C895FB28AF5D3ULL,
		0xDA146B617954FAF5ULL,
		0x77A78D7F6BE2ABB1ULL,
		0x68EE0B64305747A4ULL,
		0x4E2159639719FDE8ULL,
		0x3BB3B4532660C529ULL
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
		0xF88766311C8E7AD5ULL,
		0xC83D04DC6DE95DC1ULL,
		0xEF4FDF8018AB243DULL,
		0x5F3E8CAF7AD2F71CULL,
		0x2A62682B42F2C82CULL,
		0xD8EC715DFD308DB7ULL,
		0x33EC5ACEC0285952ULL,
		0xE0F54B8399AF0A3DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x8E4C89D990C950DEULL,
		0xC1D42A7D7546BF07ULL,
		0x4B20F52787AB5E88ULL,
		0x3F525325AA3BDA48ULL,
		0x529F2C3488C2BFE4ULL,
		0xC0E6882E8FA45D75ULL,
		0x1BB5A493B0E5DD50ULL,
		0x6A304F97405C0221ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x81731D7F0B5AF0ECULL,
		0xF277ECD3A081AD89ULL,
		0x9B5DE3902337817FULL,
		0x790A80E744255150ULL,
		0xEAD73B09BBDA7B29ULL,
		0x3B0472DC79E3A417ULL,
		0x318058D28C1BADCEULL,
		0x7C29773FB3525BF3ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xC34A8F868353D972ULL,
		0x24FC43A0FD42AEEDULL,
		0x117359C2EF1D0FCEULL,
		0x7DA6B2AB9BFB0CDCULL,
		0x4CB5DFF13A5080A3ULL,
		0x5854D49082E24638ULL,
		0x4D4FBADC627C3C84ULL,
		0xE2619FB5E4787296ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xAE1B1D27B589EA6DULL,
		0xA860AD103F433C56ULL,
		0x0624ADDFB4A5EF83ULL,
		0x4040703E836A1EA1ULL,
		0xB6E0F71B899B7351ULL,
		0xB0D1C80060DE3A80ULL,
		0xBA17E482AD5CC1F5ULL,
		0x0FAF0A3DC58B5CC9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x3B97498994B649D7ULL,
		0xBF88374ADBB87647ULL,
		0x20C8705001D815E4ULL,
		0x4609ECB2533F026EULL,
		0x3764D683AB0ABFCFULL,
		0xCDC9CD81EA1E9795ULL,
		0xA6DE2D0375463EFCULL,
		0xFC73391425E66D95ULL
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
		0x1AF5340E139DF9DEULL,
		0xFCF6DE0D29633F10ULL,
		0x9E4CAED4303E824BULL,
		0x6550EDAC7E8CDFCFULL,
		0xCF70D04E899C1838ULL,
		0x5322D1E4411BE0BCULL,
		0x8492EC46D799CAFDULL,
		0x7CD05B6B6A7E8F4EULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0xF822F95FF8570640ULL,
		0x610705D55E801154ULL,
		0x29F408C2B0AF30CBULL,
		0x3DC29AA2A4E67A7FULL,
		0x15A1A346076FF386ULL,
		0xD95E8833F46893B7ULL,
		0x4ED48812030CBFE0ULL,
		0x0235693EAE68E178ULL
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
		0x2039638B0E5F4EE7ULL,
		0xA3B5A171D109FC65ULL,
		0xAFE9BA403592502DULL,
		0x31A50F58DAF14D94ULL,
		0x8EDEA9DFC4CF0BD3ULL,
		0x84CC7C909A5B98C9ULL,
		0xFCBFF03184DE28D6ULL,
		0xA8857F014AB37BC8ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x4A8BEEFA742B29B5ULL,
		0x0ED58D87876EF093ULL,
		0x3327B7D6A225D1A0ULL,
		0x86ED2D0BA0ED5970ULL,
		0x4390B8FF066B7FBBULL,
		0x0BA9753F8E99A8B8ULL,
		0x2E87A277771B819EULL,
		0x7963919EF025DD1BULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0C119FB9E0D8FBBCULL,
		0xB67BB2CC09338EDCULL,
		0x0B85243335A041F5ULL,
		0xE47837A600C3D679ULL,
		0x5E803C3BF4113946ULL,
		0x1DD123D285F2ECF5ULL,
		0xB42A41D34A2D994DULL,
		0x1D9AAC6BCA7E26A0ULL
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
		0xA9F7D216419379A2ULL,
		0x6438E6E55A242446ULL,
		0xFE306E2A41A94C9DULL,
		0x967F7BCB67234083ULL,
		0xA058777DB3248E51ULL,
		0xE7636D7E1A1B3D41ULL,
		0x40A6E6A3DD4B0635ULL,
		0xB257EB2082781174ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xC282690C8EB7B5FCULL,
		0xE38F6D31FEE77096ULL,
		0x81FF468BC2316B5DULL,
		0x0969A6223CF403F8ULL,
		0xCE5FDADEB9661778ULL,
		0xD8B1A33A3B338879ULL,
		0x3C0DEA4312384394ULL,
		0x0B2B2C8505C39730ULL
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
		0xA12C0211252BAB8CULL,
		0xE5C1B49565EBE014ULL,
		0x6C97767384B5EC6AULL,
		0xC0927DA03FDB2933ULL,
		0x0844FCC44A0F3C34ULL,
		0x428491DBAE468417ULL,
		0x0257ED7A706287EBULL,
		0xC22C64FAF416B03BULL
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
		0xD3C347CA66411802ULL,
		0xB617B59D6074679AULL,
		0xFE8F5C2E4B87C8F7ULL,
		0xCC872542C86D3AADULL,
		0xD167C3EF1FAF1289ULL,
		0xBACC5CA9B0269B06ULL,
		0xE528ED8A3F4D2D2EULL,
		0x481003B0DE48CFBFULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7228E98A09CBFCFCULL,
		0xF660CBEE4C446D09ULL,
		0x469B2D59A867366BULL,
		0xDB65630404B68AC9ULL,
		0xE384886CDEC85DC7ULL,
		0x0D80B3AD3F44A1DEULL,
		0x4D91475B97E33EF0ULL,
		0x6FDC98806883299CULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x119DD04D599EA086ULL,
		0xDF07A1C2721B7D3EULL,
		0x0439AA5D6D45E4F5ULL,
		0x838B7373F3D4781FULL,
		0xD55681EBB4C107D2ULL,
		0x3313A0FFB7A62F8AULL,
		0x15A0185789D364D0ULL,
		0x1432DE9E475F3BE6ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5A46F10207492CF5ULL,
		0x88A80DA0918764BCULL,
		0xB4309594320EE5F3ULL,
		0x8BF2F031A0196B84ULL,
		0xEAC8C8FEF930461DULL,
		0xCBB91BAB51167F03ULL,
		0x28F446DD8B83545CULL,
		0xA2D25B3B00C35072ULL
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
		0x073A468440F2EF6BULL,
		0xBA94E85765BF4D42ULL,
		0xE25E20339578DE79ULL,
		0xD2DE6C4041818D82ULL,
		0x61BF7B1D46E6E859ULL,
		0x11D7D3A80513A2FCULL,
		0x9AD817089B98D34AULL,
		0xA23C6652ADDC56ADULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x781A74B57686069FULL,
		0xB77787042F880704ULL,
		0x4DD3FA9AAB1C2F8EULL,
		0x372D3237C60FEA65ULL,
		0x548350A4CB558C39ULL,
		0x38453EC1C011D10AULL,
		0x66B3306F5C115989ULL,
		0x67CA9078C0948ED8ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x411527F38145C0D5ULL,
		0x441DD77B4F58FC28ULL,
		0x49A3C0E0BAE1838CULL,
		0x7D88F89445D050EDULL,
		0x6FC1040602F6CF75ULL,
		0x5BFA5E71AF06D141ULL,
		0x310E26F514C31643ULL,
		0x461E9C2CC9375DA6ULL
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
		0x451FBA9FC054FC44ULL,
		0xAA400198B2ADAD49ULL,
		0xC1119E82540C847FULL,
		0x4AE4FC97B00BCAC7ULL,
		0x438EE3EA7F5B55F1ULL,
		0x2FF7E6685B3FB316ULL,
		0x581B9E118F884F82ULL,
		0x8F222E19C4BD851DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x5A145BEBFB2DDEC3ULL,
		0x4DDB81ABCA1BD13AULL,
		0xBB67882B47088AC1ULL,
		0xA29480A425049B62ULL,
		0x6938F8C5961F5962ULL,
		0x4E572CA75A3342CFULL,
		0x22042E125EC13485ULL,
		0xEF16D336EA68D33AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xCA736E035E607833ULL,
		0x21D6B19280301E39ULL,
		0x0B4E91AE12CA789AULL,
		0x50A1B03FD4486A54ULL,
		0xB4E98BA37FE7EB3CULL,
		0x8A9F1B7252EC6409ULL,
		0x426CDB2F6D6FB665ULL,
		0xF1DD3AECABC73FAEULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x8822D315D690108AULL,
		0x8B7FF2C45CABF923ULL,
		0x9B7CAAA857858E1FULL,
		0x9AEC31B323EE091EULL,
		0x0886A8C2715081F6ULL,
		0xD9EC55D7355DA655ULL,
		0xF3A0A06B8038C7DFULL,
		0x3DDE935D86B183D9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA154B87E4E53C4C1ULL,
		0x33BC451839A916AFULL,
		0x01D3A1472BB2B704ULL,
		0xB000AC338A8DA213ULL,
		0xD10E5A377519FCB9ULL,
		0x0504F4B5ACB9E480ULL,
		0x5998F82C6C39EF9BULL,
		0xE3CE9B43A188CA84ULL
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
		0x0C963D04F95F6EEFULL,
		0xC6FC0421306B2491ULL,
		0x5D1C902A9C7126F2ULL,
		0xE1838A0155A6E4D9ULL,
		0x45DEBC3716E2A753ULL,
		0x4161F409793E69CFULL,
		0xC5CC881FBCB646E1ULL,
		0x98C4A224D447FF7EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE5A117B27BA78D78ULL,
		0x1809DA4ACB01A7DFULL,
		0x158C29F12DC3B60BULL,
		0x90148B7BA681231DULL,
		0x47251C292322F458ULL,
		0xF7EDC37B7C727732ULL,
		0x09257A4D9114B0A3ULL,
		0xEDFD83B3BE4D4458ULL
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
		0xEBA2EFB1839E8CF6ULL,
		0x62A93E09F193CB66ULL,
		0xB41C41E958D3BD5BULL,
		0x32C26950C403B6E2ULL,
		0xD54AB0D8AD527C28ULL,
		0xD092B352DE4828E0ULL,
		0x76A7FA332B7BE726ULL,
		0x8694609975B5C044ULL
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
		0x482715A5357275CCULL,
		0xD57F296893289BCAULL,
		0xC462CFE5A872AEC6ULL,
		0xE2E41B749AA0F494ULL,
		0x85E4CF2160A70D6BULL,
		0x1BDD673F46055FD2ULL,
		0x6839F933D9CAC4C3ULL,
		0xEBA8ABA485D415FCULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x068D58440381B606ULL,
		0x3E29E4C8A7DD4441ULL,
		0x8635788AE5E209FFULL,
		0x6FF659FF4A26BA33ULL,
		0x5951B4B0894DEFF6ULL,
		0x640E7187DD66F5F5ULL,
		0xE92492FA16C9A928ULL,
		0x5A736B20BA24F6F9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7D34C6718963911CULL,
		0x2513254EA8BFDCC2ULL,
		0x2E632D6AFC73E018ULL,
		0x91F6282D03D5AF94ULL,
		0xAA607E7F284B55E6ULL,
		0x7A2141E3AE0E9FABULL,
		0xE69B4198B08114FEULL,
		0xEAF2864F51CF9F32ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x56B733A66CF795C3ULL,
		0x92CA38DD94FEB0ABULL,
		0xB7628BEB8FC42E0AULL,
		0x0B2397FDD3EB8B69ULL,
		0xA65FF494EABDA33BULL,
		0x14E70AB752115FD1ULL,
		0xD5D17FED3F8BBF48ULL,
		0x278B1522EC0AF4AAULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x1556D3DB8C1C5192ULL,
		0x32724A8BC6F1C654ULL,
		0xB61BCF682A0F1219ULL,
		0xC3B55419AB8567EFULL,
		0x6AE83029F0523602ULL,
		0xC343D0D43BCC36A1ULL,
		0x00D99CD47E97E3B8ULL,
		0x19CEDAF0BA920218ULL
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
		0xA98D8D984E870071ULL,
		0xF99DD74B5FF0990AULL,
		0x02D1DB8AC286DA0EULL,
		0x24863DE7E0DD2C73ULL,
		0x8727AA92198E9F9FULL,
		0x072D787ADF9248E2ULL,
		0x44B2DB62009EBAC9ULL,
		0x41613057378C7B5AULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x0010712B0536AF1DULL,
		0xF345705594AC0D44ULL,
		0x56FA9472FA2C5E6EULL,
		0x21FF233E2C465F05ULL,
		0xEDA17D00CF7F83E9ULL,
		0x68B0783DED10D789ULL,
		0x47BB117521F90CEEULL,
		0x8A15B52FA3BF853FULL
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
		0xEF2B2217E61310F8ULL,
		0x63123D05CDF6E938ULL,
		0x6A58CF1F487782EBULL,
		0x9F3AC10B26C7BE8EULL,
		0x62EEEE1AA25E9921ULL,
		0x8CE8AB3AB9364605ULL,
		0x0B8CF6E7EA3F0ADFULL,
		0x852F9B1D6F9B8AE0ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1AB9DDA6FB24D1B6ULL,
		0xC922DBE56830722CULL,
		0x8C1E4EE1A665127FULL,
		0xC3DC7EB652FF93B5ULL,
		0x7DFED554C845606AULL,
		0x4C9D7C95EE235BE9ULL,
		0x513204CA7E8B7D2DULL,
		0x41D7FB775D324A69ULL
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
		0x0B114F874D2DAB5BULL,
		0xB67B1848B404599DULL,
		0xFB018A993F14DF3CULL,
		0x51CCA7694E5E947EULL,
		0xCB7BDAA38FED970EULL,
		0xD23899F2D0465E76ULL,
		0x337BCDC41F73C5C3ULL,
		0x6E98BF0CE0655E63ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xD9A6EEC8E5EAD8B8ULL,
		0xB0449AC68AAC3128ULL,
		0xC0D5E16D571F4305ULL,
		0xA5DA099F8C16AA0BULL,
		0xA751ECD9B2816543ULL,
		0xDB8462FB0FB02CA5ULL,
		0xDE36AEC10DFD6B51ULL,
		0x377C7A3C8F1B026DULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x76516E9089DC8998ULL,
		0xB3C74E31D42E9BBFULL,
		0x5F2023E9CE5F2781ULL,
		0xCB18DD8B46E3161EULL,
		0xDB5BDD289422EFA5ULL,
		0x2EB029B323901607ULL,
		0x32C2AAE20C6962E5ULL,
		0x4E78DA86BBAA51BFULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x33074C3A02309AF8ULL,
		0x1AE23D7095998D9DULL,
		0x4988C6584766AC60ULL,
		0xF54C2A4E09904D77ULL,
		0x34143606C452F058ULL,
		0x7FBD141B5091A014ULL,
		0x09123839231ED6B7ULL,
		0x97E9F10652FE7365ULL
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
		0x1DF6BC615B2F6465ULL,
		0x0697C2B96EF483FEULL,
		0xA5AC43F8A963E107ULL,
		0x2E1B1F7B28A80AE8ULL,
		0x59D282D6D94189D0ULL,
		0x843040BD3566DDF2ULL,
		0x20C187CF98263684ULL,
		0xB84194E61E9B3A06ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x84E50453FB0A4A48ULL,
		0x93FF40F3991BB1B7ULL,
		0xBCDC668377CD8CBDULL,
		0x66ED8D738099D0CFULL,
		0x5FBD0C010E4898FEULL,
		0xD4D4A8EF08260B97ULL,
		0xB2A549A6080C2898ULL,
		0xD67FCDD3E4FDA99CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x693006D10F6B1A51ULL,
		0xA511F1EB625EAD8DULL,
		0x59E2F8DE55BB6838ULL,
		0x6B49D4DA9A8CAA30ULL,
		0x295065AE34F16D16ULL,
		0x63D0588E9C4C86A8ULL,
		0x193CCF9549839FDEULL,
		0x622926CCB1281283ULL
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
		0x2782CE7DD5A5DD0AULL,
		0xE140087F732B88A7ULL,
		0x8FC0AC2BF2FE05A9ULL,
		0x3FEAF811C0B75A5BULL,
		0x5803A8D5B79F1E5CULL,
		0x3DE1CBC1CFD61433ULL,
		0xCA2A4D43694CA5CCULL,
		0x66AA5D570F0C4B47ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1C2D67799EF89CA2ULL,
		0x2E1A33082AC65D88ULL,
		0x17C33D0E78BFE1F2ULL,
		0x4AD6D320A4FF0B39ULL,
		0xE1DCD9F2B6D35110ULL,
		0x81498E97F127EF4EULL,
		0x26F0CA51A576F04DULL,
		0x923A6E9C031C2219ULL
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
		0x55E51702D4695E48ULL,
		0xAC5707644546AC5FULL,
		0x47931398E3FE4A2CULL,
		0x744D75B0F12342CEULL,
		0x4AC06018A8DE95EDULL,
		0x1A97500337A10F0DULL,
		0x5799154F5FDF4A22ULL,
		0x9D674CDB66191B12ULL
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
		0x6B0ADB934DBDB0E8ULL,
		0xA2BFAFAB0ECA14A8ULL,
		0x6BC65C625DE908CEULL,
		0xF4A6959F424A86AFULL,
		0x3D694E58E96791AAULL,
		0x123A9217C36FEAB7ULL,
		0xD8F4FD3222BB229EULL,
		0x47BAAA4528D010AFULL
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
		0x648B8DD3EA2AE693ULL,
		0xE34660C6E5B2824AULL,
		0x9F6DD4D0AC312883ULL,
		0x0864F05DFDD08DE5ULL,
		0x5E2D651B394B0BDAULL,
		0xD03A305B216E98C9ULL,
		0xD8F2FD2E4D95A268ULL,
		0x60DBD9C508CE54E4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x9CC48246683D0B28ULL,
		0x352742C7E4CC5CE5ULL,
		0x80AD260B4ECD9E74ULL,
		0x756E2DA862BA8745ULL,
		0x24B6A7786EA94C1FULL,
		0xBA227E4DFC625A0EULL,
		0x1B7A0EE3F2EA4497ULL,
		0x9E4F3DE25EC1E463ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x89BCA8778A66934BULL,
		0xC995F1FBE5938812ULL,
		0x7A61619A89E3770AULL,
		0xFCD3A54BA025DAD1ULL,
		0x5BE35FE8760C21C8ULL,
		0xB00D1975CFE1F2B2ULL,
		0x0CFD6D37D0C05CBBULL,
		0x805077310FDBCAA3ULL
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
		0x4D34EB5FFE7DFBFDULL,
		0x331C23B41C3473BDULL,
		0x57D7360271126765ULL,
		0xFE63A0B377916FF0ULL,
		0x8F31472FEF3CE5BCULL,
		0x181AA3CADCEA981DULL,
		0xF13D887EB983692AULL,
		0x8E2705DF50BD7A62ULL
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
		0xAE2C33F2CBD1D3BAULL,
		0xAE49F792CEAA8A45ULL,
		0xD67A5A8F4C583B31ULL,
		0xB300A8336148C83DULL,
		0xC06B561A53A353EBULL,
		0x159D15F3CC77FB30ULL,
		0xD0289B5CE35272F0ULL,
		0x6F447871B326C840ULL
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
		0x242F13AC9B128508ULL,
		0x8329199C34A6C938ULL,
		0xA8E6B87FBF640A2BULL,
		0x1CABCE0FDCDF7F10ULL,
		0x7EADBB8334EB601DULL,
		0xE9593D7F1AD9A0DDULL,
		0xD2F30BC81441BC78ULL,
		0x772E3F04222316ECULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x139C7227A8746EDAULL,
		0xF206E56E5894E1B5ULL,
		0xB2139E8A5065F58BULL,
		0xA4EBEC3B7D9BC926ULL,
		0xE3049B6AA9F68998ULL,
		0x52125F9A2433E4CCULL,
		0xD337ECEC18935E78ULL,
		0x277EFDB5D46237A5ULL
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
		0x1480D7D42572D161ULL,
		0x8E09ACDD6DCFB8CAULL,
		0xA20FA4C85FF0D4ACULL,
		0xC0FDF308266867E9ULL,
		0x8A6793316B6ECD27ULL,
		0x6DBAE7F968DCEB28ULL,
		0x0140BD132D1D54DCULL,
		0xE32FF764D037F8F2ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x405A7BA9D88CCAF9ULL,
		0xA04A9D8256D825F0ULL,
		0x008121A0C9E6E708ULL,
		0xDEA3775F226F5D2CULL,
		0x811BB83A3FD7AB78ULL,
		0x121A59756C0CE42CULL,
		0x533182763BA46058ULL,
		0x2A1FB54AB6625725ULL
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
		0x6E4AB4C2BBC9A72DULL,
		0x8A6A9CBC8A421BF0ULL,
		0xAB920B8DC7857542ULL,
		0x4F955D8C0FB039BDULL,
		0x03FD3D6B2D95F348ULL,
		0xE45D2A7276577FF5ULL,
		0x519622A9D17C4ACDULL,
		0x902878F6C8788368ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xDA54D76AB85CC4DFULL,
		0x75FA6E875E12D7FCULL,
		0x986803B27A4CC503ULL,
		0xF098C79D475EFACAULL,
		0xDDBE0059A9C08299ULL,
		0x032AC60884ECF357ULL,
		0x762800301A738092ULL,
		0x7DD727CB15BB1A8BULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x159D20DB5D33C969ULL,
		0x1CD3A996CB802399ULL,
		0xB05A990D2DFE8DEEULL,
		0x784EB854C01B761FULL,
		0x39ECAAD1B03BD87DULL,
		0x5A9A917B63BA6AF1ULL,
		0x5A1D1319882E2245ULL,
		0x02D829A2C7E118DCULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x770B768B0A3E6B1CULL,
		0x129742B641C55304ULL,
		0xE82B339C8982CFE2ULL,
		0x14D5059D312F547AULL,
		0xF86D0F3578576DECULL,
		0xBBA36DE8A9A091D2ULL,
		0x0108CB3E00AE650AULL,
		0x0E9521659755CE83ULL
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
		0x6D162B8B665FB2B1ULL,
		0x8A42B703E94754E0ULL,
		0x09B56B549610D02BULL,
		0xCF14121A7A0DBB05ULL,
		0xB258AE724221545EULL,
		0x203F38E3FDD18B21ULL,
		0xAA510F97D4CFA9A2ULL,
		0xA6BA5889502FD056ULL
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
	la = 505;
	k1 = (curve25519_key_t){.key64 = {
		0x1C2FCAD41FD7047DULL,
		0xBEBF43C944E9665CULL,
		0xE7730E010DDD3934ULL,
		0xCB54C24264AFDFF1ULL,
		0x991C01D7B77B462DULL,
		0x994B0472DCB39DBEULL,
		0x989C8F868A28CBD2ULL,
		0x02192F61D937748DULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x37A61355DC289CCDULL,
		0xC97E058CEDED56FAULL,
		0x8C017FC764D90018ULL,
		0xD31C143FD3CCC2EDULL,
		0x54AD04978022D95BULL,
		0x12A8AC15AE76C9DDULL,
		0x9678DD326497059CULL,
		0x1AE1FAC9A459440BULL
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
		0x8C1E445111AB3B07ULL,
		0x6F27536C174C60EDULL,
		0xDA534673359468C2ULL,
		0x3FC5C67FC773C67BULL,
		0x4F8D6FB26A24632BULL,
		0x4DF46AD05A474A86ULL,
		0x14B6CDD98E2E6F2DULL,
		0x9C97C226EB5268E8ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x35B9BE3DEC53F6F1ULL,
		0x20F5BB6BAEF957F6ULL,
		0xE1CC11949F8CED38ULL,
		0xAD050A28E4E6C93CULL,
		0x47735E5F0A77DF9AULL,
		0x007878D763088DE0ULL,
		0x70B6562FEF2F3763ULL,
		0x34FA383C556088BBULL
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
		0x528CC1EFC3DF4F63ULL,
		0x6FD48385A7139403ULL,
		0x6CECCCECB1493BDCULL,
		0x4BF3992C05889792ULL,
		0x37228E9E9F0F6A97ULL,
		0x4A0F0A3537AC9723ULL,
		0x47875F18AF630FDCULL,
		0x9ED2A09122C275BAULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x69073401FC1DAFCEULL,
		0xC0F7E51C2FBB1EDCULL,
		0x2ACBAABD90815CB9ULL,
		0xA0FFD7EC2CE5A780ULL,
		0xE193E3AA2D22FA22ULL,
		0x7A05D3F7E36D311AULL,
		0x288463074F03FE7FULL,
		0x7B479003F1E42277ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x31351C3B41510F5AULL,
		0x6EFB93B365D74BD2ULL,
		0x2059875B66CDA230ULL,
		0x64D857367ABA3389ULL,
		0x41A18E7E58A24C54ULL,
		0x10538075D84FE650ULL,
		0x5D885FD37147322AULL,
		0xD41430B2BF13624DULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x02ACE020A40D05F5ULL,
		0xB8F85881C3AA874CULL,
		0xA488F022874D5CDEULL,
		0x0CEDC7D8DC74AA6AULL,
		0xBFC71396D5D95FC7ULL,
		0xA75957C581AF3429ULL,
		0x441E80B1DF6AE2A4ULL,
		0x28267A24DF0D89EDULL
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
		0x39DDED42185CDDD8ULL,
		0xB6008B674A0E3F92ULL,
		0x90EB8F75C71725A3ULL,
		0x8AA75E1279F1D97FULL,
		0x306089454DDB69FEULL,
		0x8555A0448FBC5016ULL,
		0x7A83EE5BBDCD1603ULL,
		0xF6976F1E986DC588ULL
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
		0xE41AC04F8F53FFA9ULL,
		0xB9300F5E71E3A57EULL,
		0xD44C3E3D4A11A06AULL,
		0xEC6B7F32900AC017ULL,
		0xC01802FE13803400ULL,
		0x0B7121BF181A6C24ULL,
		0x37A154D6725402B9ULL,
		0x75144B76BC6052FCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x90483AD6F7148434ULL,
		0xE8537902EB420EF3ULL,
		0x89EAAC69B9436FB0ULL,
		0x4F14F9AB4EDF9EE4ULL,
		0xEDDB7B21B00DB8C6ULL,
		0xBA5CE289A5AFF701ULL,
		0xD71ED0B7598380B8ULL,
		0xA4D1395BFECB48B7ULL
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
		0xDEBE05BD75FE84DBULL,
		0x651CEE506AC17005ULL,
		0xA2A1C39295713106ULL,
		0x2D338D0F00219E03ULL,
		0x0C17F7731D92094BULL,
		0x24FB5B05E88D5C65ULL,
		0xC6F3E14B4FDD33D0ULL,
		0xE53725F4D15FC596ULL
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
		0x552EB5446DB01215ULL,
		0x65D8851EC7F15A48ULL,
		0x2C5BFE3CC9A8A6EEULL,
		0x7570C5851B9B22D7ULL,
		0x46B1B8F0FC5B90D9ULL,
		0x4EC4EC60418354C8ULL,
		0x7E8C2D1A209A420AULL,
		0x88534D4A054C5FB1ULL
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
		0x42C012BF02F1B30DULL,
		0xEF81A1FCFA08F49DULL,
		0x8C4F1BEECBFA4D43ULL,
		0xBC764F4F1F395074ULL,
		0xA503D1FF0C3FF2AAULL,
		0xB69DD9F6433CEA49ULL,
		0x26CBFA3572AF62C5ULL,
		0x46E08068AC26AEE4ULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0xBC97217FD69BC6C4ULL,
		0x8A415524DF7AA992ULL,
		0x75D9A4EDDE04C17BULL,
		0x31B1245C52A2B08AULL,
		0xF0D82356FEFE1455ULL,
		0x7F2FB0F7BAF000DCULL,
		0x964AF5F45FC24124ULL,
		0x0E1DEABE09C08FCCULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x290901838E4A3B6AULL,
		0x84D8C459E1E98C7FULL,
		0x309AB1E9816F5702ULL,
		0x28743A4BE0ACD285ULL,
		0xF40EACF97E88C0A3ULL,
		0x4F8F5727EE8A35D7ULL,
		0x901B1E536E82C2F3ULL,
		0xC53221C2C0F92EF9ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x54D902713DD6DA12ULL,
		0xDFDE525856A268B9ULL,
		0x16C48ADC5509950DULL,
		0xC781ED18F8807063ULL,
		0x354E380CFFA61238ULL,
		0x65FA58AADD571F5DULL,
		0x70150AF83A97E014ULL,
		0x7E86D6748EF67A9CULL
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
		0x09474D9945C9653BULL,
		0x606EC76209C35FDEULL,
		0x5D7F285E8001F5CEULL,
		0x6E8B35962846D789ULL,
		0x428236BD919C70C1ULL,
		0x7DD16402A8E4F3AAULL,
		0xFA9BECE9016D6FA6ULL,
		0xF6CE7485D6899A15ULL
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
		0x06FF35F403EA5276ULL,
		0x431E2A75C504A0CDULL,
		0x13A85C85B2BB1D22ULL,
		0xCC6C4E1C21740713ULL,
		0x757C3E7344D5A433ULL,
		0xC1BD743D61DFEF3FULL,
		0x83534CCC0B051BA8ULL,
		0xE191D3EC6FE736FDULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x56C3FF02092253CDULL,
		0x010DDCE46323F9A2ULL,
		0x68EFEF3D7BD1AC27ULL,
		0xED8E574CBF9900A3ULL,
		0x1B01CB367A664AE1ULL,
		0x8EDD1619D95C26A0ULL,
		0x2CCC172ABE1FF247ULL,
		0x2C5C2AAD90810470ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x80B8F564B6A49AC8ULL,
		0x66C438DD1703BBCCULL,
		0x8248E5F57C9884CAULL,
		0x8D7AF501596D7952ULL,
		0xA04FCC603A001FF9ULL,
		0xCCBCC20C66F3BE48ULL,
		0xEE6631B760719667ULL,
		0x4DFFF1F55E9BC82DULL
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
		0x37A0665E29D4644AULL,
		0x67BD6C127DE52B19ULL,
		0x09B9C83A6F0AE864ULL,
		0xA06E800BAE42AB53ULL,
		0xDE6EC88FE399FE85ULL,
		0xCE3843307D96E0D3ULL,
		0xC002210084FFA7B5ULL,
		0xEE31F67C9BB967C3ULL
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
		0x28E2F3CA5D542A5AULL,
		0x390BAA6AA7D0641EULL,
		0xF92756920A549516ULL,
		0x7F4249AD9A6170BCULL,
		0x881CB80EE18377E4ULL,
		0xBFD67DF5CD0089D9ULL,
		0x64D09B6BA6964107ULL,
		0xB6A7F5F023097D13ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x4125ECDD4C255E0FULL,
		0x17CF216E0AB52F27ULL,
		0xC69116610E5E66E0ULL,
		0xC3377C07DB64AB5AULL,
		0x91F3585B2C04117BULL,
		0x46D8DAFC5A560527ULL,
		0x81BC3B4E3EF4B551ULL,
		0xEBCBB4DD43BF3384ULL
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
		0xF656DA35C417A99AULL,
		0x06488FF003E2D449ULL,
		0x9FD27589CCC0DF34ULL,
		0x293EC2968EDF197AULL,
		0xA0DB51534F91A8BFULL,
		0x1441DD84D58D9001ULL,
		0xF1A1EB8FDE55A6CCULL,
		0xBA38F21A19DC0A35ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1B66B086B9DF1D3FULL,
		0x92877D02AF2AE727ULL,
		0xA6BACB5A3960A50FULL,
		0xEE6CCD0558885C5EULL,
		0x9342D612FC049C3AULL,
		0x6FF6795D772479A9ULL,
		0xC988BFC6C398E599ULL,
		0x62050CBC50DD2F7CULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0xD254823FFDECC0F7ULL,
		0xE49DA77D1A4FDC6DULL,
		0xF2F1957494700E03ULL,
		0x1EC175AE2414449DULL,
		0x31E08A0BFCBFA86FULL,
		0xF532529CA2D0C94FULL,
		0x242035C0630C4D88ULL,
		0x04756758E3E2A318ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1168DF8381EB8686ULL,
		0xD24BA453F04B024AULL,
		0x5089C61814AAF824ULL,
		0xB5AE7C333188B3C8ULL,
		0x6F2E291DC620E9FDULL,
		0x7C25DA29813D8726ULL,
		0x53E1AADD2C6F44A0ULL,
		0xBA7E7F0996BC932CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x978F631FE2B066EBULL,
		0x5790B3567930E4E5ULL,
		0xF8A71C6FCC062429ULL,
		0xF1F4997EBF152A6DULL,
		0x7BB351D474390E24ULL,
		0x9FE7FF3670B2C2B3ULL,
		0x81A5886FBBED128AULL,
		0xA1CC0AC97BF1376BULL
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
		0x26C954700842E20AULL,
		0xCFA2C38A1C030039ULL,
		0x1A24E37B152D880BULL,
		0xA6E948EB811C9B91ULL,
		0x7FA3ED59A4A0F2AEULL,
		0x88B2D13F0B104A91ULL,
		0x3F81739143E25660ULL,
		0x280D26FF830D3DD7ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x339181226E707013ULL,
		0x0718BAD81D760BB1ULL,
		0xC299152DA5DCB3DAULL,
		0x1C208D5DA020C075ULL,
		0xE49C9C9125BA5C17ULL,
		0x85A4880C063D36A3ULL,
		0x3B5A65A52BB8FD0BULL,
		0xC94B3A09CC847252ULL
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
		0xF12FAFEB8664E94DULL,
		0x56B7F5AD54C13C9BULL,
		0x2BB6AC639BA7B1A6ULL,
		0x0DE40B4C14B35895ULL,
		0x1FDD5C8F92B502B9ULL,
		0x7BD526340FCA9880ULL,
		0x79E71EBD7BB3FCA1ULL,
		0xEFECC0111601C90AULL
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
		0xF075DB7FC441626CULL,
		0x78B1AC4119BDFD36ULL,
		0x6FE954C6D802F4AEULL,
		0xBB890990C00D86EAULL,
		0xFF772DDC7E0BF739ULL,
		0x0FBA88ACCFF9E03BULL,
		0x3E8CD61D7831C608ULL,
		0xA0057B856B6E25D7ULL
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
		0xEA55CB7BDD812367ULL,
		0x067D46E29F20F288ULL,
		0xB976FD65902CEB30ULL,
		0xD2248015A6A148B4ULL,
		0xF2FC05ADDE5AC6E7ULL,
		0xD1158E6CB3EAE7A5ULL,
		0x18DA26DF9F52D8B6ULL,
		0xCBBC7E0014CE6B72ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xA02A4CEAAA473520ULL,
		0xD61E287736827A89ULL,
		0xD5CDA2170C7E6BE8ULL,
		0xF77973641A04B899ULL,
		0x9B4935A2D71EDE23ULL,
		0x724FC36A044D27BEULL,
		0x0835758BA0A23374ULL,
		0x91C23A26C88FD07EULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x682EB9BC0986F039ULL,
		0x1863B4A67C294D75ULL,
		0x4D7AE2B9D6AC24C9ULL,
		0x7DE0A0EA8D38B2E7ULL,
		0x9C9202988EA3BFE7ULL,
		0x05DED0DA95AC0BD3ULL,
		0x7277E0D0D10CA90AULL,
		0x7BCD5E2B05B31544ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xABF2CA640A66390EULL,
		0xF4B89260551DF22FULL,
		0x28CE15DC4F3BD471ULL,
		0xF832BA3F92DDE27CULL,
		0x8AEEBD192989186CULL,
		0xAF5575F66F825B33ULL,
		0x91FB4375EFF893F1ULL,
		0x35E0C09A83BD2365ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xEEEE929069D75DCEULL,
		0x212E530C96B7AF74ULL,
		0xC2AC9D7940CF0DECULL,
		0x7A5E4B151B958A2CULL,
		0xB1EA80A4BA790D05ULL,
		0xAF4CBE30EE7696D7ULL,
		0x7383AF7991D7B5A5ULL,
		0xF1301AB32A35B5EEULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6BA2829B5F51F05BULL,
		0x6246B319F4B16843ULL,
		0x3B2ABC718F821C9CULL,
		0x9D2A89EC17A7CEA4ULL,
		0xA402FCA78EE709B6ULL,
		0x6770688F950799A7ULL,
		0xDFA090AD89A3A94CULL,
		0xF5064DDC07425D5EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE36603E1ECFE8ABEULL,
		0x15F44E9D4B23B4A6ULL,
		0x2F26C580F3ED9143ULL,
		0x1523472610E7F558ULL,
		0xE90781F4AD9F6B12ULL,
		0xF7B96B30C4DE8BF0ULL,
		0x2C882B6B1D913C7FULL,
		0xE0503C012506709BULL
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
		0x9819EBCD81E48F83ULL,
		0x39C334EBDFC9B9AFULL,
		0x034B71EA65B8C52EULL,
		0x258F2A15A5B84E01ULL,
		0xC808CBF3D205ADDEULL,
		0x23CDC8E6B74DD31BULL,
		0x226CEFE7DA4030FCULL,
		0xCD4280ED01FB789FULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xB88E1F95D7FA6F1DULL,
		0xB458F0F90BC21CEEULL,
		0x51BC4D6D162FAAA8ULL,
		0xC9DA9B294675D152ULL,
		0xA6F3C89425415102ULL,
		0xC1DCE7D16A673E57ULL,
		0xC99E64592DFA60D2ULL,
		0xA1DDD87EB511AF6CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x85D239D3D1DEF272ULL,
		0xDAB7CC0EA1F62089ULL,
		0x00EAA3D143021B0FULL,
		0x15494870999DBD68ULL,
		0xACF92C876EE4DEFEULL,
		0x961C98F9A5FAA059ULL,
		0xF348F47C2DADB49BULL,
		0x5A32257E03C55776ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xA5245AB414DA9696ULL,
		0x3197063848006082ULL,
		0x7C44BA19917592FDULL,
		0x98A28D8B7F5A8B15ULL,
		0x03D8C644EF58CA0FULL,
		0x550F888E5311D44EULL,
		0xB4A31B782B499616ULL,
		0x25EC97C7F562E499ULL
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
		0x741CC60AB51F035FULL,
		0x949123EE2DD6A559ULL,
		0x860AF772F9054240ULL,
		0x06B5BB3521B1185BULL,
		0x7FBC233298939FC8ULL,
		0x90731F3367CAFDD5ULL,
		0x698423CAB41A20EAULL,
		0x795327B68C46ACD4ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x150931EBE88DC4EBULL,
		0x1940538592121CD0ULL,
		0x004F56EB61AFE864ULL,
		0x17F677C5E3C1FFF0ULL,
		0xF57CB807F09E856BULL,
		0x015F58F71F75F598ULL,
		0x4A6EBA24CCB09505ULL,
		0x3BC2474664BA6EF4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF3921774B6E15DF9ULL,
		0x94737CEF507A0C22ULL,
		0xB36F31B0299C14CCULL,
		0xE9D841C059088BD7ULL,
		0xCD121F0CDE4E0A15ULL,
		0x82DC2A7A1DFC6E8DULL,
		0xD58BE579163AE79DULL,
		0xCD4CD770BDBF6032ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0xE2FF757BCD4F7637ULL,
		0xF3CBBB466D4C0264ULL,
		0x03B856EF2E4C8B53ULL,
		0xD4F4B20B72473C38ULL,
		0x454315F09E7BC348ULL,
		0xF4B20CE5E3BA28BAULL,
		0x3C1FA418CC69EEB5ULL,
		0x2CC3F265E8A2259CULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x57D4E6B7DE751B90ULL,
		0x2089222DFD6827BCULL,
		0x18BDF3057F4F3724ULL,
		0x2F11960A1B2C6466ULL,
		0x75444B915A6271C9ULL,
		0x3F3FE23D0091A7EFULL,
		0x95C991640C512432ULL,
		0xD3B1FA412116052CULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x21F6D8F1F3BDA042ULL,
		0xAF8F014B79A9317EULL,
		0x5D27221683BA35D9ULL,
		0xD7ABFFAAD20D3FC3ULL,
		0x7E8AACF7735278D8ULL,
		0x0561B732A5B1F571ULL,
		0x8240D4EA04A90A2EULL,
		0x73F7712F8AE742E3ULL
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
		0x2DECA74916E4E47DULL,
		0x670D69B0CCB9B8F4ULL,
		0xD3773C70F84BB2DEULL,
		0xC721D8A054469CF7ULL,
		0xB1CA481AFD30C718ULL,
		0x133EAF122B830B0EULL,
		0x48222F32CDDD8C27ULL,
		0xF13EECBC34FF0449ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x63FD16E60F02C045ULL,
		0xE385C151D92EAD9DULL,
		0xAF79CA162DA4C51EULL,
		0xDC29ACF24380338BULL,
		0x866BF24E3944F764ULL,
		0x0030DAC82D227562ULL,
		0xC82D5DF95280AD62ULL,
		0xC43CE00E4DB264A0ULL
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
		0x035EFF7B43B283B2ULL,
		0x06139495384035A8ULL,
		0x64D65E4E6C220245ULL,
		0xE20CB66D453E4B27ULL,
		0x7E728812D9E3A015ULL,
		0x1EFC5E4E6FD7AE72ULL,
		0x399DA937B12994A7ULL,
		0xD4161F10A81C67BCULL
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
		0x34540FBD74BAFC8FULL,
		0x3B272DFC4A03B4C7ULL,
		0xE892C6DBB3C48FC4ULL,
		0x13F71179FABD381EULL,
		0x1A95F8F4EC40A2E9ULL,
		0xDED369ABBF842258ULL,
		0x5EB653FD964C3ADCULL,
		0xAC9DF5090B91CCE6ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x09C380E8B9B10ECCULL,
		0xE7D759E3C7553EB7ULL,
		0x66DCCB3D8A003525ULL,
		0x2BDED9770223E2F1ULL,
		0x9D6A7A4F3F079FCDULL,
		0xD8AAB71CB77E4882ULL,
		0x9A5A46FDC39A617DULL,
		0x6D420E4FEC320797ULL
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
		0xD32416E03051110BULL,
		0xCC904D6964CB04D1ULL,
		0xAEC0224FB640F799ULL,
		0x25C531B3DD9638F6ULL,
		0xF55C699CB9C6181CULL,
		0x4A036483C78ACD57ULL,
		0xF301899780DC5721ULL,
		0xCE16D24DAA9F19E2ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xBB84BED74A084611ULL,
		0x4000982B42DB260AULL,
		0x7ECCC8C269682874ULL,
		0xB632F0D918E2B3C8ULL,
		0xFDB98C6894A165C4ULL,
		0x196D29A288F68F24ULL,
		0xCB6EF4AEB2CA26A5ULL,
		0xF9F189CA0FA4D78CULL
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
	la = 507;
	k1 = (curve25519_key_t){.key64 = {
		0x69C9B17A20EF6A70ULL,
		0x4EA1AC8727430BFBULL,
		0x65F13DD9B2B34AA6ULL,
		0x36E1F5528575A10AULL,
		0x9592CF4A006C28CCULL,
		0x43C015DD65200442ULL,
		0x1C691012C8EF4685ULL,
		0x0961F71E0DCD0B7AULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xF30B4D367C9B25E6ULL,
		0xF62C0B73DDAE9B0DULL,
		0x91016C8E1705B086ULL,
		0xB03DB37B7B9507F8ULL,
		0x3EEDDF7E26CD4438ULL,
		0x2F1E2CCBAFA26227ULL,
		0x2D866B6E4053D3CCULL,
		0x74E7E66CA8216D7AULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x73FB9874D4A036A6ULL,
		0x2CDAC108C2AF95B6ULL,
		0xAF311115B84C01C9ULL,
		0x69244BF3D4183E3CULL,
		0xF02D55F1538C8CE2ULL,
		0xA64FBE6BF45F8A37ULL,
		0x2A758294558C9CACULL,
		0x2F8A625DB960A73DULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x35DF2DD43CD1FFD0ULL,
		0x95329017E8299402ULL,
		0xB10CB197D0EE3AC8ULL,
		0xBAA73EBA1CEA0EC1ULL,
		0xC90CBD8DB6E70A58ULL,
		0x9EE1F9FB3D3EB46FULL,
		0x9BB653804F93772CULL,
		0xFD5C774AD8C2A605ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x2AAACECB8CAB2601ULL,
		0x55B28E409869182DULL,
		0x5AFA78D2A70D11E3ULL,
		0xFF2E79C9C3EFA131ULL,
		0xB656817906843AE4ULL,
		0x83DAD8F1721067FBULL,
		0x9002DAFCEC5E4B58ULL,
		0x20B7E7C8B24FC536ULL
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
		0xD482DCD1508A6477ULL,
		0xFE975CD3D5168E57ULL,
		0xF2982A4184B510CDULL,
		0x9C94CB26C8F08ED6ULL,
		0x55FB128A6318AF76ULL,
		0xFA9CE8C9A207806AULL,
		0xFF09A435578026F0ULL,
		0x810A1BA2A0BEFE43ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x0CECBD031562AA9EULL,
		0x98EECD94C9FFA363ULL,
		0xFF6D9CE9A592ED96ULL,
		0x4004AC5B8819ADCBULL,
		0x19AB871B905E01F3ULL,
		0xA44CF1F3B613FBC7ULL,
		0x731DD67B2E030AE6ULL,
		0x1251137DDF72CAFCULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x6F76D1F8DB06AC54ULL,
		0x07BC1509E4D965BCULL,
		0x807D46B202A335A9ULL,
		0x50AA70F2CE7E1D23ULL,
		0x7CC4BCE7C81E734BULL,
		0xDF0E0DA1AF72DBE4ULL,
		0xC8280BC8E01D73BDULL,
		0x34B779F21ABEDF65ULL
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
		0x1A880A626D5055BBULL,
		0x01F266FFF289E2B5ULL,
		0x6802C31A00007FB4ULL,
		0x3E535A435F2787BFULL,
		0x1D2BDD552BFD94CEULL,
		0xCA1D449E8116F855ULL,
		0xCFD6AD664249ED22ULL,
		0xD1E063C4470B4964ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2719F526FA8F68FDULL,
		0x4B836BF05F06CBA9ULL,
		0x9EDE2B5A7E6E05AAULL,
		0x141D4D30A258C12BULL,
		0x5F0F33163E2BB153ULL,
		0xF82243782F262FB7ULL,
		0x7DC1F1763026B89CULL,
		0x5B32B0C2B42E39B1ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x6609F464C660DDFFULL,
		0x7231BEB91D1587C0ULL,
		0x9D2EBE9109CE8078ULL,
		0xEE985986FEAD2EDFULL,
		0xB8AC975CDF4AF5F8ULL,
		0x1B3FE80787D7C9D6ULL,
		0xED1BE7F468B3E4B7ULL,
		0xA706974A804943D0ULL
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
		0xDE93C3338A276DF1ULL,
		0xE39A5BAFDFB48972ULL,
		0x75843A68DF0A6E6AULL,
		0x3F1B142014AFA1D5ULL,
		0x1CACF43853993374ULL,
		0xCD52A4146DF400FDULL,
		0xAA68510491ACFB06ULL,
		0xCCD916AA9B930CACULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0xD3ADE24F7EC9C8BAULL,
		0xE1B46164FA36E6D4ULL,
		0xE0F46CA08900D26CULL,
		0x678E405F49B71C4AULL,
		0x3489D0275D44F4BCULL,
		0x4A03065FC12C257BULL,
		0x621B6D0371A8D491ULL,
		0x677EEAEA0CEF109CULL
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
		0xAE95C4F5C699F068ULL,
		0xD3BD0F52F8FD2FF7ULL,
		0xD0A33541481125BCULL,
		0xAB3F8EEB2C727F24ULL,
		0x62E1BC71983C00C2ULL,
		0x824E75500DFA520BULL,
		0xC7BC5A33CCF33158ULL,
		0xC5601AB82746F614ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x3054519CEEB383A1ULL,
		0xB1B0D3B9BE07AD08ULL,
		0xD545F44EB82A6F9CULL,
		0x3DFF44A171216C5EULL,
		0x640FF4BF0DD28E91ULL,
		0x55D805EAA4491190ULL,
		0x2D1448C9AB9BC197ULL,
		0x5AE91C8E4E740B3BULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x7C652DB05902803FULL,
		0x87E31065E05213ACULL,
		0xB1EB7592B793ACC5ULL,
		0x1C84B69EFDBCA390ULL,
		0x7410C13F16391549ULL,
		0x8C9E499D91854E41ULL,
		0x1DD09C924DB71ED5ULL,
		0xF7DE3DB77D2CD2B9ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xF07FFDF0C7AC8EDDULL,
		0xC4601B2DE35EB17AULL,
		0x7814355DDCA3F459ULL,
		0x33402FF8FB9FAA4DULL,
		0x60885C47E40E032BULL,
		0xD1C52197ED95D963ULL,
		0x3E22A98F65C17F80ULL,
		0x81F3C49F77699089ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0xE4A6F1FA61AF8C79ULL,
		0xBCCF8FE6286E977BULL,
		0x9DBD89F39B2CF212ULL,
		0x9D4CD647FC0B6459ULL,
		0xC90200E7F867095AULL,
		0x735B05D3304EE8DFULL,
		0x3A6737AD490387A1ULL,
		0xE64705523F2B45E5ULL
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
	la = 508;
	k1 = (curve25519_key_t){.key64 = {
		0x46742A1CD5C31451ULL,
		0x8CE3880C5BFC8D8CULL,
		0x75C005ABD12EA61DULL,
		0x7288AC05D7C0154CULL,
		0xBAD28BD703C09C84ULL,
		0xD19CAFAC5251000EULL,
		0x3B2141BB95635AF1ULL,
		0x16DE4FACDCF70402ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1C05EAC164180EE6ULL,
		0x9F028CBA08E3B1BEULL,
		0x3B41B6AF858AEAFAULL,
		0xCE720238765034A3ULL,
		0x4E21A947D02D944AULL,
		0x82672BC15AE53DC2ULL,
		0xD3673B4315B69F15ULL,
		0x7FE64BA7D769ED0BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x1D38D71CC52EDA45ULL,
		0xCEB30B9D232CD3A6ULL,
		0x7B8F1B194CB5F888ULL,
		0xC5AD94174BA08794ULL,
		0x16416DAE09BD824EULL,
		0x49B36E5393F0D4CFULL,
		0x5DCE1BBE68D56CEFULL,
		0x4F63DF77D27AD170ULL
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
		0xB90219D77D208468ULL,
		0x7771E8DC9C16B855ULL,
		0x4D0ACF38A147B510ULL,
		0xF57E406D56F4B9ECULL,
		0xECDA592970EE3F45ULL,
		0xEE8883A35A8C39DDULL,
		0x1C1FBF52D307623AULL,
		0xBF2E9A45FD332264ULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x17F2FB1194E97F94ULL,
		0x3C21EA8EA4B0C47EULL,
		0x6F835AC9C8261F1CULL,
		0x0075C6C670F0B684ULL,
		0xAF14A19ED78F1908ULL,
		0x274B589C6A988A3BULL,
		0x525968B610BF25C7ULL,
		0x324EC4927DA6A8A7ULL
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
		0x162557A014F33BBDULL,
		0x196AEF55F59F5DECULL,
		0x9EF2DF3A810265E8ULL,
		0x2598ABFEA106A577ULL,
		0x97926FBE18806710ULL,
		0xEAEA0DFC47BA5B8AULL,
		0x3686E0CBEB1D388DULL,
		0xDB68C00DA4EC8C0FULL
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
		0x56F5ED343EC3E425ULL,
		0xA195456CC424B7DFULL,
		0xF4A011EA3D233ED2ULL,
		0x93D5B59DD9CF7A57ULL,
		0x633CF1A1D2E1B7B7ULL,
		0x398A6FB0BE6E9BCDULL,
		0xCFDBE49F2BDC2B1EULL,
		0xC44EEE58FE4D616BULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x54BEBA6559B4AE61ULL,
		0x0B8DBECBB45A23F3ULL,
		0x964E14E4A60E1AD9ULL,
		0xE1259804AA9E81B6ULL,
		0x02F0B1CE622C705BULL,
		0x75B110D5128855ABULL,
		0xE8DF1D1702797CA5ULL,
		0x7C3A86266424395EULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x12D370EA654D6E0BULL,
		0xD8417F58E57E7A6FULL,
		0x922C8C40E2BB6C3BULL,
		0xF1D269AE7FF8BFBBULL,
		0x72B34958B292A65EULL,
		0xBBFAB2E5ADFB53DCULL,
		0x2B84097383B67CB4ULL,
		0xC4E436A669CF3F94ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x7EF6D079F3BFDB7EULL,
		0x5030D94CE974638BULL,
		0x13B263EDF61E45ABULL,
		0xEF62D48F2C45D0F9ULL,
		0x60E1A462E8A6F8A5ULL,
		0x8BC3AA2087ADD4D6ULL,
		0xE2DCF3E6C819CF50ULL,
		0x51839E64D0D7FDE4ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1BFCF824C5CB2B66ULL,
		0xD7805F3134A7D6F0ULL,
		0x5F134B8E28A6749CULL,
		0x4569FAC6C6A44B6EULL,
		0xF726D0EF4DD10106ULL,
		0xA4BC244A77B24214ULL,
		0x4311FAA863B9ECD6ULL,
		0x9A32E306FE1675C8ULL
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
	la = 506;
	k1 = (curve25519_key_t){.key64 = {
		0x3212A030DC577632ULL,
		0xC534D7520599A588ULL,
		0x694E7CB6932EC86BULL,
		0xAC6B6DD06263F257ULL,
		0x02EC816ED1F2C7C4ULL,
		0x4256A7459575DC46ULL,
		0x12630C6247E87D8EULL,
		0x05016EF701CF366AULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x367420D52FDD6C79ULL,
		0x7AEC28366DC1AFF7ULL,
		0xA2F199070651726EULL,
		0x1716815C69BB8F3CULL,
		0x0A9F1528D996065DULL,
		0x22F83DCCCE199AD7ULL,
		0xD28CA8518A9E6C00ULL,
		0x318378CFC4911F9DULL
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
	la = 509;
	k1 = (curve25519_key_t){.key64 = {
		0x982DAC9B3850E155ULL,
		0xFE38198ECF866A56ULL,
		0x11F599F4D47FC7EAULL,
		0x158B37F4723F9C33ULL,
		0xFAFCAEAABED2788BULL,
		0xA7A70F61B00BCBEAULL,
		0xC976A77571C99D21ULL,
		0x337898DD06D90F93ULL
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
	la = 510;
	k1 = (curve25519_key_t){.key64 = {
		0x2121F30AF2FF5F12ULL,
		0xDDE23476BA1243F7ULL,
		0xE5934A2DAC649D8EULL,
		0xC01E1E32A3D6FA3CULL,
		0x876F2D59D62AD22CULL,
		0xD700221C340F6843ULL,
		0x76E9D01B4A923093ULL,
		0x767B42B524D7E647ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x8AB729F9A1561123ULL,
		0x2EAD46B08912F887ULL,
		0x34E40283B8B14308ULL,
		0x8D982C6DC90828C4ULL,
		0xC28CFB48C6F9152BULL,
		0x4A379EAD01616D9EULL,
		0x650AAD96885153A2ULL,
		0xD982B0376BC6CC20ULL
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
	la = 511;
	k1 = (curve25519_key_t){.key64 = {
		0x1FE87BBE13D4C8F0ULL,
		0xD9ACA08326C4266EULL,
		0x64BE223F03978FCAULL,
		0xF9FD27AC22E64E7FULL,
		0xAD1DF071636F3766ULL,
		0x39B59E3376E5C87DULL,
		0x9E1F68E0EFABD47CULL,
		0xFA1870CC2D2F473EULL
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