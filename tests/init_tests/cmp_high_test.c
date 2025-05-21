#include "../tests.h"

int32_t curve25519_key_cmp_high_test(void) {
	printf("Key High Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0,
		0,
		0,
		0,
		0xED5D879FF80982BCULL,
		0xC4115C9505C2E8CBULL,
		0x6A6C0261E126498CULL,
		0x2318CC8BF944DF3FULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0,
		0,
		0,
		0,
		0xD08036AC54C93AD8ULL,
		0x4A8E85DCF9CC5297ULL,
		0xCD1DC5E7477B0E26ULL,
		0x713B35314700C280ULL
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
		0x07662C814C14ACF2ULL,
		0x594B4B5844011E29ULL,
		0x6638A5E19EC4E235ULL,
		0x01A639423DD464FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAB46367151D69205ULL,
		0x42658D187C6327D9ULL,
		0x027443620C2211BFULL,
		0x568D78E6C83B4AEFULL
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
		0x05EEF6FBE29D891DULL,
		0xB48430AF6C972F17ULL,
		0x53B37661AC7C5B19ULL,
		0x1A276CC44868BD5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2B007EF7FEC9BF5CULL,
		0xC7E31DBF8D13486CULL,
		0x3B1BE73F99EA8A80ULL,
		0x14FB36EE5A414414ULL
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
		0x4151966D6C43353BULL,
		0x799633E566FF0E65ULL,
		0xE03010CCD2C1FC42ULL,
		0x2E2A2279832A1E22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4979C34E723E0F5BULL,
		0x8E77AD7F3C62D31EULL,
		0xE904647C2DC26E10ULL,
		0x4407CC2B8C921926ULL
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
		0xCFE356C7A98A88B0ULL,
		0x2037B3407DDF5B09ULL,
		0x4E7969F8E3740102ULL,
		0x1552C11D4A023A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCFE356C7A98A88B0ULL,
		0x2037B3407DDF5B09ULL,
		0x4E7969F8E3740102ULL,
		0x1552C11D4A023A23ULL
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
		0x49F98CD925FF8337ULL,
		0x3A8BA80A66090F36ULL,
		0xC7E10EC4CA6AAC49ULL,
		0x030199896EF3801AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE96BE6B56267F009ULL,
		0x67A431CFDC2DD61DULL,
		0x6005307407C018AAULL,
		0x6B7BA12C30E8A0CEULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE441E0AF47DA0A0CULL,
		0x29B95D07B29BC1A4ULL,
		0xF667B41C2D102F85ULL,
		0x2725F4D04CDA0CD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06D015CDC312A3ABULL,
		0x64733B7081210C9BULL,
		0x2521457F045703B3ULL,
		0x3960BF2B00B7DE79ULL
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
		0x26CF98E5976E08B7ULL,
		0xD88E48E136FCA150ULL,
		0xDB0EEE1F47501A11ULL,
		0x35D1F2C73E5CCA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9013FE35529E58B2ULL,
		0x60F28BB82B98BC0CULL,
		0x06B7F58F95FD0E59ULL,
		0x1F8E963DB7E36D9AULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2E8D6F236A98450DULL,
		0x26D344F920A82C53ULL,
		0x657E46D17AEAFE87ULL,
		0x6909F75D74686558ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2E8D6F236A98450DULL,
		0x26D344F920A82C53ULL,
		0x657E46D17AEAFE87ULL,
		0x6909F75D74686558ULL
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
		0x1076BADE16682852ULL,
		0x72B30B653D38F933ULL,
		0x6E8AEA42002E5C5CULL,
		0x1703AF6844333B28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF17B7C104542DFB4ULL,
		0xECAF462360ACFFD3ULL,
		0xF0665508C98A440EULL,
		0x695FD107F27C9367ULL
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
		0x5E18FAD2876EB8C3ULL,
		0x1967A44DCE5CC52CULL,
		0xA38D50F061150E70ULL,
		0x608F4A84445D7DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x472B2CFA6FDE136DULL,
		0xDEC61C71FF7F3937ULL,
		0xF15629AAB95613F6ULL,
		0x7F4329E90C921F59ULL
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
		0x4156069E8AEF6DC1ULL,
		0x94E1AD84A3786DABULL,
		0xBA4C2B4814B793DDULL,
		0x02E648E2D4CCFAB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6931C2C604E34218ULL,
		0x95546BE42BDDB82CULL,
		0x1E3DA015A4513ECEULL,
		0x50D33BBDC2728A7BULL
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
		0x75218F264DA4D93CULL,
		0xF047084D685CCCA1ULL,
		0xD20583C4E4E1D4FBULL,
		0x55461F1BB2798338ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x75218F264DA4D93CULL,
		0xF047084D685CCCA1ULL,
		0xD20583C4E4E1D4FBULL,
		0x55461F1BB2798338ULL
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
		0x0D42EE525D327240ULL,
		0xF7E7B910602E4042ULL,
		0xBE2902B5DF13BD04ULL,
		0x6906FB0D997848C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFE87F2D9A3B4449ULL,
		0x2478F3CAB1044A6CULL,
		0xF561BB3C4448770BULL,
		0x078DC47A8BF94995ULL
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
		0x5785F344585704DDULL,
		0x3B05A81AB4961F61ULL,
		0xE2F1CB8149C36A7EULL,
		0x5DBC2A00609311AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDF577935CBF420F5ULL,
		0x65B7B22A8DCE12B4ULL,
		0xD43411A4C5062BCFULL,
		0x7AD69D317C99AB2EULL
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
		0xA7A4220F3B6AD737ULL,
		0x62FD006FD5643420ULL,
		0xD2ABAC8D67DA0073ULL,
		0x5419A97D32C40714ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB5A5AD33EC3E4637ULL,
		0xBA8202A496B8A878ULL,
		0x3FD76144994306A7ULL,
		0x17A8F1FAC37C2950ULL
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
		0x5807D3275FE023C3ULL,
		0xEC8FB17F3EEAB031ULL,
		0x42A31FF1734A5993ULL,
		0x65D6DC0D2E17F32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5807D3275FE023C3ULL,
		0xEC8FB17F3EEAB031ULL,
		0x42A31FF1734A5993ULL,
		0x65D6DC0D2E17F32CULL
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
		0x653C56A90F5DB8ABULL,
		0x89CCDD0D6FAD6C8CULL,
		0xEF07BC0C44573D40ULL,
		0x1A8B166BF3531307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB0DF20051E146953ULL,
		0xA5CC9E51ABF7902FULL,
		0xA5123704BB3F1D7DULL,
		0x0D60E799E8462980ULL
	}};
	t = 1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x26F11B163EC3B3D4ULL,
		0xC64EC11288FDC172ULL,
		0xED91DDB88AC827E5ULL,
		0x59451B8178333696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFAADD501822C00D2ULL,
		0xF75E47DB934F6FADULL,
		0x7AC66DACE6DDC1BEULL,
		0x7030034D1FB52792ULL
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
		0x86D4ECE8FDFA5AC3ULL,
		0x57091B1C52769E06ULL,
		0x6FFD4C7C9516021BULL,
		0x2027E3274313BA32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEFAD91EF9FFFBFE8ULL,
		0x248D622D13D6D630ULL,
		0xFDB012F79C0384A6ULL,
		0x60FA6960B713BD42ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4B36DFB4F6E683DFULL,
		0x5ED39B32EA21E99FULL,
		0xA9478AE280433AD6ULL,
		0x6A7F312FC541CA7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4B36DFB4F6E683DFULL,
		0x5ED39B32EA21E99FULL,
		0xA9478AE280433AD6ULL,
		0x6A7F312FC541CA7FULL
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
		0x94AB4C009160037DULL,
		0x5C654D1980146A91ULL,
		0x670D11E588F1E769ULL,
		0x65BC1877598BF24BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x475348F9DB86089EULL,
		0x4B4408A1D7325C8AULL,
		0x3470859681A27652ULL,
		0x1B7F84899B18C794ULL
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
		0x2CBBCF1D4BD09F05ULL,
		0x9D5564BDADC7CDB1ULL,
		0xCC41658A808003CFULL,
		0x15A37E74EA003783ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E26238383C1E83CULL,
		0xBE28631DEAE66C3AULL,
		0x296F3D0A38A10719ULL,
		0x0942AF9C4A829E41ULL
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
		0x0EBC0963A1AA8AACULL,
		0x5F198B34D49D79BDULL,
		0x3E1F22C5D86AC0CCULL,
		0x57802C939D348826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEAF1381FEF346456ULL,
		0x3A46D56D0CCFB065ULL,
		0xB130426E0CEF8F4DULL,
		0x3811F8BA5DE001BEULL
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
		0x914EF2138628D6F8ULL,
		0xCFB8624A24C158C8ULL,
		0xDDF563480EFF67AEULL,
		0x1BDDC30CAE009B43ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x914EF2138628D6F8ULL,
		0xCFB8624A24C158C8ULL,
		0xDDF563480EFF67AEULL,
		0x1BDDC30CAE009B43ULL
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
		0xEB67E3340F4EEFFFULL,
		0xF286BEF7EE352CDFULL,
		0xEA8E6FCBB9253FEDULL,
		0x72A66948AFB86079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEB3F491F6B45F5A2ULL,
		0x79328B0E9546A61AULL,
		0x87739CBB4AA3B43CULL,
		0x351EEE628D9517E7ULL
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
		0xFA490163DAA9FC1FULL,
		0x6264E54DEB0327F4ULL,
		0xA89BB4BD79148765ULL,
		0x42FB211AF86D29F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x27EF83ACBC6F9DB6ULL,
		0x9A30989A5B43A92EULL,
		0x5B6308AC8E29320DULL,
		0x0F28F2F58A7549CBULL
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
		0x69D2BD2D85647EADULL,
		0x7C12C5D9BBA03988ULL,
		0xC9530F619A8951B4ULL,
		0x7AAE79934F98E200ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBCB345AA98F945A2ULL,
		0x4DE99EB7679F26D8ULL,
		0x1C4E78B40E706FD3ULL,
		0x2FC8448DDED8EB2AULL
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
		0x0738EE41DBA0939CULL,
		0x361E19A5A1CCA6B3ULL,
		0x549468BF20C71689ULL,
		0x609A642B86DEB1E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0738EE41DBA0939CULL,
		0x361E19A5A1CCA6B3ULL,
		0x549468BF20C71689ULL,
		0x609A642B86DEB1E5ULL
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
		0xFC0462C094ACDB37ULL,
		0xC6C4FD266A69BD37ULL,
		0x7F73D1A4AA1DB9F8ULL,
		0x6DF3ABA2A83A904EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD72E82E95ACD08F7ULL,
		0x7221C025DDFC4423ULL,
		0xB6346343906DC724ULL,
		0x76F9EF5FF49E2F22ULL
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
		0xE4946F0C9027CF6AULL,
		0xC3B2286DDAA1F51AULL,
		0x257418194B6B8E7CULL,
		0x65FC4D1681CB1E51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x036E31D231BB93DCULL,
		0x319EF673C7FDC854ULL,
		0x8AF5CA321A4D38E5ULL,
		0x1BAB5C02EB021319ULL
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
		0x577708521765582AULL,
		0xB10CE9AB23A9D5EAULL,
		0x1D7BA2B1BCBD8480ULL,
		0x35D1DE9935AD6848ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0ABAB84ACB436DCAULL,
		0x2F2B35109C02685BULL,
		0xA98A66B338CF6C44ULL,
		0x1A011D1A03AC4982ULL
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
		0xB0E0A801DF0E444DULL,
		0xC0415028224777DFULL,
		0x3E68893AC8385568ULL,
		0x6A228ABD3DE350DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB0E0A801DF0E444DULL,
		0xC0415028224777DFULL,
		0x3E68893AC8385568ULL,
		0x6A228ABD3DE350DFULL
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
		0x7FD64F96EB407700ULL,
		0x0BD694F685052715ULL,
		0x9046A6DB05B8AF8DULL,
		0x0EF42F4AB119D6CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x140CA8B5CCF066D5ULL,
		0xC9D0CF7547A57055ULL,
		0x2D36F044A2A190D7ULL,
		0x6F9B1D55ACFDEDC3ULL
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
		0x162E900DF0DFF161ULL,
		0x4AE25D8DA69C27CEULL,
		0x13B8C8E634B61ED2ULL,
		0x1DA4F3583EF8564EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x05623B22D2354DF0ULL,
		0x8BFB0E24AD5EDF5CULL,
		0xE361D37D946D3512ULL,
		0x26912E6240274CD7ULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2BBA2B1D23029DF7ULL,
		0xC81E1235A0D7B94EULL,
		0xD38851CAAC1271ABULL,
		0x55AB676614F7E413ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3C2848FC445FC6FBULL,
		0x9662794881C2D393ULL,
		0x30A45AF2D989A470ULL,
		0x08CFD3A044B3AEAAULL
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
		0x41F3C07F9042ED7FULL,
		0x06641EC263DA7223ULL,
		0x576894DFA9179CCCULL,
		0x5894D469152CEDD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41F3C07F9042ED7FULL,
		0x06641EC263DA7223ULL,
		0x576894DFA9179CCCULL,
		0x5894D469152CEDD6ULL
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
		0xFD14E96B72062652ULL,
		0x6F3FE19DE3FFCCAAULL,
		0xE07A0A3E8713C3A4ULL,
		0x330010CD2C12F510ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFEB00D98AA61D18FULL,
		0xFAEE0DF8ABD71614ULL,
		0x262FA2785D8F5A93ULL,
		0x302DC66D83D7C3DCULL
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
		0xB211D43CD0DFDA25ULL,
		0x2F7BA10C9143F846ULL,
		0x630E3031D2753B31ULL,
		0x4F19F27B4A2EFB47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7DEC006AB127F524ULL,
		0xDBB7CE88AAB1F663ULL,
		0xC5124F8DABFB428AULL,
		0x562E724643320B0AULL
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
		0x54379DD3D0DE5B42ULL,
		0x1C6482842C7CE925ULL,
		0x8E71C8B0ADB01735ULL,
		0x4DA418F1CEB427D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x39E29FD4A9608A52ULL,
		0x1ED1CE5F4583A7B7ULL,
		0x0CF6B9D6FC2E4AC2ULL,
		0x247158FA277075E1ULL
	}};
	t = 1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x41FE8BB2871D4C58ULL,
		0xEC9B8D1085C3BE54ULL,
		0x427BDE19A03F0B2EULL,
		0x79A44EFA0B756B29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x41FE8BB2871D4C58ULL,
		0xEC9B8D1085C3BE54ULL,
		0x427BDE19A03F0B2EULL,
		0x79A44EFA0B756B29ULL
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
		0xB7FAD03164141CC4ULL,
		0xE4948A1B261997FEULL,
		0x1670E1D68DBA3431ULL,
		0x6CB4B5CCA08A7699ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D14CA7EF801C1A7ULL,
		0x2C45D739B6133816ULL,
		0x589EA15A7937093EULL,
		0x24DFFE64E528596FULL
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
		0x47533225A9D2BA8FULL,
		0x15093C606FB12253ULL,
		0x0A5597FB40DFDF5EULL,
		0x15E7E0A57A82EBADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5DF9B0D0D3AAFF39ULL,
		0x154E1FCBEBFDC1FBULL,
		0xD6D073BC24BDE4FEULL,
		0x38DB3953DB7051A2ULL
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
		0x6D62421C4F5D3F2FULL,
		0x5418DE4161B70896ULL,
		0x49DB3DDA6EFD44B1ULL,
		0x2D1DF4875AB64575ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE29FE811754F0C87ULL,
		0x4E1044FC1E531BACULL,
		0x5980ACE4F7492E43ULL,
		0x61FBFFE539209081ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x16A08E80CB1AD435ULL,
		0x8E15E41A62FAA40DULL,
		0x22094F1AB37BB4ADULL,
		0x53ECD203DB62B8FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16A08E80CB1AD435ULL,
		0x8E15E41A62FAA40DULL,
		0x22094F1AB37BB4ADULL,
		0x53ECD203DB62B8FCULL
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
		0xB72267590E824A30ULL,
		0xD1C56B9F4EE04FEDULL,
		0xD4E14A81C8CFAA3EULL,
		0x7491AA25D7B07AC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x1CCC35F0450F82E3ULL,
		0x8E99D4126AFEB42DULL,
		0xFE715FA449652366ULL,
		0x7A30E2CD0DEF09D8ULL
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
		0xDD9931B8BB972A69ULL,
		0x6955D04FF6AC09D0ULL,
		0x186703896E2D5C78ULL,
		0x02A34F03A28C0FDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x70A62A51B8A47B3EULL,
		0x69BBB5F375B133FCULL,
		0x89F130CA2A4B7C3AULL,
		0x699CAEA38FCCABEDULL
	}};
	t = -1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6B3EBEEBDE79DFBEULL,
		0x716900E192BD84C4ULL,
		0x3A5DEA679216BC54ULL,
		0x547454998311FC34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9CCE268E36B7C86EULL,
		0x3A2006280F810DB8ULL,
		0x7CCB522F69C72CC9ULL,
		0x00B6E7C08D335D02ULL
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
		0x163586C8DE439F76ULL,
		0x21695311ECFEE4C3ULL,
		0x4DE919C42D40B4ABULL,
		0x16BFF49A5BE29B8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x163586C8DE439F76ULL,
		0x21695311ECFEE4C3ULL,
		0x4DE919C42D40B4ABULL,
		0x16BFF49A5BE29B8AULL
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
		0xC1CACE78C3C52DB7ULL,
		0xEE02DDA48B100441ULL,
		0x95CA132FE43A8034ULL,
		0x2094A70EB3A8BC4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA7F873A4E70C5B3AULL,
		0x341E8CFAE4E5FB9CULL,
		0x091CC2DA10F9C1BEULL,
		0x332865E5765FF61BULL
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
		0xBB0ACEBEE070A02BULL,
		0x58844E28783FF38BULL,
		0x0CE69079C9B85587ULL,
		0x57E09D2DB8A77034ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE87694ED5E8E0E46ULL,
		0x2B1E3CD64DF3610DULL,
		0xC7281FAC8C2E910CULL,
		0x701A26B04EAFCB74ULL
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
		0x5E96C98551326C54ULL,
		0xA2D05E8E1A5118C8ULL,
		0x6915DE1873E31067ULL,
		0x7BE6ACF3255A65B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0D79BB915383F68AULL,
		0x694B479725394F24ULL,
		0xA1277FB2CA1C7F18ULL,
		0x0A8F1CD54D873587ULL
	}};
	t = 1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF63A1B5D3610C794ULL,
		0x1E07C9A030BD70B1ULL,
		0xF198F895A7EA3990ULL,
		0x0D60D248B46563F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF63A1B5D3610C794ULL,
		0x1E07C9A030BD70B1ULL,
		0xF198F895A7EA3990ULL,
		0x0D60D248B46563F0ULL
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
		0x5AF0055865C19DBEULL,
		0xFAECEC241DE8A71AULL,
		0x1240F7E60A621E98ULL,
		0x181F369115E1E792ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53259CDA85E7806CULL,
		0xD810BAA49B8CA918ULL,
		0xF2E7506ACDD0B8CCULL,
		0x5B0056BFCE2BCAA3ULL
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
		0x31D60CB4655FDFE2ULL,
		0xE5008B09A5A635AEULL,
		0xC220513AE329064FULL,
		0x7A38C15DCAB81937ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x396EB4B122E241ACULL,
		0x71C62901E4F4B41CULL,
		0x8116F266C6A3117DULL,
		0x52BD3FA2BD73E762ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x47A8D9700BAA7060ULL,
		0x093D162281561363ULL,
		0x3E3B06EAE6291E69ULL,
		0x7D161EC7FA3AC3DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x533D55718D826C4CULL,
		0x2F2CA68C69CB91F4ULL,
		0x561D214882DB0A61ULL,
		0x71755200CC8D04FEULL
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
		0x9130EDE140F40FCAULL,
		0x0D5EE89406FE223BULL,
		0x84E542FCFE6D525CULL,
		0x2E77217E3D71A2ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9130EDE140F40FCAULL,
		0x0D5EE89406FE223BULL,
		0x84E542FCFE6D525CULL,
		0x2E77217E3D71A2ADULL
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
		0x3D27E8D144D0F6E9ULL,
		0xF26C673BFCF3A510ULL,
		0xC35890E0E23872EDULL,
		0x1568AB716C1BF7E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF8CE95D4D9C7849BULL,
		0x3594154F1B21E50EULL,
		0xEB435E5E737990A6ULL,
		0x4C968A639D1A0FDEULL
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
		0x13DDDBB30F5A7FF5ULL,
		0x79C5D003120871F6ULL,
		0x3CE51B3E11295B14ULL,
		0x5EFCAF8AABA3F341ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0CE51A3771FEAF9CULL,
		0x05558ABC89CB9A9BULL,
		0x513D94762889064EULL,
		0x1742CC9D272A7633ULL
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
		0xAFBF09080F20CE63ULL,
		0x7AD28DD9C5BEF2D6ULL,
		0x02D353410421995FULL,
		0x235FF669F3173F81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6C520D324CDC7672ULL,
		0xB04AD62BE0B4BDA6ULL,
		0x5EAAF8267F3C24DCULL,
		0x430EABAC6B8FC1C6ULL
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
		0xC659A68521DA1D79ULL,
		0xAFA15977390770D2ULL,
		0xC84138A9945BA2E2ULL,
		0x26AD65BB4B7EACA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC659A68521DA1D79ULL,
		0xAFA15977390770D2ULL,
		0xC84138A9945BA2E2ULL,
		0x26AD65BB4B7EACA0ULL
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
		0xCCAF785573D715D3ULL,
		0x6D58BB41DD1E7A77ULL,
		0xC6EFF791DC7A1CF7ULL,
		0x09E06A85BDB01E10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9B0504F9DF86C9A7ULL,
		0x4BF93FE57088AB64ULL,
		0x4FDD96D6BFEDC1AEULL,
		0x6FDE40F62C8DE12CULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x661BE50560A66152ULL,
		0xDD37CD0E726C098FULL,
		0xC08AE2405E815103ULL,
		0x110FFA38EE999D62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDCECCC383C1E1500ULL,
		0x46D362E913BAA99EULL,
		0x887FC7002F606245ULL,
		0x7A59B25ACCBB6BF3ULL
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
		0x1F67F2799E051EA7ULL,
		0xA7B8347CE4782B2FULL,
		0x4D03F84C7016E1AAULL,
		0x175ABBD5C92BD8B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDAE472E46A4A82B9ULL,
		0x6DF7EFCC9FFE1C4FULL,
		0x65A5936DCE07EE81ULL,
		0x622E739DFD3BD5C7ULL
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
		0x4EFC7CC7A04AA406ULL,
		0xDFD50D1341998292ULL,
		0x2ED6164C64ABC5E0ULL,
		0x203156D8BAA7C523ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4EFC7CC7A04AA406ULL,
		0xDFD50D1341998292ULL,
		0x2ED6164C64ABC5E0ULL,
		0x203156D8BAA7C523ULL
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
		0xA23EE6839B2ACB27ULL,
		0xF70D94024FB0F7F9ULL,
		0xB6D13417A282E844ULL,
		0x59C23FB0651C8EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xD0B32FFE1C82E6DFULL,
		0x64F632A941062D89ULL,
		0x0654A7D43F4F2526ULL,
		0x081EC82BAD25B69AULL
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
		0x3C577A43A27A589CULL,
		0xFE6D5C62028693B0ULL,
		0x44DB20170FE3DA26ULL,
		0x760BEAAB21076CAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7551647FE8FCB4EFULL,
		0x0FF41B4326ACD9B4ULL,
		0x3749EF4B06E65179ULL,
		0x0CDDF8DD5D3B5659ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBBAFE8C614DF815CULL,
		0x61785233E6033CA7ULL,
		0x2D5E6661C642FFFDULL,
		0x7F1DDC7E4DBF9167ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x31824CA34118007EULL,
		0x6CA5CC2944D00333ULL,
		0x7D90197F9409F75CULL,
		0x622E3C747CD69CD3ULL
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
		0xB8CCBC4D02577236ULL,
		0xC4B9E465F9ACF3E7ULL,
		0x65B56947AF1F87CAULL,
		0x03D855456E350A84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB8CCBC4D02577236ULL,
		0xC4B9E465F9ACF3E7ULL,
		0x65B56947AF1F87CAULL,
		0x03D855456E350A84ULL
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
		0x8EF8B3909DC32361ULL,
		0xD35374E9DE51C5D0ULL,
		0x24F6589310844050ULL,
		0x0B22A672F9C32869ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x229641E407147078ULL,
		0x50E3D9DA45F99DBFULL,
		0xD0732A7F4F1CA7FEULL,
		0x089502DC28533227ULL
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
		0x52FC58AB5A4DED6EULL,
		0x5FE9B7AABB648F39ULL,
		0x1C4FDD678ACB0BD3ULL,
		0x3EA49DC4B697BE82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7D23FD232730973BULL,
		0x1B5E95DB08D1645BULL,
		0xFA2A41FA76DC337BULL,
		0x5483EEF2B8203C86ULL
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
		0xDFD64CB6694F26E4ULL,
		0x8CDF6ADA874E5100ULL,
		0x9D27994EC14E0966ULL,
		0x5BC1F19D27171085ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5AEB147B0E1CCDEDULL,
		0xCD8AEBA886C3E6CEULL,
		0xB02329DDA3EAE84DULL,
		0x38415C7F3CAFA712ULL
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
		0x5ACBC78C0CB42C84ULL,
		0x22D95AAA6BA16954ULL,
		0x85B847F9E1D43CBFULL,
		0x3C199041E87C2E6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5ACBC78C0CB42C84ULL,
		0x22D95AAA6BA16954ULL,
		0x85B847F9E1D43CBFULL,
		0x3C199041E87C2E6FULL
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
		0x39764ED0956C5B68ULL,
		0x6B9E8340ED2B6D94ULL,
		0xDD7B71560AC6931BULL,
		0x1A345F2411B31410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD5072D5D6AC67F6ULL,
		0x16FAC8BFDCC39E2AULL,
		0x49400C3426F1A308ULL,
		0x76DFF4B6EDECF668ULL
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
		0x81184F1E3993ADE4ULL,
		0x5A04AE3BACC58CC7ULL,
		0x4C050E1EDB1E46BAULL,
		0x0C6DEFE9E28E13FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7D2175A6F7B08DB8ULL,
		0x4F7ACB5854B34F02ULL,
		0xA48DE9F35277BC23ULL,
		0x04A3B7C0A685227EULL
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
		0x73ABC8F589F10E9DULL,
		0x250ED7E9897A1A9BULL,
		0xDB81709383229C6FULL,
		0x7CE42D6EF5FA9CD4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x59EA072C64F617D6ULL,
		0xD1851110C91BF49FULL,
		0x0D961064C6883258ULL,
		0x2C9F3992F38271DDULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7BD03E00F5D7FB0DULL,
		0x3C7FCE0D19A89170ULL,
		0x3CF93B9A07A2A69BULL,
		0x4FF189E8302146AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BD03E00F5D7FB0DULL,
		0x3C7FCE0D19A89170ULL,
		0x3CF93B9A07A2A69BULL,
		0x4FF189E8302146AFULL
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
		0x01E5B32F5F79229DULL,
		0xAE9B292C16A5BDC5ULL,
		0x62E40F6E381ED35EULL,
		0x55267D10EB219AC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xECBFFB3F7B7C4B65ULL,
		0xF8280F042E2A50FBULL,
		0x059446B64048AE22ULL,
		0x0FF68D7160518E03ULL
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
		0x5BEE54A654696F04ULL,
		0x53F24BBB708E85F2ULL,
		0x1657DB2401028873ULL,
		0x7214C7BEAAA8F7CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E6BFB88C9634B5BULL,
		0xFAEDDFFEAE5F5264ULL,
		0x22B95C4DCD4D199EULL,
		0x0ED6D05A3D8CF4F6ULL
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
		0x3B1D3BDDCC754399ULL,
		0xD6F520A9DBEB759CULL,
		0x8E0C4316F81EF297ULL,
		0x4F6E257E36908E19ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x925E35EDFBA53BFFULL,
		0x5B9ADB80276AD681ULL,
		0xCA0C13F8A25DD5C6ULL,
		0x42EFA0DD15501249ULL
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
		0x746D42F5513F2533ULL,
		0x012CACAB651B287BULL,
		0x36A611AD073C8B53ULL,
		0x235CD9E33E77984AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x746D42F5513F2533ULL,
		0x012CACAB651B287BULL,
		0x36A611AD073C8B53ULL,
		0x235CD9E33E77984AULL
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
		0xEE137EC5CAD3C8DCULL,
		0xA38DE620D38CCE51ULL,
		0x1E7CCC37F87BBE4DULL,
		0x38D624389906EBC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x14723B966EFBCCF2ULL,
		0x0DCF64AAC89B2D9AULL,
		0x32A2A5D9A1659ED7ULL,
		0x70CD68C886511466ULL
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
		0xD2E923E164BA62AAULL,
		0x0A652BA4B7491D4EULL,
		0x115DAF06DE40AAF9ULL,
		0x0FAF39451C3F3F41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0F83DE5AC093A42BULL,
		0x61487230F2931A3FULL,
		0xC5A176890B1FECFBULL,
		0x0D6D7E387F0FB8CCULL
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
		0xE8EBE84DAB703010ULL,
		0xDD2C29A7C160F519ULL,
		0x32F748C2F53D097CULL,
		0x77DD163FF934FB63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x057045DC731B95B5ULL,
		0xBDC87B622A752828ULL,
		0x7BE3DC2BAC2170CCULL,
		0x6FF3EF0D23199A58ULL
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
		0xB1A919CDE9DE3CFEULL,
		0xF9D755CEAB72DB22ULL,
		0xCAC4D94F35988658ULL,
		0x7AFB9EEB396CC337ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB1A919CDE9DE3CFEULL,
		0xF9D755CEAB72DB22ULL,
		0xCAC4D94F35988658ULL,
		0x7AFB9EEB396CC337ULL
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
		0x39BDEF55770C0115ULL,
		0x7525DEF2E35F0288ULL,
		0x4E83D9C6B051B19FULL,
		0x6A4449A59DE344C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC2F99AB6E7F080C7ULL,
		0x84917C1AA904AAEBULL,
		0xD042B2E1D8669003ULL,
		0x05E43DDE5EC26151ULL
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
		0x4B1687408C1D7DC0ULL,
		0x727AE580C493E1D6ULL,
		0x140305FF9EBF5765ULL,
		0x21A514E9F948994BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x018993CED4DB05D1ULL,
		0x76EB85BAC61E15F6ULL,
		0x057C090D7EB6D814ULL,
		0x5EABE134801358AEULL
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
		0xC9B5E81F6E365276ULL,
		0x299F798BA9877338ULL,
		0x70EFA395B5EA82EEULL,
		0x58A3BF38B1B2C521ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x20D4DFFE45CF32E3ULL,
		0x224A59E7985D7792ULL,
		0x4CD4A016B34408C6ULL,
		0x39585BC11A978B37ULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBD72395895AF01D9ULL,
		0x09C430E5A8E7FB75ULL,
		0x6A800101BDB2208CULL,
		0x0BAF1EC76AA59F78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBD72395895AF01D9ULL,
		0x09C430E5A8E7FB75ULL,
		0x6A800101BDB2208CULL,
		0x0BAF1EC76AA59F78ULL
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
		0x7419811B2EB5A656ULL,
		0x0C1D44457FEBA556ULL,
		0x40A6A2A274E705CFULL,
		0x6C51074841F19FFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x518730B311BBFC3FULL,
		0xD18797009868DE4CULL,
		0xDF04DDFE01A2CAC4ULL,
		0x4C10DDBBB47738B7ULL
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
		0x22A5DFBA48F8B379ULL,
		0x1E3063B58834F26CULL,
		0x09B19FB6CEE714FBULL,
		0x5525F918A8133683ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8D604DE8C5BA469EULL,
		0x8F3953F04933FAF6ULL,
		0x5605FD2101BFD7A6ULL,
		0x33DD4CB4C360A638ULL
	}};
	t = 1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x24ADD5C1B5E0C273ULL,
		0x0CA2BB11A6D9E29BULL,
		0x5E22375EF2077357ULL,
		0x0EB76AB5B69D15F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFC1804C58915323BULL,
		0xC9DEA206888F852AULL,
		0xEF22DF8D1E2FB922ULL,
		0x0373BD08603BD0C1ULL
	}};
	t = 1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x62B70BB9B9BB1029ULL,
		0x750A98C7090E9728ULL,
		0xB7E0C0DFD5E673C2ULL,
		0x2F66C65870B735DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x62B70BB9B9BB1029ULL,
		0x750A98C7090E9728ULL,
		0xB7E0C0DFD5E673C2ULL,
		0x2F66C65870B735DEULL
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
		0x4B2B23B54D6582D3ULL,
		0x9A5D1D4745F15EBEULL,
		0xFC06F8A208F6BE37ULL,
		0x4AF8BFA43620E6FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C4F7B37EFFEEBD6ULL,
		0x0A5982B97A9E9BF3ULL,
		0x792C288FF9A2BB8AULL,
		0x6D79D69C59DF2FD7ULL
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
		0x94A1B3676D967AE6ULL,
		0x6E0659D636F7FBE4ULL,
		0x200428D140918379ULL,
		0x74C7AC6788015C39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x050B99C859CE6BB3ULL,
		0x95B594BA51CA8995ULL,
		0x3170F3CFCB02E689ULL,
		0x0CF21CA78006DBC6ULL
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
		0x6AFA6B9638E0994DULL,
		0x1E8250A327A41FB1ULL,
		0xD688035A16BCCD6CULL,
		0x326EFEF3829EE825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x71C0A1314A6821EDULL,
		0xE3B608AFCCA33C04ULL,
		0x332D99CF5DA61C08ULL,
		0x0A8F47CA5816FC6DULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x8F714EB84DF9B41CULL,
		0xE30176C06AB8D1DCULL,
		0x24A01FFF67C3578DULL,
		0x39E723DDDB7F84D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8F714EB84DF9B41CULL,
		0xE30176C06AB8D1DCULL,
		0x24A01FFF67C3578DULL,
		0x39E723DDDB7F84D7ULL
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
		0xC61EF132247CF06FULL,
		0x632C328C3DF9A9A4ULL,
		0x4EB4A731A5C850C6ULL,
		0x549DD56C14F2BFC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3B5B0FCC83CEA99EULL,
		0x91C3E77C9E7D91E3ULL,
		0x67C18DB0954D58C6ULL,
		0x49B76B65A05DBCA8ULL
	}};
	t = 1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA75296D6FDDD752AULL,
		0xFDA42CA0EB23FECFULL,
		0xB389DF877DF0C89FULL,
		0x03D5DC9F2FF9DFAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB114E099814FEDB2ULL,
		0x381671D071943C18ULL,
		0x28167F29B07F0F7EULL,
		0x47B767613BA34124ULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5AF74678A78FDF29ULL,
		0xBCFA9DEA2FA69650ULL,
		0xAE47FB0511DDA17EULL,
		0x516DE297341AB0B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x730111B15FDB72D9ULL,
		0x4348171330E1E383ULL,
		0x23DB3FEAE2FF1BABULL,
		0x53467FD83546372EULL
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
		0xE16595639185B995ULL,
		0xF19D1BA382901B20ULL,
		0x0F3BF378175F3CABULL,
		0x7D23B88CD311244DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE16595639185B995ULL,
		0xF19D1BA382901B20ULL,
		0x0F3BF378175F3CABULL,
		0x7D23B88CD311244DULL
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
		0xF0BFDE46453432D7ULL,
		0x430EF2A9E2DA03C9ULL,
		0xF64D53E17308B701ULL,
		0x1417DFE474F6AD2CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE1560EE9886455D2ULL,
		0x6840483D9A47436FULL,
		0x0A203F6ACC067385ULL,
		0x1459F8CB2FEA78A0ULL
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
		0x78B7B6E7FEEF1E5BULL,
		0x0A18813999F239A2ULL,
		0xF93545A1D4E88BE4ULL,
		0x3CEA2F163D3FD326ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x3CEA2C44C06EC0A6ULL,
		0xFE8960D9BD5C5147ULL,
		0xA67FD89EF51C3A08ULL,
		0x7DF3B780329B8B70ULL
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
		0xF2DDC6A402A9882CULL,
		0x3AC35A3A4589A751ULL,
		0x947606AD27FB0800ULL,
		0x09402716FEE6EB98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x07B7AF5E00C6D906ULL,
		0x2F242D6E7D5F52B1ULL,
		0xA8F9472DED424D3EULL,
		0x2CF8C2FD80B00927ULL
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
		0xBB2A5CA9D81E52C7ULL,
		0x5CB2E8E6377E640DULL,
		0x1970A186DF723A0CULL,
		0x5A4FFC912012C165ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xBB2A5CA9D81E52C7ULL,
		0x5CB2E8E6377E640DULL,
		0x1970A186DF723A0CULL,
		0x5A4FFC912012C165ULL
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
		0x590878231764D72EULL,
		0xF0499F3F004878A4ULL,
		0x8E24B61AF858122CULL,
		0x30F8C5C93E90E100ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4D31B395F6571C5FULL,
		0x95CE2D6DB4A5B0A7ULL,
		0x6C48AC1980373B8BULL,
		0x303AB851466DD1D6ULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCB7CC40A1CCBFC7BULL,
		0x93C098EE455365BFULL,
		0xBE35F9C33C6A7F6FULL,
		0x6FAC8CD85348DCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x06AE0EADFD075FD7ULL,
		0x68CAD8E5B926B830ULL,
		0x1CBCAA3721BCE9FFULL,
		0x2225946616F88F84ULL
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
		0xEE032BC00B6ADC62ULL,
		0x5C1E26331B798441ULL,
		0x88842BB08022AFE9ULL,
		0x2EBAF37CE240175AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x69F5F6CFC2927704ULL,
		0xB7C20A9F2B5BE8E0ULL,
		0x550BAD9B26C5C100ULL,
		0x1C11F8308156132AULL
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
		0x25F7A16449CD6656ULL,
		0x88E3FCFE5DE3CD16ULL,
		0x64AAE15DCA7FC8ADULL,
		0x69B9B68AC5D30C9FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x25F7A16449CD6656ULL,
		0x88E3FCFE5DE3CD16ULL,
		0x64AAE15DCA7FC8ADULL,
		0x69B9B68AC5D30C9FULL
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
		0x7EA4CC9E9C11FBB0ULL,
		0xB280821B8DBD0D95ULL,
		0x23816BA26C629A0AULL,
		0x583788BCBB7ECCE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xC5B77318856E0B32ULL,
		0x0CAAC372B5FF22D8ULL,
		0xFD55CDF703D40B45ULL,
		0x5B6456306439B025ULL
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
		0xB2D23F3C84932C1BULL,
		0x5A8559C6355BB589ULL,
		0x46D0DC3F2CEB041DULL,
		0x335C19A24A25EE37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF637D55ADDCD8C75ULL,
		0x704603A120B7D9D4ULL,
		0xBB511DFA6DC5A1BFULL,
		0x2E3E420D3668D36DULL
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
		0xD7686F5192B4C1A3ULL,
		0x0BFA71E445850E21ULL,
		0x831269F3336C413FULL,
		0x7E0AF1D1252C0F5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF490864C7CBBDBF7ULL,
		0x7F5CA44A7C7B8612ULL,
		0xCDD8467B31FA3BEFULL,
		0x692A814FAABC47C0ULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFF7E7B839613BA74ULL,
		0x61BFF89D959D0A84ULL,
		0x5D9BE01BC8B7E8C3ULL,
		0x103B9BF59B44088DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF7E7B839613BA74ULL,
		0x61BFF89D959D0A84ULL,
		0x5D9BE01BC8B7E8C3ULL,
		0x103B9BF59B44088DULL
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
		0x0C94E2922613CA4DULL,
		0xE01A1EFBF5EB3B2BULL,
		0xBF3ED2191DA2BCE2ULL,
		0x2E20E3AB9A1D9BE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB407E16A12B458CEULL,
		0x05A848D31D8C6925ULL,
		0xA653C34992DC28E7ULL,
		0x19E75BDFEE1E0A7BULL
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
		0x30503B49B77C0045ULL,
		0xD5981C3B420B3C5EULL,
		0x7C106E3D775F9E57ULL,
		0x6F9FAF0BE5A516F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8BA405E595E13856ULL,
		0xB72A181DD0923D25ULL,
		0xCBDE42ADBEA13E1BULL,
		0x7696EFCBBA7F9D41ULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2531627551C10F47ULL,
		0xEC56B062938B8E8AULL,
		0xA832CFF839F9D1B5ULL,
		0x3BC0AF46C11C1DA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB4689CD8B9061FFULL,
		0xD5D6B8E3154BAEF3ULL,
		0xBFBB33CAF51BB8A8ULL,
		0x13E28E1D5A978C82ULL
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
		0x53A499781AD69964ULL,
		0x796CBDCB29B75346ULL,
		0xD909A699D15C6000ULL,
		0x6D5AD92C4E7EEFEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x53A499781AD69964ULL,
		0x796CBDCB29B75346ULL,
		0xD909A699D15C6000ULL,
		0x6D5AD92C4E7EEFEBULL
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
		0x4AC55886030DE5BFULL,
		0x87DEC19D45561283ULL,
		0xD17861942B6813D1ULL,
		0x6AD4C3C3F8AF7BFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x993F12579D28273AULL,
		0xA54B7443971FA163ULL,
		0x7711BDE1189B1A24ULL,
		0x6D9304CE2609DA5BULL
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
		0xBF032BB1DF3B84E3ULL,
		0x5BBE0DD70C18D006ULL,
		0xD14E879BF92E9CE8ULL,
		0x7EFB1A37B326D6F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x223003383141BC0BULL,
		0x11813F720FDAE3F1ULL,
		0x4CC3142CC2EFFBECULL,
		0x5224246A18BBFD1EULL
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
		0xFB643461EC67B8A3ULL,
		0xE8F3706A1E049912ULL,
		0xD99F5A11C9EC3FB8ULL,
		0x7042D594BCCD705CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDB1FF8F431EE9AE9ULL,
		0xA4DE68B3207C8F98ULL,
		0x3CCCD9DFEE7E410DULL,
		0x61E4C6CB5FC2EF3DULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x87BA0B4704693DD8ULL,
		0xA3E4B2BB23688D0CULL,
		0x987A561E7A41396EULL,
		0x41C85537724FBDB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x87BA0B4704693DD8ULL,
		0xA3E4B2BB23688D0CULL,
		0x987A561E7A41396EULL,
		0x41C85537724FBDB0ULL
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
		0x026937EE4A9440D0ULL,
		0xE2E70591249F995FULL,
		0xEA3AE0FF28046EE0ULL,
		0x67CE510CC832A7EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x44EDA97C6D8B90AEULL,
		0x623D718D9B44D3B2ULL,
		0x84BAA416E11D2F45ULL,
		0x4165B238E1A11C3FULL
	}};
	t = 1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4DCE32EC29936659ULL,
		0xDEF3F636ADB4C22FULL,
		0xCFB65866DFE7ACCDULL,
		0x604857732004922BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA65499058D127824ULL,
		0xB4FE85ED76CBF037ULL,
		0xE1ADDB83BC45A7E8ULL,
		0x7EE0381B9319C971ULL
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
		0x44FBECF6404B1780ULL,
		0x65D6FA288AEB9E7DULL,
		0x023B8811366AFF70ULL,
		0x18388152DA6CD214ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x190AE1010134B02FULL,
		0x8752D6C61D2A40E6ULL,
		0xC072000D6B0D8580ULL,
		0x222518D2E16A1D68ULL
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
		0xF2687DB8B98E36FFULL,
		0x55852CA33DDC0C54ULL,
		0x21F12FFC6C0579A7ULL,
		0x5D2FE66F7EDF1794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2687DB8B98E36FFULL,
		0x55852CA33DDC0C54ULL,
		0x21F12FFC6C0579A7ULL,
		0x5D2FE66F7EDF1794ULL
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
		0x6472C65BA953130BULL,
		0x279CB145F9F44EF0ULL,
		0x801D088BC08CF717ULL,
		0x217F31418D12FE1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7F28E2EC8A501E4FULL,
		0xE774D28B14DD2764ULL,
		0xF09831FFEA609159ULL,
		0x5188AE87A15B984DULL
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
		0x47F9A47D0DEB5287ULL,
		0xD8A1B1A461D3B6CEULL,
		0x9856AAA18A819EA7ULL,
		0x4570D44BA50606B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE893A4FBB8D29174ULL,
		0x10E4AC17371EB6FAULL,
		0x2E088628A46C5C16ULL,
		0x3337CBDABDF165CCULL
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
		0xC903A1553D04A6D0ULL,
		0x74ED66A051E7D5FBULL,
		0xF934222B61CEA6FEULL,
		0x361EFD9DCD4A4B4FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5E40C61BC99910FBULL,
		0x77D73E66A7F7FD94ULL,
		0x13DAFC18CEFA6F0CULL,
		0x72DDBF90FD6324BEULL
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
		0x2EE64D8AB9B82CF7ULL,
		0xD7BB64965A7BDECBULL,
		0xAA51C1C0B9495181ULL,
		0x116EC40D23EA92FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2EE64D8AB9B82CF7ULL,
		0xD7BB64965A7BDECBULL,
		0xAA51C1C0B9495181ULL,
		0x116EC40D23EA92FBULL
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
		0x59DA2091557F3F18ULL,
		0x79ED1357DE1D0EFCULL,
		0xAAF6DA1FD9BFE73BULL,
		0x05176C3F18EA5F25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x694BEF69C93319BCULL,
		0xE3DFC05BA5091D6BULL,
		0x78EBC6EB3A466DDDULL,
		0x3D1E68A543700DABULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9747E66922AFC28DULL,
		0x16CCB3581F05DD78ULL,
		0x726A1C249877B59AULL,
		0x10F0922B1B14181FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x236DED8514BA539EULL,
		0x74DC808E1AA372C1ULL,
		0xA9E653BCCE03283AULL,
		0x2C2AAC8DA3D5F5C6ULL
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
		0x0408731A09541C03ULL,
		0xF0FD3C4EA5587C50ULL,
		0x6FB4DA9909CB6957ULL,
		0x09A46D175ADAB460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2C4FA9F845AE882BULL,
		0x19B0FCC866D8E342ULL,
		0xE135A199D73BCBCCULL,
		0x1871B25B0E6A680BULL
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
		0xE3C4D563D9F230A6ULL,
		0xC9DF6AE7AEA6E7F7ULL,
		0x7318DD58B108D8DDULL,
		0x23564B9066E06182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE3C4D563D9F230A6ULL,
		0xC9DF6AE7AEA6E7F7ULL,
		0x7318DD58B108D8DDULL,
		0x23564B9066E06182ULL
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
		0xC7640585B77D0580ULL,
		0x9B8DCCCDC075E15CULL,
		0xC0023DCF42C5EB28ULL,
		0x57F5521711EA064EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7BEB56A60FC08356ULL,
		0x755004D44FDD7758ULL,
		0xFC3341E13EF1FA86ULL,
		0x7EF99B648E413919ULL
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
		0x001CE7E698BE5531ULL,
		0x26C518FBA2F24806ULL,
		0xD2BCE6D9630A7B63ULL,
		0x1AB66C9E1112AF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x56E25376A6D055BEULL,
		0xC4287038D7A4DECDULL,
		0x2246353A3F0DAEE8ULL,
		0x41DB3F72A4B4BCD2ULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA58327BB36252932ULL,
		0x4C5A1BAE5F3DA4E7ULL,
		0x848DB8CBF7C58CF2ULL,
		0x000F3A9ADD07DCAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB88757B24E912667ULL,
		0xE872FEE7BDC315C6ULL,
		0x14CCFC1D0AD0A458ULL,
		0x2DDEC55D2AEA4923ULL
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
		0x4188993F1D487DB0ULL,
		0xFD8B9FBD778F074DULL,
		0xD83FC95C3103B3B9ULL,
		0x4EB90667D928A755ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4188993F1D487DB0ULL,
		0xFD8B9FBD778F074DULL,
		0xD83FC95C3103B3B9ULL,
		0x4EB90667D928A755ULL
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
		0x0CF6F80049EEEE92ULL,
		0x787CFF18BA127083ULL,
		0x933B4661D1899C11ULL,
		0x0E574FCF254E0CBBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDC242BB115BEDE9EULL,
		0xA89B7387DE132F3BULL,
		0x6C508A5EB198B8B3ULL,
		0x0695804A50B7AC30ULL
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
		0xFBA0CC0F882F7E84ULL,
		0x6D21E733BEC57380ULL,
		0xD8BF3D08BE783659ULL,
		0x76D3DC91424E59DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x16034029691F70B1ULL,
		0x8BE33BB4AAE94660ULL,
		0x8A3FD41A269F4342ULL,
		0x7BE8E85FAF339283ULL
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
		0x8ECD036F3FE900F5ULL,
		0x83EA39BA0C2D721FULL,
		0x79928EF91AEB1712ULL,
		0x0A9BA6EA7EC5124BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF7619C400DC1B1E1ULL,
		0x3078F108541F3BB2ULL,
		0xEA7D90C84AEFEF0FULL,
		0x0C1108C19BEBAA07ULL
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
		0x98C0C6BB6640A37AULL,
		0x65EF7225F451F855ULL,
		0xF9A83D339CF1DF92ULL,
		0x42607CE520DF1BB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x98C0C6BB6640A37AULL,
		0x65EF7225F451F855ULL,
		0xF9A83D339CF1DF92ULL,
		0x42607CE520DF1BB7ULL
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
		0xE360DD4E878148C2ULL,
		0xEFB02DB6C576DA55ULL,
		0x50DA03C050B243CFULL,
		0x1D79C197C18E97A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x19FA456B2A138FA7ULL,
		0x63D99D45B51C2E20ULL,
		0x7CF0A87720DF417CULL,
		0x267F68FDFF26306DULL
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
		0xAD4C12255E4DE3FDULL,
		0x2260F474F85417F7ULL,
		0x5E6AFB4D46607CA3ULL,
		0x52D8AE7CFF19F084ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF649B9058FC46BAULL,
		0xB457D8729C1C87FCULL,
		0x7671A18C694B5B61ULL,
		0x2EDF5195BE9D4AFEULL
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
		0x8313E5A7A1D340C7ULL,
		0xFEE4DCE2456B3F7DULL,
		0x5BEF2948486E5FDBULL,
		0x7A4CD15E8F5C43CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCD2CFF745F3C33E8ULL,
		0xB7A3A1AC8984607EULL,
		0x0EAA2B7382A7F2FFULL,
		0x2AB41000C8022F2DULL
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
		0x761DAC1A43F6D46FULL,
		0x625AA265CFD8846EULL,
		0x37BCA8E0EC31E517ULL,
		0x2690BB3311AB2375ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x761DAC1A43F6D46FULL,
		0x625AA265CFD8846EULL,
		0x37BCA8E0EC31E517ULL,
		0x2690BB3311AB2375ULL
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
		0x2E1BA149A5DAEBD0ULL,
		0x57E40926FDA5C361ULL,
		0x7D0CC6F7C163B8E7ULL,
		0x3EF1D59B10C8E653ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF2623C7BF0B76E26ULL,
		0xC2EB687B5F8BF97EULL,
		0xFFCA8C9B31A06946ULL,
		0x0511B54C637EF085ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF80C445498BC27DBULL,
		0x8CC279DA1BF3E721ULL,
		0x97D1B4D38FFF67CFULL,
		0x238BE4A19C31927EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x6763393F8E8B02D4ULL,
		0x5E86F963A041A090ULL,
		0xD8D09E15A558D9A1ULL,
		0x1033851E0A7F2DDCULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB46BD06EE3C3BE82ULL,
		0x5DD4904BC8BAA5E8ULL,
		0x964DD8F35F2E6A5DULL,
		0x55A88DA25679109BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x33E8FA79F3D8143CULL,
		0x220979A8B6D041F4ULL,
		0x09DEA0ED5C511EB3ULL,
		0x0E78C9E11C9FE1D5ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEF0E5E1E177D9E9AULL,
		0xB993EEFF015F3E48ULL,
		0x8DCA740335009A5FULL,
		0x2550B2A0C53D8D00ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEF0E5E1E177D9E9AULL,
		0xB993EEFF015F3E48ULL,
		0x8DCA740335009A5FULL,
		0x2550B2A0C53D8D00ULL
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
		0xB8DE72671C97534AULL,
		0x6F1C046696D2D4C3ULL,
		0xB5604DAFB6B90570ULL,
		0x61483552E4E1567AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x23C857A1C7D69D12ULL,
		0x45BF1D02E00DB40BULL,
		0x7FA857E722F97473ULL,
		0x7FFBAA15D987B6DBULL
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
		0x5CBD5E5FAB02FE7EULL,
		0x3B226C51BD684934ULL,
		0xDBF443FDCA4FB872ULL,
		0x4714BDF1D22C9FD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x56DC4C1701F77990ULL,
		0x918ED46DB10FB745ULL,
		0x9392713D0E6DD100ULL,
		0x51E49A47E4ADA536ULL
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
		0x11C3500F1F48F34DULL,
		0x2366341E749EE5FDULL,
		0x233A82C39E491873ULL,
		0x5D9CFCEFA16B7AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x257D16CF1E8E877EULL,
		0x3C26000F03DB551CULL,
		0x04B61BBCB9D3617BULL,
		0x4F0916B32ADF0562ULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xE04482B49956F39AULL,
		0x387776C36CA647D9ULL,
		0x97CCF99E97B5806AULL,
		0x6AC8D753C96C390DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xE04482B49956F39AULL,
		0x387776C36CA647D9ULL,
		0x97CCF99E97B5806AULL,
		0x6AC8D753C96C390DULL
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
		0xDA812C81A30AB0B9ULL,
		0x23DEA62FB13BBB05ULL,
		0xC5C1B3A8715EBD1EULL,
		0x6458CFA91C2B2875ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF71E54FDD449F71CULL,
		0xE4F54FB5A3E3E39FULL,
		0xEBFDB8252ACD52CFULL,
		0x5D041657DFCAAA53ULL
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
		0x68138E8480E353C6ULL,
		0x025EAE56BC52C9E3ULL,
		0xB40AB121D47DEA81ULL,
		0x4A514D2A440FBDCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x03883A87D618FE0DULL,
		0x5B83C2348571390AULL,
		0x59E137EA7E09AD52ULL,
		0x2ADA1511EF9D1C8BULL
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
		0xBACF489273BC9240ULL,
		0x68B15FFEAD87EA1AULL,
		0x63B866CF37D4EE46ULL,
		0x0BD596AD6E5C2985ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x60977BB4F599FD51ULL,
		0x0DF09987CCDBE037ULL,
		0xD29454F82E3A9436ULL,
		0x2FAF1C9E2C1F3640ULL
	}};
	t = -1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5B98E7BF187974D8ULL,
		0xEBE431B499648312ULL,
		0x20041556404A9440ULL,
		0x2D3BF672F66C2FA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5B98E7BF187974D8ULL,
		0xEBE431B499648312ULL,
		0x20041556404A9440ULL,
		0x2D3BF672F66C2FA9ULL
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
		0x8CA96FF35BF3C1F0ULL,
		0x448420709811E8F3ULL,
		0xBDD1A5060B2CEE4CULL,
		0x7DD6C161D0AED0BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0650304C3BC859AEULL,
		0x283B6B362555EAD8ULL,
		0x82F80670A257F76DULL,
		0x6E8BBD3943D18C01ULL
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
		0x69D199994CB1C7F3ULL,
		0x0BF9837E951AAF40ULL,
		0xF7B1C1E6242BAE1DULL,
		0x45F86B907FF00F3BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x300F4499342F4239ULL,
		0xD0B03C3EE26A0ABAULL,
		0x76AAC7143272EF77ULL,
		0x0B4EAC19727120FFULL
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
		0x6B7EFB5B475B1926ULL,
		0x13BB416C91E408BEULL,
		0x9970109C36992C78ULL,
		0x78B2CD3B2CA6A774ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA929FF40D8E427E3ULL,
		0x68EAA67BB169ABDCULL,
		0x1B545018CC58DEBCULL,
		0x75789943C80E3920ULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB4FB9A3DDF439E5DULL,
		0x1B4DECB11250C99FULL,
		0x2C5BF134429A3EDDULL,
		0x50DC8F182D040CF3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB4FB9A3DDF439E5DULL,
		0x1B4DECB11250C99FULL,
		0x2C5BF134429A3EDDULL,
		0x50DC8F182D040CF3ULL
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
		0x9640FBBB684D3274ULL,
		0x7E9F194FCA8213F7ULL,
		0x27450ECB44DD4C0FULL,
		0x64283C767265011EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5687A7264C7B9249ULL,
		0xA0FCD8C97596300DULL,
		0xAE9429B799A18C56ULL,
		0x03A1D730C58EDE11ULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x58213F59A5BED058ULL,
		0x066EEF911E3EC91EULL,
		0x08908EE474A4B89BULL,
		0x1EB5B84CCFCD972CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xFF64B75D0F9D1C22ULL,
		0x4E81378422FC857CULL,
		0xF5B9882113A35D7DULL,
		0x6F0C2643D2428DAFULL
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
		0x6A6FBD2EDFA3DED6ULL,
		0xD022E1DECF1821E6ULL,
		0x27C32ADD63738D0BULL,
		0x0102F050B590BE55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8B5724C6D29BE91CULL,
		0xC422D19839F0CF1DULL,
		0x312FF9DB9B088A51ULL,
		0x447C2DCD1891ABDBULL
	}};
	t = -1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x891E2CF6E184AF4EULL,
		0x95CD59D3D6D199ABULL,
		0x3E56685E2C29D54FULL,
		0x0BBAD082D8DE4742ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x891E2CF6E184AF4EULL,
		0x95CD59D3D6D199ABULL,
		0x3E56685E2C29D54FULL,
		0x0BBAD082D8DE4742ULL
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
		0x660DAB0A26B11350ULL,
		0xD57B3E027232C53DULL,
		0x92A2B68827E8E396ULL,
		0x4D08F30067B32260ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x535376E7352B88A1ULL,
		0x60B9C320CE8D85BCULL,
		0xB692245F062B304FULL,
		0x124E6262A0C76435ULL
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
		0xF7E4B26DBE154C97ULL,
		0x3E2BFDDDCA09EEFEULL,
		0x73885F34B890E3ABULL,
		0x7B11734631D701C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7E086D5C8990D1F5ULL,
		0xD55A371405F00E0AULL,
		0x857B5C9485FD0B64ULL,
		0x26721D5B7868DE97ULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7EE81726D044AD84ULL,
		0xEC5AF54815E1040DULL,
		0x3587A29A922EF189ULL,
		0x3CA6AB6CBC0344ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x022E2BD7137E89F1ULL,
		0x3B9327D676193F85ULL,
		0x593B65208109E9D2ULL,
		0x15B4FCBC5B20C0A2ULL
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
		0x2704C212E94B303FULL,
		0xD53548DE9AA25909ULL,
		0xE5098726A063EA55ULL,
		0x5D57A1E4967B7F72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2704C212E94B303FULL,
		0xD53548DE9AA25909ULL,
		0xE5098726A063EA55ULL,
		0x5D57A1E4967B7F72ULL
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
		0x999E355E66C6B612ULL,
		0xA2D1FB3C1963AF03ULL,
		0xB97BD4C840075BFFULL,
		0x03B2114E7CBC2436ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0C1A662968EC168FULL,
		0xA46E087114BDB3EBULL,
		0x41C8946346DF1F84ULL,
		0x4ABBE884E12CB0B3ULL
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
		0xA075AB10CF846EB0ULL,
		0x30B3EF6E0CCDA83EULL,
		0xF24FA4E6FC977950ULL,
		0x0C7AA9E4C626D39DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAD8963860586C367ULL,
		0x54894D31C32B159BULL,
		0xA7EFFD38D71D7D74ULL,
		0x7759D54DB5A5CDC7ULL
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
		0x7EA9A9948A9E0B48ULL,
		0x5F918F753F2F35B3ULL,
		0x9958817BE904A868ULL,
		0x2C21D0620E7A0B3DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x26954BD548EA5F5BULL,
		0x2C1923E0B1008F55ULL,
		0x987BF50EA406C8DFULL,
		0x0D08912A901115DEULL
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
		0x7EF861A746DB5C92ULL,
		0xFABC12C962F5FBDAULL,
		0x6768A6FE743A26EBULL,
		0x793E7D35EA98D459ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7EF861A746DB5C92ULL,
		0xFABC12C962F5FBDAULL,
		0x6768A6FE743A26EBULL,
		0x793E7D35EA98D459ULL
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
		0x3AEC2E0593BCD5E1ULL,
		0x1A6677CC18F3A59AULL,
		0xEDBE33CF1F5592EAULL,
		0x6FAB04B10E2E4FD0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x83D06572EBE01EF2ULL,
		0x91855894E8FAA530ULL,
		0xD97EA6E611E88765ULL,
		0x4B2641FEB7844722ULL
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
		0x49B888D9EDE42B63ULL,
		0x70F604E6EB7463D5ULL,
		0xFA2F0569C0C1B8A2ULL,
		0x419FD1696EB87C2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xCF5B35110D08DE01ULL,
		0x5D32D4B754D34E16ULL,
		0x8C0E5ECD15EE876FULL,
		0x776BBA790C5886E1ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDC9F861D0888A027ULL,
		0xFFD4365ED62D56BCULL,
		0xBCC1B8BD6CD919EAULL,
		0x5E0A461D004FF276ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x9A599FC6EBBE0C2EULL,
		0x98EBF1E74B20F21BULL,
		0x00E8D55408763BF3ULL,
		0x2ACCE6B9B28016F2ULL
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
		0x8CBCD326F1B49304ULL,
		0x4D5453BA17D58BCDULL,
		0x4710654948B357C4ULL,
		0x30FD125E7782A0F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x8CBCD326F1B49304ULL,
		0x4D5453BA17D58BCDULL,
		0x4710654948B357C4ULL,
		0x30FD125E7782A0F3ULL
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
		0x75B1F3428838F7F2ULL,
		0xE9FC8E628FF2DC81ULL,
		0xFF63ADD626EB425CULL,
		0x151B186A05E24D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x0E1DC7128F7AEA7AULL,
		0xB7F8992AFA781328ULL,
		0x8C924F22C1DDC86EULL,
		0x34FA4221D958719DULL
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
		0xA192781136745D63ULL,
		0x76287E79F8037E72ULL,
		0xDEECF9B5E8971BDEULL,
		0x73FBE889F69514B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x5665F15CAD2C168DULL,
		0x06EBD0734A814057ULL,
		0x91AB534B56C02EA3ULL,
		0x776CB26CD4714857ULL
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
		0xB18225F423F004E1ULL,
		0xC72C7D8EA1EADF9CULL,
		0x91E0737316D4378CULL,
		0x2E055151AD29423CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xF1B39500390D39AFULL,
		0x598F93169A2806E7ULL,
		0x7F52400BF804FC97ULL,
		0x31A8F8C87B111BFDULL
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
		0x789FBEAF5FF010F3ULL,
		0x8CAAD180D22E0259ULL,
		0x4CD07290F700647BULL,
		0x563D296A15222A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x789FBEAF5FF010F3ULL,
		0x8CAAD180D22E0259ULL,
		0x4CD07290F700647BULL,
		0x563D296A15222A72ULL
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
		0xDCAF4E9E239A342AULL,
		0x65A50FE89DDE818FULL,
		0xAF8848FF40027B37ULL,
		0x11F60D34BFF3590EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA0490F43399010C5ULL,
		0xC517701D876C06EDULL,
		0xA3C419572038F95AULL,
		0x7AD5A60C6E26972AULL
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
		0x5ED1AA4458C52A67ULL,
		0x5B64C0504CA2CF94ULL,
		0x1F1BFD8B908B8AE7ULL,
		0x437AC2021DBCEFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xAF8C7BD01D863662ULL,
		0x71EDEAAED135F043ULL,
		0x5A300EFB8E683D2CULL,
		0x4F5E874363D3A438ULL
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
		0xCF5E0EE8A1D776FDULL,
		0x0DCFD0ECEF9B8138ULL,
		0xD195F39F8E6EBF5EULL,
		0x363020BB98F8618EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x744419C4F8785906ULL,
		0x8A9AE52CF3594CCDULL,
		0x0F2A9608072282E9ULL,
		0x44FB57DEEB634739ULL
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
		0xA56419037F014A60ULL,
		0x6607A0A334BD1BF5ULL,
		0xF36A7926A5D44065ULL,
		0x5EE9D7BA9129B65DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA56419037F014A60ULL,
		0x6607A0A334BD1BF5ULL,
		0xF36A7926A5D44065ULL,
		0x5EE9D7BA9129B65DULL
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
		0xF15EAC1E0DAEDF43ULL,
		0xF06A6EA497450DF6ULL,
		0xD75B899701301721ULL,
		0x340EA21299B6781DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xA1DF11DDD69FCE83ULL,
		0x3484F0A183A8BC61ULL,
		0xF872AF21AB50C1BDULL,
		0x7794D6CB8EEC9F54ULL
	}};
	t = -1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF20AE27223F97854ULL,
		0xCAA895486D187278ULL,
		0x9D846BE665D7BBD0ULL,
		0x0AA5F286E60B28A6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x48117ED1CECECE41ULL,
		0xCB98B2D1F34CF201ULL,
		0x95E1DCAFF6C33664ULL,
		0x7B2B5A594978B38EULL
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
		0x3063F660C42ADEF0ULL,
		0xE0D12F139B7028DEULL,
		0x99486AB982CCBDBBULL,
		0x5647C9058E0921D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x2FC1282DFA8451AFULL,
		0x2A8AD583F4BEC6F9ULL,
		0x8B1F522EEDB92910ULL,
		0x7DF5DADCDEADBEEDULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x630B6C0E7A12AB59ULL,
		0xCC4F42992ED355CCULL,
		0x52537622E28C3B22ULL,
		0x01B7C0EC73989861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x630B6C0E7A12AB59ULL,
		0xCC4F42992ED355CCULL,
		0x52537622E28C3B22ULL,
		0x01B7C0EC73989861ULL
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
		0xAD2A514362D1489EULL,
		0x2525764FE54E8BFCULL,
		0xA0829FF224EA17C9ULL,
		0x46B8CFF2A2E6BF41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x86BC8A809B1220D0ULL,
		0xC04B3E22CE343B95ULL,
		0x7A41150D3E2CC877ULL,
		0x62188BAEE97EB71DULL
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
		0x0F09717DC7CC7362ULL,
		0x55D11541F994FDCCULL,
		0xA16DABBF586A93EDULL,
		0x3705392A8FC027FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x749E93F56E369169ULL,
		0xB70190522835D804ULL,
		0x6A1D4615E0D6147DULL,
		0x23317A05F65346CAULL
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
		0x0785FA13B873F522ULL,
		0x0BD01F87E8398C79ULL,
		0x148B028A5363985AULL,
		0x178C506C490BEC44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x7D174139034AC6E1ULL,
		0x39E154C2E658781CULL,
		0x2281753D70475ABBULL,
		0x1CAEAFCFB38EB687ULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB2184CAB642A7A50ULL,
		0xB155A0AD9FA148DBULL,
		0xC6EE65DCABCF3BDBULL,
		0x17D612AAC324B40BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xB2184CAB642A7A50ULL,
		0xB155A0AD9FA148DBULL,
		0xC6EE65DCABCF3BDBULL,
		0x17D612AAC324B40BULL
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
		0xA012EEBD09A54A54ULL,
		0x841E721CF4C9D5A5ULL,
		0x543E050EAC754458ULL,
		0x5D78A910A6F462EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x32DEFC6A933757C7ULL,
		0x2A82056DB5D67D86ULL,
		0x4DE7F9A2B73F70EAULL,
		0x5B8883952701DAA6ULL
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
		0x6FA157E5AFBDEF60ULL,
		0x254EFFB3150BF2C0ULL,
		0x7E27AE1541187E96ULL,
		0x2142E92D15E50E3FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xDBD57B0F383FD063ULL,
		0xFC7B1BDE47830B5AULL,
		0x20F2D18DBD4F5FFCULL,
		0x3037149A487FC306ULL
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
		0xDB89175E639B1578ULL,
		0x990D9AB2B26E9B06ULL,
		0xBD33329F91C622E0ULL,
		0x61D52BA6A89D64E7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4731455BCBF78858ULL,
		0xFBCEA3C563809006ULL,
		0x9381D306D81C6A3DULL,
		0x2D6959DEDDA200E7ULL
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
		0x09988F2EBD0FB9E2ULL,
		0x0DBC74F4A8FB047EULL,
		0x7FDA08C2298178B4ULL,
		0x1DA617F0D3640581ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x09988F2EBD0FB9E2ULL,
		0x0DBC74F4A8FB047EULL,
		0x7FDA08C2298178B4ULL,
		0x1DA617F0D3640581ULL
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
		0x9022090E7F4E4A5BULL,
		0xA5A814F76CBA0F7AULL,
		0x609D6E13546303EBULL,
		0x1830A4994FC701D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4DDA909F4C7C543BULL,
		0x6C06806523B9D019ULL,
		0x21AC0BC8CFDE77FDULL,
		0x2B243CCAB27059BAULL
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
		0xA3FA52BC8514A558ULL,
		0xEE3F9E56115155BCULL,
		0xFDC29D9B74D395E1ULL,
		0x0431262655D948BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0xEEDA6B2DA16D6036ULL,
		0x5BF0886D49414B93ULL,
		0xF46846918C68FC2FULL,
		0x55BE28B20586CF0DULL
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
		0x20F49E6433701BEDULL,
		0x4E2233F70F9D8705ULL,
		0xA1AD44A6CDD97680ULL,
		0x4212B26F096C4847ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0,
		0,
		0,
		0,
		0x4E6B9EE6F1D63B88ULL,
		0x3504DD6BF9DA7CD6ULL,
		0x9AC1002B7C00D33BULL,
		0x35BABEBD550E19DDULL
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