#include "../tests.h"

int32_t curve25519_key_cmp_low_test(void) {
	printf("Key Low Bytes Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x6A08F893AD4B8314ULL,
		0x5FC9449AA85F668CULL,
		0x323B3E64CD17140FULL,
		0x777E23DD4B1E9DA5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x212BD4AB7771AC77ULL,
		0xA0327364F34E1AF3ULL,
		0xD995F1448D60FC6BULL,
		0x75D3517B0D90AAAFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	int32_t res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9C203E949159E228ULL,
		0xE137501DF51A3BE7ULL,
		0xA5F23F078562469EULL,
		0x57A9525317DCEDCEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AB61D0A4B1B5C42ULL,
		0xBB6320F873F79F0FULL,
		0xB2B4F3F0FD1D7894ULL,
		0x6CA64344E5DB5749ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5AAE679D5C570C32ULL,
		0x96DCB47A0FBB61D0ULL,
		0xDFEFBDF77D7C9E95ULL,
		0x014538E52DBFE894ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C3AEA057F1F48E8ULL,
		0xB346CAC6727A3498ULL,
		0xE156128ABEC646E5ULL,
		0x4763F6B54DFA296FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7053977637A36512ULL,
		0x5C7C98BC8C3EEF5DULL,
		0x70D54895FD95F196ULL,
		0x6BC393BA2600A7C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18916FFD8C7E4709ULL,
		0x89F49802E24AE2ABULL,
		0xAC64CE27836FEA73ULL,
		0x469383D188C22F81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x639626123D340FBFULL,
		0x5DE335058206252BULL,
		0xE80199D03D95840FULL,
		0x385BE4FE87A81CA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x639626123D340FBFULL,
		0x5DE335058206252BULL,
		0xE80199D03D95840FULL,
		0x385BE4FE87A81CA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD6BAA11C0E4BC706ULL,
		0xF34DDA31EB4A19EEULL,
		0xF7AB3DAFCA9C9583ULL,
		0x220ADE6F1189DA13ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79E7C824F82F8169ULL,
		0xF6D5E32AEAF35108ULL,
		0xDC853507D525485CULL,
		0x59E7F7967CBD37BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8DBEA625BC786C6DULL,
		0xA93CA81FECAFE346ULL,
		0x44E4A68FD7E1F431ULL,
		0x0EB9BC39C144E3DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BE578B06855492CULL,
		0x0558BD38B2EDBE90ULL,
		0xAF11471413BB29A1ULL,
		0x7CFC2F4C8DA5ACFAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9AE59AC418ECB5B2ULL,
		0xF4609B59933F256BULL,
		0x751D8CB48D10AEEFULL,
		0x5DF523CABB7F467FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2E585522D4D75ABULL,
		0xEFF87FAEE82E665CULL,
		0x54A30F0D03B9F47EULL,
		0x221FB044B50B828AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB47D50DCE1789923ULL,
		0x756F7FC7D9F5598BULL,
		0x0CB3B2B112847CD4ULL,
		0x5A033746506910F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB47D50DCE1789923ULL,
		0x756F7FC7D9F5598BULL,
		0x0CB3B2B112847CD4ULL,
		0x5A033746506910F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCB28C03E9446C28CULL,
		0x7AB4504E22785A2AULL,
		0x590B2E45446D6B18ULL,
		0x5CA1D03AF5C2B79FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8667FFFBE6CE5DB5ULL,
		0xBC233B16E74A7080ULL,
		0xCF77E962C7C1471CULL,
		0x009075A14D8B602FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x33B06255A5BBD0F1ULL,
		0xB88548F1E75783E5ULL,
		0x4C4DD0B5B121877DULL,
		0x09B383D88988449BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x096F8A90AAB9E5DCULL,
		0xA32BDBBBE6F8E2BFULL,
		0x371A3690682F88ECULL,
		0x20883A06B561E090ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7471051A200BD61EULL,
		0xB0B401A4C87C80E3ULL,
		0x3E17C14E0BD1A2ECULL,
		0x3B2818638FE1BD8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D83FE413579F00EULL,
		0xE4ABFCAC1B211A7BULL,
		0xDCA27121E38140C4ULL,
		0x5B66AEDC45E321A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE6EF9449CFE07DDCULL,
		0x37A0F32D831865FEULL,
		0xBE4EF549FB6D3CD6ULL,
		0x467847665F3C8064ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6EF9449CFE07DDCULL,
		0x37A0F32D831865FEULL,
		0xBE4EF549FB6D3CD6ULL,
		0x467847665F3C8064ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2797F7FDE3CC8DE9ULL,
		0x88CFAF55C8F022A8ULL,
		0x69F22CEC64B4ECDAULL,
		0x59ED7EB4949EF9E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE74774E1253C3CE9ULL,
		0xF87C8B58365A8217ULL,
		0x600B9D6199A040CEULL,
		0x4852620472C48E71ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x90C01FC77C86BAF9ULL,
		0x44FE05984F8B1EF8ULL,
		0x81B9B7E8A99E78CCULL,
		0x2D17A22030FDA637ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D7DC2779D6661EBULL,
		0xBD8F3E36C7994256ULL,
		0x2106B73B3230BB6EULL,
		0x033C86A4CD15F857ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD6BC6212FE70DD35ULL,
		0x7FA4D0BA32FB2AB7ULL,
		0xEC83976EBA9BEBD3ULL,
		0x47379C8B454B37C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1678AAC153FE97CDULL,
		0xCF8AA2CC6439B850ULL,
		0xBB231C5B94314F72ULL,
		0x76388B4D499453C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCA95ADF2517A9895ULL,
		0xF5D0694675D0C2A2ULL,
		0x5C1CDA4BE1B5988AULL,
		0x6AC10F2C7525B45FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA95ADF2517A9895ULL,
		0xF5D0694675D0C2A2ULL,
		0x5C1CDA4BE1B5988AULL,
		0x6AC10F2C7525B45FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x29098EF11C2090BFULL,
		0x6601226A2E2382EAULL,
		0xB32BE5E862A6579FULL,
		0x51F2A257D07CC3BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4495CEEBA68AE5CULL,
		0x93212D8B52EFB3F9ULL,
		0x56831C8066AA6829ULL,
		0x7D02D8850E577B4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9A44135AB13A674EULL,
		0xA3C6A89502543025ULL,
		0xD56FCB2069A0FF37ULL,
		0x254722245001E691ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D0A170024F22990ULL,
		0x85E93B6B31B79292ULL,
		0x4F861E77301074E8ULL,
		0x1E803EB138E15F81ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF24E70AE555D5B07ULL,
		0x0FA21D20D98BC9BBULL,
		0x1E335E5A78EB0580ULL,
		0x2E8D27E8A93805E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6CB41E2800CD2D2ULL,
		0x744FCAA1FF975E77ULL,
		0x31CB563D186E4A40ULL,
		0x6E4ADD7DEF3C0487ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x37341D34E1DAFB0CULL,
		0x65681F5E4FEBF006ULL,
		0x7726AAC60D9F83EDULL,
		0x445B291E3DD1E7F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37341D34E1DAFB0CULL,
		0x65681F5E4FEBF006ULL,
		0x7726AAC60D9F83EDULL,
		0x445B291E3DD1E7F5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3A8F4E30105A9220ULL,
		0xB00D10A98FD72CD6ULL,
		0x7885E42AC4505F06ULL,
		0x0A905D4FE96EEDA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC5BBDEA44A1C4BULL,
		0xECCA115927C2D3A1ULL,
		0xF8F6EAAC4255BFB5ULL,
		0x7C09F2967B00D628ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2FE2C4B18AECFDF7ULL,
		0x8663EE5AC0C5973CULL,
		0x27DBEDAFEAFB3337ULL,
		0x656C988C651B82C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x988D4D4DEBDB835AULL,
		0x5607E2F7E6797208ULL,
		0x0EDA041E97B7A932ULL,
		0x588310FE1CEF5D49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE98E588CDF02E9CFULL,
		0x4E4ED0833BCB6643ULL,
		0x6BFE2BA39E53529AULL,
		0x28A50DC913967E58ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14013B6FF030CA2CULL,
		0x5FCB27D80DD12CA7ULL,
		0x260914F60057C975ULL,
		0x1D7CFA29E835204AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC6A3EBC424FFE392ULL,
		0x0DADA12A3851E65DULL,
		0xD4A9C21657F75FD5ULL,
		0x361444553E2D8E0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A3EBC424FFE392ULL,
		0x0DADA12A3851E65DULL,
		0xD4A9C21657F75FD5ULL,
		0x361444553E2D8E0EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5EEC3C3074377242ULL,
		0xEB3A19281E9E1A38ULL,
		0xB92D05536ADC133EULL,
		0x50E98C8AA41AE5AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4AF3E57ECC68BCULL,
		0x18859FDC31A61A80ULL,
		0x7C3424B2C7851C03ULL,
		0x7AD03FBA617E1013ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBEF4825065ABCFC1ULL,
		0x6F13450D6397374CULL,
		0x934A02CDE6F5858FULL,
		0x11A5D7CACFDD3F01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E4E38C41BF833FULL,
		0x2C55626486627CECULL,
		0x39FFDE20AD6847B6ULL,
		0x586A6FC6CDFF36C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x72B52F82B6329F6AULL,
		0x2C56FEF0D139758CULL,
		0x0DC7C8EC743AE727ULL,
		0x5C8021932445DAEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE787B65544E141DULL,
		0xA962414414E6CFDFULL,
		0xB651EC6FE10C301BULL,
		0x49B5ADCE74111B22ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBECB7E8AD06E2CBBULL,
		0xE33EB70EBD294E3DULL,
		0x3DA8C9554597AFA7ULL,
		0x41CE1D15DDAA1B12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBECB7E8AD06E2CBBULL,
		0xE33EB70EBD294E3DULL,
		0x3DA8C9554597AFA7ULL,
		0x41CE1D15DDAA1B12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF904A0C531000010ULL,
		0x8DAD2F8E2CCBE442ULL,
		0xBCE91B482210B168ULL,
		0x217FA424993931B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51422C6194F2D53DULL,
		0xC2C3C9BA8CCFEF09ULL,
		0xF5A9E9F73AA15424ULL,
		0x63B0256423F15056ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x512929964B7D5F4BULL,
		0x5BD31137B3B07552ULL,
		0x97BE00B380F17AC4ULL,
		0x2EE9EC7DAE2E7902ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67C7B52F2B521807ULL,
		0x4D44FD63CA9C6342ULL,
		0x1B263EF543104423ULL,
		0x13BB017AF2EC830EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9E1AD2AA752FF513ULL,
		0xB391A9D0914476FFULL,
		0xFAEB50B0AD5DB50FULL,
		0x18662C50804EF52DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40C71D3DC4B95DFAULL,
		0xE71C60AAA129B347ULL,
		0xBC2DBB0C75404F62ULL,
		0x5271F2314BBBE26AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3B32C0C67132DB37ULL,
		0x33A0853E703EA561ULL,
		0x466BD1D5C36E9075ULL,
		0x799F9482CFFB15C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B32C0C67132DB37ULL,
		0x33A0853E703EA561ULL,
		0x466BD1D5C36E9075ULL,
		0x799F9482CFFB15C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD2C3244F60B96003ULL,
		0x7C9972151BADFFF1ULL,
		0x1A867833C7EEECFFULL,
		0x53F472CD1AA908BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5EC7711A0B98761ULL,
		0x2E0847B53B3A57E8ULL,
		0xEE4E6DFD85D67348ULL,
		0x161A55D8FE736DA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7509F0D5B9C09D4AULL,
		0x9FA9BB9E5EDA7F71ULL,
		0xE41045E4BCB4E46CULL,
		0x610E4170AB94BB2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAC6C114BD36846AULL,
		0x650E9DEE5CB232A7ULL,
		0xAD409A1573EBF04BULL,
		0x20D6F681ADBC8860ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x036EB9812C7B4B93ULL,
		0xDA95E6441CB52BAFULL,
		0x36438FD453F99040ULL,
		0x3FB5187E1E0A0529ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F53FC499ADD8446ULL,
		0xFDB014C05BF83CD8ULL,
		0xEC3FA9E2CFB18EEBULL,
		0x6E5647A68FAEDC17ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE7782526B7AC02C3ULL,
		0x81E3BD66505645F9ULL,
		0x6434D142A01B1D9CULL,
		0x0D6640F466FB829FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7782526B7AC02C3ULL,
		0x81E3BD66505645F9ULL,
		0x6434D142A01B1D9CULL,
		0x0D6640F466FB829FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4110746C28017CD6ULL,
		0xE57C2E103EBAFA01ULL,
		0x813369D499477B39ULL,
		0x0392652078E1381FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA99AA496B73047ULL,
		0xF7DE97DE0019FC1BULL,
		0x0E713A0C3B82654CULL,
		0x63723AF6B3907281ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5B9DA03B684CA40AULL,
		0x0222F785EF974937ULL,
		0x8CA814D0D5C55EB2ULL,
		0x5BC0057A59131CA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F3D8E789FFDD5E8ULL,
		0xEEB511F9CC7C022FULL,
		0x23C80735E04F65BDULL,
		0x2A3375046889DDB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3BF42DF5831E57FAULL,
		0x7274B0F7C8777F30ULL,
		0x2964DDBEAE9E7490ULL,
		0x42BB5C7B044F2D74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAAA2C5B1CB50F4CULL,
		0x618DB97C06FD39F2ULL,
		0xFDBBF8EBAC3FB521ULL,
		0x7AC318A45830DD7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDFFA8671D06D835EULL,
		0xD24D50EA5F9E6B54ULL,
		0xC0DF22D5A091D07FULL,
		0x3081ADC90B856EE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFFA8671D06D835EULL,
		0xD24D50EA5F9E6B54ULL,
		0xC0DF22D5A091D07FULL,
		0x3081ADC90B856EE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x11F7BD5AED7D9E2EULL,
		0xA6D4AB0BC19A8555ULL,
		0x213AE4B1CAE9C593ULL,
		0x47EBDCCD145484E3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BBF6D13CA509B8ULL,
		0xA9B24ADFCAC672C9ULL,
		0x17122323AD3C671BULL,
		0x451AC855AD7ACAB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD06795DF759241AEULL,
		0x609CA0F047C18142ULL,
		0xC0C07E27A647203BULL,
		0x6F24D8E538055163ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x624B33A64EE8243BULL,
		0x7EC41F0C0FBC230FULL,
		0x9CEE0CD43E1BB4E8ULL,
		0x760F7C4AFC5581E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC2600C9251C5FB77ULL,
		0xA0610B2E56517F69ULL,
		0xFA868FC5AF312FFBULL,
		0x63AAB936FD978807ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05D9CF42152EBD4ULL,
		0x5BCDAE99DE1B1783ULL,
		0x6F00B81CA9C962E2ULL,
		0x69098784B8F3DF0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD86F690123E8F3C8ULL,
		0x79CFD76A80DC2D7FULL,
		0x563301A98EC407FCULL,
		0x49AAE366A1F1AA30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD86F690123E8F3C8ULL,
		0x79CFD76A80DC2D7FULL,
		0x563301A98EC407FCULL,
		0x49AAE366A1F1AA30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDF105D07771937F2ULL,
		0x19588BE30A09523EULL,
		0x7929B0A8D73DF6B8ULL,
		0x7F736458FD15E533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F4837398319CDBBULL,
		0xAFBFA05C48A97FD4ULL,
		0xEF22F68510698B7EULL,
		0x562F576BCC3E4E9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0902CE5F9CFF850FULL,
		0xE756751FBC71AAD1ULL,
		0x1A393EA544B402C1ULL,
		0x3E59F3D8DAB03338ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6DE89AB40870FD5ULL,
		0xC475FD673D338898ULL,
		0x1C29198054F07F64ULL,
		0x1DC83F09C8FAA200ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC14A2B7ECEECC5F1ULL,
		0x022E47FD5A3F196EULL,
		0x3D8D6D7D50B169F0ULL,
		0x006FF0E131B29D38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8A33F0EB4CABD81ULL,
		0xFFF491C8F1EEEE05ULL,
		0x60F90EE4CA38E56AULL,
		0x17DAA9364D676B44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB5EFCC992BD181B8ULL,
		0x4FF73A91FAD2E808ULL,
		0xF161047C5EA20C92ULL,
		0x7176BCAA037FEFF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5EFCC992BD181B8ULL,
		0x4FF73A91FAD2E808ULL,
		0xF161047C5EA20C92ULL,
		0x7176BCAA037FEFF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC4B1433B02395FB1ULL,
		0x99D4DE22C12FBCDEULL,
		0xDF4D346D9009150BULL,
		0x3BC6343C1046AC63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36CBD790FD3E69C1ULL,
		0xB5035F77A0136F26ULL,
		0x43D5797ED986709EULL,
		0x4F1641862BF52143ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2B859163414C0F50ULL,
		0x39451544F1B1C392ULL,
		0x4C293D20042C5873ULL,
		0x56D74D9562FCC39BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x648E05884DF7BC3CULL,
		0x25E04678B54042D3ULL,
		0xF21BC1022236C278ULL,
		0x40BA62A0887C170AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3E31F4A6E9B6734BULL,
		0xB83BFB29E445FBC6ULL,
		0x07285ADC767E1CDCULL,
		0x052682308A8BD187ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A714A27EA0D0C3EULL,
		0xB9109B9B61C6C6DEULL,
		0x5DCFE87BA1DF389DULL,
		0x3155742BC1CE9D26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE1BC35021F95DA87ULL,
		0x63D3257956872D48ULL,
		0x7A0656D1FD5FC9D8ULL,
		0x160FAB88F097EF30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1BC35021F95DA87ULL,
		0x63D3257956872D48ULL,
		0x7A0656D1FD5FC9D8ULL,
		0x160FAB88F097EF30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x111DD491CCC77CCDULL,
		0x112152E03532A41EULL,
		0xCF2BABE3B1E6707BULL,
		0x4F0ABABC02440109ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x353821B8B57D8778ULL,
		0x8F62DD81CD76572BULL,
		0xE89E762A3350D851ULL,
		0x36801FD39EF4381EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDAD54E8276D8BCADULL,
		0x1B641E1B3B7F1BA2ULL,
		0xF39C2A4C476E0069ULL,
		0x659FB3956614CF48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB082185A581C439DULL,
		0xF0BDF69C3571DA04ULL,
		0xE2A3D9039E8F0BA5ULL,
		0x1926CB4BBD11009CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4D44E0886C19E3C2ULL,
		0xFFFB70D039A07D71ULL,
		0x87F64D37C3E73DE2ULL,
		0x68969BA91FB9F5DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED64758DEC076DA8ULL,
		0xDB36F9EFC1C82E95ULL,
		0xA4AC2D112D192FD6ULL,
		0x15696F1539EF8106ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5C0D1E09E6546B35ULL,
		0x15454AD1CFE604B4ULL,
		0xA7AE542E941717E8ULL,
		0x1D09E4D6E8D4082AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5C0D1E09E6546B35ULL,
		0x15454AD1CFE604B4ULL,
		0xA7AE542E941717E8ULL,
		0x1D09E4D6E8D4082AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x364B87380D33B7CFULL,
		0xA8EF171B06DAEC04ULL,
		0x72458B6457A63F57ULL,
		0x29D82E2130C202B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0148091B0CB87F7ULL,
		0xB979C8A888D7FFE8ULL,
		0x0BC813228569EAF2ULL,
		0x3715AA44B59BFDC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x483F9DDDEF374606ULL,
		0x96AB76B3B46A8FB8ULL,
		0xA7B981C0F5B83578ULL,
		0x686EC2FB9B06C722ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBFF4E0ABCA907D7ULL,
		0x988E1AB554B26263ULL,
		0x28DF9D9236DE1B03ULL,
		0x3E896FBDE1AC4E8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB88F818C753A2948ULL,
		0x6931495374EAB076ULL,
		0xAC24ADF715F21970ULL,
		0x0E9E751E5606D24AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6D4DD3BC9795FBULL,
		0xE991E2866151949BULL,
		0x0F5B9A28A4BDF2CAULL,
		0x3236103B591811F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3A68872FF322A794ULL,
		0x5B8F968722710C6EULL,
		0x8AB9F90E75A60634ULL,
		0x4476B463DB76796DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A68872FF322A794ULL,
		0x5B8F968722710C6EULL,
		0x8AB9F90E75A60634ULL,
		0x4476B463DB76796DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD4A917D21DEDDB5CULL,
		0x9D3B158019AC7C38ULL,
		0x5921B56B530BC982ULL,
		0x4CDAFE722F429CC4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D7EA7093A0755E1ULL,
		0x1E4991C75C9141E5ULL,
		0x37476E165E766D6FULL,
		0x459961F5BEDFF224ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4F3CD3CA10C73A6FULL,
		0xEF2FD2D8ABD676F4ULL,
		0xE34667208687EF20ULL,
		0x707F1F5B70D6D93EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE03C3D424A39BAFULL,
		0x814017B18CEDBBEEULL,
		0x049B6B79B57BCA4FULL,
		0x20708C766536131AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCB2DDA57AA489885ULL,
		0xC75E74EA42482F94ULL,
		0xFB3DE1F7F92F0C88ULL,
		0x00CCD41AC83E9D0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2D385EB9E38054FULL,
		0xD55FCEA240BF3ECBULL,
		0xCC04F5A161A274D4ULL,
		0x565E950F082F30D4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6287D0B182CEB64BULL,
		0x1C4746219F0D1B14ULL,
		0x9A745C385F648E24ULL,
		0x66F5DC639F56EC9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6287D0B182CEB64BULL,
		0x1C4746219F0D1B14ULL,
		0x9A745C385F648E24ULL,
		0x66F5DC639F56EC9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB88A11EA0E62F1BDULL,
		0x84A2BA9743160826ULL,
		0xB74381B52A41C775ULL,
		0x3D05B3AADDB1535AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA225A81666D0EC04ULL,
		0x5605F916C995ACADULL,
		0x218D38101863934CULL,
		0x2F027687591D3F3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3DA5A714B65BF793ULL,
		0xDA2C740AA878849BULL,
		0xB7D1241366A1CA09ULL,
		0x3963C300856FBFE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B88CDF25C11001CULL,
		0x9C8A3F2507514415ULL,
		0x2EC6B9CBF9575A4CULL,
		0x5076F50809D46DA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3141F9B3A4DAD82EULL,
		0x23F4B860306FBE73ULL,
		0x85B8EAA5721C5463ULL,
		0x61F495666F9F5264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50020DAA4F45BA40ULL,
		0xC56C74803A806537ULL,
		0x5BBAADEDC61686E5ULL,
		0x1AE77B5D5346B5BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x238D34B3FE3CCC48ULL,
		0x476FC8076E040D76ULL,
		0x0E7C855B8D4BF826ULL,
		0x318916E7F35798A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x238D34B3FE3CCC48ULL,
		0x476FC8076E040D76ULL,
		0x0E7C855B8D4BF826ULL,
		0x318916E7F35798A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC2AE5E2CF8083447ULL,
		0xC8D88EAA66B0D2C6ULL,
		0x2A0F509E221EBCF0ULL,
		0x603DDDF4A4411154ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15C686F04D554939ULL,
		0x41FE7558424ACA87ULL,
		0x14B1095195E7AFFAULL,
		0x3CAF1EDE18C1FB91ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE124B7E3D41802AAULL,
		0x185A35446884DFF4ULL,
		0xDC2DF93BDCB1283BULL,
		0x61E4438DADBF38DAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1325F88BF909E1CULL,
		0x603FBA7FB9A703D6ULL,
		0x982D1D4DF9F509FDULL,
		0x48D87BD919FB66A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x06D5C7B37103A279ULL,
		0xA7FD21C8078C9854ULL,
		0x88811AE0697894B0ULL,
		0x2844CA9B136FD3A8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95A9FB9141B93557ULL,
		0x1DA5D57B0B5F17EBULL,
		0xB4FF4E3D2CC86A41ULL,
		0x62C7D03F23AAE767ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8FDF724E9415B0B1ULL,
		0xF8C71281A82DF930ULL,
		0x568113B86896892EULL,
		0x6FCDED134C5E122EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FDF724E9415B0B1ULL,
		0xF8C71281A82DF930ULL,
		0x568113B86896892EULL,
		0x6FCDED134C5E122EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x19325508C593C083ULL,
		0x5342353682ED66D7ULL,
		0x9F6892B30BA5AB36ULL,
		0x5E10CFCCED70281AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45BF84A125DCBB1BULL,
		0x1AFC4679E8980789ULL,
		0x6769701B89F45D17ULL,
		0x1BAEA94191EA6B8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8B3093BA790A8F91ULL,
		0x1D3881559664C91FULL,
		0x4FBECE4FBE876D46ULL,
		0x6C55FA8D5F3F497FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4444E33431F2C2C8ULL,
		0x3F812BFF172DEDADULL,
		0x4029160656FE4C3CULL,
		0x2B30DDF058F551C9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1E1868FB1BB450CEULL,
		0xFC4B2A71356CC03DULL,
		0x288A7C45CF5295EDULL,
		0x6D8BA54FFA30D0C6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC8C810DC34732EULL,
		0xEF614BBCB8C4487AULL,
		0xA6C90FEA6607C830ULL,
		0x348C0C7398D41DBFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6EFD05FA98667319ULL,
		0x97C9EBA328BD8176ULL,
		0x4C2E9DACBA9AEB73ULL,
		0x60FC712B59AEFD56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6EFD05FA98667319ULL,
		0x97C9EBA328BD8176ULL,
		0x4C2E9DACBA9AEB73ULL,
		0x60FC712B59AEFD56ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE98E689441D74120ULL,
		0xB4D87A00A45F62F2ULL,
		0xCAFD44C686927B0CULL,
		0x39B4C0650DC62F09ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D9B35B71E738D09ULL,
		0xA76B1905CF06B28BULL,
		0x2E20776C4C5CFC6BULL,
		0x6237D7A62EE42F88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x35002500D36976CAULL,
		0xE04946C7780ED02EULL,
		0xDC8682E27EBE4D2DULL,
		0x20C20B0745752CD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464247BBA4CF85B4ULL,
		0xEDA5BE4FF52F5E72ULL,
		0x8A7B0730FAC35422ULL,
		0x7E7AE652C93C203CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE5BEE1D6BCC75473ULL,
		0xA0A41313F356EFD1ULL,
		0xC65A849F3D7B4CC8ULL,
		0x37466AD6D0617540ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8017A3E3CFE053E6ULL,
		0x26F63315D22F261CULL,
		0x10140D0E4DBA2200ULL,
		0x676BFA65794D7A70ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1607724F33F60EBFULL,
		0xEC0FCA6D254ED892ULL,
		0xA02C65BF42E0D11BULL,
		0x497C48A349E90234ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1607724F33F60EBFULL,
		0xEC0FCA6D254ED892ULL,
		0xA02C65BF42E0D11BULL,
		0x497C48A349E90234ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEC60B014672C0AE5ULL,
		0x6E9CD39688E87FCDULL,
		0x6AA08AB8ACF1095DULL,
		0x43D7F6D8265F919CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07E6B5430F1A10AAULL,
		0x0C3CFB8D64246C45ULL,
		0x386B533D7B9E4B7AULL,
		0x068F20C0D8DB9349ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6C51124064C8BCB4ULL,
		0xAF5D730ACC0567B7ULL,
		0x4DC9E84B77C5A858ULL,
		0x42532A93691C6E0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5B16E1166E2165EULL,
		0x4161B6E345F96CBBULL,
		0x5898958A9987EB96ULL,
		0x710AE0B90EB06513ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1C50F41FC97AA177ULL,
		0x0E8A78DCA4D979B0ULL,
		0x2931F3D5A2CBE79FULL,
		0x5A9CB3C9779689BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B25682965EEA86BULL,
		0x9E265E8303EB9084ULL,
		0x3504D23B80D1D5AEULL,
		0x267532521C925B85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAB8CF229267E1066ULL,
		0x8A870DFEFA62393CULL,
		0x311F7A32AA085AA0ULL,
		0x56B10A7DB41FD34EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB8CF229267E1066ULL,
		0x8A870DFEFA62393CULL,
		0x311F7A32AA085AA0ULL,
		0x56B10A7DB41FD34EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD05512250A437A2CULL,
		0x55F70EE4DC06BD42ULL,
		0x227E23ABC19B42B5ULL,
		0x378C51F778AAF9BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49F4A6ADF9DC8703ULL,
		0x6DD71F6003001AF7ULL,
		0xC058B5FC0FC772CFULL,
		0x3159F3C9B98809C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4C80F654A6D10E33ULL,
		0x5BAC8C231C05B1B4ULL,
		0xC66B51E87B3F17A6ULL,
		0x2DA42EA238889896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA4F3A2DFA360A7FULL,
		0xE5976B45DACD37D1ULL,
		0x3986915D30DFE263ULL,
		0x7F1F9A228E27BC10ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7DD3EA9EDB72D73EULL,
		0x7EB28628709A5B9FULL,
		0xE230961E82D9A083ULL,
		0x1FE4CA876F5C61BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC79C64FF345F300FULL,
		0xD2DC128F8E603666ULL,
		0x7E536925A00428DDULL,
		0x056940F1951DED73ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7DEEAADA17213DF9ULL,
		0x95CCD578D68E95A9ULL,
		0x913FE13FD8DC3017ULL,
		0x4D131CF0F555C5E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DEEAADA17213DF9ULL,
		0x95CCD578D68E95A9ULL,
		0x913FE13FD8DC3017ULL,
		0x4D131CF0F555C5E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4662D413E7B992A3ULL,
		0xDA23C55E7D1AF5F9ULL,
		0x2221E17C0AD12715ULL,
		0x238CDC739FB2869FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19EA9F31F7B0986AULL,
		0xBB27C7AC9A61FF35ULL,
		0x87E738782F4652F1ULL,
		0x5E905E4F3C4AB2F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8F3439A5BB3C68CBULL,
		0xCC301ABEA0E75F73ULL,
		0x0A0D4DEC440742C7ULL,
		0x78AA78FE6146383DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91E03D575CB95974ULL,
		0x0271E57614B50A0FULL,
		0x46726C6629A0ABA9ULL,
		0x7F7224A340346FE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1B74126529895492ULL,
		0xC9B397972DB7C668ULL,
		0xC6FF26C66A0267E6ULL,
		0x0BBD3B3F3CB6B37CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9B04F69D3383D41ULL,
		0x0692A500E2F60933ULL,
		0x387FD6D6B091E794ULL,
		0x290FEA882796CEFFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1884C15AD165AA61ULL,
		0xD1E126A1D94A8B40ULL,
		0x9A3F02A7E586680CULL,
		0x78D340EB8E2E561DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1884C15AD165AA61ULL,
		0xD1E126A1D94A8B40ULL,
		0x9A3F02A7E586680CULL,
		0x78D340EB8E2E561DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEC1EDE8A13C165CCULL,
		0xFE8C20B8832510ADULL,
		0x0E45AAB3CE18E8AAULL,
		0x4D86CBF344B5C3EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9721DE1D9D785D4ULL,
		0x30F32EDDF7D96621ULL,
		0x7A91EFDFDA960D56ULL,
		0x4F3323FFE400F0E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA206C427BC35DEE3ULL,
		0x87A84687BC4502B9ULL,
		0x951A144EC73D280BULL,
		0x5C415A980E42AEDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07261BE9D90D629EULL,
		0x03D161A48A218C79ULL,
		0x7899A050861D58D4ULL,
		0x28FEA223926F945BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDD922099AD7D1622ULL,
		0xE7A4E33FDFAB0D93ULL,
		0x6EC7360EBE10A77DULL,
		0x4EF3308D8483E575ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7335EE20DD7BB602ULL,
		0x11B8970987C0F554ULL,
		0xCC1B7A858E152DD4ULL,
		0x23C787ED502AAD0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x94E0EADC4E4140BDULL,
		0xAACB7DDC0CAAF7D6ULL,
		0x236B60875E69380FULL,
		0x7779CB4527EB3CC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E0EADC4E4140BDULL,
		0xAACB7DDC0CAAF7D6ULL,
		0x236B60875E69380FULL,
		0x7779CB4527EB3CC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD85D2979005930D3ULL,
		0x887E65E73344C8AFULL,
		0x8A8A5A15F978C58BULL,
		0x28E468E31AA8FCEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50911F54F7E4B613ULL,
		0x3B3499870C24BDACULL,
		0x3444BFDC52542DAEULL,
		0x7285F2B82AB82322ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD0446F166A1F8EA3ULL,
		0x98A6D5BA1D3F2586ULL,
		0xD0DF1D7D56AF13ABULL,
		0x03768869F18F75E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5634E8F390784F90ULL,
		0x60AC601CEE5B8A0EULL,
		0xE483709FBE619364ULL,
		0x72EF897BC1633CDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5A172F964F65F236ULL,
		0xFC3DEEA2B9719511ULL,
		0xC523B49943F0DC18ULL,
		0x6E3A84BAFF884223ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65E64010584D34D0ULL,
		0xEA98FACF13E2A1DEULL,
		0x20828C86AFA21AE8ULL,
		0x3DCD4CD70596DF06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDCF01AA8E3AEDA7BULL,
		0x797CFE1D7CBDE48EULL,
		0x7774B6B6DA8A0B76ULL,
		0x13B09987C92FDCE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCF01AA8E3AEDA7BULL,
		0x797CFE1D7CBDE48EULL,
		0x7774B6B6DA8A0B76ULL,
		0x13B09987C92FDCE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE3D17C64F3AE37EFULL,
		0xE634EA26746E08B7ULL,
		0x6C195EFAF2C6BAE3ULL,
		0x064169268B93AE8BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7258A88D819AD0AULL,
		0x064EAB4305FB5AF9ULL,
		0xB62C089ED116E1B2ULL,
		0x2B5556C2A3138100ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0D72956B56C2B24FULL,
		0x8A9C8B4500430E65ULL,
		0xDD96C6A469523533ULL,
		0x5BDF4AFE60C7E63BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F9C3BA87DA8C786ULL,
		0xAF5708BA9590F409ULL,
		0x80740CB866733224ULL,
		0x09D84ED8BA7FBAD8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBE9299A6A44ACAB1ULL,
		0x1A0793AFAAF5707CULL,
		0x5FDA3E02B1BA0CF9ULL,
		0x032A7217ACECE1FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCCCD0A2FB4BE27AULL,
		0xF70589C436ACE0EAULL,
		0x7C39F2840CE3AE61ULL,
		0x581CCFF73610738EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDA96E9AD4D5299C7ULL,
		0x52B21000676059CEULL,
		0xA1A23ABF7EE57726ULL,
		0x757274162E33B105ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA96E9AD4D5299C7ULL,
		0x52B21000676059CEULL,
		0xA1A23ABF7EE57726ULL,
		0x757274162E33B105ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1F032E2CDD9FA3F6ULL,
		0xFEC9C0D2155C3F28ULL,
		0x6ECE152B6FFFD274ULL,
		0x5D847588F3B43BBAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9B9B5D6C092D3AFULL,
		0xE117A7860023141BULL,
		0xD02B672E36A8E05BULL,
		0x4D55E9334D0CB22DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1396D7826E18B44AULL,
		0x625971A28A674A15ULL,
		0x3EB287D2BB153FF8ULL,
		0x280D9AA0B853A5FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x171C022607EBCF61ULL,
		0x53CE897B1B332EB7ULL,
		0x7C9E7F495CA3ED12ULL,
		0x5EC313735EA607CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA9C963E0DDCF38F2ULL,
		0xA7130CDBA62C792BULL,
		0x92B152F3F0A9E886ULL,
		0x67D522CD13109B67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xECD2FF4CA31ADE85ULL,
		0xB2C52FBF6B218EFDULL,
		0x9F8793CD555D4C88ULL,
		0x2D8104F14F8B7848ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x125734DBC4E6D4F8ULL,
		0x533C859391773286ULL,
		0x7F5307B50561A006ULL,
		0x2DBFD5A32023BCE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x125734DBC4E6D4F8ULL,
		0x533C859391773286ULL,
		0x7F5307B50561A006ULL,
		0x2DBFD5A32023BCE2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCD38B424BF59BF08ULL,
		0xE272EFAA2C803B5CULL,
		0xF8D9C0D5DF2D1E67ULL,
		0x54D1BC7B93EE7B9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB28FCC94060AA1FULL,
		0x4EB16930F940D059ULL,
		0x2457AD5761FFF3F8ULL,
		0x01E02DF389A7CC39ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDD345A1EB097526CULL,
		0x1B7BC8DB98F9D5B0ULL,
		0x48215282C99DF468ULL,
		0x35B66C5F9E8EEA3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x605975F72DD27F34ULL,
		0x3A6111DB538DC861ULL,
		0xC973256F9BD0CD58ULL,
		0x2BCE113CB0F46BDDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBD4AD0850DEA4C54ULL,
		0xDDFBBC3F6ECC744CULL,
		0x858FE1B9389E33F9ULL,
		0x473E64172D0BA7C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80458A42074648B3ULL,
		0xDBC04116E6AE3460ULL,
		0x9897F45C38D58249ULL,
		0x104C9C1B17DA41CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x053FCA93B04E6B77ULL,
		0x71D8102011619D0FULL,
		0xD918FC66D2B22D72ULL,
		0x7C28BFDFD4A97248ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x053FCA93B04E6B77ULL,
		0x71D8102011619D0FULL,
		0xD918FC66D2B22D72ULL,
		0x7C28BFDFD4A97248ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE885B42FC37E7C5BULL,
		0x9BDF7FBE839027A0ULL,
		0x52482C879F421813ULL,
		0x74114EF3B4136865ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AFA53856A28CF09ULL,
		0x03C04E5F8430FCBEULL,
		0x02BD7B7346F3CAD3ULL,
		0x0DA7E4F10835E4FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3353ED849981E84BULL,
		0xFDBABDEDF930AF99ULL,
		0x875731089B0BDF37ULL,
		0x49B89C89700FA628ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4250AE1B803A1689ULL,
		0xB7396BC66D0F46A8ULL,
		0xE1326BE1640766F0ULL,
		0x4617D478463EB565ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD8BC35B5B5418530ULL,
		0x3C8F9430B0DDC170ULL,
		0x4EBB809792EEA7C2ULL,
		0x5A38DF932F91F909ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2F3113F3DE321C2ULL,
		0xE9C997293A144012ULL,
		0x528B57FBAB661242ULL,
		0x65F6CD7F9627EED3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6BACF4C4006AA7BAULL,
		0x38B1FC8B351009ABULL,
		0xDBF6D9C8A9AF1956ULL,
		0x06CEB27D61A6A453ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6BACF4C4006AA7BAULL,
		0x38B1FC8B351009ABULL,
		0xDBF6D9C8A9AF1956ULL,
		0x06CEB27D61A6A453ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x53DBCEE72569F496ULL,
		0x6462261CAECBED36ULL,
		0x63659C9CA31994E5ULL,
		0x119C037036BBE4DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9268E6CFBD330580ULL,
		0x635380E19691FC6AULL,
		0xE5F9348FD40831C4ULL,
		0x34526D6CCE2C4F21ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x129D876631EF54B7ULL,
		0xC540837E5D9F6AC3ULL,
		0xA922B71065215F9EULL,
		0x11091CC46365B32CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F9DB522132FA133ULL,
		0x484ED9C49510DEFDULL,
		0x968EFF64B7C696BCULL,
		0x0E778E3F684567EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD28EA7AF565E2F3DULL,
		0xEED871FE079B9CCDULL,
		0x6CFD76803CCA47E8ULL,
		0x6998E685A509A17FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA614C33BBDBB3ED8ULL,
		0xA92534A99D7AC480ULL,
		0x0709593F8F88F380ULL,
		0x59BD431BEA197072ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBC50CF5AF795C346ULL,
		0x1C99A61CE251D4F6ULL,
		0x84ABA62E527D0164ULL,
		0x049EC85EC7C68141ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC50CF5AF795C346ULL,
		0x1C99A61CE251D4F6ULL,
		0x84ABA62E527D0164ULL,
		0x049EC85EC7C68141ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC55E73A7F5B98CAAULL,
		0x74B2555DD652A879ULL,
		0x42FA6ABB199C0B60ULL,
		0x6E3E941AE77E754AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D77034ADF35C94ULL,
		0xFD99A757B4BE3CC3ULL,
		0xE10492EBCF100A23ULL,
		0x7E9B962D7C09BBF8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCD86D108BECF82DAULL,
		0x20F34112208CB2C4ULL,
		0x6CF9FAA555AC5932ULL,
		0x134AA9FB93777CB6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F6DC67D36D6224FULL,
		0x3DC274FCA2D22C0AULL,
		0x6013FD864934C477ULL,
		0x5F14CD91636D45A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x22FA88A39A2C510BULL,
		0x1EE8927431711D16ULL,
		0x5E49A6C21FAED952ULL,
		0x5F3EB6CCEE922666ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x886E17AC645DBB11ULL,
		0x8B3CA84AB64546B1ULL,
		0xF6ED1CD6A8BDB31FULL,
		0x7A6C4918EE585FEBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD859DB51ADC70593ULL,
		0x3A7B5A8894C0E348ULL,
		0xC9AF41F3E92D6DDFULL,
		0x268D14C55492A068ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD859DB51ADC70593ULL,
		0x3A7B5A8894C0E348ULL,
		0xC9AF41F3E92D6DDFULL,
		0x268D14C55492A068ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA1FBB984DF060F48ULL,
		0x59EFA5A1DB02506BULL,
		0xDC02EBEC66349FAAULL,
		0x6CEED5557349C5B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03BAA11699C89A3EULL,
		0x9B9E8DAFA46DFDD3ULL,
		0xEEAC68A5C5B64CE9ULL,
		0x27AC8DE699CECA27ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4C2B38AC93B674F4ULL,
		0x151522709C8692EBULL,
		0xB7A67A3F770628FBULL,
		0x4D6190270090FB59ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B4E33527E8BDEA0ULL,
		0xC4EE9678E102616AULL,
		0x7747B8D51E35AE00ULL,
		0x3597945AF88B0F28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAC7735FB9C5BF826ULL,
		0xB81E711E559CAB54ULL,
		0x4C8CA170B8338A94ULL,
		0x1FC4886A9A7A12FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95BC308BBDA0D0A4ULL,
		0x2DD100AE769F1695ULL,
		0x60C534182DD1F0F7ULL,
		0x57146A4CD4F69148ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0D241CF4CDC7CA93ULL,
		0xF7036FD762803BB5ULL,
		0xAF6F850C23017ACFULL,
		0x2E807653809CDF53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D241CF4CDC7CA93ULL,
		0xF7036FD762803BB5ULL,
		0xAF6F850C23017ACFULL,
		0x2E807653809CDF53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8E0AB9049135B7B0ULL,
		0x463CB4C55979ABFAULL,
		0x28603B2024F1D4D1ULL,
		0x26F13C223EE04788ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7916F6F04C8F3004ULL,
		0x593B383928404978ULL,
		0x7B6D163B99B38CDBULL,
		0x3284A74292382CE3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3457418D19056357ULL,
		0x3153AF80B4E35707ULL,
		0x3116A9685264B613ULL,
		0x4D60B25DA2C162F3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E61797008F559C9ULL,
		0x792C3033FFC623B8ULL,
		0x902707EBEA092889ULL,
		0x3BD7E322AEEE39B9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x58D26E5C04C337A4ULL,
		0x435EDB58A8D643C4ULL,
		0x7E5D808255CA571AULL,
		0x5C8D681C52B9DEACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61F0EB0029DC4406ULL,
		0x4DE6BDE7CAD77DC7ULL,
		0x04FC52F357F74DBCULL,
		0x4A6A3E8BC3C5126BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x63FE4B21AD3CEE9CULL,
		0xB61D1C1CF14F58ACULL,
		0xC812D54D3B2EF93AULL,
		0x370AC2B1939C9EA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63FE4B21AD3CEE9CULL,
		0xB61D1C1CF14F58ACULL,
		0xC812D54D3B2EF93AULL,
		0x370AC2B1939C9EA0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x23C25E97C946B745ULL,
		0x0DF3C434C63D0392ULL,
		0x8A9E4D237583D6E8ULL,
		0x1E71F068CA456B54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B8084AC917399BAULL,
		0x4CFBCAE130F3C13EULL,
		0x95D52ECB25A8F426ULL,
		0x12BEE27AE0FD77D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC152DBDC926D2AD8ULL,
		0x2BA1D03F26200417ULL,
		0x0E46938C2A8B03E8ULL,
		0x0B65DD51759DE67EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96FAC58E0FA6B2DFULL,
		0xFA89736974A9418CULL,
		0x23FED85DC738E0C8ULL,
		0x550CFEA53EDD2C03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x51BC46AF9688FB18ULL,
		0x40BE0D788A49044EULL,
		0x0BF7ED0BD818F0ACULL,
		0x277F348C65EC7C06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE39E92C8D16930EULL,
		0x2BE8AF98EE15936EULL,
		0x5E9FF0166B723EFAULL,
		0x718259EC27E6BB0CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x77F9C6CE9328C9A0ULL,
		0x5E359D6324B0BF20ULL,
		0x89BD531719D142BDULL,
		0x3F921ACC1BA6AE29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77F9C6CE9328C9A0ULL,
		0x5E359D6324B0BF20ULL,
		0x89BD531719D142BDULL,
		0x3F921ACC1BA6AE29ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFB52E28B54E569C4ULL,
		0x32FBF9CDFE93D8F9ULL,
		0xAF5CFEDCB95F6A6FULL,
		0x08476490615B318BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2239D8638B3490AULL,
		0x03E594C833279C11ULL,
		0xADD8325D644710F0ULL,
		0x3F4B1A9F13D32491ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFA442343B338F5FDULL,
		0x2F8A6FCAE263CE8DULL,
		0xEEDC4459374300C9ULL,
		0x56D3B8AAB28B3891ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADBAC5721351B466ULL,
		0xD09E42452BC31C41ULL,
		0x8EE1B231E4566AC8ULL,
		0x33BE251D99B4AAA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2CEC16667A784BF4ULL,
		0xFED29A8B9429765BULL,
		0x42D5702BE97C15D7ULL,
		0x20F82E1812C947A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD9A8EDB27D2739BULL,
		0xC732E66AA9B751EBULL,
		0x37FFF36A35E554BDULL,
		0x1AB61372FE34A2B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x77960A9BFF931CAEULL,
		0xF9D5C86174470A4FULL,
		0x0518FD8E37D282F6ULL,
		0x6A06487AA394C124ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x77960A9BFF931CAEULL,
		0xF9D5C86174470A4FULL,
		0x0518FD8E37D282F6ULL,
		0x6A06487AA394C124ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDBAA68D3A303EB32ULL,
		0xA5B64D67008B956CULL,
		0x6E055A37252C3F0DULL,
		0x54C1D9E4EAE43EADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD70CC51E6984569CULL,
		0x18B8D577BABE4943ULL,
		0x3251FC45DFA53D1FULL,
		0x4075FB58CFC9F2B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5BBE0FBAF16C4BF3ULL,
		0x6AF383A77EF6E323ULL,
		0x8C0F1D90F035CB9FULL,
		0x2B76816DC27ECD30ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78930146C8FA6153ULL,
		0x479F9FB3D7BBFC0DULL,
		0xDD45FE88DD7ABEA6ULL,
		0x1A1FA3B3BF037D2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2A4CF3B056785489ULL,
		0x3126EE39EAC8F61AULL,
		0x300535029CA9CD84ULL,
		0x7755680186BF357EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB59A9594080ECA09ULL,
		0x28829888668EF222ULL,
		0xDB447DF4752AE954ULL,
		0x587AA2A28B507886ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1C9336E71DD40384ULL,
		0x8E2087F27DB6D400ULL,
		0x39211B3674ED8F41ULL,
		0x5C9CCBFD97FDFF34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C9336E71DD40384ULL,
		0x8E2087F27DB6D400ULL,
		0x39211B3674ED8F41ULL,
		0x5C9CCBFD97FDFF34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8CE171359E92C18FULL,
		0x81CB2671E5E40D34ULL,
		0xA4FA287235FBF9E0ULL,
		0x7B2763B20810191AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FF665020CFBC79BULL,
		0x23EC625E6E679F2BULL,
		0xEC4C64D00F6ED910ULL,
		0x263C6A511CF8FE48ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE964CDDA9BE16047ULL,
		0xF8AD16438CA92D3DULL,
		0x6A1FE3EAAC358D33ULL,
		0x5427B4711EA36F34ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A7FD26BB5D70205ULL,
		0x78ED22D2F5EBDA38ULL,
		0xFE688630609498EDULL,
		0x5C53E5FDA9640D03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE6D451E84562D6A9ULL,
		0x07325BE50DA84DFEULL,
		0x637A126BD3A1124AULL,
		0x18FF1A5E8FEBCECBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x348D1E02ABE319A5ULL,
		0x9A31CB0C59C2FC2AULL,
		0xCFA5C957972CD2BEULL,
		0x0C747E0097AF2252ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7F8066F4B4B8F905ULL,
		0x0582045524124EC2ULL,
		0xD85B5CD16FA6EC31ULL,
		0x0CF97D5C1E130C4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F8066F4B4B8F905ULL,
		0x0582045524124EC2ULL,
		0xD85B5CD16FA6EC31ULL,
		0x0CF97D5C1E130C4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCBE88909BF2ABD01ULL,
		0x5EB0DE98E18DC08EULL,
		0xE4891C308A5B25DAULL,
		0x32FE357CA3B149A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4860B9A4CAE9340FULL,
		0x40626839BF8A3899ULL,
		0x0D47F04A885C1BECULL,
		0x4954786497ECDCBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE3F7E037F7EDF074ULL,
		0x59D10186DE5232B1ULL,
		0x091F227023DD075FULL,
		0x12D25E3E4EC80DD4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10CFCB9CD078F6CDULL,
		0xD26502CDE612DF92ULL,
		0x561E585F5B81CDE5ULL,
		0x4B07FFB64731D726ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x27BBEF52E5FAA309ULL,
		0x71F300CDF7E8D873ULL,
		0x5FF9605CE3B07BA2ULL,
		0x727ED75C58755711ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E0B4E7DC04C7609ULL,
		0xAD15150CEDE46E53ULL,
		0xA52342A1750A0415ULL,
		0x6DC4E09BEDFCEA64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x57D5039F606D29BBULL,
		0x6654E8190140A3D9ULL,
		0x2A84F2ABCBC31402ULL,
		0x4C3746B5065E3570ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57D5039F606D29BBULL,
		0x6654E8190140A3D9ULL,
		0x2A84F2ABCBC31402ULL,
		0x4C3746B5065E3570ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5D2986240F6BE3B2ULL,
		0x68FD3BB3DBAB5E99ULL,
		0x23D4AE7159754367ULL,
		0x7188296975DA23B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1234C26E9B60474ULL,
		0x89F06EE2AC7C8E3DULL,
		0xA0E7EC0388B2FB07ULL,
		0x386F9BEFC8AC5A33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7EAED0BC914A6AC3ULL,
		0xBAA3C612A6079517ULL,
		0xA63F6CA1BD3ED058ULL,
		0x3283AF1AD29DE785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD827BA6C61278C75ULL,
		0xA3CE1301869E67C8ULL,
		0xBE3D5CB599C031ABULL,
		0x1C333C103A49574EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x635DB2BDFA023573ULL,
		0x24CC67C0FFDA9498ULL,
		0x5C994E7F863E989BULL,
		0x09810FF6CB9E9B44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB053562C2B02FCDULL,
		0xAB5147BE00C81C75ULL,
		0x3F1CEFFF2CC7347FULL,
		0x038D50BABF0ED4FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE3755815CD1E59D1ULL,
		0x0618B44177F7A25EULL,
		0xBFC7F0C7A141ED8AULL,
		0x1E7A17C96ABD7D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3755815CD1E59D1ULL,
		0x0618B44177F7A25EULL,
		0xBFC7F0C7A141ED8AULL,
		0x1E7A17C96ABD7D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7F679AE42F0B53BBULL,
		0xD01A36B35B41363AULL,
		0xFB7D7ACDECE40DFFULL,
		0x65FE79E4E0D96785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58B6E62980CADB26ULL,
		0x1EC135EA2BA54F16ULL,
		0x5F5DEB628C91323CULL,
		0x6B602E5A7FF4E64DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6A67E69E52A2571EULL,
		0xBA430E22210CA9DBULL,
		0xFE69DA97FA5F3853ULL,
		0x6CA6B1A6542167F0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AD9843986BEA080ULL,
		0x84605558ED9EE608ULL,
		0x439543F2A9BF7FDBULL,
		0x470235A2DBE36538ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x618E0637C2182CEEULL,
		0x2B8B0F04FF132577ULL,
		0x458DAC1F62EFA236ULL,
		0x78F4E87BCB158D08ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E42EA3FC53C84EDULL,
		0xF736FA1C9E0FE6E5ULL,
		0x0218F06CBF02CFBDULL,
		0x7F34B9ADDE0545D8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC0D2FC17E5F45850ULL,
		0x19A3B962EFDD5AD7ULL,
		0xA224F47F05A7B448ULL,
		0x70D6E7408FFD4E5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0D2FC17E5F45850ULL,
		0x19A3B962EFDD5AD7ULL,
		0xA224F47F05A7B448ULL,
		0x70D6E7408FFD4E5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD1FE82DFF49C18C3ULL,
		0xB6B2F80E2EF11442ULL,
		0xF34E33FB17630CC1ULL,
		0x13A3BC7E4CBAA29AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB77F433D0106EABULL,
		0x190D52B4062AB464ULL,
		0xFBA5D38792DB709FULL,
		0x35E928BF57135527ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0AC008654F6D8C2BULL,
		0x6AFFBC612E596DECULL,
		0x775E7631522F07BAULL,
		0x79BC179C36300B11ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2157BECA88E2655ULL,
		0x3A578E987A9EDEACULL,
		0xD03B7CB634E79DDBULL,
		0x4C286252F35B87ABULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x72B701E989764902ULL,
		0x9440FD7F76B98775ULL,
		0x56D26CFAC2F1A741ULL,
		0x64D564C1F437D8FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E7AECA51559726EULL,
		0x23CD1236978966E3ULL,
		0x72620045388CAD1AULL,
		0x46EAE10C43F06AA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x84FEE53D85C1F905ULL,
		0x58088B644220BAEFULL,
		0x2E428EAC13C0A358ULL,
		0x40CBC231BD15AF1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84FEE53D85C1F905ULL,
		0x58088B644220BAEFULL,
		0x2E428EAC13C0A358ULL,
		0x40CBC231BD15AF1EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x853D18890DF0B30AULL,
		0x70B5D1B85207F265ULL,
		0x0587E416EF12565AULL,
		0x17833AB0A6369943ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26B9F9FE8CFC021DULL,
		0x0CC2061AA3F1E05EULL,
		0x3C61823792962791ULL,
		0x5A99AC699821A91EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0F44A1138574290EULL,
		0xDF7C1E3FC645A1B7ULL,
		0x84DBEA2E21B7C20AULL,
		0x0E3BFCB933D799FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58E99A79F70D62E7ULL,
		0x4DDF9FC5A4062A3DULL,
		0xFE86F352063A7CF9ULL,
		0x63A7291ADC7B6C5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEEEDA9C8706D7C9BULL,
		0x2F342239E51BB937ULL,
		0xE9316B37F6485487ULL,
		0x4D00C6C29C29583BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD418AA40E8FE0B6CULL,
		0x5DE864ED645B759FULL,
		0x62924A75E65B9B53ULL,
		0x43A3A1620F51E83AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x573A6A116CB4F250ULL,
		0x8AAEBB4599C12F31ULL,
		0x83915BFDD734D091ULL,
		0x52DC05E7F659DE1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573A6A116CB4F250ULL,
		0x8AAEBB4599C12F31ULL,
		0x83915BFDD734D091ULL,
		0x52DC05E7F659DE1CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x946839504D2F3787ULL,
		0x1B687CEC26079677ULL,
		0x996FCD9D6BF85E0BULL,
		0x353E795EF24D73A2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x957067D29E81FFA0ULL,
		0xCC7B50F30886D1C2ULL,
		0xFCE0FFB7EE711807ULL,
		0x2213A9808C6DFD5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5BD3857293E7E108ULL,
		0xBF6F2F7691F15022ULL,
		0xC97EB750FDAB43EFULL,
		0x534A10D4B89B7D00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x704ACD32BF5EAB57ULL,
		0x56F8366E328DE1E7ULL,
		0x9C692D741D223F66ULL,
		0x57BE8787402C42CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF99CF4D53316493FULL,
		0xE8484CCACDFF97A8ULL,
		0x3EB8CBF7FA8F8D95ULL,
		0x2BA4FA05F71F123DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF41C1842346F1579ULL,
		0x3CC9D3ABC0948CB3ULL,
		0x6618309AF3801A49ULL,
		0x6500FA9BB2AA1589ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x69A2CE911088BB09ULL,
		0x1ECE7C9EB4041EA1ULL,
		0x1A1CD0D67FDBBC6FULL,
		0x444C260F88AA3040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69A2CE911088BB09ULL,
		0x1ECE7C9EB4041EA1ULL,
		0x1A1CD0D67FDBBC6FULL,
		0x444C260F88AA3040ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x800BE58461298BE3ULL,
		0x43080DF3211A21C6ULL,
		0xBAFBADC1F6184E9CULL,
		0x0AD18D22E3AC6780ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6221596FAD32AACULL,
		0xD2D9A8175155E17FULL,
		0xEA5407293C75BA63ULL,
		0x74089EA239FBC5DCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1A1CD2B0DD710B9FULL,
		0x069CDD80F5BCE064ULL,
		0x9110101C94F194CEULL,
		0x39C4D0EFEA8A240DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F75F18A87FFCB46ULL,
		0x7013B3F35467AFABULL,
		0xC13CC01C400163BBULL,
		0x42A43E86765C2412ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4D0BFD553F8B5525ULL,
		0x7EA9B5A019BB3A73ULL,
		0x63F9B1A1711250E6ULL,
		0x541AC7637759F64FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11C3EFC2298CA4E6ULL,
		0xBF571217E7E25D99ULL,
		0x5F6BC654AFBD0DBDULL,
		0x191C3963A3443EB2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8DA80CD2A7A6D31BULL,
		0x740FCDC56B72F577ULL,
		0xA5EE40022C3CFD7AULL,
		0x60D7580C5C636CF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA80CD2A7A6D31BULL,
		0x740FCDC56B72F577ULL,
		0xA5EE40022C3CFD7AULL,
		0x60D7580C5C636CF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCAC757867BF8F966ULL,
		0x9ADE7A6D827D6BD3ULL,
		0x15BFEC244C259D73ULL,
		0x0505626589C67911ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DED90D8222FD695ULL,
		0xA558F7895F4A4997ULL,
		0x874815B1849DB7D1ULL,
		0x2CFDDF7948E46085ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8D7751A7E1948A1FULL,
		0x9575C0B6047ECEF6ULL,
		0x10D8D32A0A9A55B9ULL,
		0x68C0443243B3BD36ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC65821F24107D57ULL,
		0xDB87E7C882D5B721ULL,
		0x9E05AE38859E1F6FULL,
		0x659E70A56DB6D924ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x615D5BC9152F7292ULL,
		0x4DB583679102537CULL,
		0x949637D2FDE80EE2ULL,
		0x0F99774E33B7FC54ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A479D391089B76AULL,
		0x66F73F9E18CB3221ULL,
		0xA8BE1364E43F873BULL,
		0x2CCABC293B352E5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB0BE2698A9488C77ULL,
		0xC4A8D6C6C3DC0765ULL,
		0x534C73042F4ABEF0ULL,
		0x40A41E8A7751C0CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0BE2698A9488C77ULL,
		0xC4A8D6C6C3DC0765ULL,
		0x534C73042F4ABEF0ULL,
		0x40A41E8A7751C0CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4050C5D339CEBB7DULL,
		0x5BA43C7A58BF7AD8ULL,
		0xFFF7889B089BDE95ULL,
		0x39BC178CA08EFD46ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60B90E674225439DULL,
		0xD642E9765CF7E5DCULL,
		0xF223E0B6C1AC1F81ULL,
		0x2D22CCC63B42E2DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD4A845D963418B19ULL,
		0xB02658278E8CFF11ULL,
		0xE5EA308307C4F733ULL,
		0x3F02ACF175A62BA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE4DCC5F372C8ABULL,
		0xC9D4A48733796ACEULL,
		0x113734A5E604DFC5ULL,
		0x27798EC06306E671ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC47535370DEC524FULL,
		0x35BB24162E783A4EULL,
		0x77C97774602D58C6ULL,
		0x12A98B2E743477F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3356F0A21C62BA9ULL,
		0x420CC85AB34A367EULL,
		0x9E2209CEE2ADAD1AULL,
		0x182B97B46973235CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4A7CAF60E8E746D3ULL,
		0xE13BC178DA8F2EB7ULL,
		0x9D86EB1EBA168084ULL,
		0x4DFB9936DF148533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A7CAF60E8E746D3ULL,
		0xE13BC178DA8F2EB7ULL,
		0x9D86EB1EBA168084ULL,
		0x4DFB9936DF148533ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4327E0C4AD14CF76ULL,
		0x6961813D5075FF08ULL,
		0x480127993F304088ULL,
		0x54EA4DB46EFFF1DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11855DF36B97D28FULL,
		0xA6AA94FA90F852E6ULL,
		0xD8FD18CD9FEDE3A2ULL,
		0x2CF83FF079EFF69FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB151173DA8EAD714ULL,
		0x8F4AA30CB21BEA09ULL,
		0x6C7226E25E7A8F33ULL,
		0x1B2D9872289BBF78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA961EDBDBDDC47E7ULL,
		0x50A478B189B0C052ULL,
		0x0977FE610537056BULL,
		0x05A70A75836CC571ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x88AA2E0A4DEAD443ULL,
		0xDB965A6A26AED774ULL,
		0x2D1D36B2C8493986ULL,
		0x39D6B7C895DE40E6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3DBF0B742B33F10ULL,
		0xD31BFA4E92123181ULL,
		0xE2A739E489F4BEC0ULL,
		0x7E28F3511FFF2CEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA60C9518A3A0F13AULL,
		0xE6BF935E6EE0043FULL,
		0x85254350F5324656ULL,
		0x342609B6EE28486CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA60C9518A3A0F13AULL,
		0xE6BF935E6EE0043FULL,
		0x85254350F5324656ULL,
		0x342609B6EE28486CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6BEC48AC119AFDACULL,
		0xF5C05D1D4038E958ULL,
		0xA19C02C9BCC6A9B4ULL,
		0x0D2F27BB97B5476BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EAD8AB9DA4531ECULL,
		0x776F3FA9D2B29DAAULL,
		0x35AD67B697629C86ULL,
		0x074DFF0CA6338F35ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1937F7E3F9A4E503ULL,
		0x38F51DD2E24BA5AEULL,
		0xFAC4A9C2B4F4ED28ULL,
		0x1A8688CAE42CF88FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9C65DBA02A35856ULL,
		0xB2FCAF356D374D0BULL,
		0x3BE0ED1EC7142680ULL,
		0x73A8D6AD853031B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9781E87B7C125EF1ULL,
		0x680B047BFDDFB50CULL,
		0xCE729419D7651071ULL,
		0x2FE8A4D0455D9A01ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1AF19911DC829897ULL,
		0x8332513C082E78E9ULL,
		0xA51BA1F9A94A343DULL,
		0x7807B58A1770D896ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5672771E5B986860ULL,
		0xD0A3443DC0C8B8B6ULL,
		0x010A7293727D924DULL,
		0x58852B216A257C5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5672771E5B986860ULL,
		0xD0A3443DC0C8B8B6ULL,
		0x010A7293727D924DULL,
		0x58852B216A257C5AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6262211A95BDAE9DULL,
		0xF15F5128B009BD1DULL,
		0x4B34C4E0429BB82FULL,
		0x4FD6E57397BFDDF1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2AE0BAC7636F008ULL,
		0x4F922AC84417F19DULL,
		0xC55709E1390540F4ULL,
		0x1E4735D5FEF61459ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF03310AC0C7AF7F3ULL,
		0x92156635E8D2A696ULL,
		0xB7086CD061C7D4ACULL,
		0x2FFEE6DFE11CD9FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF24FAA001D25049ULL,
		0x08E86A2B912FEE6EULL,
		0xDF33E50835047BEAULL,
		0x5C06604BA5F587B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x68E0994B351FAA93ULL,
		0x1E3F6A4D664ADE84ULL,
		0x454119A298439065ULL,
		0x1335240BA3DD1785ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B74E991A6D31ACULL,
		0xE9C1FF1E0EF1317CULL,
		0xEA36C6F55DA5A33BULL,
		0x4AAF8D3D4FAAE2E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8809EBF09600558EULL,
		0x943E1DF45BB1ED39ULL,
		0x0C1AA087185D1231ULL,
		0x69A5B53CBA1C92B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8809EBF09600558EULL,
		0x943E1DF45BB1ED39ULL,
		0x0C1AA087185D1231ULL,
		0x69A5B53CBA1C92B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF50B227794701F91ULL,
		0x3B72ED8A36A4366EULL,
		0xF9DB5F93506883F6ULL,
		0x26358C68ECBC8399ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB91053CA86EE85BAULL,
		0x6E2B2AFE681E6AEAULL,
		0xE013FB4819254C8CULL,
		0x0DBEADB0AF4DE9BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFB835330DAF5D7ABULL,
		0x8565B5964B808D64ULL,
		0xD8304F2615F8A6AEULL,
		0x2FE9DB8B9F4393F9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FCC4810734E13A8ULL,
		0x9C5CC3D945D76403ULL,
		0xDF1E77F632AF24E8ULL,
		0x38D6F8E09D819566ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3891BDC8FB3E60ACULL,
		0xADA0700AA7B707EBULL,
		0x86E528F09EEC2478ULL,
		0x27CB3F601AB3DFACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E96D418D5159B57ULL,
		0xFE63906B084E30D1ULL,
		0x6B3D9385CAD838DFULL,
		0x58C6A56342F1785FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE2C07BD0DB00D3DCULL,
		0x3331E63BDED63EB7ULL,
		0xE8C160BFD9578BCEULL,
		0x70005E9796EE5FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C07BD0DB00D3DCULL,
		0x3331E63BDED63EB7ULL,
		0xE8C160BFD9578BCEULL,
		0x70005E9796EE5FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 201\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2D8B943C4338FCEBULL,
		0xFBF6C955F005F1F2ULL,
		0xAE93F375BD71BA46ULL,
		0x6C5EFE7123B1E913ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04E6F124D4800668ULL,
		0xD118EB0BB44C75E8ULL,
		0xE59F59D549684247ULL,
		0x541F1C9CC61393A0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 202\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x447A36EA0FE8086FULL,
		0x5E0C68F106FC6DDAULL,
		0xB1B0282FFD0BA9B8ULL,
		0x193306A7E390157BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x785A9A990271E0B7ULL,
		0x6B452B8B2C96229FULL,
		0x31C1CF53D3929351ULL,
		0x3E47FBF15907E96BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 203\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x33BD0CEE2E7469A5ULL,
		0xAAA4ACC1B4BEB090ULL,
		0x8F8ECA1E7C5C4582ULL,
		0x73F3C371F53F89ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1DE22021A8C9BC5ULL,
		0xB8B512B174D7DBBFULL,
		0x7CD3979682BE676AULL,
		0x404D6401DBEACD49ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9C01FF1C7BA465B2ULL,
		0xEA652EE815B0345BULL,
		0xFCD73E317F120211ULL,
		0x6567EBBC3564973DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C01FF1C7BA465B2ULL,
		0xEA652EE815B0345BULL,
		0xFCD73E317F120211ULL,
		0x6567EBBC3564973DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 205\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x09EC065BBD1AAD41ULL,
		0x362290A1C2B36352ULL,
		0xEC0BEEB431526043ULL,
		0x1AACE94856F1999EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37D3CA3C87E3A5D5ULL,
		0xAE58C75A354EBDE9ULL,
		0x31067E0A57F325A1ULL,
		0x329F7308CD059688ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x51D6E00E0F197E93ULL,
		0xEA011B575BA2D499ULL,
		0xC1A0E630C7B4CA9CULL,
		0x162F495AE3BA76C8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2E9C85902C00A11ULL,
		0x14AB6EEA1DC1C261ULL,
		0x4FBCC2552B87554BULL,
		0x03FC935870350114ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 207\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA8A1D353933D86E9ULL,
		0xC85D2E04DE76BFCEULL,
		0x2FF7C4583F03DD85ULL,
		0x45E6900E3D7E7F2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18D2DF83F8C95779ULL,
		0xAF91E1CFB552EEA5ULL,
		0x807B51C36F60FD13ULL,
		0x2FD82FD56767A914ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x488FC2A968D95BF6ULL,
		0x631148BD06E5F166ULL,
		0xA5A4E965AA9A4B01ULL,
		0x06D96152BD48C6C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x488FC2A968D95BF6ULL,
		0x631148BD06E5F166ULL,
		0xA5A4E965AA9A4B01ULL,
		0x06D96152BD48C6C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 209\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x56CFC19C500B6E98ULL,
		0x7CE6D2A67D8F3476ULL,
		0x08DE2532BAA68E9DULL,
		0x7CB71A9897CC8EFBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF23F71166543E47BULL,
		0xA6A0DE749C7D6231ULL,
		0x5911E92EA5C8F7B1ULL,
		0x165D3AF1C4B6B577ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x160FE66CD4B6809FULL,
		0x298FED9829AFBA91ULL,
		0x5BF316156D7DDC82ULL,
		0x2BEA4DFEF9061354ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98AFC80AA81EA31AULL,
		0xF0E857D59AEEFAECULL,
		0x293685C92D9D4652ULL,
		0x3B18DC4389E22FAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEB15534804F03282ULL,
		0x1DA52C60E7BC6C49ULL,
		0x1920ABE221C06091ULL,
		0x725E9C2E10D535D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3511116B8696368FULL,
		0x6A10FE40FC461B6BULL,
		0xA38B49BA55A5E2C6ULL,
		0x207A1ADFCC9F8994ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 212\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE10EEB36B17199C3ULL,
		0xE58E6453C1870600ULL,
		0x527F39F1EB4EF7A7ULL,
		0x5B75903F64D71162ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE10EEB36B17199C3ULL,
		0xE58E6453C1870600ULL,
		0x527F39F1EB4EF7A7ULL,
		0x5B75903F64D71162ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 213\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5235A8CEF9E2ECEEULL,
		0xD312CEEB29F39B7AULL,
		0x7A86E379B1159185ULL,
		0x74072FED5A9AD242ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04C1FCA06A32D541ULL,
		0x9A697D86D0927DC4ULL,
		0x1F43689083F37EE1ULL,
		0x5CB3AC3D1862873CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 214\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC0BBE383905F7FA9ULL,
		0xC0F1634FD36FA745ULL,
		0xAA4C78C9C1638BACULL,
		0x73A4334CAD6976DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2355BE85DF47D84ULL,
		0x8D9241C40B58508DULL,
		0xD62C0F783CB4C50AULL,
		0x574DC9ACA32351E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x39C348DDDAEBE1DEULL,
		0x329C11B0A1666495ULL,
		0x78B2EB1D723B253AULL,
		0x10A7214AA5C8BF82ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D2E4DE1271A791ULL,
		0x6D2CBB30210FC18FULL,
		0x2E87B66F4B007F68ULL,
		0x099045B56DFF586EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 216\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3B21E87CEA9178D2ULL,
		0xA3FDEB7591C87E36ULL,
		0x96C918566DA6BD17ULL,
		0x2534CB45C6DD3E07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B21E87CEA9178D2ULL,
		0xA3FDEB7591C87E36ULL,
		0x96C918566DA6BD17ULL,
		0x2534CB45C6DD3E07ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 217\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x22A2C836A1966ECEULL,
		0xA66BD0A4B83A8512ULL,
		0x63B1273EA27BD358ULL,
		0x38445EA45D96BE8CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51480E7B204AAFA5ULL,
		0xEF5E6CFCD407BF11ULL,
		0x20334AABB54D7EF3ULL,
		0x35B4BC32609870DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 218\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x68FE9712F81072E9ULL,
		0x9688DED060FFA4A8ULL,
		0x70D840362380A5D9ULL,
		0x3DEA2D421AB9D865ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x329CAF60073840C1ULL,
		0x3B8372E8D9FEC0E3ULL,
		0x574FB16F6D8CAF1AULL,
		0x707D7A3383F40BC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4D5408DDFD924D84ULL,
		0x18D2ED5BAA19B052ULL,
		0xA600E016E32071D3ULL,
		0x450CD686C4DFEF5FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x586BE5711C240F6DULL,
		0x94316679A3661885ULL,
		0xD45FDA28559761CFULL,
		0x71A812FBEEF71DA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 220\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE2C642EEC67B89EBULL,
		0xD76C500F1E5AE9FDULL,
		0xF2547B8B0790CBD1ULL,
		0x4FB000AB1564A997ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2C642EEC67B89EBULL,
		0xD76C500F1E5AE9FDULL,
		0xF2547B8B0790CBD1ULL,
		0x4FB000AB1564A997ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 221\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3335530D2194FD66ULL,
		0xC79FD81FC73691FDULL,
		0x32048EF430FAADF9ULL,
		0x445F84A901FFF4FDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x964137A14AAF36D9ULL,
		0x1AF20DD52E58DD18ULL,
		0x4A5F823E7A66B213ULL,
		0x32145A9DF7D7A498ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 222\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD267E8BC8A960CB7ULL,
		0xED06AC7629143393ULL,
		0xDF1FC96D4932CA59ULL,
		0x7D4DDFA3A76B9195ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x041869A81B8E7CF3ULL,
		0x2C8BCC6F6A2BBE64ULL,
		0xCDDE1F28B8C22D50ULL,
		0x20F308F6A8461A7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF0FAD58FF4953B46ULL,
		0x43DCCCCDE15CA592ULL,
		0x7701BEF451FEA595ULL,
		0x5D6335508B67FBA9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC293C7EFC8AF1624ULL,
		0xB0F2A6574B4A5335ULL,
		0x5A3DE21325131F22ULL,
		0x6C3B9E5E56FF2747ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 224\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x62563AEC775FD58AULL,
		0xEBC4659DE5868184ULL,
		0x480DD66FCC38A39FULL,
		0x2F99A1C7E3E578F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x62563AEC775FD58AULL,
		0xEBC4659DE5868184ULL,
		0x480DD66FCC38A39FULL,
		0x2F99A1C7E3E578F1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 225\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD736DA9CBB1391FDULL,
		0xAD4E5D1671609B32ULL,
		0x1414DF8C8544FEEAULL,
		0x23545CA5F7A210B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD787E21891EE016ULL,
		0x43CC8CB95122A6BDULL,
		0xC1B80E41FE15D0B4ULL,
		0x50FCEC4CFDDBDE75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 226\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2E801EF518C3BC31ULL,
		0x83CC80363ED5DFBAULL,
		0x80E04FFE9C44874AULL,
		0x04ED2A4A6DC996C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00CA4D74A3CCE93EULL,
		0xF28CCA51D60FF241ULL,
		0xB6F6CA548253D74EULL,
		0x5696E7D32453E3C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7D7A913970A34CA1ULL,
		0x79A1C054AF53D9A0ULL,
		0x721A4403AD3FD553ULL,
		0x340158AEC02774EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A81A847CC59410AULL,
		0x16E2665E6F41154DULL,
		0x3B70D206A2C89527ULL,
		0x1176AE365C9753A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x934CB91C59EB1B73ULL,
		0xE6AA5A8925405E05ULL,
		0xC5CDBC34C74B27D0ULL,
		0x3FE7599B516B8C55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x934CB91C59EB1B73ULL,
		0xE6AA5A8925405E05ULL,
		0xC5CDBC34C74B27D0ULL,
		0x3FE7599B516B8C55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 229\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE6A1C31A0CE17DE8ULL,
		0x07BC93C1DDC9CE73ULL,
		0xCEE6ABFE3BD57F21ULL,
		0x05077909BC2D5DE9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C8A3F71823E63D2ULL,
		0x647D15B9EF813FC6ULL,
		0x867C09E7C763E741ULL,
		0x2472E5904793F57CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 230\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x32716339F986F4FEULL,
		0xA8BB6F133103F8EDULL,
		0xE6C86FA61911970DULL,
		0x105648D63D950522ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65629B4907F69ED1ULL,
		0xDE709639E41CF108ULL,
		0xF0025861C1FCCA1DULL,
		0x4BDD1323D8A3B5EEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB7AF95D2918E00ACULL,
		0x45FBAEB5C13C8E19ULL,
		0x19F291D3F262CC23ULL,
		0x3B5217CEA7D1876AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x007619FF50603A1EULL,
		0xAFB5AAFA360F3535ULL,
		0xE6611421D77902DFULL,
		0x41C5DAA8DF897B00ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0CA9DCE471543E29ULL,
		0xE51207184C37B1EAULL,
		0xFAA1718FA417EED1ULL,
		0x7E7CCC1919BE270CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CA9DCE471543E29ULL,
		0xE51207184C37B1EAULL,
		0xFAA1718FA417EED1ULL,
		0x7E7CCC1919BE270CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 233\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x08D09A9034E417E8ULL,
		0x52EE958046CC2F8EULL,
		0xB4CB8BFBE6844620ULL,
		0x244C6556AF97EE1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98EB34003F2D01E0ULL,
		0x8ADE194636E12F7CULL,
		0x7096EB5D43E4EEB9ULL,
		0x441A160F88EA0A6AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 234\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x43B0C5BA9C5BF550ULL,
		0x0F747986D855FEE5ULL,
		0x5A1C6ED14C7BA595ULL,
		0x2BB2A7A512693AA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB622717CE9D8B6AULL,
		0x29C57CAD4E779A9AULL,
		0x7AB93C4ABEF4E297ULL,
		0x64B1E7A0C8E4EDA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF52E814F2FA287D6ULL,
		0x9BA23EB21A7B01CCULL,
		0x52245385718BC1FEULL,
		0x7C86BA5B14161659ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3AFA58A1D4E1D5FULL,
		0xEF57497D25394904ULL,
		0x3B20AA9F2AC40900ULL,
		0x211CA17C0417B886ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 236\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD1D5AD0CEDF49AA3ULL,
		0x65B002172ADD2FFDULL,
		0x0B228A5B49A8CA62ULL,
		0x7E99A514450C41E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1D5AD0CEDF49AA3ULL,
		0x65B002172ADD2FFDULL,
		0x0B228A5B49A8CA62ULL,
		0x7E99A514450C41E8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 237\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3A9D100A57B9FB59ULL,
		0xDE751463D29F3A83ULL,
		0x774D72421A274E64ULL,
		0x1692E26D940C3D41ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4CED631C095FE33ULL,
		0x9322A413C10471AEULL,
		0xCFE3AA9C00072E5BULL,
		0x78C4C7B58F9302ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 238\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB7705CEE0DFB825DULL,
		0x063D76823D260A61ULL,
		0xE53D1E5BF8CBDE46ULL,
		0x2D9BC1455DBBAEEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20590E8299B5543BULL,
		0x30B62CB0632C7DD3ULL,
		0x178C11B7423D739AULL,
		0x1417D3C5C0D4A739ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x82DF64D433638E94ULL,
		0x290F470DD46823ADULL,
		0x8C5A20FF9A8A0AB4ULL,
		0x2B7312EA3BC330CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE80B535F75F36B1FULL,
		0xCC7B6B42810449C3ULL,
		0xA4044F442B6BEB22ULL,
		0x7C6976E9B1B184ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 240\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6E91A6AF8A3E1007ULL,
		0x047DCD89504A2185ULL,
		0x3FA71039037E0409ULL,
		0x5A4B585293FAC748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E91A6AF8A3E1007ULL,
		0x047DCD89504A2185ULL,
		0x3FA71039037E0409ULL,
		0x5A4B585293FAC748ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 241\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1DB13783727695A1ULL,
		0xAD655964735978D0ULL,
		0xDE6B43A8576D7C14ULL,
		0x1BA4F1A0E6D86F3FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9A27587769D3A4ULL,
		0xDD155BC34B705E16ULL,
		0x84A74DE8B4012EB6ULL,
		0x0779741E3EEE4B24ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x099090B15B21BF1BULL,
		0xCDE968DB4E0CE2DCULL,
		0x4C0D43D56B599B67ULL,
		0x50BC392FFA405CDCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09E6F9FE53AC2DCCULL,
		0x370D727B6BBB1CB9ULL,
		0x356B6B169460814FULL,
		0x27B631B0F74F3530ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3190902CE2088997ULL,
		0x7D39516D5CCE8573ULL,
		0x3607EECEEF416062ULL,
		0x734104698C8AB3A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA237FA7DEA4E9E93ULL,
		0x7E8FD21DEF21D5F8ULL,
		0x6D184B52B9FF16E7ULL,
		0x65887A71BDC016ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xABEE546140A9D5EDULL,
		0xFD920D49EBE6C415ULL,
		0x7296560E15B65BD0ULL,
		0x4DB4F365125B866DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABEE546140A9D5EDULL,
		0xFD920D49EBE6C415ULL,
		0x7296560E15B65BD0ULL,
		0x4DB4F365125B866DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 245\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x13490F259A0D041FULL,
		0x447A3429CCB0D7D3ULL,
		0x5BA553654E4BD487ULL,
		0x3420F0A330C5C49BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B153A9323D479FEULL,
		0xE449D054D6A5E953ULL,
		0xAF03F9BA7973D6AAULL,
		0x2C443C15379D59AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 246\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x14D3EC76845F8CE6ULL,
		0xFFD8D972C92AA713ULL,
		0x75FF43670416BF6CULL,
		0x03632BC62E466B4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB60864C235F6BC37ULL,
		0xA92BBEE50F3D81E8ULL,
		0x439AAE6E81BEC746ULL,
		0x7B08BB17EAAE3E26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 247\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0E89366ED96CA54DULL,
		0x0E7D927F1B562E1CULL,
		0x9B994D0A7D1A6A3BULL,
		0x544A6A7020491865ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x022FFD92AEDB9106ULL,
		0x8291579CB4572065ULL,
		0x551307895A0865BEULL,
		0x1885B1ABD19B96E5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 248\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC69131C63C2240AEULL,
		0x052BC61B27787F30ULL,
		0x22C0D71A9D074CF2ULL,
		0x6D2FE4F1D0A884C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC69131C63C2240AEULL,
		0x052BC61B27787F30ULL,
		0x22C0D71A9D074CF2ULL,
		0x6D2FE4F1D0A884C5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 249\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF270D2B79567AF8AULL,
		0x9F9EC82BD2A24519ULL,
		0xC86F46836DE8EA03ULL,
		0x7DB9133B5E51A805ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE919A7B802D998EAULL,
		0x3D87DEB73089E56FULL,
		0x74A8FB4253AFBB48ULL,
		0x1CE869E2FAC2341AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6A373514DD0EB3EEULL,
		0xD2976AE606D45D4AULL,
		0x5E95502FD2B30AFEULL,
		0x5F4B88A0008F9581ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D6DE02AD9C6D9BEULL,
		0xEF772827DA6B0AE4ULL,
		0x2ECB2A28B18C51B6ULL,
		0x577223BE0FBAC4FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x53FD03970687FA66ULL,
		0x78E151984C729AF3ULL,
		0xB4F75EF6CE9E807BULL,
		0x6786F2FACA1BE5F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FC07D8B80F08E1EULL,
		0x9F8DD25CAE547B8DULL,
		0x172F2086AC320F39ULL,
		0x56B18F2EBDC84458ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 252\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9E58C2E5E4CC51B9ULL,
		0x265C24C642B83203ULL,
		0xA72B9009CE62D2ACULL,
		0x3AA0A03DFF59B683ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E58C2E5E4CC51B9ULL,
		0x265C24C642B83203ULL,
		0xA72B9009CE62D2ACULL,
		0x3AA0A03DFF59B683ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 253\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4FBE28AC5448A1D0ULL,
		0xCED2C44B5E231431ULL,
		0xB3EFD5CEE33A9449ULL,
		0x396316485869C08FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB52B0E9B70D6027AULL,
		0xFDCA05D15D85C34EULL,
		0x96916CF9A9E497D4ULL,
		0x1230A28F982D68E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 254\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x823E4A61D1C32D7DULL,
		0x43A7907A43783266ULL,
		0x0F7F9F002F72463EULL,
		0x3AC1A642D894E858ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9989FD3B9C6CD897ULL,
		0xC1945C391B715697ULL,
		0xC339C0914A0900EEULL,
		0x1F7B51F5AA81919EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 255\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6608E1A2D2C7F5E9ULL,
		0x7FC6D623FB82A609ULL,
		0x2395025AEE43079CULL,
		0x0FF63AB6D65906F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x672F7360B569528EULL,
		0xC557B1A1781A480AULL,
		0xB0BF5E74795A1053ULL,
		0x10B8E43E97B7386FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 256\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEC724D11C82492C2ULL,
		0x3E2AF77DC1D35E21ULL,
		0x2757F3F55F0E44D7ULL,
		0x58CC581B37358A53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC724D11C82492C2ULL,
		0x3E2AF77DC1D35E21ULL,
		0x2757F3F55F0E44D7ULL,
		0x58CC581B37358A53ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 257\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x09F7D1154A308E5FULL,
		0xDBFEBD252313C4E9ULL,
		0xE7578179CCE68171ULL,
		0x6503D6FC06DF87C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EF0C1731C00E46CULL,
		0xE6232EBD8A8D7157ULL,
		0xD3D4825B83050D6FULL,
		0x212CF9D0F0379EECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 258\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF3DBFD41D21FDC1EULL,
		0x6EC3ACDCB5959748ULL,
		0xB60C10EF07FFE51AULL,
		0x20A0FDE4D5E81BD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04816602C2CC8BFAULL,
		0xDC15B56905DB72DAULL,
		0x3987B3CED0B905A2ULL,
		0x56E3F81CEEFFDFD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2EF6AD31C8E979CCULL,
		0x5414865953D15437ULL,
		0x6E6CAEF39BDC9FE5ULL,
		0x465EE2B114EEAFF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45954373159E9D4DULL,
		0x753B240AAAB390EDULL,
		0x67D377A06EFD80AFULL,
		0x6C461CEF135F40BBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 260\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEC231114ACC3D070ULL,
		0x7B800C264E1FB024ULL,
		0x33FAEE666F3847D3ULL,
		0x4C6FC372E03583AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC231114ACC3D070ULL,
		0x7B800C264E1FB024ULL,
		0x33FAEE666F3847D3ULL,
		0x4C6FC372E03583AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 261\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4E5B7E70949589C9ULL,
		0xAC52F13F10E152FFULL,
		0x668F09C4AECCC9AAULL,
		0x54D4AC0927D7546DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE12114D55FE6344ULL,
		0xF6A50A1583313801ULL,
		0xB0A500AE0F80085FULL,
		0x2307FD761F10C019ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 262\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCD3E8E6ED2F01EFCULL,
		0xD3372017FC1DCA10ULL,
		0xE6B3AD12C91F7647ULL,
		0x16DD1CBE0D03D851ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB41336B40A79384ULL,
		0xA26AF5BAD0B36907ULL,
		0x4CB3C0BE9B1D2CA2ULL,
		0x1EEB99B2139A451FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFE37354C30C2E749ULL,
		0x312460EBE6B6FDB2ULL,
		0x04FA1A75DD7C9259ULL,
		0x3C52C774724AF947ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x868E0E49A9D073A3ULL,
		0x32C9D8E6E54843B1ULL,
		0x3BF492FDD5265381ULL,
		0x2490355BAB71165AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 264\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7A9BCF3EACF1E293ULL,
		0xDAE242BAE3C7D926ULL,
		0x0E6EAFA4F7E2CC5EULL,
		0x1CC872EE3DF08936ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A9BCF3EACF1E293ULL,
		0xDAE242BAE3C7D926ULL,
		0x0E6EAFA4F7E2CC5EULL,
		0x1CC872EE3DF08936ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 265\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x16B90B7B2F0980FBULL,
		0x5AD9899C2F0289C9ULL,
		0xA356DF28DC71B35EULL,
		0x677CBEEFB6165E94ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF44BAC4E1F410338ULL,
		0x70153D4AA51B50EDULL,
		0x556D506018BC96A9ULL,
		0x57D399C52B338BC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x924B7ECB4AF69C4AULL,
		0x933C7C0DC2C19D65ULL,
		0x22451F73153D8046ULL,
		0x781B0C9F62952178ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F978BD902E18251ULL,
		0x1AAF75B4978882B4ULL,
		0x690B9A6E61397299ULL,
		0x797D5B374382850DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 267\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB50DD4E5F5A43ED3ULL,
		0xFBA6745FACFBF34EULL,
		0xDBC7B9E9843D210FULL,
		0x7F095148B89C365DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22CC80CC530AF2E3ULL,
		0x3D244FD38869B612ULL,
		0xDB54DA7457215433ULL,
		0x3BAF3570DD7E7B04ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6D1D4EA92CECB520ULL,
		0x94D6E0FC321BFEEEULL,
		0x4DA340264DB9C00BULL,
		0x77086A6BF1B9D23DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D1D4EA92CECB520ULL,
		0x94D6E0FC321BFEEEULL,
		0x4DA340264DB9C00BULL,
		0x77086A6BF1B9D23DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 269\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3B9146CC21320694ULL,
		0x4BE8BE0F02344C31ULL,
		0x6913364E2DE6081AULL,
		0x2DD5FD516717F6B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x333C7A6AC3905F26ULL,
		0x97E53F69F050C984ULL,
		0xD60506A7F339895CULL,
		0x6374357FC58C547DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 270\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4BD19094E6D6BBB2ULL,
		0x74D640A6D28F7B96ULL,
		0x5B9BD5BFA3647EDFULL,
		0x40C78F0D282FB2FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x379907CF7F8C9679ULL,
		0x9B807DEBE11E02A6ULL,
		0xA77DD97BB36C804AULL,
		0x04EEEE3809DE1BACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 271\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9131D96F03933B43ULL,
		0x0E1B9ECC4FDDC646ULL,
		0x28CEDA86D0EF9B3BULL,
		0x6514AAEC105354B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x330542048D4805ACULL,
		0x5B19B6092D9A1BBDULL,
		0xDD1DD98BB0EB2CA6ULL,
		0x2EDBE727E45C3661ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8AA9AC62D52258F0ULL,
		0xA50CFD2A4161A42CULL,
		0x9020578C0A764203ULL,
		0x6CFA0758231F3C26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AA9AC62D52258F0ULL,
		0xA50CFD2A4161A42CULL,
		0x9020578C0A764203ULL,
		0x6CFA0758231F3C26ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 273\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6044F14CE422BB8CULL,
		0x5D83525A2E803AA0ULL,
		0xC6EAE367AF3071A2ULL,
		0x688C4349A57F9CE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39B9D4AFF93ED613ULL,
		0x299EBC5846996CEEULL,
		0xFF96AFAB92670BB4ULL,
		0x7FDECA324168E758ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1C3941022B78EED4ULL,
		0x02F186E8D7C6FFEBULL,
		0x8A8BE1F4C0A95AF9ULL,
		0x6157742216D36227ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30EEFD45E170CB34ULL,
		0xA2124B15CD8E92E7ULL,
		0x4849F8F9C951AAEAULL,
		0x64DAC0D240783A85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 275\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD3ADD53CF1977F51ULL,
		0x9A191AB36FCE8D68ULL,
		0xBCD323B87ADEF617ULL,
		0x00A81ECCCA00DD88ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE66756D8FC45623ULL,
		0x9B87E9978C52CB55ULL,
		0xA3CF10AB52DAAFBFULL,
		0x519C300A5CBFC14AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 276\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC3F092DA7226BD36ULL,
		0xBDFDFAC3C4885C86ULL,
		0xFAFAB3117113804DULL,
		0x6D18B972DA94230EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3F092DA7226BD36ULL,
		0xBDFDFAC3C4885C86ULL,
		0xFAFAB3117113804DULL,
		0x6D18B972DA94230EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 277\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2B89018F43C86230ULL,
		0xF085EF549F63965FULL,
		0x8F36AE9AA1ACF420ULL,
		0x04F30891B6038CF3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BC09DA914E3B84CULL,
		0x0B5C5AB0FAACC3C5ULL,
		0x0D9CA64B42452051ULL,
		0x2BA1494FCDD5E908ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 278\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3BB7E1B9B75B2B27ULL,
		0x578036A2F15B0247ULL,
		0x8CA0D58C969F6D8CULL,
		0x5F4AF277AE8C0DBDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E5EEEE4E19F33A4ULL,
		0xCAC077F099AD2136ULL,
		0x1482F59EC7073772ULL,
		0x5CF7DB36DFA8BBD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC373DFCC4A90C562ULL,
		0x15629F7BD4B6B45AULL,
		0x07A0FC373C8F736EULL,
		0x7F41779F2D9B683AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E41DAC3BE646634ULL,
		0x130337C3CB928356ULL,
		0x1623607857267F7DULL,
		0x2DE64EFF38056D67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 280\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE1D8C20749773660ULL,
		0x1203BF7B5AF293E6ULL,
		0x22955D35D7E1D6ADULL,
		0x05783EE9653BB0B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D8C20749773660ULL,
		0x1203BF7B5AF293E6ULL,
		0x22955D35D7E1D6ADULL,
		0x05783EE9653BB0B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 281\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE87E77D4F1CEE088ULL,
		0xD89B6C5E6CB3BBD4ULL,
		0x6A5D3788A6F998BAULL,
		0x03B055BFC36DF9A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F0B741AE5EF8A60ULL,
		0x0F4F822AC9A18F3EULL,
		0xBB242670017FFF4FULL,
		0x0A445A69AB68432EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD026F43BB3214B17ULL,
		0x50D698A154798154ULL,
		0x414A9EC674094F4FULL,
		0x153960430E82474CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB410EAAB04997717ULL,
		0x4132C37F34F74A27ULL,
		0x88DC99F1C9844A85ULL,
		0x588883DE24C14CF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x16671AE605A19C38ULL,
		0x8A55AA0A88B9F383ULL,
		0xBA974CFB2F81069FULL,
		0x19294E983F90EE97ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDF053305D95F5EBULL,
		0xF463A5B820123B3FULL,
		0x4C26EE6DF312B2BDULL,
		0x5895C2B0E50743D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x08336805C6C1A61EULL,
		0xA46DAC3395901F7BULL,
		0x9C4653DF7BE4E16DULL,
		0x6947E46B0034C4CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08336805C6C1A61EULL,
		0xA46DAC3395901F7BULL,
		0x9C4653DF7BE4E16DULL,
		0x6947E46B0034C4CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 285\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFC60CD664CEE47D1ULL,
		0x04225DA8E5038401ULL,
		0xB09D0872E8586C39ULL,
		0x066B53F6B965731CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE823573172476DE0ULL,
		0x0BA0EABE224858ACULL,
		0x4A6C01468E5A1217ULL,
		0x276518B5929883C3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE85D314591FFF41CULL,
		0x9DA7B36B42FD6CDEULL,
		0xB2DE448ADD36BE4DULL,
		0x0CE0AD4970072960ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEDC8448743282D2ULL,
		0x8133396A6767A575ULL,
		0xF364592CFF89290CULL,
		0x5D9B446FE5899307ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 287\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAC0D0C619FBF1CA6ULL,
		0x1594B12BFB146544ULL,
		0x184D35B3F7A8B244ULL,
		0x6C40F73E8209DAB3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25A2BE272BE24094ULL,
		0xE1DCFC68A82231C3ULL,
		0xBD8C139CA20C205EULL,
		0x1212FA007EC72AD3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 288\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFCBCDD5AC25040BDULL,
		0xCAFA8B8E68C61E64ULL,
		0x488A4B3A9B8ABCA8ULL,
		0x49D539CE82DF9503ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCBCDD5AC25040BDULL,
		0xCAFA8B8E68C61E64ULL,
		0x488A4B3A9B8ABCA8ULL,
		0x49D539CE82DF9503ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 289\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9C653E3D386BE247ULL,
		0xE797245ED35B72D3ULL,
		0xE6CED8306210EF5FULL,
		0x5F6C095F445AAE1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3FA40495D418424ULL,
		0x0BAAC9DBDDEFFCE0ULL,
		0x3F73C094C4F78F84ULL,
		0x4DD5D11696612C16ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x104DCF410EAE3D0EULL,
		0xEB12BCBB645927E2ULL,
		0x71F8B30CDA5F967DULL,
		0x15BC1457A2E27BDFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504FDA289DF7C549ULL,
		0x123D4F231EE532E4ULL,
		0xF23E2C3E10619091ULL,
		0x0DE745F201FF3802ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9AB5116F5FBD2128ULL,
		0x5171AEF1994F4346ULL,
		0x5027A017305A737BULL,
		0x0BF5EFBC5AA2DB0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE7E8AFAA27EABC4ULL,
		0x65F04CAED9548859ULL,
		0x42A08965E300F2F1ULL,
		0x2C31712D7F94D0C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 292\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6AB82A2E62912BA8ULL,
		0xDC6E2B7BAA4DDAA7ULL,
		0x18D99E9E2F113359ULL,
		0x1F20C9767937ED85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AB82A2E62912BA8ULL,
		0xDC6E2B7BAA4DDAA7ULL,
		0x18D99E9E2F113359ULL,
		0x1F20C9767937ED85ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 293\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7128AD2D9076D867ULL,
		0x58544AEBAAE80238ULL,
		0xE3D3EBFD8F0B177DULL,
		0x712D8B897FCBA861ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB63C161354A6974ULL,
		0x9461FC96B60BB3AAULL,
		0x4E2AE76E462FF07EULL,
		0x6E6E30CADB7E8609ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE3D9DAED0082C49CULL,
		0xA3767357125CA431ULL,
		0xE8973632DC6B8D02ULL,
		0x441C0A17DC85E5DDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7C58198DAF80E0DULL,
		0x5CD6C003F542478FULL,
		0xA3DB43EDD5DC97A2ULL,
		0x15D489C30E63DC6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 295\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDABF78FF1BCB129AULL,
		0x9AFAAB668E57AD57ULL,
		0xE942EE98EBF29EAFULL,
		0x52A3C5097D69ADDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE9CA9FB93E513B3ULL,
		0x79FDC1EEE7EDF85AULL,
		0xDEF9F9EE601A96CEULL,
		0x07BE511FA2338661ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x98766342C661C9ABULL,
		0xBE68A6FC3A227816ULL,
		0xDB64B8F311A3B110ULL,
		0x178258417FF0F0C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98766342C661C9ABULL,
		0xBE68A6FC3A227816ULL,
		0xDB64B8F311A3B110ULL,
		0x178258417FF0F0C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 297\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB3309D53F973FDC8ULL,
		0xAD50887FA0DFEA34ULL,
		0xD4A80E1B54FD98BFULL,
		0x0542F482079B57D6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46DC2012468F88FFULL,
		0x766FD39ABD0ABFA6ULL,
		0xAD432614E667078BULL,
		0x129EA7EC5A06C4BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 298\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAE0034FC57CC9AD1ULL,
		0x0746F2C5DABAFE95ULL,
		0xF6290AD61900DB1CULL,
		0x4B0F17F0D71FD450ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE05817D0A7CE0BULL,
		0x03991ED5C1C5D6DAULL,
		0x6A314EEC7C4DD730ULL,
		0x454F0C8A3AB3F5FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAB245DF5F9047BE5ULL,
		0x7F53D729C8856C05ULL,
		0x366EC4F7554C24E1ULL,
		0x1D83FCEF3ACB2B33ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3A2ECBC369C6CC8ULL,
		0x93D45EE71F4D9815ULL,
		0xD08F2445EC5A0363ULL,
		0x20C91E73A73F11EDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 300\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x91235946A3EA92AAULL,
		0xBD0A2DCA37188020ULL,
		0x83FAAAFC5072F929ULL,
		0x3F71EC11BB6580E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91235946A3EA92AAULL,
		0xBD0A2DCA37188020ULL,
		0x83FAAAFC5072F929ULL,
		0x3F71EC11BB6580E4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 301\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1E7DE7F8BB417DF5ULL,
		0xE8A0A361166B3D37ULL,
		0x0C33D14536161871ULL,
		0x3957145719779B9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E921BC0898BD9F2ULL,
		0x6E77ED839ECFED0DULL,
		0xCA5355E35DA8F825ULL,
		0x179E19393603169BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 302\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA5E68E9D60AA64BCULL,
		0xD91BEADEC4EAD16FULL,
		0x20BD09EF46B53A1BULL,
		0x71F64486E133B49FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14EC15B423553645ULL,
		0x16FCA3BBB624B417ULL,
		0x0C9A6DF9F76C91AEULL,
		0x1CD7FAF6D6E5BF76ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1FDCAC9E3892559EULL,
		0x963D220249B6FE1DULL,
		0x9C71A649234E25B2ULL,
		0x3EF8A4F2DBEAC8B8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CFBD0500298B8A0ULL,
		0xDA79B4B9C25AE1DAULL,
		0xA4E0644F55A5D748ULL,
		0x314D1B363EEB9B65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA0025A3BCEEFD42EULL,
		0xFA676058337829C8ULL,
		0xEBDD8E28D8B5364BULL,
		0x79DDD04516FD7102ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0025A3BCEEFD42EULL,
		0xFA676058337829C8ULL,
		0xEBDD8E28D8B5364BULL,
		0x79DDD04516FD7102ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 305\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC7988A310B025E54ULL,
		0x4984532B4813686EULL,
		0x27BD701DE6E7FD0AULL,
		0x44B5623DBAD01915ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF10BF7CEA1495965ULL,
		0xAD0ADD8E02F8E4F9ULL,
		0xC11C9DFDBF5A5FA5ULL,
		0x6BFAB95B0FC179DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 306\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA0571709F265301AULL,
		0x0B874AAC550547BBULL,
		0xAE157EA00D2D9726ULL,
		0x0101FC0E527C0761ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB53C9948816B89D1ULL,
		0xE07DF72E14538712ULL,
		0x77AB2A7A590858D2ULL,
		0x2AC5FF6E0CC80316ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 307\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEDE2DBB3D33BD72AULL,
		0x4EDB1FDD50315983ULL,
		0x18BBA7D3F9783439ULL,
		0x411A56625C5749C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x717E4AF841A3C55FULL,
		0x1320254079494E7DULL,
		0x1BB15B2DB26B2F04ULL,
		0x748A3FB88CDD992DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 308\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1CA1CB1C7A38208BULL,
		0x63A748ADB5476A40ULL,
		0xEBD13724F586511BULL,
		0x7746DFC7F181504EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CA1CB1C7A38208BULL,
		0x63A748ADB5476A40ULL,
		0xEBD13724F586511BULL,
		0x7746DFC7F181504EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 309\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x11A31141A28C4FC1ULL,
		0x33B7E752DF49F16DULL,
		0xCAD75D0D704112E5ULL,
		0x616A9C4409360D0BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x61D37A8D769C644EULL,
		0xC65554C46929A6AEULL,
		0x48E48BB5922B6B84ULL,
		0x1464433BAFF73664ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 310\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4A56CFA96B0B42D6ULL,
		0xFF25C40D96C61E2DULL,
		0xD2B4FDA913271238ULL,
		0x2BDA1C37FFE7C5CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FF1191BD942CA83ULL,
		0xDBA96B97F3F587A1ULL,
		0x764B3137F1FBBF47ULL,
		0x519EAF053893654AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x48606245DD69660BULL,
		0xC4F0B88C9DF59ABDULL,
		0xA6AA20CA70BD6BB9ULL,
		0x56CAC2EECEC0AC4AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF9177A7CBEEFEAEULL,
		0xD151A8D4337B7E31ULL,
		0x3B2D1C1F1E7ABBB0ULL,
		0x3A7085859BD9FF44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 312\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3ADED4CD5978097EULL,
		0x5C90C69969A2BCCDULL,
		0xB79E2504DFC23DF8ULL,
		0x609CA7CBF378DC06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3ADED4CD5978097EULL,
		0x5C90C69969A2BCCDULL,
		0xB79E2504DFC23DF8ULL,
		0x609CA7CBF378DC06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 313\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x56AE8F713334FABEULL,
		0x26B938EA648D0799ULL,
		0x87875D851694C6B2ULL,
		0x7E5BFAD93DA88925ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD902F74AB07B1517ULL,
		0x6EFC4E3B223E8688ULL,
		0x3317828ED3DC1D16ULL,
		0x54CA0D6324A5B380ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE88398C6DC0C8261ULL,
		0x7D479FAF20DA8D2DULL,
		0x689459181A4BBC12ULL,
		0x1CD206B5599AB5BAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DF60BC84324BE31ULL,
		0x4CAA41F770AEED84ULL,
		0x387184C1D34AC1F0ULL,
		0x5F60C4486F4AE765ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7BE419699A9B9641ULL,
		0xE13F9137B051B305ULL,
		0x42C6BB6AFFFDDC27ULL,
		0x33C82419936C397AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1618C797CD356CF1ULL,
		0xF7B8281753AC8937ULL,
		0xC7E5B952C72C02B8ULL,
		0x282CCCA596D68FB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x95895BCF84691D49ULL,
		0xC547A7D6848CB962ULL,
		0xA576B5F47A031599ULL,
		0x1CF2C1382D555542ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95895BCF84691D49ULL,
		0xC547A7D6848CB962ULL,
		0xA576B5F47A031599ULL,
		0x1CF2C1382D555542ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 317\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0B41E61EDD692E66ULL,
		0x6217CFEA53578837ULL,
		0x96BDDF50AB1206B6ULL,
		0x297EDF453B96E7B3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01BEDD8A4F2F4FAEULL,
		0xB4FF1AA08D1F2FE2ULL,
		0xEBF8816FC3E87F02ULL,
		0x6033150747779076ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 318\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x87D25D196AEFE457ULL,
		0xDC5330591099A3DBULL,
		0x318BADBA27D74A10ULL,
		0x59679369C71D5824ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC95829BA498C273ULL,
		0x69D3E5BB43092654ULL,
		0xDC2BFA2FB12845C0ULL,
		0x6DDA5856117509DFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 319\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x908FB0202DB43DD5ULL,
		0x69254F10716E1381ULL,
		0xBE42A70D71A23F3AULL,
		0x5AC96D5F7F2C815AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92DAD073E8E0D7FBULL,
		0xA894DFCF85ED061FULL,
		0xFC35873C3FF2DFF1ULL,
		0x43460F2186D18563ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 320\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE95477C99736B904ULL,
		0xAF6239B412BD9114ULL,
		0xCC572DA0C31F5995ULL,
		0x5B2E4FF4C0E63A3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE95477C99736B904ULL,
		0xAF6239B412BD9114ULL,
		0xCC572DA0C31F5995ULL,
		0x5B2E4FF4C0E63A3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 321\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x050B0E8A8E4478ABULL,
		0xCAA19C5EBAA64D75ULL,
		0xA646AA21F64F6A5BULL,
		0x59AF7E1DC9D12890ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A6F4A0A21EA83A3ULL,
		0xA14AF817E9F08C48ULL,
		0x2C8E7CE16BDCB57AULL,
		0x630274BFBCE6EC06ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 322\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6B98016A91C25E87ULL,
		0xC0F046FA72E7FFACULL,
		0x1DAE9E30D4DD2A10ULL,
		0x3919AA1FAC530625ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F78CF1B89DA268FULL,
		0x8B0F67BAE77F0DACULL,
		0xCF6BEC81709E22E8ULL,
		0x38DDA7CA0EF8BCF0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0C7F4A0DF7286856ULL,
		0xC293847111DB000FULL,
		0xCF14EE94070F37FEULL,
		0x0AF27E1D87A7A576ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA904635644EF80ULL,
		0x09FEB46079EBC5B9ULL,
		0x5AAC2D66BD194658ULL,
		0x1F729699B108AA8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 324\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x55011FA3DA2B2552ULL,
		0x0850730E07EA83D9ULL,
		0xA41F6DE0FE75AC9DULL,
		0x36E45E71068D4821ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55011FA3DA2B2552ULL,
		0x0850730E07EA83D9ULL,
		0xA41F6DE0FE75AC9DULL,
		0x36E45E71068D4821ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 325\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE170000B3E2BF219ULL,
		0xA9CFAAEB58A567CAULL,
		0x7AF194C56017A44FULL,
		0x32736165AD211CC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A77BF78568B16FDULL,
		0x95CC8E98C90FF545ULL,
		0x8484BFBCFD89C1D2ULL,
		0x74374CC7B483AD2DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBAF64FC68863FBFDULL,
		0x4B56E56176DBDD08ULL,
		0x15A1B966C0584B7DULL,
		0x371D87EA9EC336FBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6A9F3AEEB26BB00ULL,
		0xEBC6E1A346FFCECBULL,
		0x1996B7B8CBE83E76ULL,
		0x138E624B5A1A9979ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 327\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1ACE2273DC174FF5ULL,
		0xC3486FDDDA94C1F8ULL,
		0xF7D174510A36D41EULL,
		0x7AB4EDEE1256E426ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD65684B09063C14FULL,
		0x4BCBA304E688EC75ULL,
		0x0AC43B6CB54E519CULL,
		0x4312C6B223708445ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 328\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x82B3227D6E966303ULL,
		0x6AD9677DEEA113F1ULL,
		0xE172F9FDCAFD81AEULL,
		0x74212B7165209264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x82B3227D6E966303ULL,
		0x6AD9677DEEA113F1ULL,
		0xE172F9FDCAFD81AEULL,
		0x74212B7165209264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 329\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE2C6B3351C293CFEULL,
		0xB36C74A6598B4E44ULL,
		0x0DE1CC1AB07E20B6ULL,
		0x71EE3E46CBEDDF1FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x280BF84D939091ABULL,
		0xB8926EFADBFDF2C2ULL,
		0xF85BD7FD7EABD9A3ULL,
		0x7D93A6B4532C67FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 330\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x33FC71314358A668ULL,
		0xF7BD35D10897309DULL,
		0x5A7B91A9891AAA98ULL,
		0x53C37D2172596D4CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E486C9A2A93637AULL,
		0x60CF6D4703751E8BULL,
		0xB3E24F62304DBA51ULL,
		0x6160C627C65D2240ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF31C3EF858790C61ULL,
		0x661A0499D45C6887ULL,
		0xE171F4D21464E2B7ULL,
		0x3153D8A081756B3AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9912EF41814637A7ULL,
		0xFA172EA75DC3D45AULL,
		0xE9936A6CF557D1ADULL,
		0x72E6C86C3B207388ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 332\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA02553B77EAC1002ULL,
		0x20124EEBDB8BCBDCULL,
		0xED6B602727963260ULL,
		0x76F93E209CED7C55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA02553B77EAC1002ULL,
		0x20124EEBDB8BCBDCULL,
		0xED6B602727963260ULL,
		0x76F93E209CED7C55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 333\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x110A701360A300C0ULL,
		0xD92FD9FFF51CE66BULL,
		0x6FBE150266132E4CULL,
		0x69DD75879FB2FE74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1572B3626E0DA023ULL,
		0xF99C42C76DC093CFULL,
		0x3D0A9B1F1166F498ULL,
		0x2A8A6DD510B65F55ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 334\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB7BFAB90F76BE39DULL,
		0x6DDCA601183AFE5BULL,
		0xD31A2A567DB20612ULL,
		0x6B5FCC216666E95CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCF58189BBB5BF59ULL,
		0xF9A1D5C54FC69159ULL,
		0xEBB8B42A8B169C71ULL,
		0x16F86BCE1786C6BCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC4938507B4AE4862ULL,
		0xA3B27FFA5D8EFBCCULL,
		0x5E1DB2B783B4D9B0ULL,
		0x208E7A7B30DC5635ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63BAC98C04B0D5F3ULL,
		0x4A9F1FF1BFF07AB9ULL,
		0x3A7782B6E0BF1B2BULL,
		0x25E0223FB5A64EF5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x16D88CBCAF7E365FULL,
		0x262F96FB3A13B8D4ULL,
		0x6607BD66E4522273ULL,
		0x2B123B1A522FB5DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16D88CBCAF7E365FULL,
		0x262F96FB3A13B8D4ULL,
		0x6607BD66E4522273ULL,
		0x2B123B1A522FB5DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 337\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x714BEBC18CF37B90ULL,
		0x3D08B42C6C545B2BULL,
		0xD7818492D466B2A5ULL,
		0x493904ABBE57A050ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x878A8BA113826CEFULL,
		0x9297C7C1CA60CDE0ULL,
		0xD15567FDE6A1BC11ULL,
		0x182DF18E44F77D8EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3FCEFA64B52B6019ULL,
		0x08E45E1A7C4C5768ULL,
		0x9E85401A48489CDDULL,
		0x4B88C9F486E31220ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD874D38C518C527EULL,
		0x470EF628F1B22BF3ULL,
		0xA428EAF1768F86F3ULL,
		0x0F9B989CCC24E973ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 339\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0F9233D7A254DCBCULL,
		0xC0BC571E4D543E83ULL,
		0xDB4168FDF75D183BULL,
		0x2644FCF3B7D1A20BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FF61B0F7224BCD1ULL,
		0x2D8AC6AEC1D18980ULL,
		0xF31DD4D61868FE7EULL,
		0x00201E6A41F2CE78ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF8F432E0E5FC570AULL,
		0xF391BB4AF2449D7AULL,
		0x7D282973A74D3DACULL,
		0x70520B53B7FEDD42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8F432E0E5FC570AULL,
		0xF391BB4AF2449D7AULL,
		0x7D282973A74D3DACULL,
		0x70520B53B7FEDD42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 341\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x38C2C4A5A8F4B125ULL,
		0x873AA172398DA287ULL,
		0x0B54F268CF3732A4ULL,
		0x5FF767DD644576A3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C1BD6FA8759B4BDULL,
		0xC7756AB994747115ULL,
		0xC0B1315CEE737D5FULL,
		0x4BE92F683B7A0109ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 342\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xED8208884E87D2D4ULL,
		0xD28CC4C3BA2D3A7BULL,
		0x06774139FB84B3E0ULL,
		0x281BE562E507A787ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1256838F28D22FB1ULL,
		0xE9FB5EC1091C11E7ULL,
		0x408E329C071B8D25ULL,
		0x22C8777649669D60ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDA0397DE50D34B94ULL,
		0xB2F80258BF952133ULL,
		0xB2E7FB48CED75E4BULL,
		0x50037B6A87630423ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0835B863CBB00D8ULL,
		0x748331DC966FB886ULL,
		0xF2299AE06537F1E4ULL,
		0x3A8DC3E04602BAC7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 344\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF5440F68447512ECULL,
		0x71F2715BFA58E868ULL,
		0xB649725A55906031ULL,
		0x749FDDE30B2CAA64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5440F68447512ECULL,
		0x71F2715BFA58E868ULL,
		0xB649725A55906031ULL,
		0x749FDDE30B2CAA64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 345\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1C2C54681A46BF98ULL,
		0xEA4106FFF9287553ULL,
		0x951F0CA8AF803F44ULL,
		0x0BD5BDE0C27E076EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x612246E54C017117ULL,
		0x68EC0E859DD48D10ULL,
		0x3539123FA6ECCA3FULL,
		0x7D567601A9B75029ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC9D47D7BF02DDA02ULL,
		0xD4FA932F77CEA29AULL,
		0x5F7D66485C3EFA92ULL,
		0x79309977C89B6154ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E7FD8B2EF611EDULL,
		0xC66CC5903D81F7D1ULL,
		0x828304137C504F43ULL,
		0x7BAB8FF33934A826ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3E7C194D12CB3755ULL,
		0xC168AD995233BDFEULL,
		0xCD2C1F06556A746DULL,
		0x161C2C0DA959CA9EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE29D26F7CA4E022DULL,
		0xBB8F6AB7C797E737ULL,
		0xB1C4CE10F53BACD1ULL,
		0x357896AEBF5DE2B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 348\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x01E117CF8CD045E4ULL,
		0x3AECAC5EEF710BC2ULL,
		0xFD9377408503777BULL,
		0x6B190832825C25E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E117CF8CD045E4ULL,
		0x3AECAC5EEF710BC2ULL,
		0xFD9377408503777BULL,
		0x6B190832825C25E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 349\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4BCD7C29AD2C8624ULL,
		0x2691FBF8CF69F148ULL,
		0x5245FD2D236D4C33ULL,
		0x3AC3BD44C860BB67ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C01CDAC508E25B3ULL,
		0xCFF14AFF35558CF3ULL,
		0x6FFD77C455345B3DULL,
		0x640FC6EF3E25D2A7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE7D121C1DF4AB6AAULL,
		0xE5F758B29C19F1D0ULL,
		0x397B9D40AF29A0CDULL,
		0x3F15C3B21D76E5C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x824E2DC220A90BA2ULL,
		0xFAA074BF4F4C8A9AULL,
		0x3826ED49AEECCB92ULL,
		0x7F60908E37B66618ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7DAE885C7262F1E2ULL,
		0xA43C8E6ED87105ACULL,
		0x63B93CADDAEBB2D3ULL,
		0x37523DFBE57CC2ACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x140FD0D48310E00BULL,
		0x68E97731C46C0260ULL,
		0x26D8B2A27A387D35ULL,
		0x2A42ED9A99C2F3E2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 352\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD50F601843F45756ULL,
		0x98402CBD8DD7B3A1ULL,
		0x407D07DD080D1077ULL,
		0x0627447600621AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50F601843F45756ULL,
		0x98402CBD8DD7B3A1ULL,
		0x407D07DD080D1077ULL,
		0x0627447600621AD2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 353\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xADBDD7583C2FF15DULL,
		0x1C74DB3D39E568FCULL,
		0xAE93F7D53542A4F4ULL,
		0x3E1F9D8998EAC4C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55787BDFE88BBEFULL,
		0x4BEE55940FACCAA7ULL,
		0xABABE085D9C9EEAEULL,
		0x722AE9E3FA36EE89ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5273B419A9D3A5C0ULL,
		0x4529C3C8ED8E58F4ULL,
		0x05C12ACE77B809D8ULL,
		0x25AB7A7C83C44712ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17FE44243115C2EEULL,
		0x99A9F82F506D5C1BULL,
		0x258CFC8A5C44D759ULL,
		0x321AE03011510C64ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 355\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5DD9757484D648F7ULL,
		0x3978DEF6799EF190ULL,
		0x0ABBB204F33DC3A8ULL,
		0x1700B3BF448F1C40ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E31185EF13CAFADULL,
		0xDCC64396840A6EE8ULL,
		0x7806158B2B228520ULL,
		0x34C08A6DBF22D3E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 356\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x89BCE6F252A4B6F6ULL,
		0x8997897AE61EFDA5ULL,
		0xF2F07240CCA4ADBBULL,
		0x67B377B0FD38BDB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89BCE6F252A4B6F6ULL,
		0x8997897AE61EFDA5ULL,
		0xF2F07240CCA4ADBBULL,
		0x67B377B0FD38BDB4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 357\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x322F0D0C57DC107EULL,
		0x021E72DC3570A07EULL,
		0xC6F606138DCDF388ULL,
		0x69BC777B59787369ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6057FF891F248D2ULL,
		0x4A4D49209239E5C3ULL,
		0x80308E190B35E2B9ULL,
		0x574E1F6F1C61973DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE9D43716410189A2ULL,
		0xCC5242B44C84D5C7ULL,
		0xB60E7A3784C663F6ULL,
		0x456E8ACD443F78EAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6593F32960231202ULL,
		0x982D6CBC05AC7340ULL,
		0xC1E2F464C168F23BULL,
		0x46A7CCF34070DB8AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA0E45237C8DC8905ULL,
		0x2DCBAF22625A9871ULL,
		0x9DD4A9D31AA93EE6ULL,
		0x010EBF8AD8CB8384ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFF648E352C05B47CULL,
		0xA7CF7E97BF7275B6ULL,
		0xE92C942C85A6FDDEULL,
		0x3853551DF4B468CCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 360\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x58D1C615CAF4F122ULL,
		0xB41B21E7E134C614ULL,
		0x0717F52B99D740EFULL,
		0x6746693DEB2AD53EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58D1C615CAF4F122ULL,
		0xB41B21E7E134C614ULL,
		0x0717F52B99D740EFULL,
		0x6746693DEB2AD53EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 361\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAFE21959C77C79BDULL,
		0xF4693DF0CDB28896ULL,
		0xC31BB6259B5D0868ULL,
		0x24BC836DA6478777ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F3A55FF158B5E20ULL,
		0x9975CD0D938826DDULL,
		0x3488D5D791597422ULL,
		0x6F9FC0FC40EEDDD1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 362\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xEC2C4815572D17A3ULL,
		0x1F51C70300B454F7ULL,
		0x3507C0EF0D74791BULL,
		0x175F180A16AF67D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF334AE5C1409A5B9ULL,
		0x94946786B3D1128BULL,
		0x127393ADE30BB69AULL,
		0x7BC1953F87ECAAFCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x30F870BB56CD787EULL,
		0x511A8B530552FE02ULL,
		0x40BB4C681AE41D38ULL,
		0x4F535F996EC62E2FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F65C777DD38960AULL,
		0x660B74C82D2831FAULL,
		0xD07971F9E7F750E2ULL,
		0x62AAC91C2EA32B4FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 364\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8E0863185CC303AFULL,
		0x976BF52794B1C46EULL,
		0xAE2386CE6B9488F3ULL,
		0x574E6048D4CC7208ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E0863185CC303AFULL,
		0x976BF52794B1C46EULL,
		0xAE2386CE6B9488F3ULL,
		0x574E6048D4CC7208ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 365\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDF1691EF0191AF6CULL,
		0x8A935FE2A14E91DFULL,
		0xECC0F0E5C78AAC1BULL,
		0x53F0A031BE896495ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAAB463E49B413BEBULL,
		0xDE4805522A470397ULL,
		0x6931E6416849C26BULL,
		0x2A5739D45311B7D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 366\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBA3220B9AC0FB277ULL,
		0x21134D88113A784AULL,
		0x8510B6B3EF1C193BULL,
		0x78D51EB24F3643B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC539C12145E4CF7EULL,
		0xC8A85A336F8BE85BULL,
		0xDE69E542F54A21A7ULL,
		0x59BFA0FEE33444DBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x74DEA4766F405E01ULL,
		0x8808C35DFB250E06ULL,
		0xBDF0A1439798D15FULL,
		0x0EE29FCFD9A9BE7AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DA459FDF56E7402ULL,
		0x60CA2184FF0163EBULL,
		0x258819F1DDE9744BULL,
		0x26EA319C0C7D3645ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 368\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x681FB2BAFAB208CFULL,
		0x6377C04E48988196ULL,
		0xFA61F70B9F09CA2CULL,
		0x4F3F7D4F16FE7312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x681FB2BAFAB208CFULL,
		0x6377C04E48988196ULL,
		0xFA61F70B9F09CA2CULL,
		0x4F3F7D4F16FE7312ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 369\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3139646B738E7324ULL,
		0x988C3E1D741C8D67ULL,
		0xB7D60E6F0611CDDDULL,
		0x00933E2C2F272BC9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D72B0946B85CDCFULL,
		0x82EDADB1B8658A95ULL,
		0x32D64A3D0C2C4594ULL,
		0x181010C4188EF532ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 370\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDDB554C3B94ADC61ULL,
		0x242BD1CA6112F456ULL,
		0xA8FA59A8FEF8015FULL,
		0x764A4DF7AA7BF374ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69DE6D0F96A4C10CULL,
		0x871E9CADFE53A576ULL,
		0x320B73496EE57720ULL,
		0x1100008E13EE0587ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 371\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x39D32410ECCB6D32ULL,
		0xDC2E751F13F55358ULL,
		0xB77EC50F9CB0487CULL,
		0x7B9AF73FD4C9F1BEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2DD3FD67D83F8A4ULL,
		0x820DC5E6B6447A32ULL,
		0x731C29BD62A05366ULL,
		0x67D66DF51044BBEDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF6981DDCDDCDE311ULL,
		0x059FB604F78AB024ULL,
		0x08FED4E10A3C42E5ULL,
		0x716B2513413AC1CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6981DDCDDCDE311ULL,
		0x059FB604F78AB024ULL,
		0x08FED4E10A3C42E5ULL,
		0x716B2513413AC1CBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 373\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5FC2950C2E57E452ULL,
		0x225D36244426CF68ULL,
		0x3C6733955ED746F3ULL,
		0x773B85974DA971C1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDB0E38E752EBCFEULL,
		0x7711D0F6ED52CD42ULL,
		0xF083A7ED15A3C2E6ULL,
		0x2E60BC9DA3A544B5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE93FC570390A87D0ULL,
		0x3DFBEE05D95F2355ULL,
		0x55659B77E8FC4F44ULL,
		0x30663160F9793D72ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA99CBB666BA7F49DULL,
		0xD1222755AD9128A7ULL,
		0x2BD5752B2887E19CULL,
		0x094DE0EFA9279782ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9D086FEA5FD25FF8ULL,
		0xD6865DFEC40A4D98ULL,
		0x4118CB629523C1E6ULL,
		0x56CFA08593EE3078ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FEA7E343E1D8D61ULL,
		0xA0EED26EE59AD5D5ULL,
		0xE5B54BF12FF8867CULL,
		0x791C1E2C83967393ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 376\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x15A144AE7130B416ULL,
		0x16552BB2EDA58E06ULL,
		0xCD54B7B3AFBE78AAULL,
		0x44506D25F593C545ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A144AE7130B416ULL,
		0x16552BB2EDA58E06ULL,
		0xCD54B7B3AFBE78AAULL,
		0x44506D25F593C545ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 377\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0C1345B7CCD64E59ULL,
		0x78AA25550566590EULL,
		0x2B97087F57CE966BULL,
		0x1CB0EFAABD364D1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7FA526F690AA5D8ULL,
		0x324EE136080C457BULL,
		0xEADBA4F2E62DE418ULL,
		0x7EFD04F4F3B715D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 378\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xD4E1A3FD63F3BC8BULL,
		0xAF1A50A9036F5BFCULL,
		0xC3DBB1692433670CULL,
		0x36F8912CDEF95A6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D10E084E133D8BDULL,
		0x97CC546D6F68A61DULL,
		0x73F393BC2FA89B38ULL,
		0x7BB78B85ECA6392CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 379\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2EBDB383CE62A5DAULL,
		0x6C26D71F79B823DEULL,
		0x9B520F02C9276BA5ULL,
		0x49E450B372E6C3A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB7CA094DB9DEE1CULL,
		0x10BAAED9A3FEC32CULL,
		0x53B2BDBDE7AB92B6ULL,
		0x77D7349258B85E8DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 380\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x798BB156959A2B82ULL,
		0x10B2BCC3777CE9EAULL,
		0x5BD1B76689650E8EULL,
		0x2DB98F2B78B55934ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x798BB156959A2B82ULL,
		0x10B2BCC3777CE9EAULL,
		0x5BD1B76689650E8EULL,
		0x2DB98F2B78B55934ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 381\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5D810847A3874E97ULL,
		0x36B86D50E3C9EE53ULL,
		0x577DDBF3A44C1900ULL,
		0x6C09B5EE9B29AC6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x148039A9BCA07353ULL,
		0x95B667CC9F7DF17EULL,
		0x5093B69A130E5AC8ULL,
		0x3EB55E05761AAF9BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCDC8B4C3AF6CBE67ULL,
		0x68DF3FE5047AC282ULL,
		0x04CE0B1967C7DBDEULL,
		0x1A5BE3595402AEB1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA15CB80C454EF63FULL,
		0xB9243104CD60723EULL,
		0x8A62954B54637610ULL,
		0x461D932444535FE6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 383\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x11F61E2301664D3AULL,
		0x19EB7AA6456AB8FAULL,
		0x9EAC209006A10BFDULL,
		0x7390F84C8FF259C0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF4E452C97603331ULL,
		0xCBDF7F7A2936BE5FULL,
		0x1A272ADB04EB9C5FULL,
		0x7DA8607F09BC8B4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 384\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCC3D53DEA647A96BULL,
		0xFEDBCA24C241672AULL,
		0x028CE32ADE54B315ULL,
		0x4965007B9322E808ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC3D53DEA647A96BULL,
		0xFEDBCA24C241672AULL,
		0x028CE32ADE54B315ULL,
		0x4965007B9322E808ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 385\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x652CEA8A73BA0535ULL,
		0xD1D4849FE3C16B76ULL,
		0x8F648145978F27C5ULL,
		0x298FA489B75585D5ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B80FF3DD95CDB17ULL,
		0x8BEED8E1D4CCA62FULL,
		0x9639CC916F708624ULL,
		0x0B71ACEA2AF3865CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 386\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE62CDB0727560359ULL,
		0x64DE31586E2051A9ULL,
		0x92F274BE0AC6442DULL,
		0x10EDD7F88353E3DEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE49D5C96A20CA8DBULL,
		0xD4956C480D80435DULL,
		0xC45602E2A952435EULL,
		0x3E4E4E1988AA71F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 387\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x702C60DE38F7C147ULL,
		0xF560FB4EA692FF11ULL,
		0xE2911D1DAB60AD32ULL,
		0x70119239A0109AEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDDCB1D1FE06D17C5ULL,
		0xDAF4C59C11D32156ULL,
		0x17618C342A7DAE26ULL,
		0x18C416DBEC3F870EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 388\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4482BB5F10F39F20ULL,
		0x67B419FFC24324E1ULL,
		0xB9675FC42FBBD57BULL,
		0x799BE43900A695C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4482BB5F10F39F20ULL,
		0x67B419FFC24324E1ULL,
		0xB9675FC42FBBD57BULL,
		0x799BE43900A695C2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 389\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x13F9B297B1BD27A2ULL,
		0x6B35F69F31D0FAA6ULL,
		0xEEBAE7714CC702DFULL,
		0x755E316B596BB5FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7E5C0D742366C1BULL,
		0xE543E3E2B8D8BBCBULL,
		0xA469785A964965FCULL,
		0x363F8A302C31F372ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC59A97C8C408B08CULL,
		0x7CAB57EB74A5E3FBULL,
		0xEB0F319FC11572D1ULL,
		0x6D519DD45BF30B9DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73862B7996CE58F3ULL,
		0xA350FD86BCD743B8ULL,
		0xD5888E4479EA4736ULL,
		0x51DC96191013CC6FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 391\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA5EB32C1B3441613ULL,
		0x825C325B742FBB52ULL,
		0x8ADA990A133B60D7ULL,
		0x4659FC515B846336ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF640A2ADC14B39FFULL,
		0xE00913BF56B3D13CULL,
		0x7C58B0C22ABC8A5FULL,
		0x2C9839D555A017F2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 392\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x58839B1E4E75A03FULL,
		0xE947D6903FCEC916ULL,
		0xC5CAE5B7F4260E3EULL,
		0x55CF160DABE69CDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58839B1E4E75A03FULL,
		0xE947D6903FCEC916ULL,
		0xC5CAE5B7F4260E3EULL,
		0x55CF160DABE69CDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 393\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB39C5AE92CD48051ULL,
		0x35F39CA527F4A01DULL,
		0xB5BDAEA73EB59A97ULL,
		0x12EABF99482E3216ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CCA7C2A56CE9D01ULL,
		0x47106C525C138BACULL,
		0xBA584D5D6BAAAE15ULL,
		0x1376CF290A78E3B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 394\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7837A9DCCD99FF12ULL,
		0xA93230387863772BULL,
		0xCA5567B2BBD6470DULL,
		0x224362CA61F10F03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F00482074124743ULL,
		0x7E992E5B9AC550E2ULL,
		0x7406BEE3B072E66DULL,
		0x6D8FA67631E78278ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA9D0793B68C89457ULL,
		0xEF4C5B3943B7CAA9ULL,
		0xBDEEB548DF19A961ULL,
		0x71F49DC8B8A67F2EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79DEFE4257BEBCE0ULL,
		0x0AA4351B833D1E6CULL,
		0x00227E1D4B40E16EULL,
		0x2457E0D34A67275FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x98A8D9347EC28EE6ULL,
		0x11E10E3D8F032716ULL,
		0x5369B4EEEA7BD88FULL,
		0x09B1D515EBA3D8B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98A8D9347EC28EE6ULL,
		0x11E10E3D8F032716ULL,
		0x5369B4EEEA7BD88FULL,
		0x09B1D515EBA3D8B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 397\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x93C7E5B9FE4D2378ULL,
		0xE463918C5C9CE554ULL,
		0xF951AF0FD1C3BDBDULL,
		0x0CED59A2A314A91BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29F3B4DCBCCEEC81ULL,
		0xBFFC6049C76688A3ULL,
		0x44DE7027D695F11DULL,
		0x2486F866EFED1912ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 398\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0ECF0668C10E2096ULL,
		0x0EDF9968417E5C2BULL,
		0x8744F2F4A23221CBULL,
		0x11F92D5343BEDE05ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38029CF644B54E38ULL,
		0xDCD4012EC2009998ULL,
		0x51233142FCD03116ULL,
		0x0AD32277B2E7D1A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 399\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC258B108C239FE36ULL,
		0xDAEAAB9DA3A5D082ULL,
		0xB3A582DE920C79A2ULL,
		0x3E37FCED4F3BE9B4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56E1F6D4A72C4B1AULL,
		0xCF5B495B50B7D1BEULL,
		0xC2DEA951865DD6F4ULL,
		0x7C5E6EDC6CE4E055ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 400\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x375D374B9D7CAD4CULL,
		0x9822C630FE696DF1ULL,
		0xAEA2A0A98951E396ULL,
		0x0EC4F38FD8B4F60DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x375D374B9D7CAD4CULL,
		0x9822C630FE696DF1ULL,
		0xAEA2A0A98951E396ULL,
		0x0EC4F38FD8B4F60DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 401\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBA0BB6F4081D4E12ULL,
		0xFC16DCAF112C4523ULL,
		0xFF1144CCC964C1DBULL,
		0x7A2065FFD16029E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD130F1110A0F6A45ULL,
		0xE3D1114FB923A9E4ULL,
		0x9AC9F29A62469524ULL,
		0x0AAA91B68F5744D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0B6194F25626A37AULL,
		0xD5CCB59A93FE1EDFULL,
		0x338B28865744D6AEULL,
		0x0F3091C6AD296AEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1AD54B2AA7C0A7CULL,
		0x325893A1061B1F90ULL,
		0x43FB8D3CAE58AF93ULL,
		0x41F102E548BBC22EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE4311C7E8D37A9B2ULL,
		0x45B100A1F9107446ULL,
		0xF6012F62FA718E97ULL,
		0x231F9A7F0A149387ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67431A55D64D38DBULL,
		0x36993DA859E11A33ULL,
		0x34FAD79E3B80A1A4ULL,
		0x3EB6D51D868F4055ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 404\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFE13E7E607575E80ULL,
		0x14537D7286458E71ULL,
		0xBB3AD6485D35FF93ULL,
		0x7DDD22C8CDEB1FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE13E7E607575E80ULL,
		0x14537D7286458E71ULL,
		0xBB3AD6485D35FF93ULL,
		0x7DDD22C8CDEB1FC8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 405\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7B8A3CC2CD06A250ULL,
		0x6C60D8FE926B805BULL,
		0xB3A74B8599262BC9ULL,
		0x4935CDDE81C06676ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01DDC03CC5B09E6EULL,
		0x32411614FE0BE209ULL,
		0x41E13A2A067843CFULL,
		0x62D66393D352C061ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 406\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7E5394A9481A447BULL,
		0xE2B2032FE766FB0CULL,
		0xE39870FCBCF3DEDFULL,
		0x71A8DD72024FFACDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x133E21F2D3F6F3B8ULL,
		0x06857FDB771F886AULL,
		0x752BC0CB5C2B96BDULL,
		0x2AE0A83421F1F12EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 407\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x09A9E9669253C10AULL,
		0x6888A6BAFBFAF96FULL,
		0xBE459156CBE91162ULL,
		0x4B60B8EA83111558ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6E1E93460AA97C8ULL,
		0xF9093987B3875F4BULL,
		0xB34A5725D2ACEFBAULL,
		0x4A093517E22DC25DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x31D2E84DEF7C551CULL,
		0x72716027945FE948ULL,
		0xD3B98A3C16CB6916ULL,
		0x19FD6549123EDB5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31D2E84DEF7C551CULL,
		0x72716027945FE948ULL,
		0xD3B98A3C16CB6916ULL,
		0x19FD6549123EDB5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 409\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA00F01C20A22AC87ULL,
		0x509E9D7236184CF3ULL,
		0xD2D7AFCD87402ED4ULL,
		0x277791D212E06520ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70C26D8F130A2C17ULL,
		0x7BF205D22F0E590AULL,
		0x8AD894E23EB6D5F4ULL,
		0x7AA44F41ADCAEA6EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0C3301110B40F10AULL,
		0xB9B4FB319BD5CB39ULL,
		0xAE8C61E9626621B4ULL,
		0x18177C5BA48D788EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4436D8C6FD5488ULL,
		0x23F9CDCF01F25676ULL,
		0x1AA1F5C98162997BULL,
		0x21B99DE55B05E3CDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4676773D17286996ULL,
		0x5063EEFDAC408B47ULL,
		0xBA980F1D22D42668ULL,
		0x4ACA9C870C6FB5C4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE70A8F7F05519CC5ULL,
		0x2580F288974D0972ULL,
		0x876AB122B341CC9FULL,
		0x00E3AE9CC944444AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x077564F570D699E1ULL,
		0x553A1D55E5986F1BULL,
		0xBA52F1EBC457EA0CULL,
		0x240DCB5771DD10AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x077564F570D699E1ULL,
		0x553A1D55E5986F1BULL,
		0xBA52F1EBC457EA0CULL,
		0x240DCB5771DD10AEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 413\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x111FE610DC5B8043ULL,
		0x120B8C47F7CA914CULL,
		0x9087C195FB8171E9ULL,
		0x71358E9D47D02B66ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2193233F78CC4D8DULL,
		0x646F1600CDAC798CULL,
		0xC979ACA14CF3EF76ULL,
		0x10AD264919F0B0AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 414\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x440FF0A2C878A7BFULL,
		0x4C3030D440DA4012ULL,
		0x4AB5DBA693DC78B1ULL,
		0x63A12C6F0582C33EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DF1042B495322A8ULL,
		0x534D6DC8D28F3B6BULL,
		0x0077264D733D6F54ULL,
		0x38704E8D166B081EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x444BA8090628DD15ULL,
		0x9A27AE6BD9F27D99ULL,
		0x6670BD8F7BB9FBA4ULL,
		0x358F9B068897B60FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x395465D3E73F4700ULL,
		0x1AC6E3ABD5CE059EULL,
		0x1A48556EB8CB909CULL,
		0x587C2C9ABC60D1B2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 416\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x13333AD41BC85B31ULL,
		0x05AB5EC9EE84B639ULL,
		0x6C980966A96B90A1ULL,
		0x0F54482B42EBB7A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13333AD41BC85B31ULL,
		0x05AB5EC9EE84B639ULL,
		0x6C980966A96B90A1ULL,
		0x0F54482B42EBB7A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 417\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5550D44EDD1DA5EEULL,
		0x7823F693A0B77EC3ULL,
		0xE35A907C9A8E5397ULL,
		0x76BEB11EA30C868EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CEBB91B0D8B1660ULL,
		0xE55A9DAD969CCA50ULL,
		0x90B4DD6DE310ACE1ULL,
		0x7CCE3E9FEFEA8940ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 418\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x036513F7D610EF7BULL,
		0x4832CD2FA0CD6441ULL,
		0xA6FF9FE6FF539B07ULL,
		0x12EAB74A9D4670CFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41E4F7FE2D604647ULL,
		0x6EB211F31BBA170CULL,
		0x51FC4247F474C597ULL,
		0x663AEBDA27F449A1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x78EC32A25EC7D018ULL,
		0xDBF23D78639CCF7CULL,
		0x39AEE2E919F84D1DULL,
		0x11790E9A5C1B49ADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x735B0D8A9A520E3EULL,
		0x836D0C722B3065A1ULL,
		0xCEC2FCBEC6694598ULL,
		0x3EA532C398330AA3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 420\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA476E51AC96DB11FULL,
		0x4FBBDB73FCC3D738ULL,
		0x3D3033E6DC353BA6ULL,
		0x2F888D8B43687B3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA476E51AC96DB11FULL,
		0x4FBBDB73FCC3D738ULL,
		0x3D3033E6DC353BA6ULL,
		0x2F888D8B43687B3DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 421\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5249E90E4B5C1587ULL,
		0x63593462BB7B4A3BULL,
		0x90E22778DA04D018ULL,
		0x0BAB2F0DECE3F1CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF16FA5BDB49FEF0DULL,
		0x599CBD35B8E9DAEEULL,
		0x72DF21ADFD8B358EULL,
		0x3FC8AFDC474FCF87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x939537AAE67E5ADAULL,
		0x37884311EAC46303ULL,
		0xE98E155FE8C33138ULL,
		0x0CE9DB4514E885D2ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04190FB6EBB53028ULL,
		0xAC2D27736C393767ULL,
		0xB0BBCCA14490A2FDULL,
		0x175F71623BAA389BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x490A37602FB2F910ULL,
		0x4A3820D3E62DAC37ULL,
		0x31D0EE60F3E1E7C1ULL,
		0x267C03F6FBA4680DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40ACB6EEF1FD0342ULL,
		0x7D3055CA22D62EF3ULL,
		0xEF1D3F6E9B9C66DCULL,
		0x3BD0894BB89771D3ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC651B9FEB0514403ULL,
		0x25CC8BF1D2161756ULL,
		0x618665523D37AB4BULL,
		0x14279DA3FB2E2161ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC651B9FEB0514403ULL,
		0x25CC8BF1D2161756ULL,
		0x618665523D37AB4BULL,
		0x14279DA3FB2E2161ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 425\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBB17D6999D295124ULL,
		0x04E66B3EBC924211ULL,
		0x3686D9BAF740A6B8ULL,
		0x07358ABC97DAA37BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x613D768723E2D7DBULL,
		0xF922D7AB198B7DA1ULL,
		0xC3639459585331DBULL,
		0x3407BFC34447BABCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9890362503D46E81ULL,
		0x9C4A010946B12CCAULL,
		0xFC863C4AD9309D49ULL,
		0x4A0E6A718B1CE426ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF4A5239EE3BB763ULL,
		0xD17BBADF677A1CD3ULL,
		0xDB3D9EF2DC413A87ULL,
		0x443FF4E211203CA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 427\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3291C5285A73587CULL,
		0xBF16FC0D0A2F89DAULL,
		0x71795A604CF095B8ULL,
		0x3AD9152E3A6C4C63ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF865B2F3F639B0C5ULL,
		0x9211487981ABB633ULL,
		0xB13F749DFB0A3D5EULL,
		0x5591E8C1464DC667ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 428\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xCA7C32369C3C5913ULL,
		0xB1B1706EFC593F01ULL,
		0xEC7F00218D4A19ECULL,
		0x58F791A83297EBA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7C32369C3C5913ULL,
		0xB1B1706EFC593F01ULL,
		0xEC7F00218D4A19ECULL,
		0x58F791A83297EBA1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 429\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA87FEC7245FC98B1ULL,
		0x1F188A5A33002D38ULL,
		0xF306549D22D4B449ULL,
		0x688F60492C9F6085ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4F21FF1D9009F2ULL,
		0xF7513F50F2C441B4ULL,
		0x0325ECD10664AB45ULL,
		0x254FBED558D66ED1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 430\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x785CD298AC5BB9F7ULL,
		0xB2BA141A916306BBULL,
		0x5E9FABEF28D94405ULL,
		0x0E04D939C1221449ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D9DC54C57B709F8ULL,
		0x6F15EF18142100EAULL,
		0x29B77771F297F51EULL,
		0x2DA5D29D0F8349FAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6B48B2ED3DF5520EULL,
		0x31A7B1DEB84B8FD3ULL,
		0xD8D1492E8B50096AULL,
		0x14E4C15C2DC3B6F4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BE507CFD163C2A4ULL,
		0xE6D28DA412874E30ULL,
		0x1E979B83D8080648ULL,
		0x7A9F7A8E4BE7BF74ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE7DD883D460CDE69ULL,
		0x0970088F980DCEB8ULL,
		0xC920CF75552F46A0ULL,
		0x4831BD436111DFA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE7DD883D460CDE69ULL,
		0x0970088F980DCEB8ULL,
		0xC920CF75552F46A0ULL,
		0x4831BD436111DFA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 433\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4C945E695C6BCE9DULL,
		0xC815680407BB16C9ULL,
		0x68393BEAF887D1EBULL,
		0x4EF98D8E80059A28ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5035C54F5104B733ULL,
		0xF55299DA9F10C8BEULL,
		0x9DE67A1D441FFC63ULL,
		0x55A1CA51531593A6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x99C423B5716B8B33ULL,
		0x0822DDD3596303C7ULL,
		0x51752BC77AAF68D7ULL,
		0x2D74A72E2600BBE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29C68D5C8CA350F5ULL,
		0x9380B3E8F85C7F19ULL,
		0xFA093DE97DE8C937ULL,
		0x63AD3D979FCCAF44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7EB7F1CCAAF74124ULL,
		0x78BC1A0C0597B861ULL,
		0xE89C2E43B658DAE0ULL,
		0x2317063E25562DF9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F00AB945C56FB26ULL,
		0xC90E252160D754F9ULL,
		0x9EC436C87C698EAFULL,
		0x49C7AE281CF7EEDAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x04BD81FA4E7A1EBBULL,
		0x7A6C0F4B9FEF4096ULL,
		0x2578794A7575B22CULL,
		0x3BBAA01D7F10DF96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04BD81FA4E7A1EBBULL,
		0x7A6C0F4B9FEF4096ULL,
		0x2578794A7575B22CULL,
		0x3BBAA01D7F10DF96ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 437\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x918A2929A1AFCB93ULL,
		0x9370A3439FFF8BE5ULL,
		0x4E38D9C72B812F10ULL,
		0x61BC299C00481AD0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE1DA0A68D9360D5ULL,
		0x58D726F4D44200B4ULL,
		0xE8D5527505FD75BFULL,
		0x788EB544C6262EE7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 438\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7827850AAB6C0B50ULL,
		0xA25AF1B21FC15255ULL,
		0x5BE233117FEEEC7FULL,
		0x2ABC89D3ABEDF1FFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF26A369EA8B7E91ULL,
		0xD01FD89257ECB670ULL,
		0x05570630F77A558EULL,
		0x540376255D84388FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1E54839ED7F35B41ULL,
		0x70114EFDE04149BCULL,
		0xD5EB85CCF9D3EF6CULL,
		0x571F3A2F0855ECEEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63A60F91DC888E51ULL,
		0x5B025982D290C3C9ULL,
		0x62E10B6B17DE4EFFULL,
		0x7773C1EF4EAA5A9FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDA838FDE15A4C4A5ULL,
		0xBF97A8A11380840FULL,
		0xF79F1FA00B894854ULL,
		0x1914BC6C7F838DEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA838FDE15A4C4A5ULL,
		0xBF97A8A11380840FULL,
		0xF79F1FA00B894854ULL,
		0x1914BC6C7F838DEFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 441\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x425D3D69357AB3BFULL,
		0x59BC44E51C4E4F83ULL,
		0x060D96492BD5484BULL,
		0x623143F037EE87B6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0392D34D193D476ULL,
		0x7324F2C0E815F68FULL,
		0x314E720ACAD5D577ULL,
		0x6747EBA4095236ECULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9108037E23639E33ULL,
		0x75F59833CC681719ULL,
		0x6BBC076CC8B3AFAEULL,
		0x2FFD639C316E488BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE72D62A16969E767ULL,
		0xDA489B6550E63BB3ULL,
		0xE66421BCFD1CAFF7ULL,
		0x2CF7F4E0A46C2441ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 443\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xAC9202C3C11E1F41ULL,
		0xAE3CBD0AC051A87CULL,
		0x712FF764D888EB4BULL,
		0x6C46B1785C728DC1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7302CD76B62537CULL,
		0xB045E368677DC606ULL,
		0x65580BC3DB11482BULL,
		0x0E42BCF2ACD8EAADULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE46A6657501978BEULL,
		0x9C8F2E5EEA809913ULL,
		0x998A81D37E23480AULL,
		0x758837EEF6ADBD65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE46A6657501978BEULL,
		0x9C8F2E5EEA809913ULL,
		0x998A81D37E23480AULL,
		0x758837EEF6ADBD65ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 445\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5D3AFC3758B616B9ULL,
		0x69C3327B998177DCULL,
		0x7A9357CA704D41E8ULL,
		0x3280E5FB3C4F9628ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24C53723054CD4DEULL,
		0x8DBB5889BE6F9D0AULL,
		0x2709EB7AFE754562ULL,
		0x57C9EF49F6BBE9F8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 446\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3819514A5AE7EB63ULL,
		0x99E31073D4C52B54ULL,
		0x37064F0F7DFC9ADFULL,
		0x673199095BF00387ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x47963AC252A171AEULL,
		0x9974E0406AD0D155ULL,
		0xAF5C0B874F8FC212ULL,
		0x315284B3DC51FB4DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 447\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA623A975B4BD18E8ULL,
		0x656D51CC825EA82BULL,
		0xAF8C3898485D9A4BULL,
		0x1D43EF3BAE78CDA8ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD5A93D9397471E5ULL,
		0xB95DC73EADB727C0ULL,
		0xB880DBB06EBF2104ULL,
		0x5199937CAC6EA6C7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 448\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x3D3F840CEC76A4D1ULL,
		0x8A5E0826E046D075ULL,
		0x7593ACAD44180D48ULL,
		0x34218B96F0653EACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D3F840CEC76A4D1ULL,
		0x8A5E0826E046D075ULL,
		0x7593ACAD44180D48ULL,
		0x34218B96F0653EACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 449\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x9DBAFD76051A732AULL,
		0x9CC0EC03434A0A00ULL,
		0xF5E865E80C340D80ULL,
		0x3A6B26B793F74D38ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCE0ED5899AE58EBULL,
		0x1B820BFE90C78412ULL,
		0xB364DB934CE7EFD4ULL,
		0x61FF8FAE6C9A8641ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 450\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x98AAAA26665F13BEULL,
		0x7F5E450EB46D5570ULL,
		0x829CBF6C20DA1ACFULL,
		0x032DCDD36659407BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x214C71BC1184EBFEULL,
		0x16B3C96EACC33122ULL,
		0x730164600E94F70CULL,
		0x7670109303192A0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5D1EC3FA0D75D89FULL,
		0x1EFF73F7E657D1B0ULL,
		0xA3E66433AEECD109ULL,
		0x7C772D071FCD9F42ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD116EDB0DD0DD2EAULL,
		0xB08933014BF723C3ULL,
		0x258AAEEA034454C6ULL,
		0x196DFC7197ECE110ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFFDF0D09A9F5EEF9ULL,
		0xCA00981613C29188ULL,
		0x61C7211AD3D56AEAULL,
		0x731A52CF9D014264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFDF0D09A9F5EEF9ULL,
		0xCA00981613C29188ULL,
		0x61C7211AD3D56AEAULL,
		0x731A52CF9D014264ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 453\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x85EFFACE8EC09C58ULL,
		0x164E548DBBB8FD6EULL,
		0xBD7D2A5C8A6C22D5ULL,
		0x1AC752D793A0FD92ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAA02FB78B466C0CULL,
		0x0B6246C96B603834ULL,
		0x0481C4C68E8666B8ULL,
		0x6C02EECEEF9185E7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 454\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x59E823FD00A57F11ULL,
		0xE7BA3BB8E4B239EEULL,
		0x5EF0ABF75D8DB2B3ULL,
		0x144F3F8737CF5D12ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CC4A12E2CF600D7ULL,
		0x798DFC3175163855ULL,
		0x6F6D19A8AE8AC622ULL,
		0x3336C2AA17828EA6ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 455\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x506C422CD0562A80ULL,
		0x955B41609841C861ULL,
		0x4D4E249F9C849F9EULL,
		0x6685D9A08DE5D8A9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37B2A56D398DD7FFULL,
		0x05E020D7BD894646ULL,
		0x709C67E0BE752B87ULL,
		0x325B0A40FB7E4DE0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x66E0A21A88E40DA3ULL,
		0x624753B7A40BDA95ULL,
		0x2EC751E663DABA75ULL,
		0x22DC3DF1C896E604ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66E0A21A88E40DA3ULL,
		0x624753B7A40BDA95ULL,
		0x2EC751E663DABA75ULL,
		0x22DC3DF1C896E604ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 457\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7A5CA9742908074CULL,
		0xC2EC0C5D3D0CF7CFULL,
		0x7A1FC8A06D51DDDFULL,
		0x602B9AD5C7DD828AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5C00A95921B28F6ULL,
		0xF485FD09D5C0AFF6ULL,
		0x80051FBFE145DB1FULL,
		0x01F7D04819EDB528ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBF42C146D00034ACULL,
		0xAD415660789710CCULL,
		0x7B56C3FC3BE137B4ULL,
		0x12D81B10E162BD52ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x277211DE17F2D832ULL,
		0x81EA231F55680735ULL,
		0xC6E5D8D4E3F841B4ULL,
		0x0027C48210080E03ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x988593274D04B9E2ULL,
		0x181D5CD99288E33DULL,
		0x90C2CA368FAD5E11ULL,
		0x6D8ED2F3235F419AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A944F9A56DCCE53ULL,
		0x02A38EF9EF55C6C9ULL,
		0xEAA0E40AA22F204CULL,
		0x5840EE0E21D0CDAEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 460\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5589CF739BFD041EULL,
		0x30D7D570510E60E6ULL,
		0x07C830398537D067ULL,
		0x26B348B82166429AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5589CF739BFD041EULL,
		0x30D7D570510E60E6ULL,
		0x07C830398537D067ULL,
		0x26B348B82166429AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 461\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xE1C26139725011FDULL,
		0x705EEC691F7F41C8ULL,
		0xC132C084C7F43ED7ULL,
		0x1B33EFFB5DE94B5BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58765E5F3EBEB78CULL,
		0x2E38799AFECCB8ADULL,
		0xCE61CD04AAD667BDULL,
		0x007CAB8355D09E4EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 462\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x91F2DB37B0CD83B2ULL,
		0xE09D203FCD074D7CULL,
		0x1B3D2F27A0C186A3ULL,
		0x41F14FACB77B1408ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC0C0108FD8603569ULL,
		0xCD6375005F2A4096ULL,
		0x52EA2EA55A9917F1ULL,
		0x3CBFF4D28064C1FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA160926A00FA95E4ULL,
		0x2C07A3CDB6BA6E23ULL,
		0xFFAF6D64AC38C9B9ULL,
		0x1DA0325E6C169EB0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D180FAA08A2860FULL,
		0x4EDCBEB46FD55219ULL,
		0x1AA2C1DED2EDBC82ULL,
		0x552A4B10C843CBDBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 464\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x31F96DFB312814E5ULL,
		0x66DBE15262F92CDEULL,
		0xE16BBEDE36E2731EULL,
		0x5008D32625F7F917ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F96DFB312814E5ULL,
		0x66DBE15262F92CDEULL,
		0xE16BBEDE36E2731EULL,
		0x5008D32625F7F917ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 465\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x7F95275487C6A46BULL,
		0xCCDEDC24E58123A2ULL,
		0xAEC9B8A737127545ULL,
		0x4126391473167874ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FE1EC8F0EB12953ULL,
		0xD04A128DD748E0C8ULL,
		0xD71C210EF7BF1D44ULL,
		0x73CAF2DF7E07BB14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFE454A925CC1357EULL,
		0x294911F216F91339ULL,
		0x578D8393C8FDF811ULL,
		0x76187A73EB63F07FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88B5F90D46378314ULL,
		0x9B5253D7C045F9BDULL,
		0xC9E931F869AEB07CULL,
		0x2FE67EAA3344C49CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBC162060221F01F1ULL,
		0xD48ADCB4DE458FF3ULL,
		0x3843F0730BC445F6ULL,
		0x65F2F675088EA97BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DD973C7A2F4F0F6ULL,
		0x3F8BA4A9EFDA3458ULL,
		0x4F9A8388D150FD54ULL,
		0x79BC9B583A0B1950ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 468\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1E39DDE41949B7D9ULL,
		0x96449B4FEBDE8021ULL,
		0xB341D9FBA8FFAF65ULL,
		0x4CB8DAD786FB79AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E39DDE41949B7D9ULL,
		0x96449B4FEBDE8021ULL,
		0xB341D9FBA8FFAF65ULL,
		0x4CB8DAD786FB79AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 469\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x674CCE6D44187505ULL,
		0xB9E36E7D77D4C2C8ULL,
		0x4AD71BCD401E5D5DULL,
		0x33C03F05555F303DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC712E52C477F30A2ULL,
		0xDB87923AD1121B6BULL,
		0x1609186260699E5CULL,
		0x74563E3FF93D8E1AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xFF4C1905A5D0FE38ULL,
		0x154D2758EED85B32ULL,
		0x6CF2A606AB41A2DBULL,
		0x29DC62A916EABFB9ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFD949A898F57C0AULL,
		0xA1A00F57FFECE339ULL,
		0xAC7B4F0F93DF8D8FULL,
		0x27961B457D171B7EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 471\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x810EF0060ECF9CA5ULL,
		0xEEEA4DC0DBA9155DULL,
		0x55C796A0689C13F7ULL,
		0x5CDF365F301319CAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E1A912FADA1553DULL,
		0x567CE8CFEFF5888BULL,
		0x30D6D90CCB771EE6ULL,
		0x42618E57B8EE5874ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x6403627E2C346E18ULL,
		0x3BD9A9C365A05509ULL,
		0xE90D4614C11A5FF6ULL,
		0x60F5F2831D1C87FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6403627E2C346E18ULL,
		0x3BD9A9C365A05509ULL,
		0xE90D4614C11A5FF6ULL,
		0x60F5F2831D1C87FEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 473\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x67C309B7E73EA353ULL,
		0x24CE0583D2771E72ULL,
		0x3F6E7DFEA3DEB3F5ULL,
		0x2841BB446046FD7FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43B7EDEE7698D989ULL,
		0x210989C0C366D2CDULL,
		0xA6F49D3AE4577816ULL,
		0x76683CC2957864B1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 474\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xF32FB1DA43510119ULL,
		0x4F7B4C931FD90070ULL,
		0x8FD78C0B3A67B786ULL,
		0x10AF880D4303C4D1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40157E5BFBDCB943ULL,
		0xBF5B5DF1FC0C0007ULL,
		0x69AEC3FDE0F796D0ULL,
		0x04D294ECF71DCBA7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4E23B21DA18DD293ULL,
		0x441E83688F63D17AULL,
		0x47D5AC94A0134887ULL,
		0x2BCDBF42A22D2E86ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x36979B721A692378ULL,
		0x0AA5C43B0D31B693ULL,
		0x5F38E4797A48BE93ULL,
		0x1ED9E38B1ABCEA4BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 476\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x71E3567C219C5516ULL,
		0x0BB68BFC14AD0792ULL,
		0xAF6DFFF9B4B0A9B3ULL,
		0x6E5E73B3DDD74D5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71E3567C219C5516ULL,
		0x0BB68BFC14AD0792ULL,
		0xAF6DFFF9B4B0A9B3ULL,
		0x6E5E73B3DDD74D5EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 477\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC522E674CC0BA46FULL,
		0xC28CBD8ECA21ECE7ULL,
		0xC777DED2D5AE10A4ULL,
		0x712E856C5F74B3AFULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5737543436AE3187ULL,
		0x3689A9AD83A7139CULL,
		0x366C2A003022DA16ULL,
		0x25AB1B4DA0CB88AAULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 478\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0142284D05F8A4E0ULL,
		0xE20D8A6B661EF2E1ULL,
		0x40ACADCDED7C0839ULL,
		0x5766EE967FE8EF93ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF204081F99C99EEAULL,
		0x59556B7E009A62AFULL,
		0xF22B413052727D79ULL,
		0x7F0AD8D46C1BE472ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x86A68E65FC233440ULL,
		0xE5331183A2647599ULL,
		0xFD938696031CB486ULL,
		0x2F5EB7F9036099E1ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x659724639BF0E1B2ULL,
		0x4C12B120B74CB62CULL,
		0xD1E7DCED59609885ULL,
		0x6E805C3B95F276B7ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 480\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x1E2B0BE86D409A74ULL,
		0x161D147F56A02519ULL,
		0x8F58DC262D0B0E47ULL,
		0x0F40AF3B6B54ABACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E2B0BE86D409A74ULL,
		0x161D147F56A02519ULL,
		0x8F58DC262D0B0E47ULL,
		0x0F40AF3B6B54ABACULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 481\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x8B20D844EE606697ULL,
		0x3594AA52D3EA07C7ULL,
		0x9B5E88DD073D95E2ULL,
		0x29C02BE0F9A98E44ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79034B04E18CDACULL,
		0x77F974B1EF99DFD4ULL,
		0x40A24DABE46FB5B1ULL,
		0x218B62289C6726FCULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 482\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x0209C364D0AF3C3FULL,
		0x0A710BF87BABF1DFULL,
		0xF12FB265F8C6A5D0ULL,
		0x31E6550277496D0FULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF610F4823A4C6A04ULL,
		0x4E2DD1E14BA1DB46ULL,
		0x7271570E10270720ULL,
		0x6660730F6087A1CEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 483\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB878A9FC9A8CA521ULL,
		0x199489848E219821ULL,
		0x2B8543A670C6495BULL,
		0x1EB600A8F2F0D30DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC530F672EF6897DULL,
		0x6011275CD210DE8FULL,
		0x4A8A1923B153E724ULL,
		0x58DAB0F537788D43ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBCC69D73A6DE0F04ULL,
		0xF0B0C6A4366D743FULL,
		0xDA4C15FAF9CE4838ULL,
		0x0F3E0C035212C226ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCC69D73A6DE0F04ULL,
		0xF0B0C6A4366D743FULL,
		0xDA4C15FAF9CE4838ULL,
		0x0F3E0C035212C226ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 485\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xB1F94B7E32FB4353ULL,
		0xD521808E74B7B448ULL,
		0xCD0D6689A8F33FD7ULL,
		0x471F3307C9738504ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE6107E69CDFD8C8ULL,
		0xE3FAF204164862B4ULL,
		0xF56C890802274F41ULL,
		0x5BC229FF491EA2A4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC4C9FB6AFE4237AAULL,
		0xDCC27B4F60A0076CULL,
		0x9029F2AD837B04A3ULL,
		0x5CF36384B35DA297ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACF4DF4AA7C18DDDULL,
		0xFA161B51B514408DULL,
		0x6497B3E36ED8AB49ULL,
		0x32C76407B2710CA4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 487\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xC2E253A8F0F6B395ULL,
		0x89966ED6C4DE1EF5ULL,
		0x282CAE0E91073526ULL,
		0x40E140957F4C2A25ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52D69CE9CB03F597ULL,
		0xE24036AEE3C0B0BCULL,
		0x84EE9A7CCAF6471AULL,
		0x354B4C6792D396B0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x909008E4AC95F1EBULL,
		0x4834728F013E3A2FULL,
		0x21BA0019C548A160ULL,
		0x7CD5C9C51AB73E6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x909008E4AC95F1EBULL,
		0x4834728F013E3A2FULL,
		0x21BA0019C548A160ULL,
		0x7CD5C9C51AB73E6BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 489\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x10FEA3E359CF5DAAULL,
		0x86DB1B3324C3A5C4ULL,
		0xC27C378B88B849D7ULL,
		0x019B77A0CA29D720ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x658A96E6E008E054ULL,
		0x113B53B8E9565905ULL,
		0x2448EC21C23D3208ULL,
		0x00EC19923359684AULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5DA3F397B522B9F4ULL,
		0xD9D93A1F2FA990BAULL,
		0xDBFE8E3DB547B74AULL,
		0x11D8CCDA3FCEC307ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C8E6F54824D52F5ULL,
		0xE5736BE6C5606580ULL,
		0xB9948320A2218401ULL,
		0x1242C47E40727C98ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 491\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x2AA8214EC2A79551ULL,
		0x8A38B918A0F53B88ULL,
		0xBE2D6826236E3F7CULL,
		0x1055C29845A5C620ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x17A6626E3C6544FCULL,
		0x60947B7CCB79FB32ULL,
		0xB736E52A2C997BE3ULL,
		0x504DE0B7998E8528ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 492\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x4969CA4509A3D6D4ULL,
		0xD2991FBB145BD811ULL,
		0x7C28824260926280ULL,
		0x68C02C37320AAF87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4969CA4509A3D6D4ULL,
		0xD2991FBB145BD811ULL,
		0x7C28824260926280ULL,
		0x68C02C37320AAF87ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 493\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x382514D54C29E10DULL,
		0x99665EB0C01AE3BBULL,
		0x1CAC3F524533052CULL,
		0x7CC9D2CF13345101ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1267CB28618CD571ULL,
		0x6337C96E46EC483CULL,
		0xAFF17169897DA2A0ULL,
		0x35E4A9AE476AFD0DULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 494\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xA6636462FC94D16AULL,
		0x80408E3994672850ULL,
		0x6D8075609C073C73ULL,
		0x38866D4005B3BAF4ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x819136E8D0E602EBULL,
		0xDEA9E54A2DCEB98AULL,
		0xC3DA54187889AB2AULL,
		0x29328D870FCDB4E0ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 495\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDD4321B1A9A1F8D2ULL,
		0x1899E1230E23F6D2ULL,
		0x426883688B4F402DULL,
		0x12AE3682A537E57BULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1713C79FFEB71E8ULL,
		0x8FA2793F3A38E30DULL,
		0x20E57B1292AB605CULL,
		0x1EBDF1782D41FC75ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 496\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x206DC14CFEE4F725ULL,
		0x100815FB5D94A60AULL,
		0x302368CFCD650800ULL,
		0x6B031DE5417B076EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x206DC14CFEE4F725ULL,
		0x100815FB5D94A60AULL,
		0x302368CFCD650800ULL,
		0x6B031DE5417B076EULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 0;
	printf("Test Case 497\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xBDF9DCECC888FE45ULL,
		0xB5776356DFDEAFF8ULL,
		0x75EF719E9AEE72C4ULL,
		0x7F6BA09E01142CBEULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x431DCF816FF65E3BULL,
		0xFB58D024E2D26743ULL,
		0x9906E90A62957869ULL,
		0x0A82BD1764DAC4EBULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 498\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0xDF6991486DA18BEAULL,
		0xEC82ED415FB309C0ULL,
		0xE6495B9B6DD5CD34ULL,
		0x2DB3C47FBAC11B14ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF692D507934F2BULL,
		0xD7B553B4ED86BECDULL,
		0x99C949BB8CD4D6A6ULL,
		0x75E390EC14EF863CULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = -1;
	printf("Test Case 499\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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
		0x5BEC220D72EF4397ULL,
		0xFF53D4B8DCC5E4CFULL,
		0x72174AD1E2F1D6DEULL,
		0x2230911D7B90E531ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E4D8FD9F4EFA1CCULL,
		0x26B4463A0B4048BBULL,
		0xDE096505E6728C8EULL,
		0x034034274E362CFDULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL,
		0x0000000000000000ULL
	}};
	t = 1;
	printf("Test Case 500\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
	res = curve25519_key_cmp_low(&k1, &k2);
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