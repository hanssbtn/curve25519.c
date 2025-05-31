#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x16E003E9D2739CDEULL,
		0x5D7509C58F764460ULL,
		0x63EDE8B2200E601AULL,
		0x733E74FFB6D43861ULL,
		0x39CE9F9FEBFB3B11ULL,
		0x10BAB6B9F1B92FBEULL,
		0xC79DC64B31FE55F6ULL,
		0x479FE7D1588D2B44ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA37100CBA64CB034ULL,
		0x0BE3ED7BCAF0E628ULL,
		0x8B9FC223F04064FCULL,
		0xC6C22FE64EE14FB0ULL,
		0xE348ECC0C5D78C6EULL,
		0x1714844041615462ULL,
		0xFB8EBDE7B6E8AE0FULL,
		0x60DEEE2FB7122C93ULL
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
		0x716B9BF9F465F87AULL,
		0x272CF0E25A6365A0ULL,
		0xD96286E18EFB0002ULL,
		0xE29F822ABB22F856ULL,
		0xF0EDA7C20828B817ULL,
		0x0917656EFCCE82B8ULL,
		0xEDBDDCA137BB5CE7ULL,
		0xA4987904EBE61AC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DE9A6D1C617BE8ULL,
		0xA172520529569644ULL,
		0xB5125B4BDA5FA6A4ULL,
		0xAC74B798DF6C9C41ULL,
		0x4E22C2522EA427E9ULL,
		0x4B5593F7C1E2D5D0ULL,
		0x9B857A04332C5B50ULL,
		0x4AC6FE1D415173C5ULL
	}};
	t = 1;
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5DB8A928C7FC25C9ULL,
		0x91585A617BB8C823ULL,
		0x28C22AE2A85C1F0CULL,
		0xC8DC3CCFA53420B7ULL,
		0x9BCC0DF3B4B15976ULL,
		0xA92F548253539F36ULL,
		0x0501F9CAAAA5F335ULL,
		0x059696C1583873F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C93104B7404FC36ULL,
		0xAE94F3A39D2BA4F2ULL,
		0x71F493A6CE647C69ULL,
		0x6E497359FC4A4202ULL,
		0xBFD3C6CF021696CDULL,
		0xFE35D27E03342BD4ULL,
		0x249A0DF0FE13FFBBULL,
		0x0A4AA5CC97D4FA44ULL
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
		0x8B271905D217E764ULL,
		0x952B760C4E13DD9DULL,
		0xBD21F6A1CF4F6003ULL,
		0x89AAB16C0389EA40ULL,
		0xA296F30F6338162BULL,
		0xEC74B4C113CC0618ULL,
		0xD1FACB0B8303C18BULL,
		0x2897155DC9A28FCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6E4EF4F150DE542ULL,
		0xA19243C744E18661ULL,
		0xA91C9337AF3A0940ULL,
		0x65B2A40762B1DF04ULL,
		0x186E1D0C926E1782ULL,
		0xC736DC9C54A90436ULL,
		0x9CF5117BADEFFA66ULL,
		0xE2F652D7FBE4AAB6ULL
	}};
	t = -1;
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x194289EBB6FEF863ULL,
		0xA5A5448319B5EEF5ULL,
		0xCE8799E5247E6158ULL,
		0x27726243CC514D87ULL,
		0xECDAD84B7E571323ULL,
		0xC190E4C873F49229ULL,
		0x27B65312C7F7175DULL,
		0x8EDBAA59C080676DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x194289EBB6FEF863ULL,
		0xA5A5448319B5EEF5ULL,
		0xCE8799E5247E6158ULL,
		0x27726243CC514D87ULL,
		0xECDAD84B7E571323ULL,
		0xC190E4C873F49229ULL,
		0x27B65312C7F7175DULL,
		0x8EDBAA59C080676DULL
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
		0xFD23BF027CA43C4BULL,
		0x1A112E64489F9399ULL,
		0xD7498DC89BA42E2FULL,
		0x29EE136A6EED859EULL,
		0x27A57627777E0489ULL,
		0x09EA7B639EB78C4EULL,
		0x02C9FE7CE41FE5B1ULL,
		0xA77ED299B036303EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83474144651EB726ULL,
		0xBADD5AE79DB5D65FULL,
		0x34CCD44D38BCDD25ULL,
		0xA80CA78E5496B63DULL,
		0xFBA90C7C115CBEEDULL,
		0xECDC513832058BA2ULL,
		0xE8734739BC821F19ULL,
		0xE8117B670B843104ULL
	}};
	t = -1;
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD9C4761F176953F2ULL,
		0xEDC000D3259BEF59ULL,
		0x23467CC0013356DFULL,
		0xE64F926F80750DCFULL,
		0xB3D0E48ED06183A0ULL,
		0x5A8A493898676927ULL,
		0x7A2D58096BA51DA3ULL,
		0xE01C9DE0BA892FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E4660D43C2CE8ACULL,
		0x554C8B25F51BABD3ULL,
		0x0FD25037D6BC7ACFULL,
		0x6A18EDCC223C2214ULL,
		0xF88FD4E181FBC1B7ULL,
		0xE9C9F7AAA069582FULL,
		0xDC9E947239244EF9ULL,
		0x45009C35510AAA87ULL
	}};
	t = 1;
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9C2F492EFD717CF3ULL,
		0x042A56B50FEA7EE6ULL,
		0x56BA97307D29A1D2ULL,
		0x8A7D405410DD3F40ULL,
		0xE9B19CC446C55C80ULL,
		0xB0CC8A5C2D332026ULL,
		0xDB3A24D21FB04A2DULL,
		0x1D28825474EB2B85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0A845AC241761E7ULL,
		0x034D3277A0E0FB24ULL,
		0x19A34099E43A92EDULL,
		0x78E4237B155B417AULL,
		0xE839A3FE5DB084E6ULL,
		0xDFBFF0C1006F7254ULL,
		0xAA170AACE0CE7536ULL,
		0x4515CA3EAC0EF218ULL
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
		0x766827B6B515A84CULL,
		0x9F459B8B27784A66ULL,
		0xEAA37774340F6B48ULL,
		0x3E0B7C9F466BA15BULL,
		0x91E8167CB9CCE8BCULL,
		0x0B67D6137AEBFFBBULL,
		0xC10D289705C80359ULL,
		0xEE80949AAB758293ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x766827B6B515A84CULL,
		0x9F459B8B27784A66ULL,
		0xEAA37774340F6B48ULL,
		0x3E0B7C9F466BA15BULL,
		0x91E8167CB9CCE8BCULL,
		0x0B67D6137AEBFFBBULL,
		0xC10D289705C80359ULL,
		0xEE80949AAB758293ULL
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
		0x7308D617634F7EB1ULL,
		0xF8541D99A7B8302AULL,
		0x440E92BD588C151EULL,
		0xE4BBA124168A595FULL,
		0x51838887F884D9CFULL,
		0xA1E897D71246D841ULL,
		0x9DE94503CB3D553EULL,
		0xCA8641260E9D1B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4D7F62E350640FULL,
		0xC33F594FAF0577E2ULL,
		0x3CE90BEFD5B94F01ULL,
		0x514604F24051ACE8ULL,
		0x18B14ECA3977D9C8ULL,
		0x6E2155F6DE8952DFULL,
		0x08EA5B6E8FFBB8EEULL,
		0xE89EAA8CF43EF5C5ULL
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
		0x1C7AD742990CE932ULL,
		0x1F4994DCA5F9398AULL,
		0x7ED78C30F5335690ULL,
		0xDD18F16C6345AF50ULL,
		0x24FD6130826E8440ULL,
		0x34CE587721359DDDULL,
		0x1BB7E9436BCBD9D3ULL,
		0x279D36E6AE49BB86ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B94A62AA4A07457ULL,
		0xE05CD5ED9895B2AEULL,
		0x7674B54AAD60E77FULL,
		0x881D9B9F4EA0B9B8ULL,
		0xBD2A76C6E8BE0C1DULL,
		0x8208DD366134574BULL,
		0x8C850D7C642AC937ULL,
		0xE7727782719B2067ULL
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
		0x77916D7CA7CC57ADULL,
		0x64C9AA61A2A016E0ULL,
		0x3B02DC91C9827398ULL,
		0x26EFBFA38C1DC299ULL,
		0xEB9A79BED83F7FB6ULL,
		0xEEE1753F32978939ULL,
		0x7B96BA4E5A07A5B9ULL,
		0x8B8902434BD1A4DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA7081B27AFD24C1ULL,
		0x63E46648B3D19BB2ULL,
		0xF04AF7FCBC8862B1ULL,
		0x6648FE057949BADFULL,
		0x3D9FB343CB188EFBULL,
		0x7DD9D7EC3FCDF081ULL,
		0xF1373208218F9989ULL,
		0x3A3498C356335E82ULL
	}};
	t = 1;
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6DDF65088336FFA7ULL,
		0x063680A2E348A687ULL,
		0x69DCFBCFE92550AEULL,
		0xF094615A5E5D5FFEULL,
		0x058366213B14B706ULL,
		0xE0E29807635FB458ULL,
		0xCE95E8974D8FE856ULL,
		0x1DA847524B9438AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6DDF65088336FFA7ULL,
		0x063680A2E348A687ULL,
		0x69DCFBCFE92550AEULL,
		0xF094615A5E5D5FFEULL,
		0x058366213B14B706ULL,
		0xE0E29807635FB458ULL,
		0xCE95E8974D8FE856ULL,
		0x1DA847524B9438AEULL
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
		0x960ADBEAF2308C6AULL,
		0x2B232364AB6D46D7ULL,
		0x1CC7AA179A389E85ULL,
		0x7E92B88EF2449EF1ULL,
		0xEE8DFF0DA80CC998ULL,
		0x1C0BE39C3E13D4BBULL,
		0x05E039402E7051B1ULL,
		0x57B7C1604C7E2513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16DE281991B0B183ULL,
		0x81931C3BD3D67078ULL,
		0xAE51274CA3CEEEF7ULL,
		0xAB2F213A6BB897D1ULL,
		0x6CC83EC5A7009CA8ULL,
		0x9F27EAC1CBCE6A27ULL,
		0x1CE83F567F0EE21AULL,
		0x38BD21694D78717CULL
	}};
	t = 1;
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x45DC9FE45EC50A10ULL,
		0xF5FE9A74F02211F1ULL,
		0x8309DC7D57E2E529ULL,
		0x7551F778A7DC71D3ULL,
		0x5AF1633C8C5289B6ULL,
		0x2136B3B2F35BC9C1ULL,
		0x19F23FF6B6540DF6ULL,
		0x53817F9A29E43F9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D682842E659B06FULL,
		0xC1C2875E9BED5EE9ULL,
		0x1B0E3341F8111FCBULL,
		0x0F025CFB24EF9DA5ULL,
		0xEE10DA09AFAC0E95ULL,
		0xC5F69E2ABBC885BDULL,
		0x85DE43E552F70B79ULL,
		0xF59FD6A1629DCB5EULL
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
		0x9DF30F835653AA20ULL,
		0xCA382D3D7367DAEFULL,
		0xA4F0EAE92D063024ULL,
		0x0170ACA489652C41ULL,
		0x0740559FC3258B19ULL,
		0x7534CF59335E7DDFULL,
		0x38C8D0B37710E8C4ULL,
		0x24DA80B7B36DB3B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5491CBE86F6AE07ULL,
		0x3D4A147AA1EAAAAEULL,
		0x5353386684FCC097ULL,
		0x398EC704C7439D6CULL,
		0xA36B2809A40D7C03ULL,
		0x15792318193DFB4DULL,
		0xC933DDA18287FCE0ULL,
		0xD55CFC3D956B9611ULL
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
		0xD20A8E0F2D68E676ULL,
		0xAD3063DACCEE0387ULL,
		0x34281EDE8E4A4871ULL,
		0xCB8CD5A480EFD59EULL,
		0x9828AB385E0F2D8EULL,
		0x893E9A746DA20247ULL,
		0x96E5CBB4BCEB3991ULL,
		0x76D994BA34B19F51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD20A8E0F2D68E676ULL,
		0xAD3063DACCEE0387ULL,
		0x34281EDE8E4A4871ULL,
		0xCB8CD5A480EFD59EULL,
		0x9828AB385E0F2D8EULL,
		0x893E9A746DA20247ULL,
		0x96E5CBB4BCEB3991ULL,
		0x76D994BA34B19F51ULL
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
		0x129081EDFA72A6C5ULL,
		0x61B12E3530C71394ULL,
		0x729D1145C002D808ULL,
		0x52BF6EDB0EECB178ULL,
		0x2DEB09B46A166801ULL,
		0xCB4B170EBD93779DULL,
		0x6AE5E933BDB9B3EBULL,
		0xB053F148BA823859ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54F235D4DB59DEFBULL,
		0xDCE854D9B682FBBDULL,
		0x4D5DFD1C6C090B74ULL,
		0x7AA203BED34989ACULL,
		0x89F6EEA9CD11D090ULL,
		0x117627918C40631FULL,
		0x4E9D293202E96315ULL,
		0xD2482A2DACDAC68FULL
	}};
	t = -1;
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2C3EAE9692C984E3ULL,
		0x903018D3D8E11548ULL,
		0xBB7021700536DD79ULL,
		0xC402E654E24D1BEEULL,
		0xA4EC3A7EE99D093FULL,
		0xB048A0F90BB5C488ULL,
		0x08C51ECBF90837C6ULL,
		0x5F2CDCBC7FF7C0EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D80B11B6791BDE9ULL,
		0xD0DA27226B2FFBE7ULL,
		0x0165F20DAE7C7DA7ULL,
		0x4B25CF3FC63FA3B7ULL,
		0x2CD3B49F07B4C91BULL,
		0x9AA61964F3F5A316ULL,
		0x4454131F270367E3ULL,
		0x390528B4992504EAULL
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
		0x245725B1CB7538BEULL,
		0x731895294CF0EDC4ULL,
		0xAA40C2BEE7F199BDULL,
		0x0A36B2D74AFA9115ULL,
		0x7875D2841BF747A2ULL,
		0xC2D707222C6E808DULL,
		0x78CE4FFD3D7D54EFULL,
		0x920D640E2F478112ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11AB3DD00DE74ABBULL,
		0x4ABFDD89A68B75CDULL,
		0x5117F5FAD8098019ULL,
		0xCBA65470DFA05B96ULL,
		0xA62A49421BAAD6A4ULL,
		0xD651E0D3E60C3877ULL,
		0x6D4A50AE32DB2C68ULL,
		0x3CE2F11E9AD87012ULL
	}};
	t = 1;
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF44C2BCAA7024FA0ULL,
		0x3970676DBB0BEE9BULL,
		0x7115C34E0B74AE26ULL,
		0x69EDA431D7C000E0ULL,
		0x381D9D3DFF29A2AEULL,
		0x37C2A5152FFB0E13ULL,
		0x5C66861986C8536BULL,
		0x1887ACC9DB3BDB57ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF44C2BCAA7024FA0ULL,
		0x3970676DBB0BEE9BULL,
		0x7115C34E0B74AE26ULL,
		0x69EDA431D7C000E0ULL,
		0x381D9D3DFF29A2AEULL,
		0x37C2A5152FFB0E13ULL,
		0x5C66861986C8536BULL,
		0x1887ACC9DB3BDB57ULL
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
		0xF3FAE1DDC3E9501BULL,
		0x2216F1FD561DE6E4ULL,
		0xC85DFBEA7A0B5F9FULL,
		0xBE2D0C33A5CFC17AULL,
		0xF8A57CD97743284BULL,
		0xB7B0E8431D04B035ULL,
		0x5350C10265970E9EULL,
		0xFA70CC2DA14119B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD29788F88D28054ULL,
		0x4C23E4BCECFD97D7ULL,
		0xF0093C6D9BF5390CULL,
		0x331583A7940D7C18ULL,
		0xD80BCAA4A8EA4A38ULL,
		0x9BF98A4EA0B00D7AULL,
		0xCE2F03F0E2D205FCULL,
		0x2F07DC178C3B7BC2ULL
	}};
	t = 1;
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6103B32C334C9836ULL,
		0xB3D01DF14A394182ULL,
		0x66DCA5090E4F3841ULL,
		0xE2A558E82B6EB1CDULL,
		0x23E1772C29608499ULL,
		0xD75E9691A4A3FAA0ULL,
		0x0AAA503A736FAA36ULL,
		0x77835950FF6B3EA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42CA4C90CEE001DFULL,
		0xDEFD65ED12967507ULL,
		0x2D64545C795C4E46ULL,
		0x96D40F66597E0574ULL,
		0xF85A5E5627DA2011ULL,
		0x6EFB1B92DE3C194FULL,
		0x3AB831F6D4A6E249ULL,
		0x69B6C325942B05B9ULL
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
		0x0A270E2E430CA1D5ULL,
		0xEBA9775094F8440CULL,
		0x0BD1DED1C9067631ULL,
		0xAF416F6925036848ULL,
		0xF4D6B1CE1108E649ULL,
		0x16155E5D427A069EULL,
		0x1600874842A07E46ULL,
		0x51D4DA2BBD7F8F2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3D39872C9E0973ULL,
		0xC501CA4E083FE88BULL,
		0xF28442037B5D6042ULL,
		0x0C801168C0E1519BULL,
		0xCC7A422B339989E1ULL,
		0x0402D39370CB4CB8ULL,
		0xF8384AEA95B1072FULL,
		0xDD113E01272E4C90ULL
	}};
	t = -1;
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x12876A4ED99C1548ULL,
		0x8EF8FE702A617BB4ULL,
		0xE950DF52E538C12BULL,
		0xE9797303C016EE67ULL,
		0x544FF015F9EC1E57ULL,
		0x3BD92EF92A4E9A00ULL,
		0xD6855777A246FFEBULL,
		0x74DC11E8A63A2661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12876A4ED99C1548ULL,
		0x8EF8FE702A617BB4ULL,
		0xE950DF52E538C12BULL,
		0xE9797303C016EE67ULL,
		0x544FF015F9EC1E57ULL,
		0x3BD92EF92A4E9A00ULL,
		0xD6855777A246FFEBULL,
		0x74DC11E8A63A2661ULL
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
		0x9D7C7EFF0A1418D3ULL,
		0xBAEFA7EF36A56877ULL,
		0x1C0E31FFDB2FA26DULL,
		0xFE51473449A2FC78ULL,
		0x26A054CD26466FBFULL,
		0xC2DFE2FA83B83634ULL,
		0x3F56890283C9312CULL,
		0x4F336C15409F91F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C40D79014E1F53CULL,
		0x63F4137904A69F4FULL,
		0x77FCCBF395AF8958ULL,
		0x2950EBB0FEFD511CULL,
		0x2BD372D3D0F3BED5ULL,
		0x5E2E0C58808EB698ULL,
		0x80B86E67E83AD32DULL,
		0x144C5123DBE90204ULL
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
		0x3525E1E04CF65BD5ULL,
		0x66A6B9330BCC76BDULL,
		0x7A1724B9E3D1B838ULL,
		0xAE0BFE2E376CAF11ULL,
		0x92CB324354CD38FCULL,
		0xBCD6B77B7843E9EFULL,
		0x6BF70A00CD180E7CULL,
		0x0E2B6564CD603F35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x422DE1C6EA52F508ULL,
		0xA96D98D575ED3BE9ULL,
		0xE42D505615B48D51ULL,
		0x21FAA1F4236EB311ULL,
		0xD164405B0048CFB0ULL,
		0x83D75352C3B13C82ULL,
		0xAB0B68E048327ECAULL,
		0xE63A95A1F9A0EC20ULL
	}};
	t = -1;
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD1029B23747509A2ULL,
		0x07AD6623367543E9ULL,
		0xD028BD6CFA84E498ULL,
		0x49CC043C269C375FULL,
		0x1573BEBCC7054331ULL,
		0xB9FBAA136494643DULL,
		0xA5F087990C33B7A5ULL,
		0x8FD44CD03606A6B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72819FC53350BCDFULL,
		0x8D14F12C3CBDE679ULL,
		0x7F740A6AECE1FB03ULL,
		0x19767CBC435D2B28ULL,
		0xEA8461D9CFC1D1AAULL,
		0x2E4DD136206C0792ULL,
		0x5CBB29DB9B0234A9ULL,
		0xC2E535ED66CF114DULL
	}};
	t = -1;
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCBAE7EE9995C56E2ULL,
		0xB81E35F02E6389EFULL,
		0x51905EFB3364BA0AULL,
		0x3F69CF154403FF78ULL,
		0xFF37E9F7BF942D70ULL,
		0xEA48B52849E28B8CULL,
		0x8A43569B91F355A6ULL,
		0xCB0C3526514BC0E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBAE7EE9995C56E2ULL,
		0xB81E35F02E6389EFULL,
		0x51905EFB3364BA0AULL,
		0x3F69CF154403FF78ULL,
		0xFF37E9F7BF942D70ULL,
		0xEA48B52849E28B8CULL,
		0x8A43569B91F355A6ULL,
		0xCB0C3526514BC0E1ULL
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
		0xCBF3ECE1B7B7EF0EULL,
		0xCBD322E6203A0B18ULL,
		0xD299519D8DCDCA7CULL,
		0x19FE466EE004DCDCULL,
		0x09B8A3CFE1EF1936ULL,
		0x1D3B0007B775226AULL,
		0x157E8232480B147CULL,
		0xC5C79C6475D1FEA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A2BC60B5BDD798ULL,
		0x96D6D73CF7D1240AULL,
		0xB2A313C360B719C4ULL,
		0x4238D37B25013087ULL,
		0x466779330AC61D3AULL,
		0x769FBD90DBB5B2D5ULL,
		0x25AA3FE99E42D987ULL,
		0xBCB9AB31552FEAA7ULL
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
		0x0E29E9BCA33B4431ULL,
		0xEC48109E1449036EULL,
		0x8611C4F7735251D8ULL,
		0xF49D6ECED0B1C15AULL,
		0xDF55E59771EF8D98ULL,
		0xC82F4017474246B3ULL,
		0x3725A589B18B02F7ULL,
		0x961161C56F7B72A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50B26E311A73CD51ULL,
		0x5F649C3811CC6744ULL,
		0x58EBBCB8F78F9F4AULL,
		0x0E6340D8B24DDDD8ULL,
		0x51A0074CBAD525BBULL,
		0x743E0D94AE8B9F69ULL,
		0x76DD4AE32B71217CULL,
		0xBD808D9CD9E67CFAULL
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
		0x723806BF5EFEA605ULL,
		0xBB2F7C9BB6D517E8ULL,
		0x0A5B43A08914A94AULL,
		0xA25CCFEB61FFB3CEULL,
		0xF36FD9B4E56A9F2DULL,
		0x33DD68D79574A643ULL,
		0xECBCE60AF39E9F65ULL,
		0xFFD210C6512E8738ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CC4E2748A9AEF5BULL,
		0x5D419AF97873AF75ULL,
		0xE78940F6D1F987D0ULL,
		0xF79189F3C38DE765ULL,
		0xFBCF6C213A945A90ULL,
		0x22B9B6DDAADF4BFBULL,
		0x957D10F376E46F6AULL,
		0xA4B01C2A8351096EULL
	}};
	t = 1;
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDA3A005B587622B7ULL,
		0x958FA9A2A419AB09ULL,
		0x10330613BCC864A1ULL,
		0xA9F5B343F3552C44ULL,
		0x531BFA3A7E64D70BULL,
		0x795745A31407E663ULL,
		0x80AF79DF332564F2ULL,
		0xD9ABCC7E736CEC0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA3A005B587622B7ULL,
		0x958FA9A2A419AB09ULL,
		0x10330613BCC864A1ULL,
		0xA9F5B343F3552C44ULL,
		0x531BFA3A7E64D70BULL,
		0x795745A31407E663ULL,
		0x80AF79DF332564F2ULL,
		0xD9ABCC7E736CEC0EULL
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
		0x1C24C5B81CB3E37BULL,
		0xE037C7AED052CBCBULL,
		0x98677908D2A4BF25ULL,
		0x9171A624F70891A9ULL,
		0x32B362459081846EULL,
		0x3643DFBAAEBD8DCEULL,
		0xE83821290EBC1068ULL,
		0xC658CA3C385C8533ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F489C4A8D577021ULL,
		0x2FA87D170E2C5620ULL,
		0x64181A867161CBC3ULL,
		0x66D8391219F648E5ULL,
		0x302E288AF37D8F42ULL,
		0x8832C55FBC3153F0ULL,
		0x88B4B93BCDF8EE70ULL,
		0xD110C03EE0DE77E4ULL
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
		0x3A006441B7B13642ULL,
		0xF914EBDDC5A55A18ULL,
		0xE2DF990CDFE23793ULL,
		0x0B1F97C1F6EA192FULL,
		0xF794F2338A319A6CULL,
		0x3E5256CF2357E9B8ULL,
		0xB9CEE6D78E708DB5ULL,
		0xB612FEBEE1FF3871ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4D7ADD2EBEE1DA1ULL,
		0x0148D4AB2531F039ULL,
		0xAF01419A20736A9AULL,
		0x7965778AF32D5197ULL,
		0x8CFDB50DF79533B5ULL,
		0x8E71FB46B6D13B5FULL,
		0x86B9B81027F23D84ULL,
		0x8338CCB3DFA2E9CDULL
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
		0x7AA7623DE52EE648ULL,
		0x43278D0B2AC24A70ULL,
		0x93EA6AA82563C68DULL,
		0x4F1AF78B55953E5BULL,
		0x327A97296CF1B4D6ULL,
		0x799EC4302449B80BULL,
		0x9A1376BC8A8F2195ULL,
		0x1112A6C4672B39B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB85990F8849D841ULL,
		0x1C25C30F3175EEE9ULL,
		0xD7BEBF2B1C04518EULL,
		0x9D25AA585F0DBE40ULL,
		0x602D6324EE172898ULL,
		0xDAC29B48740DCA6EULL,
		0xF748D92F13B5FC08ULL,
		0xEF747591192C5201ULL
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
		0x89110705CB915224ULL,
		0xB799765CCE9CE497ULL,
		0xCF78B6C86096525CULL,
		0x248AC5C0D189B398ULL,
		0x4FE14F4AAFA7A465ULL,
		0xFF863A2102282491ULL,
		0x5D588452895DD3B8ULL,
		0x0152F65CC2092B1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89110705CB915224ULL,
		0xB799765CCE9CE497ULL,
		0xCF78B6C86096525CULL,
		0x248AC5C0D189B398ULL,
		0x4FE14F4AAFA7A465ULL,
		0xFF863A2102282491ULL,
		0x5D588452895DD3B8ULL,
		0x0152F65CC2092B1BULL
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
		0xE5545DBE8C633DEFULL,
		0x597AEF1A58222E6FULL,
		0x8D8AA6211172FCC6ULL,
		0x4D480FFD0E49B65CULL,
		0x57D0E145A2F24BECULL,
		0xF77D8162DC9F0428ULL,
		0x2BB967111CA39829ULL,
		0x2CDBC1CB616468DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x899053E21DBEB9A3ULL,
		0x74C060AE34F99799ULL,
		0x56F79A7451A6D5EBULL,
		0xA14D4756C5D0843FULL,
		0xD229CAFAF784EF81ULL,
		0x756273949E0D3A76ULL,
		0xB18732A124237D98ULL,
		0x6F17166A25CF0193ULL
	}};
	t = -1;
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x10C8F727CDFED49FULL,
		0xB3436F3F59FF2D40ULL,
		0xD16ECB1A4D20301AULL,
		0xC281E25474F2DC17ULL,
		0x714F20D774F0CB1FULL,
		0x292133EE6233641FULL,
		0x82863A2E3B9A3F45ULL,
		0xF6E1F6827A72F486ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FCF12B5CAB38592ULL,
		0x6D5236C94082F76CULL,
		0x86594CA3C3978837ULL,
		0x72CF7A725CBED62BULL,
		0x4BFA307A0CAD9833ULL,
		0xEE9B7B020180BF35ULL,
		0xF5BE8982BB412565ULL,
		0x36627E636D860414ULL
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
		0x8ADF9CFA2156CDA4ULL,
		0xC2DD2F530B8B4CBEULL,
		0x6EB1159BB6683049ULL,
		0x47B22D37E9056EE1ULL,
		0x0B4E704BC03CC9C1ULL,
		0x4C4896A84B31C461ULL,
		0x48901509815B9476ULL,
		0xA0F8679AEFA4BB8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE5A67D365CEC68ULL,
		0xB66A099840799956ULL,
		0x991189418F8DF432ULL,
		0x76EEB19245244286ULL,
		0xB6DE133B4627924CULL,
		0x1D37F1808886B63BULL,
		0x25DE59B85F6B74A1ULL,
		0xB63C6E84DF731904ULL
	}};
	t = -1;
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5EA5C8B5C8B0FA13ULL,
		0xFF407C231A7208C3ULL,
		0x6DFE4FD9A471033AULL,
		0x1DBBDBB1341D536FULL,
		0x70595434ABF9614FULL,
		0xFB5A5A769A512D27ULL,
		0xCCA1AF24A1C3139AULL,
		0xA5A6681E91896360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EA5C8B5C8B0FA13ULL,
		0xFF407C231A7208C3ULL,
		0x6DFE4FD9A471033AULL,
		0x1DBBDBB1341D536FULL,
		0x70595434ABF9614FULL,
		0xFB5A5A769A512D27ULL,
		0xCCA1AF24A1C3139AULL,
		0xA5A6681E91896360ULL
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
		0xA9255EA77384A41CULL,
		0xD46DFD0DE71B8E2FULL,
		0xF8ED9D0735CA0B0DULL,
		0xFBD0DB57746382F8ULL,
		0xC4FF52810111762CULL,
		0x4DDAE532B36296CFULL,
		0x29E176736EC0A5D2ULL,
		0xA24800C0BA8B3CDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5F2D5F4157B9405ULL,
		0x30A01752D5E39F80ULL,
		0xCE61D2E6F4710B6DULL,
		0xBDC11AD61F858631ULL,
		0xFC6B0ECBB14959ABULL,
		0x363C14A01BBCBA56ULL,
		0x09371DD631934257ULL,
		0x54DB01BD8B8BA129ULL
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
		0x45964A58600EA72CULL,
		0x9A84F5EAD985B2FCULL,
		0xF0AD1DBEF081DB3FULL,
		0x976DA73D8E2BBFE1ULL,
		0x68B1167297C09ECBULL,
		0x3B12929E5779ADCCULL,
		0xB0B001ACB3BF29BDULL,
		0x80643E244C6820A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD9CB64C337C063DULL,
		0xF15EF83C02A06875ULL,
		0x9A6C34ABD5D99483ULL,
		0xB577FF5EE026875AULL,
		0x102773C3E013E87DULL,
		0x492C0FA17F094B3FULL,
		0x0781CFFC08A2DD2AULL,
		0x4C7FFFD0FD57E002ULL
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
		0x57B895E6CE646220ULL,
		0x66C35EFECD101446ULL,
		0xBE6C04ED4AA1E494ULL,
		0x946724ADCC2085FEULL,
		0x0E664C646BF32AEBULL,
		0x3763C31BE98402A1ULL,
		0x855B92BE76A44A18ULL,
		0xB08BB804C57EB32CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C45302403DB3D7ULL,
		0xA7155EDD0EF6C516ULL,
		0xFBA98A3805F8FF29ULL,
		0xBFAE7555166DB1ECULL,
		0xC98CAE25E99818C9ULL,
		0x3FA86AB3C330B88DULL,
		0x3714ED6BF02D0BDBULL,
		0xF75D6126B1C97B21ULL
	}};
	t = -1;
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x66CC7B16EDB2C70AULL,
		0x9D67AF0FC90B6915ULL,
		0xB50111A6ADBDA9DEULL,
		0xB6C303EC2C5D3790ULL,
		0x61EF4794B8A4F612ULL,
		0xD91D19480883B543ULL,
		0x4786983D38D073A6ULL,
		0x1AFD5E644CD2431DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66CC7B16EDB2C70AULL,
		0x9D67AF0FC90B6915ULL,
		0xB50111A6ADBDA9DEULL,
		0xB6C303EC2C5D3790ULL,
		0x61EF4794B8A4F612ULL,
		0xD91D19480883B543ULL,
		0x4786983D38D073A6ULL,
		0x1AFD5E644CD2431DULL
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
		0x51E09F6225A75DE9ULL,
		0xCDDF2E4EC0498C36ULL,
		0x7AFB9A105198583CULL,
		0xABDBD49055EA5F67ULL,
		0x64799FA8F7DB822DULL,
		0xFD07F5336DEF45EFULL,
		0x8ABAF9C2EB111124ULL,
		0x78DCE6A95884DCD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x015A14A2ED910AB6ULL,
		0xF6427BC825F163C2ULL,
		0xD96CB0F253DC54E6ULL,
		0x8A9A5D53E34143D2ULL,
		0x69D5A807BD0F0007ULL,
		0x3CF01370734F27B5ULL,
		0xC3BC65854E33717FULL,
		0x4278CCAC16F81AA4ULL
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
		0x9A048E3D5A16FEC7ULL,
		0x14345CABAA8DA19FULL,
		0x8571972C4DCE6CD0ULL,
		0xF991F9AFC265CE71ULL,
		0xF809205C77C4FC0EULL,
		0x65CEE75E453708CCULL,
		0x2CD1A4BD4E13C88DULL,
		0x479BF71033AEF686ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C81357D47EB39A6ULL,
		0xD83096AF7F9146EDULL,
		0x4201BAB4110570FFULL,
		0xD1BCB38FCADD2C52ULL,
		0x30E7F03388A5FD95ULL,
		0x59BE47BEB3AA7BB5ULL,
		0x3B32A20CA32D5875ULL,
		0xD9B32DD20E497EC4ULL
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
		0x8BCD7849CC380E7AULL,
		0xF92661055609D2B4ULL,
		0x5643A22AAF924846ULL,
		0xC9CF4F63C04EBBC9ULL,
		0xB6BF5A2D0DE2D393ULL,
		0x5A832891B9B9030BULL,
		0x0F1CA03B76A6E84EULL,
		0x87E5C09BDEA66D61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C32BD3094D6D0BAULL,
		0x1F0E0C93A6B9383FULL,
		0x8723CA281C53FAC4ULL,
		0xE29FBD5A3889A268ULL,
		0xDD86B5AEA8DA87FDULL,
		0x43BD4213960766F9ULL,
		0xF7AC3A2CB3581C14ULL,
		0x8EC7F8085CB07284ULL
	}};
	t = -1;
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8E5B75E4F6205E84ULL,
		0x0661D0CD6DFA6AECULL,
		0xE7FCF4295D65F4C5ULL,
		0xB217FB12BDDB3044ULL,
		0xA05863DDB6B5D443ULL,
		0x5A89FDE462530B9FULL,
		0xA997E6BC4A6519BEULL,
		0x51856FA050F76B91ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5B75E4F6205E84ULL,
		0x0661D0CD6DFA6AECULL,
		0xE7FCF4295D65F4C5ULL,
		0xB217FB12BDDB3044ULL,
		0xA05863DDB6B5D443ULL,
		0x5A89FDE462530B9FULL,
		0xA997E6BC4A6519BEULL,
		0x51856FA050F76B91ULL
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
		0x2083AFDD5646500EULL,
		0xEAFD5D24BFB7972BULL,
		0xC2F1AC4BB81D924FULL,
		0x5600BD9AD185DB90ULL,
		0xE3DD6A8072E374B1ULL,
		0x2B913E5DDD489D26ULL,
		0xDA65087D66840E7EULL,
		0x5A4A6D36DAAC9877ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7DE513A564C15C1ULL,
		0x6A4677F5A2EC9709ULL,
		0x588DD9C53067DE02ULL,
		0xBC79CB93E5200C97ULL,
		0x6B4FF6F1C4290FD2ULL,
		0x9BE6B1C38BFD4CF2ULL,
		0x51EC5CB435086BE1ULL,
		0xFD0854E6E4B363EFULL
	}};
	t = -1;
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1AFC85B3335FDA85ULL,
		0xAD23A3E589C7D30EULL,
		0x7056B3720E80A320ULL,
		0x62802A9BF3FD5F58ULL,
		0x4AAD6EF836B56649ULL,
		0x2FE613777C9C121EULL,
		0x118D1922608A7C3CULL,
		0x710F7FAF4229677EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3594F23179518CE4ULL,
		0xA1CCAFECF28015AEULL,
		0x948F7A1021A36D09ULL,
		0xE1B0A8C0EA99B649ULL,
		0x142D603AE6F70618ULL,
		0x1518C3E115CF3094ULL,
		0xBCCC4742C9F1A9E8ULL,
		0x2168D17DF9870021ULL
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
		0x7848E9B5545FE65BULL,
		0x2EDA531B3FFFDD9AULL,
		0x7AE27D94B6F33E39ULL,
		0x37C25D4264F6683AULL,
		0x7237D581FC4F3865ULL,
		0xA252337D1F30D0F0ULL,
		0x5CB4975186B2FE74ULL,
		0x087DE5BCDFABEDCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51BC535D38E30266ULL,
		0xBCE0ACE011E10E4DULL,
		0xC983F9AB3DB6B630ULL,
		0x17CCA228DCAB3D52ULL,
		0xBFEAEC02000565ECULL,
		0xB7B60C0CD7C6889EULL,
		0xB7A651E285BDDF96ULL,
		0x5813594374BFB992ULL
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
		0x847AC1C6C1BC861BULL,
		0xF1D82962DA8AAC64ULL,
		0x1A0F02C8D7703FA9ULL,
		0x9EFDA6095D49597FULL,
		0x0FB046D7B818D2D2ULL,
		0xC73846A96ADC519EULL,
		0x9F4A1026FE92E985ULL,
		0xD99A75665F01CB90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x847AC1C6C1BC861BULL,
		0xF1D82962DA8AAC64ULL,
		0x1A0F02C8D7703FA9ULL,
		0x9EFDA6095D49597FULL,
		0x0FB046D7B818D2D2ULL,
		0xC73846A96ADC519EULL,
		0x9F4A1026FE92E985ULL,
		0xD99A75665F01CB90ULL
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
		0x379E70E87F0C6765ULL,
		0x2D65995FD499CF2AULL,
		0x0B475FE824AF151EULL,
		0xA0EA1E5E6B617A2CULL,
		0xDA524B02C6CE95C3ULL,
		0x314BC2AA71F30997ULL,
		0x0DAE69C3E2A3FBB4ULL,
		0x25B036329E32BF1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x217A3BCB0E7C5C7FULL,
		0x73C20C5925823413ULL,
		0xF2DEA7FDDDB54464ULL,
		0xC107A08FF85615B5ULL,
		0x3DDF9864D38C8CBCULL,
		0x2B387F6F1CCC0DF7ULL,
		0x2B0B0953C6145594ULL,
		0x9C89C5F83543799CULL
	}};
	t = -1;
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEFF6C751B20F84B9ULL,
		0xC0E09D8FFA94866EULL,
		0x6017E9D4B084027FULL,
		0x20C92DF1B7EA929FULL,
		0x28D1C7127FC6BA9BULL,
		0x77001E5EAC2E5BBFULL,
		0xC3CB5BC5C5BCE7B2ULL,
		0x30DBF6908D305603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93676E717EE8270CULL,
		0x3DF048591CA4582AULL,
		0x9FAB3B2DC819BF93ULL,
		0x76EE9A57D1B5A912ULL,
		0x119114E23FD1E40FULL,
		0x4E50724480BFFD39ULL,
		0x5CD92DFAC71B1715ULL,
		0x4A853EC36D3BEDBBULL
	}};
	t = -1;
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDD0F8EB128A078D1ULL,
		0xC9407713D1A40C53ULL,
		0x148A806FAB01E55BULL,
		0x900C9CAC7D419F85ULL,
		0xD4AF9E6CA06E75D0ULL,
		0xA2D45C6F4E4DEE53ULL,
		0x86FB00ACD3BCF5CBULL,
		0x8D08F59B02A58C8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7352EFFC2F512BA5ULL,
		0xE2EB8DE947B6A01EULL,
		0x6124130ED5DC55EAULL,
		0x333A5FEE1CC10C81ULL,
		0x3BBA6DF374B025F6ULL,
		0xA2D7A98C34CEF065ULL,
		0x1EBB914BF4A1C1A3ULL,
		0x11125A4A35F64756ULL
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
		0xF366B7F6C428F012ULL,
		0x7CA492FF534442D7ULL,
		0x009914F3717483B8ULL,
		0xF91D5CBD4A817853ULL,
		0x1D211F99D3EE584CULL,
		0xADC2BA680EC03423ULL,
		0x1EA0846D267BDBCAULL,
		0xAA4C225697144AC1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF366B7F6C428F012ULL,
		0x7CA492FF534442D7ULL,
		0x009914F3717483B8ULL,
		0xF91D5CBD4A817853ULL,
		0x1D211F99D3EE584CULL,
		0xADC2BA680EC03423ULL,
		0x1EA0846D267BDBCAULL,
		0xAA4C225697144AC1ULL
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
		0x798C803305D2C5B1ULL,
		0x00D3036E4190F5C6ULL,
		0x5C5FCC0DDC0D23ABULL,
		0xE872EBAC2D118062ULL,
		0xBE4B4AC6B2EBB5ACULL,
		0x929F04427205FD95ULL,
		0x1C5E63170CD4C006ULL,
		0x73FD7311D5113794ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE9966887B3C42D7AULL,
		0x7D8DC8FA2DC045E2ULL,
		0x6B113B9FC31E153AULL,
		0x9BB3005C74169BA9ULL,
		0xECE9D815DE0C02BBULL,
		0x81DA4FC20C5366EBULL,
		0x22084CE8781AA2F9ULL,
		0xC3453D5ACE165C3FULL
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
		0x6C7707FB52757A86ULL,
		0x614203F5FD6EB5F2ULL,
		0x6619EA616EF4E289ULL,
		0x691C55073E9A2162ULL,
		0x41014BADD5A66607ULL,
		0x80C0EFDC7EB11305ULL,
		0x8764841F9A69ACA0ULL,
		0x551A216F7008B79FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C6EB25BF2FF87ECULL,
		0x0CB955597DBFDB77ULL,
		0x5ED44A99E3B3D505ULL,
		0xBCE39B02B548716EULL,
		0x782AF664D280E227ULL,
		0xA0974A9196BCAC29ULL,
		0x15FA14AB42246CEEULL,
		0x165903192C7EB165ULL
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
		0x2AA93AB3FA5078B4ULL,
		0x50EC2C6563719053ULL,
		0x7CCC3CA60283D3C5ULL,
		0x7A2174B612EF9A2FULL,
		0x6EEDC9102E1B05ECULL,
		0x1D8084CDCA710160ULL,
		0x04908C55189009E6ULL,
		0x19185C8264CEAA39ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1702987369B2F863ULL,
		0xCAEA0A7D1A54056BULL,
		0xD49A3663A1B7773AULL,
		0xC8D2010E53F91891ULL,
		0x9BAD0AAAED7BCB5FULL,
		0x7D6F721F788B4E08ULL,
		0x0445D55E3FB6164DULL,
		0x0AA59D5786B3195DULL
	}};
	t = 1;
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5E3F0CABA3C214E6ULL,
		0xCF4452CE8FF1FD29ULL,
		0x88BE7DE51DB67D2FULL,
		0x0C2DD336CAEDCD4AULL,
		0xC68FB781EE4C7C86ULL,
		0xF58EC28DDDCC18D6ULL,
		0xB28A465359FACAE1ULL,
		0x775DC5ABAF5A5EDEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E3F0CABA3C214E6ULL,
		0xCF4452CE8FF1FD29ULL,
		0x88BE7DE51DB67D2FULL,
		0x0C2DD336CAEDCD4AULL,
		0xC68FB781EE4C7C86ULL,
		0xF58EC28DDDCC18D6ULL,
		0xB28A465359FACAE1ULL,
		0x775DC5ABAF5A5EDEULL
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
		0x65BB519737EF8F67ULL,
		0x1E2B08C8140863ACULL,
		0xB4DDF45D132C8011ULL,
		0xA783344BB279727AULL,
		0x19AD3E5B0219E8B6ULL,
		0x76C133035C8457B5ULL,
		0xD623D419A33BFBACULL,
		0x5E48F718A61275D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3F78EBC928F0F4AULL,
		0xC3524B64796E28D1ULL,
		0x95438CA656148AA7ULL,
		0xC31059453B17B113ULL,
		0x21674DAF5B2B4CEBULL,
		0xCFCA0E201D160F4DULL,
		0xCBF79AB6B4FB4B78ULL,
		0xE848F479E7E2AF3FULL
	}};
	t = -1;
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x94CB27A047650740ULL,
		0x5EDE3DBD3ECA7925ULL,
		0xC5412203BBAA4749ULL,
		0xFA3BF020501B9884ULL,
		0xCFF00417C0E6AB58ULL,
		0x2D52ACD74BE8DC20ULL,
		0x6696AB47FBCFA2F3ULL,
		0xFC2D4FFA533887B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC65EC3B6E077A97ULL,
		0xD134E2226D27EAFEULL,
		0xC96C301A1A2BBD99ULL,
		0x38F8D368C9656AD0ULL,
		0x7E31385D5FA86613ULL,
		0x6CDE4475F15998D7ULL,
		0xCD8DB3CC9E8FE54AULL,
		0x5A349AA37C735DB6ULL
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
		0x5ACAE2455A081777ULL,
		0x089C66F57A84BF23ULL,
		0x346C507CD79A5672ULL,
		0xA068453265B34550ULL,
		0x1DD04A7E04825938ULL,
		0x394DFF954E129AAFULL,
		0xD84CE6C98806A2EAULL,
		0xDE25A581591BB809ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21A1850F8EFA8E65ULL,
		0xB121A4404D87FA87ULL,
		0xBE395FB99D07E4E1ULL,
		0x65B5174C4F8C9517ULL,
		0x5E5DF3D022535E8FULL,
		0x6B2240364E6578F1ULL,
		0x9690013E73F3B11CULL,
		0x7BCE7E5D9A9DD347ULL
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
		0xAE16FE4742C075BDULL,
		0xF9C1D81F9A1B7EFDULL,
		0xBD2DB4DED13A8D7BULL,
		0x1E35A95D2F9B3ACCULL,
		0x2ED1D21B5F78D85EULL,
		0x58B6CEE5C7513B94ULL,
		0x52D1DCB9A99028B4ULL,
		0x8039A5D1DC64D42BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE16FE4742C075BDULL,
		0xF9C1D81F9A1B7EFDULL,
		0xBD2DB4DED13A8D7BULL,
		0x1E35A95D2F9B3ACCULL,
		0x2ED1D21B5F78D85EULL,
		0x58B6CEE5C7513B94ULL,
		0x52D1DCB9A99028B4ULL,
		0x8039A5D1DC64D42BULL
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
		0xBA1E0CABEE104894ULL,
		0xBA9F44F4896FCDB5ULL,
		0x639C6F4F7A569C2EULL,
		0x6C6FF1C4BF27839FULL,
		0xB1F6C68AFF00DCD7ULL,
		0xF643C3472D675B3FULL,
		0x438357441A872F79ULL,
		0x5D072C93E0829555ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFCFEC975D371E844ULL,
		0xAAE2E6FAFF6B4EA0ULL,
		0xF318EAE35265BBA8ULL,
		0x129B11399D29C218ULL,
		0x9FEE620ED600274AULL,
		0x83237B8BBB3019E9ULL,
		0x18C0CBC0C2404F7AULL,
		0xF556C01C3F0876C4ULL
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
		0xA5BC5FD1CFAD8A50ULL,
		0x0228043C2001561EULL,
		0xCC342DB0F811034EULL,
		0x25DE58CC3FBDD908ULL,
		0xCA60272A2F45D6C1ULL,
		0x8D776DA1B94238C6ULL,
		0x2E0AD355E2EE8C70ULL,
		0xE514A07447AE7219ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDB7327C2A87D344ULL,
		0xEA0C5494208FF908ULL,
		0x2D32EC96D7F71F13ULL,
		0xC401CBABC09BF269ULL,
		0x2A3EE912D8BA3B63ULL,
		0xB7F9FECC2E058BE3ULL,
		0x1C7A4A5050A1C1DEULL,
		0x3193FB8A277219E0ULL
	}};
	t = 1;
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x23C3FC8932645F81ULL,
		0x7E880830D73B2ED1ULL,
		0x8460D984966B939CULL,
		0xA42F51F2FDB544E6ULL,
		0x246748459910EE92ULL,
		0xEBE5E3B05509A1D8ULL,
		0x3E08AC2B4398EB28ULL,
		0xC38491DAFCB70AFDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B0F834B27437E86ULL,
		0xB9609ADAA012CB21ULL,
		0x5F700375FF398524ULL,
		0x13C354A2C0503838ULL,
		0x6D0BF1E119B910CDULL,
		0x9CAD6043FA1492FAULL,
		0x6FBE0AF8FC91796CULL,
		0x1BF3AAE5EA84E72FULL
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
		0x6F1AAA7733EF63D4ULL,
		0xF5340DC9ADDDE9B9ULL,
		0x0F2D4BB019C0678AULL,
		0xD978E8719CABD95EULL,
		0xC694C649EDE00675ULL,
		0xD00C300D89F4DDE0ULL,
		0xA557433336F93B73ULL,
		0xBC0688A7E3D384BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F1AAA7733EF63D4ULL,
		0xF5340DC9ADDDE9B9ULL,
		0x0F2D4BB019C0678AULL,
		0xD978E8719CABD95EULL,
		0xC694C649EDE00675ULL,
		0xD00C300D89F4DDE0ULL,
		0xA557433336F93B73ULL,
		0xBC0688A7E3D384BDULL
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
		0x245D79C049A39705ULL,
		0x9BBAFDBAFBF09F25ULL,
		0x7D3726F594CEB9D2ULL,
		0x0B80C02FA56C251EULL,
		0x2079C7937C1CF2C5ULL,
		0x561AB576FBB32216ULL,
		0x4CD4B5077C751D51ULL,
		0xD7038320BEFDD4EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x353E1B4DA75E4EFAULL,
		0x4BC0D6EF02A86804ULL,
		0x9737F920B82A0A12ULL,
		0x275A7E37D1BF0294ULL,
		0x14353758FE74B735ULL,
		0xB2386AF856673041ULL,
		0xCEFF848D9EE5FE88ULL,
		0xA4330EBD8E676164ULL
	}};
	t = 1;
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD7E7F71D59EF6937ULL,
		0xC6CE2FFF94007A68ULL,
		0x6914B13960432FBEULL,
		0xC84A871413C2D43DULL,
		0x322246CE7FE1490EULL,
		0x7FFA3A65AABD2D14ULL,
		0x8ECCF0F1BB2FBEF0ULL,
		0x3C07F20534052CDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D4D5D6E24A63EA9ULL,
		0x8DBD937F1BF3B1E2ULL,
		0x103DB4AA0DDE23CFULL,
		0xA67AE14CBC24A3D8ULL,
		0xB7218DA2C80632F9ULL,
		0xC98C7F94183E5D9AULL,
		0xF25B932DBC229671ULL,
		0xB14D121C6CD32F92ULL
	}};
	t = -1;
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB9EDA6884D1258C7ULL,
		0xF5047A314EAA46E8ULL,
		0xA05CBD0CBAD2F9B7ULL,
		0x504CC606D53DEEF6ULL,
		0xADBA58243FA46834ULL,
		0xAE0430D9BF423315ULL,
		0x4B75EA34772EFE10ULL,
		0x7942A1D83CB0CF59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA66678848018853ULL,
		0x7A12A3C7984A60ACULL,
		0xB8DD31DF6F1BC5F6ULL,
		0xF87BC10A7CADB460ULL,
		0xCFBBFF2732142F86ULL,
		0x622D2DAD0E7B7F4DULL,
		0xD38021785C7AF543ULL,
		0xC86B76F0257E48FFULL
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
		0xA86AAE20658F0180ULL,
		0x01B97FAC66433F88ULL,
		0xDEF6CBBDA04CC9CCULL,
		0x1839324E96813E99ULL,
		0x76A7FF871D415F77ULL,
		0x10ECB27FEE272023ULL,
		0xE1B7670054934D85ULL,
		0x45CBEC214B2BD6EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA86AAE20658F0180ULL,
		0x01B97FAC66433F88ULL,
		0xDEF6CBBDA04CC9CCULL,
		0x1839324E96813E99ULL,
		0x76A7FF871D415F77ULL,
		0x10ECB27FEE272023ULL,
		0xE1B7670054934D85ULL,
		0x45CBEC214B2BD6EFULL
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
		0x0A1719FA984F6220ULL,
		0x65E8AC4C378025F4ULL,
		0x0C07F586A13943D5ULL,
		0x92A8700FC6ED19A3ULL,
		0x457F2693E52788BDULL,
		0xA9D434641A7225B7ULL,
		0x704A81E2EB49EAE8ULL,
		0x0A90BBBB38E05060ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1331FED2BEE57571ULL,
		0xCB153CC6AC23A922ULL,
		0xF65E3F072828BBB3ULL,
		0xE463CC8AA69750DAULL,
		0x21BE0A335E295F43ULL,
		0xB4795E7D72635735ULL,
		0xE14B261E1A83E82FULL,
		0x983517694AC0C018ULL
	}};
	t = -1;
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xDB6269A5FCFC2A6CULL,
		0xD9F833A5496AAF66ULL,
		0xD49E9D47CB628C4BULL,
		0x3DDD104C6D66363DULL,
		0xB58228A9E04EBC05ULL,
		0x6E7954E1312B305BULL,
		0xE7096B6274A7255AULL,
		0x10F4DACF367A8F2FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25BCF96BA0592BC6ULL,
		0xAE022A924F64E083ULL,
		0xAE28C8CC446C723CULL,
		0xD6FCF17094B21170ULL,
		0x29EB59FF13D4B43FULL,
		0x45562E6452C54A0EULL,
		0xFD347DE3A82DC1E8ULL,
		0x7B2DF4FB513D2C0BULL
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
		0xBA9BF7118130D586ULL,
		0xCFA8DBACDC72356CULL,
		0x330680CFFB8A63C0ULL,
		0x7AB3B89AC85545D7ULL,
		0x9E6DADF965E43D49ULL,
		0x901EA3844CEABE4BULL,
		0x208DBC7EA5544CC6ULL,
		0x8806C9A5CF2A192EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E26ED9D9809115AULL,
		0x91EF690248DA10EAULL,
		0x25A68F92709D2D26ULL,
		0x6E4CB35301F24976ULL,
		0xEFBB8E83F988982AULL,
		0x330F4E59C9EA5FAEULL,
		0x186809FDE979CFE3ULL,
		0x21D11A35639BD213ULL
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
		0xCAE206F140AB3879ULL,
		0xE5F7294D9239920AULL,
		0x49DC2383FCEF8034ULL,
		0x52B8B9BDC97DF298ULL,
		0x9380A7911618EB88ULL,
		0xD972B3ADFBBCC03CULL,
		0x9C4462E8AF15FED9ULL,
		0xD9F07A01803A7D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCAE206F140AB3879ULL,
		0xE5F7294D9239920AULL,
		0x49DC2383FCEF8034ULL,
		0x52B8B9BDC97DF298ULL,
		0x9380A7911618EB88ULL,
		0xD972B3ADFBBCC03CULL,
		0x9C4462E8AF15FED9ULL,
		0xD9F07A01803A7D46ULL
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
		0xF576A920894351DAULL,
		0x0AC532437CE99707ULL,
		0xC205D0F6FFA4CC29ULL,
		0x234969E0A93C5E12ULL,
		0x1A89EC19F6010EABULL,
		0x6DBCDB6FC99F08F2ULL,
		0x245055F23E767F6EULL,
		0x63C4CE4E7F3AFC50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB385E068E9B925EULL,
		0x39EB08602905B3D7ULL,
		0x570584BD9818F808ULL,
		0x1FD4577AB9BE3C96ULL,
		0x2FC1DC7C661188DEULL,
		0x5354DDB0268E0ACEULL,
		0x22AA96F855CA967BULL,
		0x0934C714120EAE69ULL
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
		0x42B8C204D8CE9728ULL,
		0x20CE384D55C3688DULL,
		0x1019725A379CE282ULL,
		0x51C3A9F00A0E4627ULL,
		0xEC30C5F6322D216EULL,
		0xCAFD5291F735A6CBULL,
		0x789B435E3375F774ULL,
		0xF68920209CD66BA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0D4B06A06FA28A04ULL,
		0x0F7EDC37827B96B9ULL,
		0x2D3D72F293BAFC3CULL,
		0x0A43965CE1C2E8E5ULL,
		0x3EA8401FE36413EDULL,
		0xC72E65A945B2E6EEULL,
		0x7A63AE0724CDFF02ULL,
		0xCBD55526E38A11A6ULL
	}};
	t = 1;
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x04213CD79150E69CULL,
		0x6D744D5768FD5376ULL,
		0x7F7F6A7D96B91FD4ULL,
		0x3943939047120FB3ULL,
		0x792179D5569B0737ULL,
		0x80F6A851FD71112FULL,
		0xED4D13C7D99FD94BULL,
		0x1678814A1473C26DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D4C29BC0592CB51ULL,
		0xEAEC283619F4E52CULL,
		0xD432A02DF051C856ULL,
		0xCACB96F06005011CULL,
		0x2CF18B1FB47D89E0ULL,
		0x7BAE21607F26A5E6ULL,
		0x85A2292783D0012FULL,
		0x5CBD540522D86D87ULL
	}};
	t = -1;
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8512B08232B6FC28ULL,
		0x11B0FD0014D8BE41ULL,
		0x94ABE43B222546A2ULL,
		0x0C859FC9D2A129F7ULL,
		0xF16F95270C1944C7ULL,
		0x354CF4ABD6655B92ULL,
		0x4223B4C52033BED8ULL,
		0x98F9D04C001523A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8512B08232B6FC28ULL,
		0x11B0FD0014D8BE41ULL,
		0x94ABE43B222546A2ULL,
		0x0C859FC9D2A129F7ULL,
		0xF16F95270C1944C7ULL,
		0x354CF4ABD6655B92ULL,
		0x4223B4C52033BED8ULL,
		0x98F9D04C001523A3ULL
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
		0x3E8FE6CE8F00D4ECULL,
		0x090BC5493CADBADEULL,
		0x643E0E580A8B21EDULL,
		0xB175179EEBD59EE7ULL,
		0x1CF8FB1739C87969ULL,
		0x867DD2634359B0CDULL,
		0xF2848F5A7B1C2AA2ULL,
		0xEDAE595D6CA0DEEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97D5B2C6990ED0DULL,
		0x6AE9B0326059D361ULL,
		0x34BB18B53B4003BDULL,
		0x663A9A10D3D4FB30ULL,
		0x139FB61F122F71B1ULL,
		0xBA99506C12020607ULL,
		0xACF39434F1EFDB46ULL,
		0x60FB06D67A748594ULL
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
		0x4C7B9E417F74FA62ULL,
		0xE3D37477B14141DEULL,
		0xEBF29488C53DD998ULL,
		0x316235C6B8A3FD45ULL,
		0xC06E40903A3A4528ULL,
		0x2633D4882006D116ULL,
		0xA13B0CEA6CEA58CFULL,
		0xF67505B484F03C61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5A7E285A3AA2E45ULL,
		0xE1F68EA6F3B304E8ULL,
		0x160B710984C44D1FULL,
		0x5CDDDB7329C9399FULL,
		0x4009755DCB1CD239ULL,
		0x2743F72DC3A3114BULL,
		0x679C92D4DDD1DEF4ULL,
		0x0AC2F5209E3DAC11ULL
	}};
	t = 1;
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x679B5E6063C3A864ULL,
		0xC214FF6483FC23F3ULL,
		0xFE47006F0A71018DULL,
		0xAAD14A84A9D216FBULL,
		0xDFE759AD4D160D8FULL,
		0xF0EA335A18B0B1A9ULL,
		0xC28B7C11DE5C5216ULL,
		0x16E41D10BA0DF3F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6F37810626F85DDULL,
		0x7372E09E5C2A37CAULL,
		0x19862D5FF39D48B7ULL,
		0x5346814188F1703FULL,
		0xCF4B3D2EB52B72F8ULL,
		0x7B68A3402E5B7D47ULL,
		0xCCC2C48E46D9672EULL,
		0x23748E07101B1623ULL
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
		0x70D1A494B5D66985ULL,
		0x49E33B542E455CC7ULL,
		0x8EE68CCD2A49E0C7ULL,
		0x636207D41A0BE037ULL,
		0x584360135F29EE0DULL,
		0x5CE4668F7122A66CULL,
		0xF370144B923EEC98ULL,
		0xD6EBA9B6C9211244ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x70D1A494B5D66985ULL,
		0x49E33B542E455CC7ULL,
		0x8EE68CCD2A49E0C7ULL,
		0x636207D41A0BE037ULL,
		0x584360135F29EE0DULL,
		0x5CE4668F7122A66CULL,
		0xF370144B923EEC98ULL,
		0xD6EBA9B6C9211244ULL
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
		0xF2F8A720A2BA0810ULL,
		0x7355D35F95B79695ULL,
		0xAF23F01C13824151ULL,
		0x3D730C951A66F9E8ULL,
		0x4518F279DECCEB1CULL,
		0x9DF898A72F986B07ULL,
		0x2F7D3893A3C119BBULL,
		0x577AAB232963B1DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261E3AD7DCB7A9C3ULL,
		0x0B7F885FDF7FD0CFULL,
		0x16FC412BC6E9E31FULL,
		0xE42E4B5157F27B40ULL,
		0x3D96F13B2A711578ULL,
		0xAC4C9FCB6BC0C10BULL,
		0xBB1641775CEDF46CULL,
		0x27829F2A979A515CULL
	}};
	t = 1;
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF3B250B440264A5EULL,
		0xC7CF8A8562946DBDULL,
		0xADC66796CBEBDD01ULL,
		0x50775981BDB959B8ULL,
		0xDF70F11A82FD6193ULL,
		0xEE196B257C54F285ULL,
		0x83D2DED0DDCF27C9ULL,
		0xDE2E6062C361EF8AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x993109727B00F028ULL,
		0xE8D9FFC9E1D706A1ULL,
		0xB2C3E7AD5DECAD93ULL,
		0x379EA84EC7DA560EULL,
		0x2B4238491203B146ULL,
		0xF5FA95E6EE84D64EULL,
		0x8E56A21BCEFDAA08ULL,
		0x0A3318354C8FC5BCULL
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
		0xB6E78513C4224ECAULL,
		0x3F7AA49DCA550B7EULL,
		0xFA079B8B41CBF920ULL,
		0xFD16F8CE0173D567ULL,
		0xB531E3926728BABEULL,
		0x09F08C4EC55CE7B2ULL,
		0xD9A56BFCEEBDF527ULL,
		0xEC6801AE36D5F0CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE10C902782709DD3ULL,
		0x5B21E0A9E750C740ULL,
		0xF3922777E64E374EULL,
		0x0993ABA8B30F1C39ULL,
		0xC8115C3210E7D6B8ULL,
		0x322664EBE71DD073ULL,
		0x79FA6FD8EF4653E8ULL,
		0xAE90966EA1737D7FULL
	}};
	t = 1;
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0CC31716CD40F849ULL,
		0x297DAB06A15BA783ULL,
		0xD66B1CC60C509ABBULL,
		0xE30C33CF2678D3B1ULL,
		0x74F36004529CA7BAULL,
		0x4A8322F5A13412E2ULL,
		0x51C54A57160E3DABULL,
		0x8EC99E59FB177636ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0CC31716CD40F849ULL,
		0x297DAB06A15BA783ULL,
		0xD66B1CC60C509ABBULL,
		0xE30C33CF2678D3B1ULL,
		0x74F36004529CA7BAULL,
		0x4A8322F5A13412E2ULL,
		0x51C54A57160E3DABULL,
		0x8EC99E59FB177636ULL
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
		0x374B8B0CF7AC8962ULL,
		0x6AEDE908827679BAULL,
		0x8D72C96FF0EC931BULL,
		0xC382612AF851C46EULL,
		0x352438C89E62F0CFULL,
		0x69F1044BB2232BADULL,
		0x011FB027E46A0BC1ULL,
		0xA58E84300C8E01BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC758CBD1141F886ULL,
		0x7E72EB64CC91152BULL,
		0xDF54A3BEDE9D25BCULL,
		0x2159F283C3AD487AULL,
		0x0AF3FE4C6C568E74ULL,
		0x6CE8CA5070535314ULL,
		0xD50B244610888D15ULL,
		0x4EA554A039649A6FULL
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
		0x54BED5F7D6AAF98EULL,
		0xAF98A72E07302A54ULL,
		0xFD77BB30B08CBAB7ULL,
		0x4C51F930727056DDULL,
		0x39ED8F3726B7FEE6ULL,
		0xB1B1125A1EF7C9FFULL,
		0xE6283DDC0804F748ULL,
		0xE7B0EC250780752EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6588BE35D03BA004ULL,
		0x9DE6B17ED172534DULL,
		0xA93D7E5A54A96ECBULL,
		0x4A7A0060D8718614ULL,
		0x9CF36A1DFA8B7CB9ULL,
		0xAA68500513D51D80ULL,
		0x56B9EB4C7BE3F430ULL,
		0x6FA79498D3C463E6ULL
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
		0x8BDB3E0C2FE061C7ULL,
		0xC2B48C2DB98F86D8ULL,
		0xFB5D1D38DC3AD806ULL,
		0xEDBD56D91BE3FE22ULL,
		0xC70A48F1133C7F8AULL,
		0x8AA623A7C3D2C2AEULL,
		0x27877C67F1FD6687ULL,
		0xCC40629D3BB74712ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB4DAB7229B9C303ULL,
		0x47D917C6C5005BEAULL,
		0x7323681A85658A88ULL,
		0x74012C0B215B91D2ULL,
		0x253DDD01BCFF5FA7ULL,
		0xDF7A7C16E0178947ULL,
		0xAFDAABB97EB8E2A7ULL,
		0x8484A8CE6B1480FFULL
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
		0xC73B4E0E81A9E359ULL,
		0x5AC2AC1AA7745572ULL,
		0x25077E5DEBC4F322ULL,
		0x7978BC48841A8894ULL,
		0x211B1FAF94FA8B4CULL,
		0x6436373D9A4DAAC8ULL,
		0xBFA6CF3E96B23C43ULL,
		0x262AA2F0C17BBDC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC73B4E0E81A9E359ULL,
		0x5AC2AC1AA7745572ULL,
		0x25077E5DEBC4F322ULL,
		0x7978BC48841A8894ULL,
		0x211B1FAF94FA8B4CULL,
		0x6436373D9A4DAAC8ULL,
		0xBFA6CF3E96B23C43ULL,
		0x262AA2F0C17BBDC9ULL
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
		0x466BACB5506E566FULL,
		0x693E5484425A219DULL,
		0xC21884E1CD217A58ULL,
		0x905AAA80893A0771ULL,
		0x723B86CEF19464ACULL,
		0x7DF87D9C280B86EFULL,
		0xC83C9ECB37565535ULL,
		0x18E568EA470A80D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B7BCA123E73760FULL,
		0xD77F80BEE129ECC7ULL,
		0x65E7681FC9438417ULL,
		0x42B93884BDF6DC96ULL,
		0xD4D1E884D1A2ADD1ULL,
		0xAA863F9E5072BE83ULL,
		0x0DAA76D420716E9CULL,
		0xF6E551E69959087EULL
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
		0x35D6238E41B9E8E2ULL,
		0x4B5D35463FF6514DULL,
		0x018136A59782AD69ULL,
		0xCE71B22B34CA009FULL,
		0xBF66587D20D490F4ULL,
		0xA9F3F1705FB476F7ULL,
		0xD756BB5BB7553E95ULL,
		0xF7F22C5854CFB750ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7EF72AB2DFA81E2DULL,
		0xB6F023AB665093CAULL,
		0x701229F147FB2B54ULL,
		0xB32FE9476E9D335DULL,
		0x1C53C85F60C6DE13ULL,
		0x03AE712A725CB65AULL,
		0x513BD18864FD4D2EULL,
		0x0446A6845CA66399ULL
	}};
	t = 1;
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCCAB5267DAC1E055ULL,
		0xA6E3B4E4737EAEA0ULL,
		0x63EE668786A58D55ULL,
		0x19B334D8BD272531ULL,
		0xB68EEF95F32BC8F3ULL,
		0xEADC98885B0BCF86ULL,
		0x9FF732CAB36FEC74ULL,
		0x69645F7F13FA95EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AB8D96E44B66B1AULL,
		0x89D6169B7BA3581DULL,
		0x872417EC22D24F0FULL,
		0x26E7BE3A72E56794ULL,
		0x1D93904E3DA5C477ULL,
		0xAF6B9E902C11EA18ULL,
		0x48F053B34197DE85ULL,
		0xF785A52070AC82E4ULL
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
		0x1A5A381DE119FF58ULL,
		0x330C2CBC6398114CULL,
		0x7495E10D068DA6B1ULL,
		0xF25A0A913B15D36DULL,
		0x435A2504A6D1910BULL,
		0xDA06521000BF9AFAULL,
		0x5C9C9921BB2F1081ULL,
		0xDCCECFB131C06ECCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A5A381DE119FF58ULL,
		0x330C2CBC6398114CULL,
		0x7495E10D068DA6B1ULL,
		0xF25A0A913B15D36DULL,
		0x435A2504A6D1910BULL,
		0xDA06521000BF9AFAULL,
		0x5C9C9921BB2F1081ULL,
		0xDCCECFB131C06ECCULL
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
		0xD1B11911B6B53ACDULL,
		0x304A7BF8B90B3B8FULL,
		0xC3430E7451194120ULL,
		0x6EE811034C946323ULL,
		0x3739EA305D9E19CCULL,
		0xBBEAF875F1471ECEULL,
		0x022AA33D19C109DCULL,
		0xD897F721F590C0F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9FD6B085BAABBE60ULL,
		0x7BD6840D1D8D025CULL,
		0x6B4BA3D87E9916DFULL,
		0x030B61D82402F48EULL,
		0x7B17F787196B11B2ULL,
		0x5E2BE0059DCA5952ULL,
		0x75C6D28666B77379ULL,
		0x0B3C0CB8A456BDCBULL
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
		0xCC0096C47EE81F21ULL,
		0x6DFB29A8690D578FULL,
		0x23641821CEED0B96ULL,
		0x958F92F1880C65E5ULL,
		0xE96D0C89BDA9B356ULL,
		0x887E8E0211FA5B79ULL,
		0xEB035871C96943AFULL,
		0xE45D328B22A73BC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E546FC7EF675039ULL,
		0x1C349A94C2359FCCULL,
		0xAD5673045B1A5936ULL,
		0xBC8C09FACA755F04ULL,
		0x342AEA3E60869A7DULL,
		0xD7142E826FD177C9ULL,
		0x82820E1A2533B901ULL,
		0x2DDEBE241C533BB6ULL
	}};
	t = 1;
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x00CA9FE06D8A4CD3ULL,
		0x0AF18E174B4C4673ULL,
		0xA64893312B2D9F1BULL,
		0xB5DDD21FB54CEA63ULL,
		0x092133357CE1A5CDULL,
		0x169AB78118549972ULL,
		0xE5DBFB0C52853B62ULL,
		0x2171374E95AE6188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53CE704D0B1997B2ULL,
		0x23A8ED54B30859FDULL,
		0x1AE640C60ECB85EDULL,
		0xA9486DC3A4DDF175ULL,
		0xF43F5C3D72E8A52AULL,
		0x787BCDBBAD90588FULL,
		0xC617F6C059BFAB3CULL,
		0x407870F3D8AE9F21ULL
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
		0x68590CBD26D82884ULL,
		0x2678452391171C9AULL,
		0x3138DB03782E79E5ULL,
		0x7EEBF6B0E9A74229ULL,
		0x4526166F1B26F4B2ULL,
		0x95A24AEA358AA1B6ULL,
		0xCE72AB225BDFCE7AULL,
		0x1B0EB6FE87840845ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68590CBD26D82884ULL,
		0x2678452391171C9AULL,
		0x3138DB03782E79E5ULL,
		0x7EEBF6B0E9A74229ULL,
		0x4526166F1B26F4B2ULL,
		0x95A24AEA358AA1B6ULL,
		0xCE72AB225BDFCE7AULL,
		0x1B0EB6FE87840845ULL
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
		0xF8855D3BB5C545FFULL,
		0x1C9D5514B3146097ULL,
		0xAE0F43915C6FF7EDULL,
		0x26417704330ADA55ULL,
		0xA9222766A2452E61ULL,
		0xB2862ABED3573A87ULL,
		0x2B23935FD3B5DCCDULL,
		0x8E2DDA9D69ABA35BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E9B83CBF303D468ULL,
		0xC3FE2DDA17E9B2DFULL,
		0xB937E1AC5AA9699FULL,
		0xBF0559383829AC1BULL,
		0x4E79322F7242C4A9ULL,
		0xD6915A75291AB501ULL,
		0xF2AC38C16EE0BAE8ULL,
		0x64C147B61B19161AULL
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
		0x546B29E1E0636328ULL,
		0xD7F8DC8C8EEE1ECAULL,
		0x7E24B8090E56D85DULL,
		0x5FF923B4C2BE5AD1ULL,
		0xE21EEAEE88384E54ULL,
		0x1A5EB3275885C6ABULL,
		0x2542705B673EF2A0ULL,
		0x4A132F615731A83BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A9A227D34440F2CULL,
		0xB39AB31998EB89E5ULL,
		0xA1A97118D8FBC6C8ULL,
		0x1BA37EB6AE357632ULL,
		0x44B47082AE40BF9FULL,
		0x9724491E2718E1F5ULL,
		0x73F79B9345B7F997ULL,
		0x0C4B52D16533A812ULL
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
		0x369E664162209AD1ULL,
		0x89F6F81709CEF413ULL,
		0xD71150BF4F16F96BULL,
		0x89EB02070680F0EFULL,
		0x55C1AEEB508306DAULL,
		0xEE51A65A3671EE76ULL,
		0xCD23DC68E0EA6AFFULL,
		0x15341F58263B06BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC5F502B86DD81C24ULL,
		0x58750D158994A99AULL,
		0x9D30A3AB7B360452ULL,
		0x2F8AD640E54D2C81ULL,
		0xA2896B6857643146ULL,
		0xA4EF94970E08C9C9ULL,
		0x2E885320FC7FA7A6ULL,
		0xFC601F2A60F2D399ULL
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
		0xB740A0F6A7967754ULL,
		0x53D6EAA72EE898B2ULL,
		0x4887C1AF61C017EAULL,
		0xC6AC5F4572588283ULL,
		0xF7F6E8430C357311ULL,
		0xBBD3D179EFF95148ULL,
		0x62B1FB8DA63FDD22ULL,
		0x9137B86E7119A9F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB740A0F6A7967754ULL,
		0x53D6EAA72EE898B2ULL,
		0x4887C1AF61C017EAULL,
		0xC6AC5F4572588283ULL,
		0xF7F6E8430C357311ULL,
		0xBBD3D179EFF95148ULL,
		0x62B1FB8DA63FDD22ULL,
		0x9137B86E7119A9F7ULL
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
		0x98CAD02D014D820CULL,
		0xF51A0886F68E03DDULL,
		0xE4C4BBEA5253B61AULL,
		0x8871398AC9382D35ULL,
		0x03BA763516CFAAADULL,
		0x32B214FB05BDD891ULL,
		0x6D4487C21C006A8BULL,
		0xB1BD4571BEF82D0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6FF9561CFED3AA60ULL,
		0x3844CECC33558772ULL,
		0x641BEDE5524C6372ULL,
		0x80E25317793F9551ULL,
		0xB0C686295EA71D1BULL,
		0x8A9504244DF09534ULL,
		0x631FCFD33C709E3AULL,
		0x5AB1E99552BB7C5DULL
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
		0x5698562718CA27DEULL,
		0xFEF9D8329C78F83BULL,
		0x9B053D9D0193CA31ULL,
		0xAA6AC160ADB6BD52ULL,
		0x9FCA1ABC04D273D2ULL,
		0x7FD82418FD216525ULL,
		0xB8CE5FDBEEDB2B8CULL,
		0x137E647DBFBAC99CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11E684AF0FE5E81FULL,
		0x8A0217DDF7A9F2D0ULL,
		0x9455D677C625C732ULL,
		0x1F7A8D3B79FBD8C5ULL,
		0x23FD77C60A39961EULL,
		0x02BC7E7B38D6023DULL,
		0x5185C4B502455F60ULL,
		0x5063536539EF38CDULL
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
		0xC896142C88257D37ULL,
		0x07E11F2BC35F4603ULL,
		0xD7B21FDD7647F974ULL,
		0x6779C939626C70DCULL,
		0xAFEF0A9E0095A593ULL,
		0x0DB2F3A090436758ULL,
		0x3114953717C13310ULL,
		0xBC14CE40AA95672AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F002FE741896D3CULL,
		0x4A57EF6F509F57B9ULL,
		0xF1907EF8A4E45F51ULL,
		0x8F531C4E4C023E14ULL,
		0xDD2A9761AE3B968DULL,
		0xA69D02588D7A1627ULL,
		0x44618A3FF4906F50ULL,
		0xE1CE347B56A6368FULL
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
		0x72C4359A7D5B702EULL,
		0x775FEAEFFC98A660ULL,
		0x69B74CF5FB5B122BULL,
		0x39756F0377488DDBULL,
		0xF93EA3C51C859240ULL,
		0x39040E9C663518E6ULL,
		0x817F6E1FC95ED3D6ULL,
		0x89989D94A4A86492ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72C4359A7D5B702EULL,
		0x775FEAEFFC98A660ULL,
		0x69B74CF5FB5B122BULL,
		0x39756F0377488DDBULL,
		0xF93EA3C51C859240ULL,
		0x39040E9C663518E6ULL,
		0x817F6E1FC95ED3D6ULL,
		0x89989D94A4A86492ULL
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
		0xCE9744F7861B4775ULL,
		0xB3EE0F4FC87C2AE5ULL,
		0x9F9977D623B946E0ULL,
		0x01C5E94950431548ULL,
		0x9F0DAA3D164CB522ULL,
		0x23034DC1FC62EE2EULL,
		0xE9CD782BE81A21EDULL,
		0xA34779E5B39B8FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA9FE69C390EF66DULL,
		0xC588885C47CD5A72ULL,
		0x96464A673A90F109ULL,
		0x87DF8F2D1A89654FULL,
		0x29BCA071F9E923E7ULL,
		0xA2F5631FF2A30324ULL,
		0x592620D4FFE549FDULL,
		0x2842286F8FEC7588ULL
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
		0x230EEE55DFD943BAULL,
		0x95D197D495411E50ULL,
		0x8049DB3F8F921201ULL,
		0x99089C682536E7D8ULL,
		0xCFEAE60644756FFFULL,
		0x8767230EC6A0295AULL,
		0xBED6821439D7721FULL,
		0x01CA9F2135342B7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BA50409BEA7A73DULL,
		0xC7E8D4652A7C6ECAULL,
		0x6A3C8CD422A52612ULL,
		0x46AB47D744CCD160ULL,
		0x7FC7B2C7C37BE460ULL,
		0x882342A28E10BF21ULL,
		0x00B3E611243444CDULL,
		0x1088016DCF6932B9ULL
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
		0x0C18D576252CD759ULL,
		0xB3CD0244371F77A4ULL,
		0x091D5FD872C20ECEULL,
		0x22B6B326B3E603B6ULL,
		0xA09B996BF07C2C6FULL,
		0xE2DC83164AC9BF13ULL,
		0xB784E6D74F2D9371ULL,
		0xBF9E25BAC7F0B6E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19BFD19DE48D026ULL,
		0x9FD83B41EB558183ULL,
		0x262850D7F1B2C411ULL,
		0x3C4734A3947DB918ULL,
		0x8CDF5BF3DED0B561ULL,
		0x15AAEA9B1423409DULL,
		0x9444F6D2E70D6F80ULL,
		0x6A10B6399214E041ULL
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
		0xE60D43778E1DDD0AULL,
		0x15C2A565304787E3ULL,
		0x668238117213E7DCULL,
		0x9F23B9444F296495ULL,
		0x0F2E82AAEE3BC704ULL,
		0xA739E245EE7E4141ULL,
		0xB256535C86C3ECCAULL,
		0x5AB77F825499900EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE60D43778E1DDD0AULL,
		0x15C2A565304787E3ULL,
		0x668238117213E7DCULL,
		0x9F23B9444F296495ULL,
		0x0F2E82AAEE3BC704ULL,
		0xA739E245EE7E4141ULL,
		0xB256535C86C3ECCAULL,
		0x5AB77F825499900EULL
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
		0x233E8B3ACAB6E796ULL,
		0xEE92F0AB86B67C64ULL,
		0xC8CC196AFF254832ULL,
		0x215317D4E970940CULL,
		0x8B48E462FCF473F0ULL,
		0x88CAC394276B5036ULL,
		0x698FDF1ACE6D8CC3ULL,
		0x460CDCFF7D7A7216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8870127FE7CB43A7ULL,
		0xAA315027E16B5A39ULL,
		0x496F92F707070B35ULL,
		0x98458C8A33E061F7ULL,
		0xAC7D99A9B2478D21ULL,
		0x14049D782D382D2DULL,
		0x8749C42BF31AF071ULL,
		0xE465F682D9FC2979ULL
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
		0x54A8733354273E9AULL,
		0x5FBD284D22D3B84BULL,
		0x2767D7F04632703FULL,
		0xFB4B64EFC26078C4ULL,
		0x1C412B714BE67AE4ULL,
		0xF5E716874716A982ULL,
		0x4B239291D72C5284ULL,
		0x5C2F06901A8B35ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x07D728859A5FAB4AULL,
		0x93CCB2D3D7C24F1BULL,
		0x791511AE1F6011C1ULL,
		0xFA424BEDA6A4B540ULL,
		0x66A35C577D22314FULL,
		0xDDCAB6AFA0486B57ULL,
		0x88B5CF97E5047E31ULL,
		0xCC0C71AC0FE1965DULL
	}};
	t = -1;
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x67C284ECEDAA66E4ULL,
		0xF84F4A2325D4268AULL,
		0xD16A21144ABA4EBBULL,
		0x300DDBF1558A36B3ULL,
		0x1DBA711C33F55224ULL,
		0x94A160D6B941784DULL,
		0xA288A5FB2FFAA8F9ULL,
		0xE75DB8CB0300CE04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55764FAA684C6304ULL,
		0x3A2A59600B70CBB2ULL,
		0xB73B28F5E867A9DDULL,
		0xBEB077D9E1A2F0A7ULL,
		0x4DAAE2BE03F850ABULL,
		0x90E3B62A76A1D4DAULL,
		0xA9C5C31AB1BD5781ULL,
		0xC8A775A7BE5ABF04ULL
	}};
	t = 1;
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x52B76C36E10291E6ULL,
		0x6BDB11EBC8822061ULL,
		0xFED64DB77C1AB026ULL,
		0xBF2A0ABB34DABD14ULL,
		0x965007BFD00800C2ULL,
		0x29A52C6B71640D4DULL,
		0xDBAAE626926C929EULL,
		0x41FF4BD7FF0FD5E3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52B76C36E10291E6ULL,
		0x6BDB11EBC8822061ULL,
		0xFED64DB77C1AB026ULL,
		0xBF2A0ABB34DABD14ULL,
		0x965007BFD00800C2ULL,
		0x29A52C6B71640D4DULL,
		0xDBAAE626926C929EULL,
		0x41FF4BD7FF0FD5E3ULL
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
		0x1DE06B1D53F6E091ULL,
		0x4E839F10A4A8AF60ULL,
		0x69833E272E417103ULL,
		0xA89FE836E9807CCDULL,
		0x6041C19537A787ACULL,
		0xB581D3E8DFC437DCULL,
		0x5856710849DEFDB0ULL,
		0x3D58A2F84CAE2B07ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E99EA7656584E9CULL,
		0x785DF69C35CA3ECAULL,
		0xBD8CC40CC4230794ULL,
		0xC2C9085E08648D86ULL,
		0x13655F809DF61ECFULL,
		0xA96DCE1621B4F817ULL,
		0x3F82537202F21092ULL,
		0x9FB27295A5AD7C46ULL
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
		0xCE499511C5CFE7E7ULL,
		0xA30FAD29150BDFC8ULL,
		0x2D1383AB2CA21079ULL,
		0x4C2C555B3DA726F2ULL,
		0xF6965CFDEDB55868ULL,
		0x5FCB3BAD6767DE31ULL,
		0xB385E2D8392C84DBULL,
		0x5954F177C7CFA43BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF17EB91126A82CBCULL,
		0x0A558E80BCA4EBE1ULL,
		0xAC586A914DF58F93ULL,
		0x0CC53B762604B282ULL,
		0x1EBB78937B327726ULL,
		0x3D679FE4436C8EF3ULL,
		0x53046BE58B5972E6ULL,
		0x4EA4D250BC5C1BEFULL
	}};
	t = 1;
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x884A64C0E34EF4CFULL,
		0xFA1EE4A96E167D2EULL,
		0x1407C51FBA66B240ULL,
		0x5E29F29AD0F6348AULL,
		0xD8E4E30EC89EC009ULL,
		0x85C8DA74FFF3A310ULL,
		0x755109DF87C25E84ULL,
		0xE92FB2051470D603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBB428671DA03D967ULL,
		0x265C28CDD0274B28ULL,
		0xC4BFEB428F98A520ULL,
		0x7E267B3439565F18ULL,
		0x954E42144B8B1903ULL,
		0x9B4EB5AE409B9296ULL,
		0x528217BEA283F1B3ULL,
		0xD5747177831D43F7ULL
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
		0xC439BBA62B993A92ULL,
		0x9A399120E391A508ULL,
		0xBE332364793E4BECULL,
		0x1B11B3489AA11300ULL,
		0xC485CF8741A20A9AULL,
		0xBF38A727394C574EULL,
		0xF05BAAADF2B4D259ULL,
		0xC01920E5D7FAC1C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC439BBA62B993A92ULL,
		0x9A399120E391A508ULL,
		0xBE332364793E4BECULL,
		0x1B11B3489AA11300ULL,
		0xC485CF8741A20A9AULL,
		0xBF38A727394C574EULL,
		0xF05BAAADF2B4D259ULL,
		0xC01920E5D7FAC1C5ULL
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
		0x2C31A6D8BB2AF70CULL,
		0x8074D9540D9E7E67ULL,
		0xCC64A3E798362AEDULL,
		0x832AD46C0603991EULL,
		0x331E6AF850E0C3C0ULL,
		0x7425A4F549A27EB4ULL,
		0xAF38FBAE2D5F3D83ULL,
		0x448397F72A737AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57F5914325F80B9AULL,
		0x58615368D0AD0D89ULL,
		0xDBDDB1EAFB42F129ULL,
		0x71BDFD9213EFCD37ULL,
		0x76319CE9E82DB1DDULL,
		0xBF5E0DA71AF14519ULL,
		0x860034B7205FC4E4ULL,
		0x2F3B60E033FF9FD9ULL
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
		0xE7532E5E1C1CFC10ULL,
		0xD112AC315791903DULL,
		0x6B2E0362F0DF845BULL,
		0xCEEB04689FDE2F21ULL,
		0x99685D5259417A09ULL,
		0x94E0B31C077720CDULL,
		0xAE3DF0BDE4370001ULL,
		0x6F4118F294E34DAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC8570F5D2CD661ULL,
		0xC00C15C32A5CFE3EULL,
		0x85CE3433F12D7D88ULL,
		0xA145DB212942F0C4ULL,
		0x49DA53CCB595B153ULL,
		0x91A399569954140EULL,
		0xB8A4F888EE1EA08AULL,
		0x858AD8EC1E66BDC1ULL
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
		0xBD4872B69289D022ULL,
		0x125B8895979FAFEDULL,
		0xB50E946E31CF762DULL,
		0x8C30B5C5183EF1A4ULL,
		0x4F7C5F4DF447A713ULL,
		0xA771D7993DE5F277ULL,
		0xA498DA8426220972ULL,
		0x44EB6808AC650894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA762B2DBAB58B6D1ULL,
		0xEDCE85BF209FA4D4ULL,
		0xA33D7F3876BE1056ULL,
		0x14E154A32374D446ULL,
		0x0D58B14C50F43E98ULL,
		0x335A7E6CD38B6E23ULL,
		0x9AC7AE68EC20D1E6ULL,
		0xBD8E6F378F31EF9AULL
	}};
	t = -1;
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8CB1CCF6DFDE0E25ULL,
		0xF2A09765CDF2217BULL,
		0xB9086E87A8285B3EULL,
		0xB6AB8939278DDC6AULL,
		0xA7FD371F3BA5CA2BULL,
		0xC51BABB8164F0494ULL,
		0x027328B7A18939B2ULL,
		0x550EBA87B67BED95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CB1CCF6DFDE0E25ULL,
		0xF2A09765CDF2217BULL,
		0xB9086E87A8285B3EULL,
		0xB6AB8939278DDC6AULL,
		0xA7FD371F3BA5CA2BULL,
		0xC51BABB8164F0494ULL,
		0x027328B7A18939B2ULL,
		0x550EBA87B67BED95ULL
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
		0xDA44EFAF8B8B7548ULL,
		0x6546793CE31ACDD8ULL,
		0xB2ECA377FE947B97ULL,
		0x530FA64BCABFE712ULL,
		0x38E0A1CEEEDEE254ULL,
		0xF97B89011446D041ULL,
		0xB35B96CEF4ACF2F9ULL,
		0x10F0E75A0CBDBCACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x504752423EF1A005ULL,
		0x79CEEB0FD92943AEULL,
		0x921D53D92B6C8272ULL,
		0x1B759AC0973975EFULL,
		0xC09F1F52D77E3B7FULL,
		0xA70C11FDABC5A388ULL,
		0xCA4DC302F07C03D6ULL,
		0x0477081729308220ULL
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
		0x4B615874542A1FC5ULL,
		0xCE00080190A75F77ULL,
		0xBFA07397598F24C9ULL,
		0x17F1A22478209814ULL,
		0x9D1F21F4D660F313ULL,
		0xB78A2C749950C92EULL,
		0x6EF93189C3BCEDFBULL,
		0x0A104AA6047424E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x227A55EBA31DDA41ULL,
		0x082ED397A7B13A0BULL,
		0x19C5A9FAD90DA7BAULL,
		0x4810FED0F52638E9ULL,
		0x62786D3E22D93B29ULL,
		0x4453B98581E9D8E8ULL,
		0x0A35B2731D35A57AULL,
		0x0A87E5D48EF2646AULL
	}};
	t = -1;
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x35207F7E53C4F175ULL,
		0xD770EAB4F9062D5FULL,
		0xECA5FFDBB218244FULL,
		0x02F3F2A7F9175A44ULL,
		0xC83C2BF9C79AB8DAULL,
		0xA9C37F00C07BCA27ULL,
		0x82FA306C0FF6BFDDULL,
		0x4B209EDC63EDBF34ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3856B7816B5E8DDULL,
		0x3F0016A7AF8973F1ULL,
		0x0BC4D6AA6FC35BF7ULL,
		0xBE86C38C2162470EULL,
		0x56CD2E8066156E89ULL,
		0xC17767781D38CD1DULL,
		0x95F834F67924ECF7ULL,
		0xEE8F3EEB233B857CULL
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
		0xF9A4ABA979AF2122ULL,
		0x5CE86610B2C9D6BFULL,
		0xB9971622882502AFULL,
		0x83FF6E5735BDF083ULL,
		0xF1B405F32B0C36A1ULL,
		0xDC553CBF2E2BFDFEULL,
		0x12162EB7B05CCD17ULL,
		0x9DB44B40B3F73E5EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF9A4ABA979AF2122ULL,
		0x5CE86610B2C9D6BFULL,
		0xB9971622882502AFULL,
		0x83FF6E5735BDF083ULL,
		0xF1B405F32B0C36A1ULL,
		0xDC553CBF2E2BFDFEULL,
		0x12162EB7B05CCD17ULL,
		0x9DB44B40B3F73E5EULL
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
		0xA22B5E2C04A9DEC0ULL,
		0x17D01D3C1F07A8B9ULL,
		0x3BE463962608813AULL,
		0xEA044963ADB485BCULL,
		0x9C34D11D0C009F6FULL,
		0x133D07DD97640A13ULL,
		0x09CD349A695E7F51ULL,
		0xB05D6B74D51C8F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5498C4448E04A88ULL,
		0xEE4CBB0B29B1F81EULL,
		0x4CCF40D9AE5012B6ULL,
		0xBDE23C03387DAB03ULL,
		0x916CEE369FBE2551ULL,
		0xE8AC00A8D38C8671ULL,
		0x8A8B0E62BC337026ULL,
		0x67D263B314275617ULL
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
		0xCA558FA790D99EAEULL,
		0x642AA35EA1B433A5ULL,
		0xF895E0C678BDE96FULL,
		0x41BFADEE921CEBB3ULL,
		0x74A278D8B20A0EB4ULL,
		0x0A77CE7FBD56F400ULL,
		0xE2093DFD6C1F5C82ULL,
		0x1C5DB92D3AF356D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5288F363AA88A30ULL,
		0xB36B712B976AC673ULL,
		0xB62032557E0CBAC6ULL,
		0xA91BE6CE7DC069F0ULL,
		0x6F1259CF6856314DULL,
		0x5FA104D9CF8D77E8ULL,
		0xBD81A6E7DC7A7856ULL,
		0x3D09FB76A10A6A96ULL
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
		0x8AF466C08CED329DULL,
		0x191F98E677055E0EULL,
		0x4C301987CAD75DB6ULL,
		0x3E0FBF8B35B56B15ULL,
		0x001A65CB1C7F667DULL,
		0xB4E4408927923088ULL,
		0xF579C7E2B469CA4DULL,
		0xEBD47C8039B9F96AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x589148ABEE5E30F8ULL,
		0x649620FF788314FAULL,
		0x3DA792A622DB98FEULL,
		0xE29998E526B86E71ULL,
		0x03FABB1D4B18DBACULL,
		0xFB7FAFA56ED4F096ULL,
		0x4F4458079B2D8811ULL,
		0xD5030FDF8506908AULL
	}};
	t = 1;
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5AC302DE1D41A1F2ULL,
		0x671F5143975AC2F7ULL,
		0x7AB72861BBA8DC1CULL,
		0x0C25BC86B04AE3E7ULL,
		0xC0B060B285B5196BULL,
		0xC366B5D527D18CBAULL,
		0xF3EAD327346B69DAULL,
		0xBA894C48C1A2E6A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC302DE1D41A1F2ULL,
		0x671F5143975AC2F7ULL,
		0x7AB72861BBA8DC1CULL,
		0x0C25BC86B04AE3E7ULL,
		0xC0B060B285B5196BULL,
		0xC366B5D527D18CBAULL,
		0xF3EAD327346B69DAULL,
		0xBA894C48C1A2E6A1ULL
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
		0x9D4D26CEDE25E6E9ULL,
		0xCB1E807263827136ULL,
		0xDF8BCEB26F4FB829ULL,
		0x6D30953E8D64C955ULL,
		0x14737DB820CBA096ULL,
		0x16AD7DF212C5D315ULL,
		0xC1E5910013387988ULL,
		0xADD6F22172E6BE22ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C472E1F6336F0FFULL,
		0xECF8B5A11BB4B99EULL,
		0x8C9601EC4EF45CD5ULL,
		0x8DEE76850F9B876DULL,
		0x14566D567E68CB28ULL,
		0x4591B5D5AD83FA82ULL,
		0xDFEAE266F6C26935ULL,
		0x799D2FFE98A042B4ULL
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
		0xF5E15F1B79586610ULL,
		0x0968C892EEDE4A9BULL,
		0x49C182130C577B5FULL,
		0x415A2E5C8DDCBBE1ULL,
		0x0332342FB609164FULL,
		0x4C04E585BF0C1D3FULL,
		0xD9159AA765209AE3ULL,
		0xDDC8C4154BB46F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1468E8EA85B43A31ULL,
		0x6467FF23840CCE46ULL,
		0x31E811C1BC66FEEEULL,
		0x2B07F1EA70DD4760ULL,
		0x3CC7CE2951C5E793ULL,
		0x8F1964896724FFD2ULL,
		0xD5BBA95F6BB71332ULL,
		0x1DD279C8386309FAULL
	}};
	t = 1;
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x08F0B2B9E5BC185CULL,
		0xD35EB392A2EDABCFULL,
		0x2F08D91AF8943960ULL,
		0xE928D0F1C47F729DULL,
		0xB8B58A725DC5DA96ULL,
		0x7A946469A7D95A6FULL,
		0x18748B5CA8C1C6AEULL,
		0xF35A946B0B6527E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02573DFBDBF6594BULL,
		0xD55A01D80365C880ULL,
		0x56139EF294B9F679ULL,
		0xCEC4ED326BBAB505ULL,
		0xC7BEEF9B44C703ABULL,
		0x55C37E418E1F2D41ULL,
		0xC33EF5F60E4251F3ULL,
		0xFB0EE290A388A6ECULL
	}};
	t = -1;
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4C28FA74BAA9C278ULL,
		0x86BEC096428ABD99ULL,
		0x1A40DEF4EFC6F84DULL,
		0x7938D30ED530A5D5ULL,
		0x05868D2BCBF4CC95ULL,
		0x098A26FF2920C677ULL,
		0x40CF62FE13C29853ULL,
		0x33453EFE24CCD9AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C28FA74BAA9C278ULL,
		0x86BEC096428ABD99ULL,
		0x1A40DEF4EFC6F84DULL,
		0x7938D30ED530A5D5ULL,
		0x05868D2BCBF4CC95ULL,
		0x098A26FF2920C677ULL,
		0x40CF62FE13C29853ULL,
		0x33453EFE24CCD9AEULL
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
		0xE37E1E1DE15C4D36ULL,
		0xD5E2E4E740A69EEBULL,
		0x86C1387725F0B839ULL,
		0x662F4BDBF9EAF411ULL,
		0xD4BA9EA7A6B6FBEBULL,
		0xD825C0E153286A2DULL,
		0x2716C40FEA855598ULL,
		0xD975BF9240B55F7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4BCB88175FA1EC9ULL,
		0x856FDC290F9DD2E1ULL,
		0x88C8C4DF13F5AA7FULL,
		0x0F48A31C4C6979C3ULL,
		0xB0F3C148FBFF458EULL,
		0x64D6532528B6B003ULL,
		0x04FAFFD123F681AAULL,
		0x636B009922E4F5D0ULL
	}};
	t = 1;
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCDC7F68885406EB9ULL,
		0x1DDB346E508BD615ULL,
		0xCA754C139436D53AULL,
		0xD1A4171F77B9FBE5ULL,
		0x032121A43FE2D7ADULL,
		0x275819E598AE8674ULL,
		0xFD8020702B14CCD3ULL,
		0x8479A5477BAA4FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC442FD81EDB0D639ULL,
		0x7AEB4FF9BFBFD844ULL,
		0xEB8AE8EA046FBA1BULL,
		0x5C65F7C673BE93BDULL,
		0xAF4D6E3336B09738ULL,
		0x6B6EB10B0D0E9F03ULL,
		0xC589D60E40ADF404ULL,
		0x6F60CE787E948E31ULL
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
		0x9597437E1D6F109DULL,
		0x16500A6F88F689C6ULL,
		0x73789FB6C1E54834ULL,
		0x335981890B0D1692ULL,
		0x700AAA38203AA455ULL,
		0x02F3EA80F459931FULL,
		0xE6CC06EF5A7C5A8BULL,
		0xA5A818F2573C89CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x09AEB072E4CFAED9ULL,
		0x268A48E417F74830ULL,
		0x4911DF2939CB204CULL,
		0x4BB3803F8C1CE9E4ULL,
		0x4E40E84507CFC86BULL,
		0x73F094693F29B060ULL,
		0xB741914FE034770CULL,
		0x61A2F9925583CF4EULL
	}};
	t = 1;
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB22425DBA4E22BABULL,
		0x3597DB2774591DEFULL,
		0xCC6A65A6C42071F9ULL,
		0xDD886FF6593B1E4BULL,
		0xADEDAC9E314BE50DULL,
		0xAF72510404EBF53AULL,
		0x84B880BFD9F22E0FULL,
		0x6C0777F6F91D4C5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB22425DBA4E22BABULL,
		0x3597DB2774591DEFULL,
		0xCC6A65A6C42071F9ULL,
		0xDD886FF6593B1E4BULL,
		0xADEDAC9E314BE50DULL,
		0xAF72510404EBF53AULL,
		0x84B880BFD9F22E0FULL,
		0x6C0777F6F91D4C5DULL
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
		0x8A84B26C70452652ULL,
		0xBC676CE343260AA1ULL,
		0xA635180E2C32CFA1ULL,
		0x841EE926D3A3539EULL,
		0x0C0AA64FE27FC447ULL,
		0xF8F0FF48F3E6DA82ULL,
		0xAB8D4D4558F090CDULL,
		0x9549BEB219D5D9AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F70FC970D4444F6ULL,
		0xEA70E4F6FAF6BCA0ULL,
		0xFD833487E8CA461FULL,
		0xAC5FADC5A1EE2128ULL,
		0xB67D7709114E646CULL,
		0xB2CAD79F8BC14E80ULL,
		0x8C2581902530BC04ULL,
		0x31512D9EB466760EULL
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
		0xCDC293CF92E88995ULL,
		0xF65AEC847473D409ULL,
		0x155C0B208D001C2CULL,
		0x5AAE073C5A57E121ULL,
		0xDC81594FBC01B185ULL,
		0x8F71C2FDB181808DULL,
		0xB94414E421F7CF32ULL,
		0x171AE651509A73ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDDF0A84C36C3F21ULL,
		0x84C6E628931ABFF3ULL,
		0x21A2F32473631460ULL,
		0x7C7801C848427DBAULL,
		0x5E3307609B547A23ULL,
		0xF4B5C603A0C0ED98ULL,
		0x8E9328AD41250A25ULL,
		0x7002F4E99A68BDB2ULL
	}};
	t = -1;
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1B9E971959E22B49ULL,
		0xB64AE591B6ED4AC7ULL,
		0xA6B51A8A5B521E65ULL,
		0x8E5EA5EB68023677ULL,
		0x8AA6E9B9C64293F4ULL,
		0x1BC71EBC64E27B74ULL,
		0x55E6D3F8DC71D122ULL,
		0x4318D0D6DB5DE5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF212174B459EC18BULL,
		0xD8033AA7317BB35AULL,
		0xC7BF397E17208052ULL,
		0xB5943B55D29B2658ULL,
		0x4CB5383F04D9B10DULL,
		0x0382F106B96E2B72ULL,
		0xB55D0C4D31B61374ULL,
		0xE44C189098991266ULL
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
		0x4AC562E9694BF687ULL,
		0x1FE42AD7E957BAECULL,
		0x0A5F740FB84E5812ULL,
		0x1A489C210AE7D3C6ULL,
		0x9561A4604F700A03ULL,
		0x69EF726384002FA1ULL,
		0x6C3DEB69F7F80986ULL,
		0x508006EB3440BA7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AC562E9694BF687ULL,
		0x1FE42AD7E957BAECULL,
		0x0A5F740FB84E5812ULL,
		0x1A489C210AE7D3C6ULL,
		0x9561A4604F700A03ULL,
		0x69EF726384002FA1ULL,
		0x6C3DEB69F7F80986ULL,
		0x508006EB3440BA7AULL
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
		0xD2C6DF63631571C3ULL,
		0x55F4168001AEEADFULL,
		0x77888ACC729C3771ULL,
		0x81A42A477FC112EFULL,
		0x21FA83C008AD965FULL,
		0xE2FEAF4E71FAFBDEULL,
		0xFC821700238C404EULL,
		0xE17D3FA7D4A1E11EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF8B95244348C4B2CULL,
		0xE118B18FA2CC2423ULL,
		0xC482808541DDCF19ULL,
		0x84902CE81607F32EULL,
		0x9B6882B5B6E9702BULL,
		0x5FC673A64DCA43AFULL,
		0xEF00C97C79F9360CULL,
		0xE2F5D11807A353E0ULL
	}};
	t = -1;
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x152544EE43AC7134ULL,
		0x49E59103F36D31FCULL,
		0x3B421AB2303FFD11ULL,
		0x05737057715750C4ULL,
		0xAA28335B3864DFA1ULL,
		0x1D4A829B9EF67AEAULL,
		0xC9C5CA13DDDAB1FAULL,
		0xCA976D738C8A92ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B7AD2D366091245ULL,
		0xD97660DAE2223EA4ULL,
		0x8C6329DC4827ABA0ULL,
		0x063EF3666A17860EULL,
		0x9E18E970D1788848ULL,
		0x9C9EB8AFCF5182F6ULL,
		0x1201EC4445C9D64EULL,
		0x65CF29832BD01422ULL
	}};
	t = 1;
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x950977A5452A9310ULL,
		0x32C48FFB17799157ULL,
		0x4935659241FF2FADULL,
		0xD1FD7110C1AADC4DULL,
		0xD0EAB9E9C4D25B6FULL,
		0xBDCA816755524585ULL,
		0xF27A91C8A39636AAULL,
		0xBB1412A60451316EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1526C2784FC5F67ULL,
		0x1F097FB030C5AC21ULL,
		0xE3383560CD2C61BBULL,
		0xA2656EBC0F6FC13CULL,
		0xEF667651D15D50BAULL,
		0xA2A099F1DB305B00ULL,
		0xEE2CD6C0D19275C8ULL,
		0xC0B7C7BA909A6B08ULL
	}};
	t = -1;
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x496793760EEE2387ULL,
		0xCC5E1CECEE0C494EULL,
		0x84BD35531B5E77A2ULL,
		0xE6B13276C0857A73ULL,
		0x71B9A7112EAD7F44ULL,
		0x30AFCA5E048542FAULL,
		0x0C96F3B1CA243E62ULL,
		0xACF94B6707A421B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x496793760EEE2387ULL,
		0xCC5E1CECEE0C494EULL,
		0x84BD35531B5E77A2ULL,
		0xE6B13276C0857A73ULL,
		0x71B9A7112EAD7F44ULL,
		0x30AFCA5E048542FAULL,
		0x0C96F3B1CA243E62ULL,
		0xACF94B6707A421B5ULL
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
		0xF2CA821C3A7BE645ULL,
		0x788AE71CC663741EULL,
		0xAAFFA16D5545649BULL,
		0xEEB5FD57577FB1B0ULL,
		0x12525BA02A568DDDULL,
		0x285DA6CECC0DEA5CULL,
		0x8F4F63310E76CB92ULL,
		0x991ACD0CC1C408FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F7A05B1A608812EULL,
		0x4A02B6DA983758F9ULL,
		0x92B4404BF7582ADDULL,
		0xA0A33C0B62049451ULL,
		0xC0D9923FC5C0518DULL,
		0x4EEAADCE1D1E1229ULL,
		0x4BE496ED7AFD2465ULL,
		0xB3B2850427F5214EULL
	}};
	t = -1;
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x52D263419B2A63FDULL,
		0x3F42C44A94013F51ULL,
		0x562D69B7063E1F96ULL,
		0xDCF77E20E0453656ULL,
		0xA313533F7A63F933ULL,
		0x82EDF57BF90D88AEULL,
		0x865D82F8DFBAACB4ULL,
		0x7D761830197EE908ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88AE010B9891FFDBULL,
		0x76A8CF4EE782EBA9ULL,
		0xBFBD3FD73EF7F4BEULL,
		0x0250B876CBA4E64AULL,
		0x9F46A5D0640B7235ULL,
		0x3A8838F2AD5FB2F6ULL,
		0x998399CB50993A23ULL,
		0x45DDA750BB6DC147ULL
	}};
	t = 1;
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3E2E8A2621F952AAULL,
		0x168BF96F27F94010ULL,
		0x36A888454B63A0E8ULL,
		0x12A2FA3400FE356CULL,
		0x35E4C277114F2524ULL,
		0x795286473039FB97ULL,
		0xAC368187E24E9699ULL,
		0x64426E24FE2889ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEACC7337DF8B731DULL,
		0xE959A899AEB1B6EEULL,
		0xDC900D01C75D3A93ULL,
		0xE86140631086F9B4ULL,
		0x7D4D9E4EE8EAB926ULL,
		0x52AB2C95AF8D753FULL,
		0xBF67947CB55FF28DULL,
		0x7700D2695B52412FULL
	}};
	t = -1;
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x428785FCEC9603C2ULL,
		0x21FFE30D197F55BDULL,
		0x2D4573C75A55071EULL,
		0xE6BCCEDAA4712E25ULL,
		0xAA645EE42D87FADFULL,
		0xB4B1CAD71CC88292ULL,
		0xC4EAE123CBAE3A78ULL,
		0xAA0BAF20619A459BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x428785FCEC9603C2ULL,
		0x21FFE30D197F55BDULL,
		0x2D4573C75A55071EULL,
		0xE6BCCEDAA4712E25ULL,
		0xAA645EE42D87FADFULL,
		0xB4B1CAD71CC88292ULL,
		0xC4EAE123CBAE3A78ULL,
		0xAA0BAF20619A459BULL
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
		0x680F6B72D975CAAFULL,
		0x0BC41C9AD0C69F1BULL,
		0x6760D67AC3C67072ULL,
		0x1B4FB114B7FFF9FAULL,
		0x31C905DB4B3CD705ULL,
		0xEB2B1539FBB791FEULL,
		0x671C8697F2502A8BULL,
		0x602DB3245BA84FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE32EA8B57D5CCCULL,
		0xA3F88F9C6EBEC454ULL,
		0x9C049DAF73EA3C06ULL,
		0x99978623A1116146ULL,
		0x9F3B4A7219120E31ULL,
		0xD4A88029D5A2488AULL,
		0xF46F3E4360C03837ULL,
		0x10834EFB14139AFFULL
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
		0x1FF51FC951AC231EULL,
		0xDA5B54BEA5973341ULL,
		0x7BC7875A699B0A9CULL,
		0x185DB8B41EA511B6ULL,
		0x16C36B130F7D05C5ULL,
		0xB0714221D7AF77AAULL,
		0x239BA346BF81406BULL,
		0x4083A77F97134CC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD09D4DAE869400B8ULL,
		0x2F30D23FAD0225C1ULL,
		0xE11A5917E74DED85ULL,
		0xDD9DDAA4DF5CE371ULL,
		0x5D20FD6A03883FEAULL,
		0x65ED7B109C046D42ULL,
		0x26D79B26E1F1965DULL,
		0x3A19C038518AFC25ULL
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
		0xE091722FDACC1CCFULL,
		0xF3433BCA63E3D4A8ULL,
		0xE83429DA6EBC2DC8ULL,
		0x720B8C612089317AULL,
		0xCB519DD0FF0C052EULL,
		0x6C714221FC9924E2ULL,
		0x1EE1644BB9A774B0ULL,
		0x26B0EB03CC9770DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92F8EB806AFC77D9ULL,
		0xCF911226FAED1C2FULL,
		0x149F5A1601DF3C08ULL,
		0x906B86FBB0BBFC5DULL,
		0x3031DBE6A0BB23DBULL,
		0x5C8A265BEE803F65ULL,
		0x258C57F66FA132D7ULL,
		0x963EEB8DAEDDAD77ULL
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
		0xF945713B3D086C41ULL,
		0x06C980FC7CA90C26ULL,
		0x92BFD2E71371C390ULL,
		0x3BFA6156268910D0ULL,
		0x727C63B5F8FC9A14ULL,
		0xCD8C8842F62E3F95ULL,
		0x430BD7C73E98BBCAULL,
		0x98728594CF1B1895ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF945713B3D086C41ULL,
		0x06C980FC7CA90C26ULL,
		0x92BFD2E71371C390ULL,
		0x3BFA6156268910D0ULL,
		0x727C63B5F8FC9A14ULL,
		0xCD8C8842F62E3F95ULL,
		0x430BD7C73E98BBCAULL,
		0x98728594CF1B1895ULL
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
		0x554294E0997C5455ULL,
		0x20156FBA91F32FADULL,
		0xA60392FDFD38F7C4ULL,
		0xA5D023DC3BBFA492ULL,
		0x036A8F43EFE3EC7EULL,
		0x2BF0097528026215ULL,
		0x77CA78A277B500A1ULL,
		0x2328EC241015B86DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9949D09766B5D137ULL,
		0x77F8449376801208ULL,
		0x7DA9CBAFCC605BB6ULL,
		0x523E63AFBF3FB110ULL,
		0x79997A639924FFC7ULL,
		0xA2F42501C5A8AD51ULL,
		0x611BE861BE173345ULL,
		0x516639B6A588E95EULL
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
		0x4E624F11EC3CE6ACULL,
		0xDF6CF08F54607B5EULL,
		0x4C5F9C995E53FB3DULL,
		0x412CCA31507BD835ULL,
		0xB444932B58264916ULL,
		0xD7EF1A12FD143578ULL,
		0x80F12F2666117C3CULL,
		0x4508452B3AE2947BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1F9DB8FB42A6F8A7ULL,
		0x86ED3D6B030C2CCAULL,
		0x1EB4F1CE90C7A148ULL,
		0x97BE4C46F21DC86EULL,
		0x0A0FDD1BAD7146E4ULL,
		0x41CBB06461AF9A0EULL,
		0x3AE6CBADBD24E4FAULL,
		0xE9E856D5C1DCA1CDULL
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
		0x6D12BB19CB932144ULL,
		0x6428350DDE94892FULL,
		0x116F3B2ACDE60035ULL,
		0xCB4DF3ABF9061B5CULL,
		0xB7F4D21BF42BC5AEULL,
		0xA83A22667E653D8FULL,
		0xAE84C69EBC38BFF0ULL,
		0xF4D540686FB2D4CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB5D519C293CE6528ULL,
		0xE76B068923BFD50AULL,
		0xD216D0B361E8CF8BULL,
		0xA5EDBAB839BB8CDDULL,
		0x71AB2C5DEA0BACD8ULL,
		0x6A84976E562D7358ULL,
		0xE031A49188366A8CULL,
		0xA1A4F03A6E87E508ULL
	}};
	t = 1;
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x8D26BA71785FD861ULL,
		0x24F513B8C6F247EEULL,
		0x33B23D2C0791CCB5ULL,
		0x6BC425283555E667ULL,
		0x1C0E01FC83276CC8ULL,
		0x43F192F8F74D7566ULL,
		0x9E991460D90354E6ULL,
		0xAB8CB5BE0B81D75AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D26BA71785FD861ULL,
		0x24F513B8C6F247EEULL,
		0x33B23D2C0791CCB5ULL,
		0x6BC425283555E667ULL,
		0x1C0E01FC83276CC8ULL,
		0x43F192F8F74D7566ULL,
		0x9E991460D90354E6ULL,
		0xAB8CB5BE0B81D75AULL
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
		0xBBDDD542C122E33CULL,
		0x11DDF11D29C9371CULL,
		0xF72982CEE448285CULL,
		0x6BF917DBC1A8A5ABULL,
		0x5A53AAB38801E629ULL,
		0xBAC5220F150C7A7FULL,
		0x57C4CAB20ADDB918ULL,
		0xF419B893C9A1BC30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34123085F6201EFEULL,
		0x5A88A440E3C576EEULL,
		0xBBACB6B03EFB9985ULL,
		0x54D9DA2BB182B898ULL,
		0x6F00D5199911C9E2ULL,
		0xBB92838B30057912ULL,
		0x9FB11EAA8BA5D8D1ULL,
		0x15AE057EC6BD67CFULL
	}};
	t = 1;
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF9B8F6F3C74BB031ULL,
		0x195C513E5ADEDFC5ULL,
		0x87BF67A37864ADFDULL,
		0x07EEF12E389FE69FULL,
		0xC7E90276A40B5EEAULL,
		0xEC0A40900FB5F250ULL,
		0x478F0FB3AC8A61E2ULL,
		0x1057F95D2875EA5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B635AD75564969CULL,
		0x42F375C2C0E0431FULL,
		0x4B331BA3126CEEBFULL,
		0x4AC0B3B4288CA096ULL,
		0x3DC42A6DD9E59D89ULL,
		0x3D692F79FC84F5EFULL,
		0xE24FB415F1CD5DD0ULL,
		0xFD78925EAD327E3DULL
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
		0x4BC30AB216F1CA47ULL,
		0xA439D6E8D743A108ULL,
		0x25B2C11601F94F3EULL,
		0xADC9143360DBFB2BULL,
		0x29947A664F7C1E15ULL,
		0x620C7B712E1AC942ULL,
		0xFF9964328BFDCC0BULL,
		0x9477979601AC44FAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF775757A1BE40E4EULL,
		0x69598AA56B85D9EAULL,
		0xF9C23E3EAE27B209ULL,
		0x615B9F651FA191D9ULL,
		0x3E611B3441A86EFFULL,
		0xA7B2C98D17CDCE68ULL,
		0xE746D34A2FE0A343ULL,
		0xDBA261AE4E107D77ULL
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
		0x5A45F2A3D2F085CCULL,
		0x2B8CA2125F687AC3ULL,
		0x05A038C601E4F4ABULL,
		0x85139ED04AF6920EULL,
		0xBF42AADFB5140496ULL,
		0x374E2C027052A9C5ULL,
		0xBD8554C136C5A0EDULL,
		0x4887D96F3876FC5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A45F2A3D2F085CCULL,
		0x2B8CA2125F687AC3ULL,
		0x05A038C601E4F4ABULL,
		0x85139ED04AF6920EULL,
		0xBF42AADFB5140496ULL,
		0x374E2C027052A9C5ULL,
		0xBD8554C136C5A0EDULL,
		0x4887D96F3876FC5DULL
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
		0x4E4724AC778A9639ULL,
		0xA3A1437CE177D45FULL,
		0x57B2893D54A25833ULL,
		0x36110BA5E51789F7ULL,
		0xD3BC10A3D09AD05FULL,
		0x779CCA412D02D6D1ULL,
		0xAD55886C725E23BAULL,
		0x23B2087B9C86B55AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4D98B3BF691AFC4FULL,
		0x60444D10E70125DDULL,
		0x6D199547246371FCULL,
		0xFEF9BE1B2F9CCF72ULL,
		0x6B3660064A196904ULL,
		0x04050EFF0804AC45ULL,
		0x1E239CEA2A97318CULL,
		0x4BD4D82C4C676964ULL
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
		0xB344B77DFEFAB3ECULL,
		0xA8957858AC3DB86AULL,
		0x82C285F6D80FF775ULL,
		0xFA3D564861AF5558ULL,
		0x9C514751D12451C3ULL,
		0x0B6581AAB490C398ULL,
		0x1865CBADFFFF057BULL,
		0x5749D0811F61ABC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9F91F7892A715710ULL,
		0x6B50652FAF4892E3ULL,
		0x9E81A596F132E6D4ULL,
		0x3BD00DA1A3D4CCD1ULL,
		0x7531769E97ADD3F4ULL,
		0xB01384B9D82802CAULL,
		0xBDDE185039793D42ULL,
		0x095661F8375CA6E9ULL
	}};
	t = 1;
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x935EDB3F35C1565DULL,
		0x18049349C1E19DDBULL,
		0xCBC9610B6FEA6025ULL,
		0x1D970E35616252C0ULL,
		0x6F9C4B20C346AD34ULL,
		0x53FF08390FE8EEFAULL,
		0xE4CEE98F47D9ECDFULL,
		0xF6718BA1CF02ADB1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF55B950B609F073AULL,
		0xE5C17D58C753E04FULL,
		0x2D507D7C2817ED3BULL,
		0x7872C62B1E54E3FAULL,
		0x679C278B7012BC62ULL,
		0xA4B814A1D432B754ULL,
		0x8C30596104E0831FULL,
		0xFA6694685E3FFC49ULL
	}};
	t = -1;
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9A716B879EED5B66ULL,
		0xAEEAC0A90A34634EULL,
		0x9C8382C8B72C746AULL,
		0x29EF5AADDB098E94ULL,
		0x2CE306AF911ADE87ULL,
		0xA556567DC1F93D4FULL,
		0x1B8D6F7535475B79ULL,
		0x84BAA640FB7263DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A716B879EED5B66ULL,
		0xAEEAC0A90A34634EULL,
		0x9C8382C8B72C746AULL,
		0x29EF5AADDB098E94ULL,
		0x2CE306AF911ADE87ULL,
		0xA556567DC1F93D4FULL,
		0x1B8D6F7535475B79ULL,
		0x84BAA640FB7263DFULL
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
		0x0801D61AC048E8EAULL,
		0x8DB7C9CBF3437A68ULL,
		0x71CAA768CD142562ULL,
		0x712E57D8B7420D21ULL,
		0xD8D18DBBBCEB9832ULL,
		0xE09433697534AFA2ULL,
		0xD0215D2C8FA98225ULL,
		0x2D45DB83C74166B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B6353F0A2C48512ULL,
		0x91E58CF083A709A5ULL,
		0x5606050C83FD3EA7ULL,
		0x2A1A8EFEF1984D9FULL,
		0x0203680382D31DAFULL,
		0x22496F0676BE264BULL,
		0xAE43367C4A939FCFULL,
		0xE94D3F86BD437585ULL
	}};
	t = -1;
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3FCCD6AF0B90D7F2ULL,
		0x99FFA18C36BA2595ULL,
		0xB3C9DABBD019A858ULL,
		0x4C338417DEDC79E9ULL,
		0x90F643B03BA1A7D2ULL,
		0x6C2BA082B6891DCBULL,
		0x7434984EE7080B9DULL,
		0xBEB18C7B5B9387C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94AC6984D40F6541ULL,
		0xDA663E7F613E90ABULL,
		0x1826AB6B556846CAULL,
		0x955551AE2887C09CULL,
		0xA8A90397C64B17DBULL,
		0xEF6D12CB32933617ULL,
		0x9C7E4A9DF1A05D01ULL,
		0x0FD014F0C19173D6ULL
	}};
	t = 1;
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCCBD16B45A9C6CB7ULL,
		0x45477B93DCD06D9CULL,
		0x32881EFE66F81FEAULL,
		0x758ED258003A3DF0ULL,
		0x7496A16DF0FE075FULL,
		0xFCF693B1136524A3ULL,
		0x347315CCA332CC7AULL,
		0x920BE0ADDC81C90EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8063FA9A7BAB813ULL,
		0xACAC4D658B79CE82ULL,
		0x8D10B38D593A9BFBULL,
		0x775FA6D11450D96BULL,
		0xEA6F9951A05A1D09ULL,
		0x74E1F12AE10689DFULL,
		0x01C8F40CE78053ADULL,
		0xEEFA461834327593ULL
	}};
	t = -1;
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0F078CAFD6418718ULL,
		0xA3963B24819DC24CULL,
		0xB957F90AF3F5463CULL,
		0x952A9A82B2BD26C4ULL,
		0xFCB148F055D757E0ULL,
		0xA2647DD48215BF50ULL,
		0x1CD3F492C801862AULL,
		0xF5C22F19DD6084F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F078CAFD6418718ULL,
		0xA3963B24819DC24CULL,
		0xB957F90AF3F5463CULL,
		0x952A9A82B2BD26C4ULL,
		0xFCB148F055D757E0ULL,
		0xA2647DD48215BF50ULL,
		0x1CD3F492C801862AULL,
		0xF5C22F19DD6084F1ULL
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
		0x287996176BC98A71ULL,
		0x00B2A10094DF3196ULL,
		0x7370BEF1601DF77CULL,
		0x9911DE48A5B7BAB3ULL,
		0x2E9400E7A3F05664ULL,
		0x391D5A0EC686B66EULL,
		0x3AC0A678E47D59BFULL,
		0x4CA39A1F7745FA46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3B6C1A601984CC8ULL,
		0x39D7324DC96B9B54ULL,
		0xDED8F50187B07594ULL,
		0x5C579F49ED3C9325ULL,
		0x6D14BB480A1A3F21ULL,
		0x1E80D3F3D578791CULL,
		0x54EC00B31966D05BULL,
		0xEEB9A8358F38F055ULL
	}};
	t = -1;
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCEE84ACD023D1E65ULL,
		0x778D6C2C4B07941CULL,
		0x390EE033E9C05439ULL,
		0xFCBBCE3C6A07FCA1ULL,
		0x772242B104B4FA0CULL,
		0x961B927A6F219B6DULL,
		0x74C6B5D2C7AC79ECULL,
		0x3DB0FA7BC8B4E434ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75457108C4C46448ULL,
		0x6A07F226828384D9ULL,
		0x0B8ECE9D7C2CEB7DULL,
		0xFE2D09CAC60CA51AULL,
		0x9D233FC5F5DBDDDCULL,
		0x5FE8DBF956DAD916ULL,
		0xE04AB2FF260F0F9FULL,
		0x91CDC967B8B96B36ULL
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
		0x6E7C4413633B48BCULL,
		0xA374C4FAD749AA0BULL,
		0x9063F1C842772ED9ULL,
		0x20E369405F229D3FULL,
		0x37921AC1A28D3711ULL,
		0x3005EA2500290346ULL,
		0x4EE2E6CE07F89E51ULL,
		0xED5EE4CB6F94A6F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D6C0E6FB446FA43ULL,
		0x09112B1EBA027389ULL,
		0xA991064599EF5A6CULL,
		0xEAC3EA8E50C29C95ULL,
		0x9BEE0B57DC418920ULL,
		0xA05CA2725A5A27A5ULL,
		0xAE72FC63221824D4ULL,
		0xEF1CE9E761F13FEBULL
	}};
	t = -1;
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x20168ECB1A1C437BULL,
		0xDA12DFE211322A81ULL,
		0x19C7C743DAD5CF63ULL,
		0x82C5B4AA3BA85E7EULL,
		0xBA1E4E34F33D2FCEULL,
		0xA8951DD1605508A0ULL,
		0x410138D923E5D39BULL,
		0xBE8762070C0BFA28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20168ECB1A1C437BULL,
		0xDA12DFE211322A81ULL,
		0x19C7C743DAD5CF63ULL,
		0x82C5B4AA3BA85E7EULL,
		0xBA1E4E34F33D2FCEULL,
		0xA8951DD1605508A0ULL,
		0x410138D923E5D39BULL,
		0xBE8762070C0BFA28ULL
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
		0xF031090D4C69319DULL,
		0x4D5C0EDF462D94E1ULL,
		0xC87D15C24D01313EULL,
		0x7BC08FE90F78F7BDULL,
		0x3C76239E6B9BAAA4ULL,
		0xFA1029DE06E92836ULL,
		0x377050AB440D7214ULL,
		0xC9D3F373A373DC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F0BABE81B78B2AULL,
		0x25BCA739C6A5719DULL,
		0xF376AFA5AFC71450ULL,
		0xCCB42AF21911AA56ULL,
		0x931AC625D962C8A7ULL,
		0x26F824625F00AC8FULL,
		0x60287F181A97EC15ULL,
		0xF397FD42A876C430ULL
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
		0xCF054637860803C7ULL,
		0x2A43CE7CFC0F4726ULL,
		0xE7CE816F6818A925ULL,
		0x32F9057F99BDE570ULL,
		0xC3CB20379409BC92ULL,
		0x30A5CB19B719E23FULL,
		0x17DF01D0F0CF72B8ULL,
		0x4CDCC318D071A707ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC99AACDBFD08703ULL,
		0x0D570F47AF4CD83FULL,
		0xE3F076277EB038B5ULL,
		0x68AC42CC9DA128D3ULL,
		0x8AB0BF11DC3674FEULL,
		0xDD84A2C8555F672CULL,
		0x9BF26DBB4042A885ULL,
		0x6804D1289113D6F1ULL
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
		0xB5E9371EEED08D18ULL,
		0x7C9BECD0D40E7685ULL,
		0x3097A3CBBFDF735DULL,
		0xC0FC942DC77EEB20ULL,
		0xF12F23C5CCC4507DULL,
		0xFABB5448E0ADF748ULL,
		0x8953A915D5E3B15DULL,
		0x156A6EEF17806CB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2200BFFFB64A29F9ULL,
		0x1FDCB26194D1DD4CULL,
		0xCD85E7D308E99260ULL,
		0xB35AF73277BE8D3CULL,
		0x09A7103A5125BAF9ULL,
		0x1709A1871220B7FDULL,
		0x57B9C2FB167ADE8DULL,
		0xC54CAE8B01573ACAULL
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
		0x55EA35DA1B311E9EULL,
		0x746ADDDA18AAF861ULL,
		0x15B7B6C3DB968065ULL,
		0xEE0F70E603A7064AULL,
		0x643216B15495F508ULL,
		0x203FA1BF3AD5F87FULL,
		0xC5197B61D60B5FA7ULL,
		0x463B8BB7508147F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55EA35DA1B311E9EULL,
		0x746ADDDA18AAF861ULL,
		0x15B7B6C3DB968065ULL,
		0xEE0F70E603A7064AULL,
		0x643216B15495F508ULL,
		0x203FA1BF3AD5F87FULL,
		0xC5197B61D60B5FA7ULL,
		0x463B8BB7508147F9ULL
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
		0xC30AB4DFCBD8ACB7ULL,
		0x88B4DB1AEB321DEFULL,
		0xB6CD085B1C40068AULL,
		0xCA03C29A8351069CULL,
		0x71D6F155BE076794ULL,
		0x20CFD7478381FE85ULL,
		0x1767364CE5267E5AULL,
		0x325609EA23CE4F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B2DCCEB32921000ULL,
		0x5DEF62F0DB169026ULL,
		0x514268752C0BD57DULL,
		0xB31ECE0C00F250F8ULL,
		0xEFCB1AF5454B25EAULL,
		0x283CFFC523C667F9ULL,
		0xF947C798CEFD6553ULL,
		0x5F23D43F70717EBBULL
	}};
	t = -1;
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7480086B91A7E60AULL,
		0x223E24EF6BFECD9DULL,
		0xA3973A6FA5368BB6ULL,
		0xB0046EF444A239C4ULL,
		0xEC2BE51A4A1B4591ULL,
		0x1D8C35892607D028ULL,
		0xD2ABB457FEF91A11ULL,
		0x70D638A7F19BCCC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC9A9711B34C964E5ULL,
		0x5BA0361A98097FEDULL,
		0xE3C2F137B9DCAEB7ULL,
		0x6FBCC4D4107817EDULL,
		0x73D911781884E788ULL,
		0xB1278D4AC23E7881ULL,
		0x9BB831D58F05D687ULL,
		0x2B8D2F2ADA30B025ULL
	}};
	t = 1;
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5ECC6428C3BB4A82ULL,
		0xA9F4101E2D6BD88AULL,
		0xF55BCC47BF907E8FULL,
		0x0092D059DC07274FULL,
		0x6CCFDA0569D7FAEBULL,
		0xFC10AB9696F4D476ULL,
		0xA533A9FF24ED5CC8ULL,
		0x48B5B919338E82FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF87F2E6397BC55BULL,
		0x4BD4303E936F8DFDULL,
		0x4457700202E8B5EAULL,
		0xB8CE5BF89C7B9AA3ULL,
		0xCCE397FE0F5FF3F7ULL,
		0x21F671A0E067B2BBULL,
		0x9C3633AEEF596958ULL,
		0x462E1B185327FC3EULL
	}};
	t = 1;
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDB3234F22AC6A118ULL,
		0xD920DF42B7243C04ULL,
		0xD56554FD3C3037EFULL,
		0x6EB1BF388633F1C3ULL,
		0x949976F55CA98774ULL,
		0x61414530AAA4E46CULL,
		0x252812B1BD84705EULL,
		0x8B254E74E5C41126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDB3234F22AC6A118ULL,
		0xD920DF42B7243C04ULL,
		0xD56554FD3C3037EFULL,
		0x6EB1BF388633F1C3ULL,
		0x949976F55CA98774ULL,
		0x61414530AAA4E46CULL,
		0x252812B1BD84705EULL,
		0x8B254E74E5C41126ULL
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
		0x1FE9429917E826C4ULL,
		0x3B0D7CBD60B5934AULL,
		0x2EDC14987ABB8C18ULL,
		0xE076567F8BA1BADFULL,
		0x270B59B62B304ABCULL,
		0xACD847724984E1DFULL,
		0x6C3A81C01FAF5756ULL,
		0x565409B78E59958AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C9C352D5F9C0C6ULL,
		0xEC222EC478048F19ULL,
		0xA95D13E2678E4E62ULL,
		0x44D5B120CCA54FD1ULL,
		0xCBE6671C29D9C5CFULL,
		0x91ED0E83D06AD184ULL,
		0x01C1A0030C12C02AULL,
		0x59CEB4699E442451ULL
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
		0xC51E2663378C429BULL,
		0x56CFEA536BD2B2E0ULL,
		0xB042C1CDFECCE94CULL,
		0xD0F363101B6681C5ULL,
		0xC5C514A7296164DFULL,
		0xD5E25FF33EE5A7FCULL,
		0x846CF667541178D9ULL,
		0xD597A0DF7A36D9B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC32C04DC9E16B84ULL,
		0x33406094F7404CC1ULL,
		0xCC591F6B0447969BULL,
		0x41C197984506A136ULL,
		0x5F78B18DF33AD1DFULL,
		0xE274D5B068C9AB7CULL,
		0xFE1FFF8A2B4D5DDEULL,
		0xC5A200B5F30C6ED8ULL
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
		0xE9B579B6C734D2FFULL,
		0xEB87A28DCA23D20DULL,
		0xE8D0EFA8A5758649ULL,
		0xC36F58C8D66EA362ULL,
		0xB1CB93DEA85954D1ULL,
		0x739BC8A721A4EB1CULL,
		0x9F834EC41A35383FULL,
		0x0ED5FCD502BA7A94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x036D4905EF41F4C5ULL,
		0xB69FD639031FEB53ULL,
		0xC4026C88E93382E2ULL,
		0x668DDC5E76C6CD04ULL,
		0xABAC2AC3BF4E4042ULL,
		0x2991F95B66D7007AULL,
		0x165903B5A38D9ED7ULL,
		0x4A42D39B8DE53281ULL
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
		0x8FCBEB518213FD9CULL,
		0xEFDED0C93E4ED63FULL,
		0x7A8C61310D2EF466ULL,
		0xF149ACE07B19DF0DULL,
		0xAA293AF99761C5FAULL,
		0x75DEA8E894C04614ULL,
		0x52A05CDAC25F394BULL,
		0xF5DD758A23D221D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8FCBEB518213FD9CULL,
		0xEFDED0C93E4ED63FULL,
		0x7A8C61310D2EF466ULL,
		0xF149ACE07B19DF0DULL,
		0xAA293AF99761C5FAULL,
		0x75DEA8E894C04614ULL,
		0x52A05CDAC25F394BULL,
		0xF5DD758A23D221D7ULL
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
		0x2EBE79E7C8642F44ULL,
		0x8F577A9A5EDB0045ULL,
		0x760EAE5DCD222F05ULL,
		0xE216B57ABC9F5D7BULL,
		0xCD4E7F4D51F3673EULL,
		0xC5A8D808190D927CULL,
		0x611179C7692EE6E4ULL,
		0x4B441875BE981FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE010F07DE67A80CDULL,
		0xE8355D3CAD7A45BCULL,
		0x3A3865CED56DBD4EULL,
		0xF2FDF12BA2DA7240ULL,
		0x32B36A62AD97456DULL,
		0x92C23CBFA53B4BB1ULL,
		0x71D821E11E24ED2FULL,
		0x78DA53D1983A0326ULL
	}};
	t = -1;
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF234C7562E02E665ULL,
		0x9F23106C36DAC0C5ULL,
		0xC620DF0F8EAA8B49ULL,
		0x0B25F0C68FBD6A78ULL,
		0x24375D93E5BFC4A9ULL,
		0xDC904A078F2A233FULL,
		0x2CCFE2E8A68D6B9DULL,
		0x2D2AB2F8B3662780ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF75363D43F09597CULL,
		0x6C951343446BEA86ULL,
		0x278DC3BADDC6EA58ULL,
		0xCC1DC3E742FD3929ULL,
		0xFB1ADA8FC321CAB2ULL,
		0xA8945097F5B1EAA8ULL,
		0x6CCBB24EE1FBF199ULL,
		0x41015770838547A2ULL
	}};
	t = -1;
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x96A42E70CA1293BAULL,
		0xBA45F30B462939BEULL,
		0x7D084923ECA61DA2ULL,
		0xE16207411E93F7C9ULL,
		0x048B4E668FEA9E25ULL,
		0x81EE20876E745E0AULL,
		0x1725E9F7164C98E7ULL,
		0x18BD963F71DFAD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D2EA4CD36EEB0CFULL,
		0xA228A67521ECB4CAULL,
		0x186A374D55E2E329ULL,
		0x17A26C55B2AA2266ULL,
		0xB705B949AF369FD8ULL,
		0xCF8117BEFB0BCECAULL,
		0x0B8B60B115B1B28CULL,
		0x59B4B016DDE72E5EULL
	}};
	t = -1;
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7D01FE0552ABB569ULL,
		0x12997A633DAC0ADFULL,
		0xA895D21BF540B3A6ULL,
		0x94C7BCB5C4060C82ULL,
		0x932F4A14A8C293EDULL,
		0x46CF465A7ECCF08BULL,
		0xEE02BD5CA80BCECAULL,
		0x4CB5DFD4D643B633ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D01FE0552ABB569ULL,
		0x12997A633DAC0ADFULL,
		0xA895D21BF540B3A6ULL,
		0x94C7BCB5C4060C82ULL,
		0x932F4A14A8C293EDULL,
		0x46CF465A7ECCF08BULL,
		0xEE02BD5CA80BCECAULL,
		0x4CB5DFD4D643B633ULL
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
		0x801AB6C18FF88DE8ULL,
		0x6F4862965AAB26ACULL,
		0xE2B9094606B8AF58ULL,
		0x7EB54B08274B271CULL,
		0xBA889F1FF06675CBULL,
		0xDCBDE7603940D2DCULL,
		0x9E25A2C10B8B4DF0ULL,
		0x4E75C9B551FAF3F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0138115978C05D7EULL,
		0xC39CBB36CE284F17ULL,
		0x5DFB9D7F689C5317ULL,
		0x7A379CD7B7E1FDB5ULL,
		0x64976040094E7DD2ULL,
		0x82AFC87981C6D42EULL,
		0x662832C1A3D1C216ULL,
		0xA32329393A5629BAULL
	}};
	t = -1;
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCD6E5A75BD2CB863ULL,
		0xAC5FAF9E80ED393CULL,
		0xBB2180414D12FE69ULL,
		0x065876572B1EEC82ULL,
		0xD61638654E7D9E4CULL,
		0xBFD3D73D516EEFC0ULL,
		0xCCEC36C28D6DC0C1ULL,
		0x737496D61342631BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4318F150A301DA6BULL,
		0xD8F977096B9B6F1CULL,
		0x0BD6649377D0CAC2ULL,
		0x880B79F5BDE5ED12ULL,
		0x99DB266541C5FA62ULL,
		0x5AF17F3A61B62782ULL,
		0xF8221C0910BFF675ULL,
		0x2ECD57E756263931ULL
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
		0x666E46A76EE04601ULL,
		0x2C5F18B6D213E0EBULL,
		0xE9D5295E6F319664ULL,
		0xB54A05EAC0E02F76ULL,
		0xD25F2412A595B83BULL,
		0xED8E0A60594A069AULL,
		0x153881823C57F5BAULL,
		0x4D9E39D4BA1571DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x185BE2D502FBCE51ULL,
		0x11278B4E8ED00E90ULL,
		0x7FB15A9DCA8CABE4ULL,
		0x0912B2AEB8B1CFEBULL,
		0xFAA925C9198D764EULL,
		0x006397381BFBE1D3ULL,
		0x8D60FD38207BD02EULL,
		0xDFE3B49372E73A2EULL
	}};
	t = -1;
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF5E69745098E4C69ULL,
		0x41BF2583724FADBAULL,
		0xA8A6063A5A94CD3BULL,
		0xE04878A624E142C5ULL,
		0x710A663B6CE966FBULL,
		0x8C434C1AE6B1AB15ULL,
		0x11C044593CD3EFC8ULL,
		0x3A0C404696CABCFEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5E69745098E4C69ULL,
		0x41BF2583724FADBAULL,
		0xA8A6063A5A94CD3BULL,
		0xE04878A624E142C5ULL,
		0x710A663B6CE966FBULL,
		0x8C434C1AE6B1AB15ULL,
		0x11C044593CD3EFC8ULL,
		0x3A0C404696CABCFEULL
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
		0xAE7DA3ADC5F037AAULL,
		0x954B1F27D4FCEF3AULL,
		0x0FABC9594FB428C3ULL,
		0x30CCC66FFE898460ULL,
		0x864E44638F7DA4E9ULL,
		0xE47A1D8006F14514ULL,
		0xAE25A063EC7F1888ULL,
		0x1907B1540682D590ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3EAAAF156BFEE46ULL,
		0x9BEA945C63827A24ULL,
		0x424FBA09F5B4CF6AULL,
		0xE0DC4DD6DECBEB74ULL,
		0x8DF8641D34568B27ULL,
		0xA8B477D2217B5726ULL,
		0xA8F550B4A52466D3ULL,
		0xBB5CAE8B489B2943ULL
	}};
	t = -1;
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA22A4F3F43CF21BAULL,
		0x60C11B8B1164C1E0ULL,
		0x060037E0FD2A073EULL,
		0x2F495060FAFF03DFULL,
		0xF0F049AC74C89D84ULL,
		0xA644CD447BA02365ULL,
		0x6C68AA975A2ED8E5ULL,
		0xEC3DD42D86C62C99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2A6145592D25CB8ULL,
		0x0074EEF5BCAAEE08ULL,
		0x9B8CEAEDC2BE315EULL,
		0x6D0E58FDA5AD2454ULL,
		0x7A968F189506FA51ULL,
		0x13765B9AAF14CE8BULL,
		0xFD427AB9F489C903ULL,
		0x9344A9C4BE837364ULL
	}};
	t = 1;
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x91B1DD77436181BDULL,
		0x56504CF5FD07A671ULL,
		0xC55D58E35CEC2060ULL,
		0x5F2B379EA0996783ULL,
		0x94B08905C7296FF8ULL,
		0x5972CED4CA58E748ULL,
		0x1609A889AB55A682ULL,
		0x604B77CCF57F411FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x339EA6228297966BULL,
		0x6F43978A8D4C029AULL,
		0x3782885DB696763CULL,
		0x595BE26935512BCCULL,
		0x575D7A7EFA31EAD0ULL,
		0x3BD1B41DA6806925ULL,
		0xA549F8F9F239ACFCULL,
		0x92428DB8C6241DA4ULL
	}};
	t = -1;
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x342C4495048A366DULL,
		0x55943266F440F663ULL,
		0x601F32F77E66E47AULL,
		0xE110F03EBB695986ULL,
		0x6F0A1DFD4BAAA67BULL,
		0xF68ED022C2EF005BULL,
		0x144B5A3B7C166FA3ULL,
		0xAF2BE67AA751BE79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x342C4495048A366DULL,
		0x55943266F440F663ULL,
		0x601F32F77E66E47AULL,
		0xE110F03EBB695986ULL,
		0x6F0A1DFD4BAAA67BULL,
		0xF68ED022C2EF005BULL,
		0x144B5A3B7C166FA3ULL,
		0xAF2BE67AA751BE79ULL
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
		0x80154C9BC1133156ULL,
		0x33C649260FB32D51ULL,
		0xDE3D37EA92DB8F83ULL,
		0x260352F1B708C8EEULL,
		0xD367A518361D524DULL,
		0xB722326D0891AAC9ULL,
		0x4DB0852D192FA70FULL,
		0xE4C9D6103C974BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73D29D47E763930DULL,
		0x615EA7415876476FULL,
		0x1B795E52FABCA3B5ULL,
		0x9A87EA9549C66F7CULL,
		0x35E3BECE90E27C1FULL,
		0x694FFE1E6E22B4C3ULL,
		0xED6D00AF2B03D7EDULL,
		0xBFAC3C9A29665516ULL
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
		0x4ECE1F755C653DA9ULL,
		0x3D16229C29F6AF99ULL,
		0x0CD4572AEE5C5188ULL,
		0x4D6BA6666AEF0A47ULL,
		0xCCBBDCAEC8D51310ULL,
		0x516E2E26FEBE721FULL,
		0x275A520A0048A283ULL,
		0x358686B18A60D13FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x122CC63B7ABD3227ULL,
		0x1AEC4D68B7A1F7E3ULL,
		0xEA128E07C85A4A1DULL,
		0xA4AA65A2F05C3327ULL,
		0xBF04336AD4BC080CULL,
		0x4818415B19D90D1CULL,
		0x038B858178FCC9C5ULL,
		0xE1F2B1C73289D651ULL
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
		0xC7BB8A6AE5D5B31FULL,
		0xA9221E75C0FE67B8ULL,
		0x330A2FDB4C913C23ULL,
		0xCBB61CACF9DEC064ULL,
		0xD637BA9759153A56ULL,
		0x4230170CCE777AF7ULL,
		0x6C2D99B5EAF41A23ULL,
		0xBD8357DF651D0BF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1926889A369A1B1BULL,
		0xD21A4F27F6DC2B65ULL,
		0x011967072E960344ULL,
		0x836988C0CB7CCC75ULL,
		0x957F52DE496A9C41ULL,
		0x39487BFA41123006ULL,
		0x55B731CE1362385AULL,
		0x063AFCE6CC682620ULL
	}};
	t = 1;
	printf("Test Case 204\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDCA35F6B899973FDULL,
		0x41A0DA1314D4169FULL,
		0x21258B568D400E45ULL,
		0x3C38C131A903B757ULL,
		0xAEDB3666C9572DF5ULL,
		0xFF341CE1B1A37EABULL,
		0x47E545C6A73E124BULL,
		0x76DCC4F197DC7E99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDCA35F6B899973FDULL,
		0x41A0DA1314D4169FULL,
		0x21258B568D400E45ULL,
		0x3C38C131A903B757ULL,
		0xAEDB3666C9572DF5ULL,
		0xFF341CE1B1A37EABULL,
		0x47E545C6A73E124BULL,
		0x76DCC4F197DC7E99ULL
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
		0x54BD22C699118F9DULL,
		0x91B87EA7CC631DEBULL,
		0xF0187BC31EA3B187ULL,
		0x1BD8951E9996D094ULL,
		0x6F0F31ECA4DDB9ACULL,
		0x4138B8EFDA1E1100ULL,
		0xDDB27B01E064A170ULL,
		0xC4615183E8D05E25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68804602ED6EC844ULL,
		0x8F76F8278F479E4AULL,
		0x39231CAD28180D54ULL,
		0xCB7D85AD3703D4F7ULL,
		0x14733808DA131DE1ULL,
		0x23A6E11EDF0541FAULL,
		0x9C3418D6AE0A59C8ULL,
		0xD0C9C4A4B1FE002CULL
	}};
	t = -1;
	printf("Test Case 206\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x69271A451B6C9D9BULL,
		0x279A33C60BFFA8C8ULL,
		0x66EE30395F1590E9ULL,
		0x9CDF02A4D9A0D4FDULL,
		0x9B03350BBE9521F8ULL,
		0x328E98573FADE520ULL,
		0x9B052B9B878999C4ULL,
		0x31BBBD200E0696A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18F78B7F0CAF5B0DULL,
		0xAA020EC462B4770CULL,
		0xD06097A472FBB9B5ULL,
		0xF3C1C9CABCA5E6F3ULL,
		0x6A31E5A73F6BE9F8ULL,
		0xED5D5CD206A1FABEULL,
		0x019CA4365D985014ULL,
		0xDC21F0F958810B79ULL
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
		0x6F24A72E630FCD4EULL,
		0x600D535822C239D7ULL,
		0xBA6902508E57A117ULL,
		0xAB9EAAB65E67A838ULL,
		0x7C4467805946A5D2ULL,
		0x467B69BB197EE5A0ULL,
		0xFCFA27BF3715433FULL,
		0x18E6A84F4621C44DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B87A8AEE1F1FCA0ULL,
		0xE039CFD83B9ACD58ULL,
		0x6FA102BC49251677ULL,
		0x3188C979C33217F6ULL,
		0xAEB2ABFE14B0A239ULL,
		0xACD4EC18925CB680ULL,
		0x0DB2A1ED92BDF966ULL,
		0x333E03AC37BA08FCULL
	}};
	t = -1;
	printf("Test Case 208\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x058147E24A77ADF8ULL,
		0x0F699669B636CA81ULL,
		0x54A4E875009778B0ULL,
		0x8A0283F2D30545A1ULL,
		0xFBAA7171BC095401ULL,
		0xD131CEB537B638A1ULL,
		0x02E942FC291B49F1ULL,
		0x915F045AF4492044ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x058147E24A77ADF8ULL,
		0x0F699669B636CA81ULL,
		0x54A4E875009778B0ULL,
		0x8A0283F2D30545A1ULL,
		0xFBAA7171BC095401ULL,
		0xD131CEB537B638A1ULL,
		0x02E942FC291B49F1ULL,
		0x915F045AF4492044ULL
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
		0x90AEA1DCC54B52DAULL,
		0x1C7B19AD8C253AE9ULL,
		0x1FE367AE1A57BABAULL,
		0x1F9A0FB40EF078E6ULL,
		0x3F8FB3A0EEFB380FULL,
		0x8D845E972C4646A3ULL,
		0xDF2B20EEDF388345ULL,
		0xCE456BFBD0F07172ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4740D8A4189B7DAULL,
		0x96B590DDFC319347ULL,
		0x6A97F4EC42F871C4ULL,
		0x1E46F0F9BB8068BDULL,
		0x2D641953867BCF9BULL,
		0xD5A7A4D533A01631ULL,
		0xC56B9E9558BDAAA9ULL,
		0x5C8A934EE3535BD0ULL
	}};
	t = 1;
	printf("Test Case 210\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD0ACA35FFFB8158DULL,
		0x140B5CF5E76CF89AULL,
		0x33607F5D4D5B79BEULL,
		0x45E80A8936B32CA8ULL,
		0x1790B45C67B0ADD8ULL,
		0x1033952C959A1AFEULL,
		0x04625E5AD6FD331BULL,
		0x2210350592ACCCB3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF791630466C61FEAULL,
		0x1C2902322F702C67ULL,
		0xD6A33745033D4825ULL,
		0x0BAC012560AACD0EULL,
		0xB5AC61830658453CULL,
		0xFA63A339C923A72CULL,
		0x58289333FD056616ULL,
		0x78B22114723AA52EULL
	}};
	t = -1;
	printf("Test Case 211\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x54985204F9FB2C9EULL,
		0xD7C9362C37FE7F61ULL,
		0x979FBC088D998EE7ULL,
		0xDF5FCC346DE46080ULL,
		0xA6ACC9D9419EF9C1ULL,
		0x6FC45AD24E0872ACULL,
		0x09C90E8432C944BBULL,
		0x44EA8CF5B4C152EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C723A1BA5DACE90ULL,
		0xF566150DE6B504AAULL,
		0x50BF4DC8E6183B45ULL,
		0x86FCFBA7B11F1FCFULL,
		0x2F986D33732AD476ULL,
		0x0DFC0045AD826024ULL,
		0x1FF262EE2CC520D9ULL,
		0xB8AB958FCF754B0BULL
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
		0x0944FFC3457E0791ULL,
		0x796D87BF96D6288CULL,
		0x2486C71450737D83ULL,
		0x545A9764311574ADULL,
		0xC73772F5196A0121ULL,
		0x949F3802C7DD8A2BULL,
		0x4D3177347341B360ULL,
		0xC5ACE64FC1AE3C88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0944FFC3457E0791ULL,
		0x796D87BF96D6288CULL,
		0x2486C71450737D83ULL,
		0x545A9764311574ADULL,
		0xC73772F5196A0121ULL,
		0x949F3802C7DD8A2BULL,
		0x4D3177347341B360ULL,
		0xC5ACE64FC1AE3C88ULL
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
		0xE242FA84C06AB7C3ULL,
		0xA3AB0E7BB39E1890ULL,
		0x5B2E659A6AFF2ABAULL,
		0x2308F06E546DFA96ULL,
		0x1DA6AA13602EF47BULL,
		0xC2A8264FD94ED329ULL,
		0x5C5F878B0E45753FULL,
		0x3B37B57F1BB34EA0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04BCAC03D4614555ULL,
		0xD48D72D3DB8390E3ULL,
		0x9A05DE0BE7F2B6F3ULL,
		0x7D8328426389824FULL,
		0x2BC4FA2601D1DD38ULL,
		0x4191630BFABA27B0ULL,
		0x006F4D6118FC72E1ULL,
		0x814096B7FF0AE8CBULL
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
		0x723F12E2F6CA59E1ULL,
		0x400536DE56181F2CULL,
		0x7250F406D78976FFULL,
		0x5A4C9091F36052F1ULL,
		0x25C025AF22588095ULL,
		0x87ED7FD5011A801DULL,
		0xEFD3E257765A810EULL,
		0x365321F2DF02F4CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8856F16EEE52418BULL,
		0xE473531413F6BE52ULL,
		0x25A194F12B3D59D5ULL,
		0xF782A4F1CAB5286EULL,
		0x662706D779B85B71ULL,
		0x1348575054087D11ULL,
		0x0CDFBFC541A83617ULL,
		0x8B1B01B8AA622165ULL
	}};
	t = -1;
	printf("Test Case 215\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8FD97976ADD0BE1DULL,
		0x4B499C09DF569EF5ULL,
		0xCB3A66424C295F89ULL,
		0xBB655D11E87C492EULL,
		0x6B6A21020F616831ULL,
		0x2C618AD52382D8D4ULL,
		0xC0B7E2D86664265EULL,
		0x641832901013C61CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x826ADF82D931DB9FULL,
		0x69F931DE03B35270ULL,
		0xF746619C1055D96FULL,
		0xF60D263C56DAF42EULL,
		0xFF550093BC61B7CAULL,
		0xB9FF7058D0DB4ABDULL,
		0x5939C913D578F8B4ULL,
		0xC491805F266B03D8ULL
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
		0x8032FC491E73D821ULL,
		0xB1870A872BE027A1ULL,
		0x36270CA33EE80FFDULL,
		0x48BC280743ECD5A5ULL,
		0xEBD0F6FD9A148634ULL,
		0x673EF688E586F9C6ULL,
		0xE655455485248E36ULL,
		0xAAEFE6C08E0ED9BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8032FC491E73D821ULL,
		0xB1870A872BE027A1ULL,
		0x36270CA33EE80FFDULL,
		0x48BC280743ECD5A5ULL,
		0xEBD0F6FD9A148634ULL,
		0x673EF688E586F9C6ULL,
		0xE655455485248E36ULL,
		0xAAEFE6C08E0ED9BCULL
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
		0xACAC9D04C6F324FFULL,
		0xE4949ECCDBAEC254ULL,
		0x2B55C13E42CAA342ULL,
		0xF80BCE3A69C2F47EULL,
		0x0E90D11C9DD40F81ULL,
		0xD24CC3EA80529D91ULL,
		0x9244FFFB18D00A88ULL,
		0xC782DFA0EF272A8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD49526E87FC23E28ULL,
		0xA34BFAFACD8B16B7ULL,
		0xA485C82AF49160F4ULL,
		0xFF0C1AF2407C0137ULL,
		0x5DCE489816F75998ULL,
		0xCC23DC5C7504ACECULL,
		0x39CAD5829406A526ULL,
		0x3EF76BECCA98C55FULL
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
		0x9C97B694D3514BDAULL,
		0xA308669A151DA042ULL,
		0x0677985C30B2F9C0ULL,
		0x493B410E393C9487ULL,
		0xCE1F6B591C519B65ULL,
		0x5B65F86646B86167ULL,
		0x5EE2E9F45D2258C7ULL,
		0x2F48F2292ECEBC13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD67B1F92397F9AE4ULL,
		0x3DF887F53C571363ULL,
		0x6D5D1D8B5A6C2F0FULL,
		0x6E4D6F801A7EABE1ULL,
		0x6B7E3638D0D51386ULL,
		0x4260FE86C6507281ULL,
		0x93AFC18F4AEEC22BULL,
		0x85C8353433A118F4ULL
	}};
	t = -1;
	printf("Test Case 219\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x156CE8602E29FFF3ULL,
		0xF7B981BF51E47D71ULL,
		0xD5A020096AE4F4DAULL,
		0x8532CD5DB131FDF8ULL,
		0x50A617697881440FULL,
		0xB39FC87DF3AF465EULL,
		0x9099AE6512ADBC9AULL,
		0xEA2F988C7A4C85B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C761B8CC6653DE5ULL,
		0xE3A1838A87A71A8DULL,
		0xEFE1099A2AD43A65ULL,
		0x91403710A1D82DEFULL,
		0x6828299C9DDE7317ULL,
		0xEA02FACC672A9178ULL,
		0x09111098F42126A0ULL,
		0x6E4A0B0CFD923C1CULL
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
		0xFE52388F1332079FULL,
		0x9C243AD7A7B6303DULL,
		0x3D3E92DAD824F71EULL,
		0xD196640FF80AA80AULL,
		0x4F5D910526A1BCCBULL,
		0x2AE75657A92E8EB2ULL,
		0x5782474E79BB4090ULL,
		0xACCA9FC69A87EADFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE52388F1332079FULL,
		0x9C243AD7A7B6303DULL,
		0x3D3E92DAD824F71EULL,
		0xD196640FF80AA80AULL,
		0x4F5D910526A1BCCBULL,
		0x2AE75657A92E8EB2ULL,
		0x5782474E79BB4090ULL,
		0xACCA9FC69A87EADFULL
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
		0x867A57E7E3D5ACDFULL,
		0x126DBF8C4F08BF2EULL,
		0x67E799DC9137722FULL,
		0x20A49BAEA36E3057ULL,
		0x2083416C467C4D56ULL,
		0x437A1F0BAC426E74ULL,
		0x04F50A480DD61A19ULL,
		0xAEC9DB3BCFB0CD73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6868F2E73CD0343DULL,
		0x2AACB532A1E993F9ULL,
		0xAA34255CCE79EF2AULL,
		0xF44697D985F409A2ULL,
		0x534C44C82C7E0146ULL,
		0x8B0FE79D343D6129ULL,
		0x97FEA8B675B28F95ULL,
		0x67CC89CAF31D5EADULL
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
		0x27D8CFCE3C5A2BF5ULL,
		0xBBA8720F3A135CD3ULL,
		0x517EF6E720180807ULL,
		0xCC2509DB5BBE9E70ULL,
		0x9CDA89327B459981ULL,
		0x8B535E409EF3DDD3ULL,
		0x4D0FE78738C85AD2ULL,
		0x4FE4F18BBC56A6C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F0A62901AF1688BULL,
		0x922A3F1A0183C9E1ULL,
		0x8F2DFFD70CE45CA4ULL,
		0xF6815213CCB83FEEULL,
		0x1A3B1B23C12C3A42ULL,
		0xC76E9CC659B2BB5AULL,
		0xF731C6DEE5893FB2ULL,
		0x9B90ED1057562F24ULL
	}};
	t = -1;
	printf("Test Case 223\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x52792135F1FB65C3ULL,
		0xD2CBE79338B91F8CULL,
		0x3DCD9B5DBBCD95D8ULL,
		0x04F70087509CAF6DULL,
		0x1A3B15C6ABFAE569ULL,
		0xCB3CB86D7E951FFEULL,
		0x188E6A20DB971232ULL,
		0x2AC2B57CAA2717BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0018091F797C96BEULL,
		0x5A2899C7DBCE1684ULL,
		0x9F744E767CAB20FAULL,
		0x4A4638D2ADDDFE91ULL,
		0x2C7B3C7FDF2AB2F4ULL,
		0xE51FDD7D72E83C66ULL,
		0x7490E8A7A4CEE8F6ULL,
		0xE6947AD7B5180721ULL
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
		0x8CF8B9C00A3A1A50ULL,
		0x87F527BB3DF30951ULL,
		0x82D46258C2A051C7ULL,
		0x5A2C529F01B7E3B1ULL,
		0x1292478F5AD14B68ULL,
		0xA56094C03805A269ULL,
		0xCF68943FA99C6AFAULL,
		0x8C54BF7D0FF08D6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8CF8B9C00A3A1A50ULL,
		0x87F527BB3DF30951ULL,
		0x82D46258C2A051C7ULL,
		0x5A2C529F01B7E3B1ULL,
		0x1292478F5AD14B68ULL,
		0xA56094C03805A269ULL,
		0xCF68943FA99C6AFAULL,
		0x8C54BF7D0FF08D6CULL
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
		0x24F564C9224720B9ULL,
		0x6B1132E3F81D9E62ULL,
		0xBD730B029CA726AAULL,
		0xFE2826940D4D1F7BULL,
		0xF26DE4C7B5C16F3BULL,
		0x5A8CA37706A8AE98ULL,
		0xB406AA68CBF4F447ULL,
		0xACBE7900E94C0927ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F5199E62AF075F6ULL,
		0xB4DC331A8D981AC4ULL,
		0xDE925FD83569865EULL,
		0xCA39B974A0E4A3F2ULL,
		0x7865838B1F34D834ULL,
		0x62ED3FD2D000E220ULL,
		0xA0BA6828F725164AULL,
		0xE0F598773B5469ECULL
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
		0xD65E8B52A33E5B8AULL,
		0xA8A46C15D0402374ULL,
		0x60F8E15B9449F4F7ULL,
		0x0336C0765BBAC9EBULL,
		0x3181B0969CD2A500ULL,
		0xAC110E127632D656ULL,
		0x77F99DA72BCBBA93ULL,
		0x07B3125B319B5744ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFF4CDACCDD72BCCULL,
		0x809ECD9AA36F5BB1ULL,
		0x4016BCF1ADAF4056ULL,
		0x1328F852414D0A10ULL,
		0x652DE5A48DF52917ULL,
		0x8B32ED5187697281ULL,
		0xAE2B189A93FF1B69ULL,
		0xDBD4FA3376969752ULL
	}};
	t = -1;
	printf("Test Case 227\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFD05E52F04B42E5FULL,
		0xD29F9E0FC28C7B1FULL,
		0x70F4320C8C37EF3DULL,
		0x9A01AE6F98BC57C3ULL,
		0x2B99ED48EE1D60BEULL,
		0x4F3AF0E4A5ED4DA0ULL,
		0xF75B60BAACF335C1ULL,
		0x64B893151C1E509CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02F32F96378A0517ULL,
		0xABC5E789E848EAB3ULL,
		0x68C012E70FE03AE6ULL,
		0x0AFF734BF2EF7B53ULL,
		0x25336F56173EA1E1ULL,
		0x9A4354E2C11824DAULL,
		0xF7089BFFDE6268F0ULL,
		0x92A409ECD55C63C1ULL
	}};
	t = -1;
	printf("Test Case 228\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF1983609F3672897ULL,
		0xD2972D32E11A4B56ULL,
		0x02C7D21F1FDB9FE9ULL,
		0x6137DC2896385FF7ULL,
		0x19A6B1A67101FD70ULL,
		0x5EA2477494EBCC89ULL,
		0xCB83F8A81A58941FULL,
		0x50F5EC51617F69B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF1983609F3672897ULL,
		0xD2972D32E11A4B56ULL,
		0x02C7D21F1FDB9FE9ULL,
		0x6137DC2896385FF7ULL,
		0x19A6B1A67101FD70ULL,
		0x5EA2477494EBCC89ULL,
		0xCB83F8A81A58941FULL,
		0x50F5EC51617F69B4ULL
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
		0x0D7F87D0F9A3A8AAULL,
		0x44ED8CAC0BBA146FULL,
		0x064990E2C7313090ULL,
		0x9211278EEEA491B1ULL,
		0x24DF4DCDEF1305B0ULL,
		0x4B486A416AFC50FAULL,
		0xB954F1F15CA43F0AULL,
		0x8646588028B72D8FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60C88102087CE061ULL,
		0x52692290D289F2A2ULL,
		0xB2533497A61CF91EULL,
		0xB11124C3D9B07CC5ULL,
		0xB8C3593CC1660DD0ULL,
		0x2F63AB831A38E9ADULL,
		0x334504A233D86E7AULL,
		0x4C3E223257D33320ULL
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
		0x9315946081DB4C14ULL,
		0x790FDB0B768818CAULL,
		0xFA550CA5A281853DULL,
		0xE9898B9C17F373F3ULL,
		0x9CA40FD1AA39A0D4ULL,
		0x29371CB19C44A03BULL,
		0x7C1A2B8D6F8CF33EULL,
		0x2DD29ED3637414AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F3D3A32C69236B6ULL,
		0x3A2DC5A36C5B50B5ULL,
		0x9E0A66494A835BC7ULL,
		0x30AF2EA807552BA9ULL,
		0xF78091115B5E13C5ULL,
		0xBADBFA859AE444ABULL,
		0x5CBFDD5DD97F6F8CULL,
		0x06E2CA0E6FA9E0F7ULL
	}};
	t = 1;
	printf("Test Case 231\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6811CF209478ABDEULL,
		0xF0A2D5A98AA060F0ULL,
		0x8CF19A375C27AC19ULL,
		0x5FCE9984C593EBA8ULL,
		0x39224295FD214696ULL,
		0xE6D6E542726905A7ULL,
		0x24D2FD38A051DCFBULL,
		0x1473F531ABB93F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3E553BC43A2F4E4ULL,
		0xA4FB00F60FADE147ULL,
		0xD74B671787BE250CULL,
		0x9C0FF6BDFADDA771ULL,
		0xED593209D503BD12ULL,
		0xFDEEB36AD91ADC09ULL,
		0xBCED35B990510F10ULL,
		0x47DA6B8C3E42FA30ULL
	}};
	t = -1;
	printf("Test Case 232\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0BC9C334BD0D1969ULL,
		0x8616E78D61CFDD54ULL,
		0x9CB5A809AFDD2964ULL,
		0xE95F0E22EF5B70ADULL,
		0x502064B74F30A4C4ULL,
		0x847F6C31354C949BULL,
		0xBFD599BA54DF65EBULL,
		0x1A14A46001A8965AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BC9C334BD0D1969ULL,
		0x8616E78D61CFDD54ULL,
		0x9CB5A809AFDD2964ULL,
		0xE95F0E22EF5B70ADULL,
		0x502064B74F30A4C4ULL,
		0x847F6C31354C949BULL,
		0xBFD599BA54DF65EBULL,
		0x1A14A46001A8965AULL
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
		0x60FA598F3158868FULL,
		0x1EA387E39B008C3BULL,
		0x4910147F541E7707ULL,
		0xFA9A50E5FAADAB86ULL,
		0x3EBF4CECDED87631ULL,
		0x86C9AC696C28CE8FULL,
		0x068014F71A684051ULL,
		0x90629290566FA777ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8AED544C03753EF2ULL,
		0x2981035E35DC986FULL,
		0x6E4AA2E5C70D4E12ULL,
		0x956EFFEE004F7B66ULL,
		0x36A3B64F5099BB7DULL,
		0x8AD997D9D3856EEEULL,
		0xE396BEB0631E4039ULL,
		0x9686D7B187D061DAULL
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
		0xB6AEF3CB00EC2656ULL,
		0xE776FBA22177719FULL,
		0xC72B329EA54CACF8ULL,
		0x3B3150FA88E8A05AULL,
		0xABF64BD8D4B7147AULL,
		0x334BACDC23C5C95FULL,
		0x1C7B3B7BD3B7E4F3ULL,
		0x072B2DC3AD7A044BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0917494EDF0232A5ULL,
		0x6C7B6023495A4BC0ULL,
		0xF17AB9279C50D631ULL,
		0xFA62EA32445F158BULL,
		0x359B2F94C15C8425ULL,
		0x8667CB944F5126CFULL,
		0x5AA5E7394EF5819DULL,
		0xEB3B12C655381777ULL
	}};
	t = -1;
	printf("Test Case 235\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xABB7257C1C839A91ULL,
		0xC8E1842375F518A1ULL,
		0x2744FAB977922933ULL,
		0x8A7187A2A540C46FULL,
		0x4317186E1A7B84E1ULL,
		0x2832F751D6DAED0FULL,
		0xB8421C43C88FFBE7ULL,
		0x547275DFCFA7F20FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2F074BF82835DE7ULL,
		0xDB9BB4B7848B8DA9ULL,
		0x091CF5AAD9CFCC7AULL,
		0x31E839397D6EAE4BULL,
		0x557C30046D65521DULL,
		0x96C33B4B46F8F635ULL,
		0xADE45D8D66738359ULL,
		0x63F628EAAA58A37AULL
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
		0x4DB543501FEC7FC1ULL,
		0x0D85C4E702047224ULL,
		0x2A9BBA218E38078BULL,
		0x925E083DB7D8EFE0ULL,
		0x321259AF8C88AB34ULL,
		0x33A6CF77F813317FULL,
		0x3CE5CC30589B541FULL,
		0x2F850D8127871BD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4DB543501FEC7FC1ULL,
		0x0D85C4E702047224ULL,
		0x2A9BBA218E38078BULL,
		0x925E083DB7D8EFE0ULL,
		0x321259AF8C88AB34ULL,
		0x33A6CF77F813317FULL,
		0x3CE5CC30589B541FULL,
		0x2F850D8127871BD3ULL
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
		0x85B3C012E32EE81EULL,
		0x16BDB325A4BC2C4FULL,
		0x9E21B73D07A8F443ULL,
		0x17E6FA7F97024B19ULL,
		0xD57052C5AB406FD5ULL,
		0x195C3097C6B8F7B3ULL,
		0xD81C96918350CC9DULL,
		0xA8773CC7F5C0ADE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC5445E9C5D58166ULL,
		0xC1DDE1DA9AD75577ULL,
		0x69D72CB20684BCFCULL,
		0x61027616E6200B00ULL,
		0xA5312B1436EAD59EULL,
		0x2BABBCB6C042E80CULL,
		0x66134846DE42F547ULL,
		0x3F9345E31D29F344ULL
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
		0xEF455377ED096536ULL,
		0x2DE6293A5A5C99A4ULL,
		0xB070657B528277EAULL,
		0x27B6B8AD88C05578ULL,
		0x84BEBF29FDA589D1ULL,
		0xCFDA0660B089D0DAULL,
		0xEABCAC9C054CE63CULL,
		0x5CFEF0E542E402A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA515BFD3F9D34FFULL,
		0xCE2D4D3F2C911161ULL,
		0x0FA7B1D6EFBAFB12ULL,
		0x2FBD8BDBB9C455F1ULL,
		0xF122C0DD129007C1ULL,
		0x14637D12B39BFEDCULL,
		0x125EEBC9EE67C727ULL,
		0x2E64BBA3BD9786FEULL
	}};
	t = 1;
	printf("Test Case 239\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6385FCBA7A700C16ULL,
		0x1D4D43DE6DF7317FULL,
		0xEB3155DA16BD6052ULL,
		0x5DF9D7A9F8BE6BE1ULL,
		0x050CC94DD543B843ULL,
		0xA45E050103760F05ULL,
		0xC5B1921C94092DAAULL,
		0xE29C319CAF302AD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC265DD9D37A71F4ULL,
		0x9DE3FDE4F4140567ULL,
		0xFC06139D0527A347ULL,
		0x2A62DDA83146DC1FULL,
		0x6A7AF05E53C83421ULL,
		0x86AB45D881976DACULL,
		0x4CAA69BC6E0EEE67ULL,
		0xC905E2BD7C3202B1ULL
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
		0xA1F8F5E4C0312227ULL,
		0x163E881119B4DDE7ULL,
		0x5B4F7BC42AA7950CULL,
		0xFD017EB58A922399ULL,
		0x0668D414FC07A699ULL,
		0x6FF9E113D97CBE40ULL,
		0xC69DC46E76598BC2ULL,
		0xBDF3DF0FBA32B6AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1F8F5E4C0312227ULL,
		0x163E881119B4DDE7ULL,
		0x5B4F7BC42AA7950CULL,
		0xFD017EB58A922399ULL,
		0x0668D414FC07A699ULL,
		0x6FF9E113D97CBE40ULL,
		0xC69DC46E76598BC2ULL,
		0xBDF3DF0FBA32B6AEULL
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
		0xBA66F3B601BDEF04ULL,
		0x4C40236E42412C45ULL,
		0xA4EA5157230D5042ULL,
		0x907A4590E2584AC4ULL,
		0x7432F5B668C115A9ULL,
		0x31EA7811424BF98BULL,
		0x8A1B4A9DA52CABC3ULL,
		0x77E5121F9091E076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9621433FB23CAABFULL,
		0x7781ED8C6F53D5A6ULL,
		0x4BD5DFA5BB2C389CULL,
		0x6441AAD45A17C451ULL,
		0x7552087620B4DB56ULL,
		0x0710A7C618F39C95ULL,
		0x057BD1E42C0237D9ULL,
		0x745DC0A5DA7E6462ULL
	}};
	t = 1;
	printf("Test Case 242\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4EF4604D6C6155E8ULL,
		0x6FCEECCC919865A6ULL,
		0xCC930098818111B6ULL,
		0x1416149620489059ULL,
		0x9AE105D5E26DD92CULL,
		0x0E1CE3D92AE64900ULL,
		0xFFD7E6747F667B32ULL,
		0x80CD08694CF5F69AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B1CF2394081252FULL,
		0x9E883AF95FBFF6FCULL,
		0x3338782950E84EE7ULL,
		0xF9EDE679791C704BULL,
		0x36E7DD0D2D812529ULL,
		0x5343DA3FC024689BULL,
		0x03B2E03703F13366ULL,
		0x16CFC3461FAEE2BFULL
	}};
	t = 1;
	printf("Test Case 243\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1062A00FC9F62445ULL,
		0x1DD279B6E4D13FC5ULL,
		0x4CFF079A0CCEB968ULL,
		0x3CD44CB033E05B71ULL,
		0xED6F43FF18031117ULL,
		0x5A75F00B3F4CAC0AULL,
		0x0CB22AB60FAEFA61ULL,
		0xE792A72E46E0788AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA437F56913EBDE1CULL,
		0x8BA651076374637FULL,
		0xFA88F71C196DD1D5ULL,
		0x2DC4CDD1099BFD14ULL,
		0x3B43B1119C0CA0DAULL,
		0x5A4D98BFB1E0F200ULL,
		0xD6C1CB6648301A37ULL,
		0xC7714A0A8957EC6EULL
	}};
	t = 1;
	printf("Test Case 244\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF668913540DEAE12ULL,
		0x7A666E8B92A48FA0ULL,
		0x0F7BF608CFB70BF7ULL,
		0x552439F12219456DULL,
		0x748DE1FB1FDEC81EULL,
		0x4754862C41CE8486ULL,
		0xFB7677322F15E720ULL,
		0xED6896A8D5A256AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF668913540DEAE12ULL,
		0x7A666E8B92A48FA0ULL,
		0x0F7BF608CFB70BF7ULL,
		0x552439F12219456DULL,
		0x748DE1FB1FDEC81EULL,
		0x4754862C41CE8486ULL,
		0xFB7677322F15E720ULL,
		0xED6896A8D5A256AAULL
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
		0x6097987AF6DDADECULL,
		0x4096CAD3C8718B04ULL,
		0x276493CFAE0CBF52ULL,
		0xC891B79BF2A4A797ULL,
		0x70F80866968B13C5ULL,
		0xC0CA86C262D84202ULL,
		0xC527926D823A9F0BULL,
		0x5FC56D35515F342DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC5ABEF08510F955ULL,
		0x753F42AC1CB9CEEAULL,
		0x74E709BEC3918136ULL,
		0x0BE15B57CB6220F1ULL,
		0xEC1351E9443040C8ULL,
		0x11CDE76657F042C3ULL,
		0xA213CAE657E21D01ULL,
		0x4B226E6AE5578544ULL
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
		0x746F80FC471562BAULL,
		0x5720DF9C3F235125ULL,
		0xEF9C794DD711BAE5ULL,
		0x0B0DFA8B5ED70974ULL,
		0x54469DB2646344F0ULL,
		0x0CDCA1268068170AULL,
		0x5E6595B378950BA3ULL,
		0x8C8AB5FAAF608564ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE951739F98D7A4BBULL,
		0x7B4864A9D241C0FFULL,
		0xE4FC95E2F6D5B574ULL,
		0x872F4219343FDF6DULL,
		0x0953A1FEBE1C4C05ULL,
		0xCB1680287007F224ULL,
		0xE964189D7F4402A7ULL,
		0x54FB2CA9B689200DULL
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
		0xE09190C0F3199945ULL,
		0x089F8A2AF1D15634ULL,
		0xE8A63857D1CACB01ULL,
		0x710BD8A7A462B639ULL,
		0x239E421EEBE86C88ULL,
		0x60419C766CC37EF8ULL,
		0x35562F63B6905DA2ULL,
		0xDC972A6BC7AB8570ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B7183E67D9B2769ULL,
		0xC3A6430D7E000AE3ULL,
		0x8911EBD96C3120F1ULL,
		0x1C123BD166E3EC3EULL,
		0xBD0F544EA40D2501ULL,
		0x89E404324CC4EB64ULL,
		0x3F9CDC715E833CC9ULL,
		0xABBCF2554B89F112ULL
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
		0x01E4CF2BF4FA43EBULL,
		0xFAA16D3673DC981AULL,
		0x69B0505B93BE03A9ULL,
		0x71B55D499BC11799ULL,
		0x9BFD3500075E527AULL,
		0x44B4FE87DE93BCE9ULL,
		0x89CF96C2A36CEE62ULL,
		0x50D6911A96220E0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01E4CF2BF4FA43EBULL,
		0xFAA16D3673DC981AULL,
		0x69B0505B93BE03A9ULL,
		0x71B55D499BC11799ULL,
		0x9BFD3500075E527AULL,
		0x44B4FE87DE93BCE9ULL,
		0x89CF96C2A36CEE62ULL,
		0x50D6911A96220E0BULL
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
		0xA50298BD0039D02CULL,
		0xF9731CA0BEBEBCD1ULL,
		0x05E5B8E4BA9824DEULL,
		0x8E904CF61CBAA0DBULL,
		0x503E931585FC3D0CULL,
		0xA0A8D9DB105BF168ULL,
		0x47BAF43DE58A77BFULL,
		0x3A51C4CEBE016F49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AB1A9BFAB542246ULL,
		0x1559769EC2F2AA42ULL,
		0x5F8F6C3747ADA544ULL,
		0x770D43FAE58E540EULL,
		0x7BC1AEA06854468EULL,
		0xA1C7B25FC95C8962ULL,
		0xD75683F5150ACF73ULL,
		0xC27C440C1BF41E48ULL
	}};
	t = -1;
	printf("Test Case 250\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9C712F5902012DE5ULL,
		0x177CCE944474AF35ULL,
		0xB274A252709FC815ULL,
		0x2A3A2395DA65D9DAULL,
		0x4B59A59F9CA6ACFDULL,
		0x8A42CDAEE155BD09ULL,
		0x36BF36B8E7596D82ULL,
		0x341F56A4165C3E13ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8A46A374C8B992AULL,
		0x2FC99DD588CE5D30ULL,
		0x0B3EA50B62AAADC2ULL,
		0xC7922F054421CD54ULL,
		0xFE27F46C96310A55ULL,
		0x67EAA8DD0470B407ULL,
		0x5B1D1B09180C178DULL,
		0x3058772B19D5590FULL
	}};
	t = 1;
	printf("Test Case 251\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x7817DD215E3A2BBAULL,
		0x926E5895CD297931ULL,
		0xE40B10A2E764ECD6ULL,
		0x7F8716009FF53B00ULL,
		0xD0D0E153481162E5ULL,
		0xEB14E2EEF8AE7224ULL,
		0xF47E3FCC122E09A7ULL,
		0x13F3C4E55C805696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2BD3AF22D06D7D6ULL,
		0x70388D3564D2EC3AULL,
		0x7951A5BFF731F262ULL,
		0xDE5CCEA580F18798ULL,
		0x22F3DE789D172394ULL,
		0x47A1A878A035F311ULL,
		0xC401EA9FEFFB108AULL,
		0xFFDB408686E481AFULL
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
		0x7606A10FB97134A9ULL,
		0x3487E430A3FB7796ULL,
		0x3D41B00BF31153B6ULL,
		0x64131C9C9BB87EECULL,
		0x9D671EF2EAE72A16ULL,
		0xA8EB9D1224CBC2B0ULL,
		0xFE5688DCF991FEABULL,
		0x319C6700166C9DCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7606A10FB97134A9ULL,
		0x3487E430A3FB7796ULL,
		0x3D41B00BF31153B6ULL,
		0x64131C9C9BB87EECULL,
		0x9D671EF2EAE72A16ULL,
		0xA8EB9D1224CBC2B0ULL,
		0xFE5688DCF991FEABULL,
		0x319C6700166C9DCAULL
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
		0xB7024A148C8FB2B3ULL,
		0xBC326292053261B8ULL,
		0xA51C621908226BDDULL,
		0x5B2B3A864D08B90CULL,
		0x205E9A11FF912C34ULL,
		0x980B6A15B9187579ULL,
		0x3A46C55FD0AF1FABULL,
		0x28F235CC5E23C891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3A68B7D211F2814ULL,
		0x94AE78F973D4D6D2ULL,
		0x34827536224195F1ULL,
		0x41C4A8924F101E6DULL,
		0x57944ED05E8EE2ACULL,
		0x433A9EC3FFFC58E3ULL,
		0x61B251CA6E62CA09ULL,
		0xC4CB82FF4219142FULL
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
		0x5B5C877A1C2DE08AULL,
		0x5118A017B4D61135ULL,
		0x534BD9DCE390AEFCULL,
		0x9A9F4A24E466F3C1ULL,
		0xFA965FC9DA004C4EULL,
		0xA32D6AE0410CD5A9ULL,
		0xFBD4A3281D5F042FULL,
		0x31C02BA7E1C1FD5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD76476AD28B43EDAULL,
		0x16BF320B619BFAE5ULL,
		0xBA50F5E19674745AULL,
		0xFAF1F9BE856418EBULL,
		0x1D1092DE05E79138ULL,
		0xEAC9A352B8A41912ULL,
		0x3A41BAFF35FA5B9AULL,
		0x6801FE0A8DB2F0CFULL
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
		0xAD91CB58F5393D50ULL,
		0x6DD0DA477052E48FULL,
		0xA54C0CA352B4D3B1ULL,
		0xF165D4038E949A29ULL,
		0xFB5EE6DE07B15A28ULL,
		0xE24A96FAE63E4E2BULL,
		0x4BB953F81224C8B8ULL,
		0x38AE44E9B25C8288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4568E23DA61985AULL,
		0x29C6766996DA670FULL,
		0x56A5CF21B86A82FBULL,
		0xE7B2F79D31367538ULL,
		0xE86BF18764BB721CULL,
		0x0AE045B101126BA5ULL,
		0xC6F9E8A0B2811692ULL,
		0x25CCFF573F4219DBULL
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
		0x415F0A2E349645C9ULL,
		0x83901AE3D3C8D024ULL,
		0xF15250CF43A46AE0ULL,
		0xF604CAECDAF68E7FULL,
		0xE960C432709CC536ULL,
		0x9741EA66BE935AFDULL,
		0x77A1CB9730051CD3ULL,
		0x6A942C5DB9000B83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x415F0A2E349645C9ULL,
		0x83901AE3D3C8D024ULL,
		0xF15250CF43A46AE0ULL,
		0xF604CAECDAF68E7FULL,
		0xE960C432709CC536ULL,
		0x9741EA66BE935AFDULL,
		0x77A1CB9730051CD3ULL,
		0x6A942C5DB9000B83ULL
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
		0x217FD98BE2C453A6ULL,
		0xA4742F96EA143AC9ULL,
		0x56C34795D5E462D6ULL,
		0xEC598A364AB52E04ULL,
		0xFEFBB9F3EBE82119ULL,
		0x93CD0EC53C42E825ULL,
		0xB2B05277EC278168ULL,
		0x325D3FB004486AEFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF79BF872E5E94AF7ULL,
		0x101AEF2BF334468FULL,
		0xD121F5A69148F076ULL,
		0x7CF388411FBA9969ULL,
		0x986B383A771521CBULL,
		0xB4F60893CA82530AULL,
		0x3517941074926451ULL,
		0x165318DF7959A81CULL
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
		0xC086D339CD35F677ULL,
		0x18F5B23E9F69CEBDULL,
		0x5576D7AF4BA6F05BULL,
		0x7AA2661C829591B1ULL,
		0xD7C4CC91AB92AD07ULL,
		0xDE7A41E9FB648BBDULL,
		0xA7342086FC08C84AULL,
		0xA86E0EF29CDD7EC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2B1F89B2D4F1A24ULL,
		0x846D1232B5FB9B28ULL,
		0x4EFB689EF6E510A6ULL,
		0x14F9BD903806BFD8ULL,
		0xD063351916330EA9ULL,
		0x8729894F14BCEF96ULL,
		0x6F2770566407427DULL,
		0xDD01A36891B9F5A3ULL
	}};
	t = -1;
	printf("Test Case 259\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x063370624F291A74ULL,
		0xCEA93BA11B3264BBULL,
		0xD61E579FA110F39BULL,
		0xA56E233F93D216BEULL,
		0x764A43F3F7AD18EEULL,
		0x2E1072B637352C21ULL,
		0x5954EA2A56357FD5ULL,
		0x7087CA9FFE5184AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A0BFE67ED3143DULL,
		0x9A21AF444A2510C4ULL,
		0x3965E187250118F1ULL,
		0xB6204F93D95B19DBULL,
		0x70461A6495B493FEULL,
		0x66E257398241C5FDULL,
		0x9F5AC40DC98C8AB1ULL,
		0x6646ADC269146026ULL
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
		0xFA246ABABC0136D0ULL,
		0x4A344B976300F7C6ULL,
		0x7A3B2C491DC760DAULL,
		0xB00F72EEA3722449ULL,
		0xBC04672D865D015CULL,
		0xA49768275EF9ADA8ULL,
		0x69C88BC74A57D96DULL,
		0x7058829F682CBF3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFA246ABABC0136D0ULL,
		0x4A344B976300F7C6ULL,
		0x7A3B2C491DC760DAULL,
		0xB00F72EEA3722449ULL,
		0xBC04672D865D015CULL,
		0xA49768275EF9ADA8ULL,
		0x69C88BC74A57D96DULL,
		0x7058829F682CBF3CULL
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
		0xB846D101A6DFDE8AULL,
		0x3071003FAE3A7975ULL,
		0xAECF1E9014802625ULL,
		0x73394AE285293DF9ULL,
		0x289505E9E7BD63B9ULL,
		0x2630AC27D5770A5FULL,
		0x4A19361B6DEFBECAULL,
		0x4CD65E7C97DA30CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x79B25EEE6F8AC3C7ULL,
		0x269E05722ACA3B3AULL,
		0xD3527FFB740F7FE0ULL,
		0x66882037A95851FBULL,
		0x5A3497EA8431128FULL,
		0x16336A31E98A98CFULL,
		0x1F105EA550692D00ULL,
		0x807458F7BBE137B5ULL
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
		0x211E9AE44D15359CULL,
		0x037238EC0D139D23ULL,
		0xAD5830823274CF12ULL,
		0xC46E5163515439E7ULL,
		0xEEE08AFD29BAEAC4ULL,
		0xAF358D44C6172768ULL,
		0xDC5C6719BD5393F0ULL,
		0xDECC29D70C278612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB68FC9CDD9750080ULL,
		0xF5672F3F9B3AB6A4ULL,
		0x0685FDD5BF17DEA8ULL,
		0xAA29BD69780AD7D1ULL,
		0x3403A490C426AB9AULL,
		0x0EAE74DC15CD1DC9ULL,
		0xCB34213550C4AFE1ULL,
		0x9E281C02A3FB1012ULL
	}};
	t = 1;
	printf("Test Case 263\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4C058512B2CED7D6ULL,
		0xFF78513F7E697C80ULL,
		0x4666B5CCC512238AULL,
		0xDA8C4971F24941EBULL,
		0x11FFBE23E1939578ULL,
		0x37F50BA17B294E66ULL,
		0x70C3BCF00CD5401FULL,
		0xAFA646E168EA437EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC4414EDDC18885B7ULL,
		0xEEA0004DCAB9EAA5ULL,
		0x2990133BDA874232ULL,
		0x478E30B71FD701F5ULL,
		0xC2CD20B0FDBE556FULL,
		0x9757B8750C82B1C1ULL,
		0xAA905287C08AA60FULL,
		0x744EAEDA52B45675ULL
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
		0x1C56F464329152D9ULL,
		0xA9EB07DF18D965EAULL,
		0x5396BBF1B44EA00CULL,
		0x6243BB0E01176477ULL,
		0xC5667ACDC8C638BAULL,
		0xF51CCA825C02E705ULL,
		0xCE7E0BC1D551B3E6ULL,
		0x673C28F273A0606DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C56F464329152D9ULL,
		0xA9EB07DF18D965EAULL,
		0x5396BBF1B44EA00CULL,
		0x6243BB0E01176477ULL,
		0xC5667ACDC8C638BAULL,
		0xF51CCA825C02E705ULL,
		0xCE7E0BC1D551B3E6ULL,
		0x673C28F273A0606DULL
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
		0xD80E15AB89E3885EULL,
		0xE63E8595BCA91019ULL,
		0xEB40F2E387839C32ULL,
		0x7D08715B6D7E4A4BULL,
		0x4E28E4C19B539D59ULL,
		0x8CC5BCEEDF61DBA6ULL,
		0x6FE6819C903534DCULL,
		0x5758F3A876017D26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x716826DA77C8838AULL,
		0x25FDB7D8265E881DULL,
		0x10322D7AFB80364BULL,
		0x46E13F1AEA4E30D7ULL,
		0x38A13530E6120E35ULL,
		0xE3970DCA0FA3CE0EULL,
		0x718459CFD7A62834ULL,
		0x68BDA19460671AB9ULL
	}};
	t = -1;
	printf("Test Case 266\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3DF01D4663FD8745ULL,
		0xBC41F28EDE747701ULL,
		0xDAD5A57335423F90ULL,
		0xAFE9742D12451CBAULL,
		0x757AF1463D6FD416ULL,
		0x32407AAE10644E4BULL,
		0x228D3311C3C14EF3ULL,
		0x55F1ED252F82ABD9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3AB2EF4FE072E8CULL,
		0xC947EFE833733F24ULL,
		0x9739D51A5836AD7CULL,
		0xE63ECACE2A3D7871ULL,
		0xDA9ADBCF998B25C9ULL,
		0x94A5AA3926F6655CULL,
		0x84DFEFDE89B7EDCAULL,
		0xBF9A2AF35DFD5390ULL
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
		0xC0DBED6D1511ADCBULL,
		0x98D35B8E18A327C0ULL,
		0x46E4C2D265F4F8AEULL,
		0x222E3A9536F11194ULL,
		0x765D3190387D0ABAULL,
		0x5EB2BA411715E739ULL,
		0x039B902DCC4AF4D8ULL,
		0x7465D9ED3097544BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8CB29CDD63AB075ULL,
		0x5E4AA9F759128207ULL,
		0xE37AACF3FC2FBDACULL,
		0x69788119DC576D0AULL,
		0x25E74C3183BB1285ULL,
		0x436941BA13AB66EDULL,
		0x8182F2D1FAE2A1E6ULL,
		0xE395D9374973D807ULL
	}};
	t = -1;
	printf("Test Case 268\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2460081C2B1D2BE4ULL,
		0x025714C535D2EC43ULL,
		0xD21A0BB49647FC9DULL,
		0x1430805FA81790B0ULL,
		0xBE17265EDBA97AC8ULL,
		0x80D4F4D112C0199DULL,
		0x3FBA1D679D3D8001ULL,
		0xC7A5087AC16DAE4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2460081C2B1D2BE4ULL,
		0x025714C535D2EC43ULL,
		0xD21A0BB49647FC9DULL,
		0x1430805FA81790B0ULL,
		0xBE17265EDBA97AC8ULL,
		0x80D4F4D112C0199DULL,
		0x3FBA1D679D3D8001ULL,
		0xC7A5087AC16DAE4BULL
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
		0xEAD8864D5B36F4E5ULL,
		0xF08AC96CFFF88EF0ULL,
		0xCE57E204AC767154ULL,
		0xD320DDCA69FAA112ULL,
		0x3752C5F5BE032D35ULL,
		0xB09185D6816E84B4ULL,
		0xCDCA2485E27C0F83ULL,
		0x1F4054866FE856B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF337EEC2F1E80C5FULL,
		0xB4CEFD77C48FEF6BULL,
		0x68F5D87F22FEBA76ULL,
		0xCFDBF27188A44002ULL,
		0x881AA93256194216ULL,
		0xC308C03283F78D01ULL,
		0xC84F8322C58360BBULL,
		0x0AB4A93008CC451CULL
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
		0x75C9AF964CAEFE15ULL,
		0x203BF1DF1BB5DFB6ULL,
		0xFAD973CBC09C519FULL,
		0x46BB1585BF848379ULL,
		0x0D0540752971C7F2ULL,
		0xE37329CE53885A63ULL,
		0xD89595B487026CFBULL,
		0xD0D0B14D39498D99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1038C4B73B79068CULL,
		0x105BBA84AB42785FULL,
		0x4E6C58AE4BFE91E2ULL,
		0xFAB7EA0E555E274BULL,
		0xB44B2CD569911048ULL,
		0x2FBDFB30A36E4D5AULL,
		0x383024FF8B89F201ULL,
		0xE84912FD9D0A7EAEULL
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
		0x35B3A1FA86D1E9F9ULL,
		0x5D0510FE97B16731ULL,
		0x8E8D4649018A9550ULL,
		0x4528D9DDB1163A8FULL,
		0x4C625208260DF8D1ULL,
		0x2FF95B0DFD57EF86ULL,
		0xBDE0DC6F6580DAFCULL,
		0xD2CAD7C71E9DC587ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x608DC2979C33F150ULL,
		0xC231377A6B92EDACULL,
		0x43202CD2C1B5508AULL,
		0xF0D3F3E67086036EULL,
		0x1118286961A10AF5ULL,
		0x6EA4E3BD13CECFE0ULL,
		0xDAB3DC0160453453ULL,
		0x02C6163948D14FACULL
	}};
	t = 1;
	printf("Test Case 272\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xCEA28B3DE85D33D1ULL,
		0xEAF91025ABA68FD8ULL,
		0x782E0E6F242696EFULL,
		0xC2EB10B0F07CD0D7ULL,
		0x068D4BB8EB638E64ULL,
		0x34FFCF4E9B238BA1ULL,
		0x9014622F66DEE381ULL,
		0xFC6A53676ACF992DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCEA28B3DE85D33D1ULL,
		0xEAF91025ABA68FD8ULL,
		0x782E0E6F242696EFULL,
		0xC2EB10B0F07CD0D7ULL,
		0x068D4BB8EB638E64ULL,
		0x34FFCF4E9B238BA1ULL,
		0x9014622F66DEE381ULL,
		0xFC6A53676ACF992DULL
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
		0xE179A364CF5D9DFAULL,
		0xF570C15F0C04E2D3ULL,
		0x3541D61184F1DFC4ULL,
		0x9873DAD2D8E9AF15ULL,
		0x3F39B422C310E3D8ULL,
		0xC05512998CC71AA0ULL,
		0x2448C9542240A9DBULL,
		0x62C7D532CF3B181FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F63B5E1D7B5DA80ULL,
		0x8EEB7DBB05DE420FULL,
		0x6059AFCBCCF58A24ULL,
		0x375DBA41B0659268ULL,
		0x186CBBD95CEB8E58ULL,
		0x97372E9399778980ULL,
		0xB176CAE94A7FE458ULL,
		0xCA80FABC10BF185DULL
	}};
	t = -1;
	printf("Test Case 274\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA7E89C9438E76923ULL,
		0xDBCD321635EB2FF4ULL,
		0x8EF0A744084B1AFAULL,
		0xFCB7269E3F440423ULL,
		0x3E60B1A447AF3984ULL,
		0xBC2139DF06CF5214ULL,
		0xB51CEEAABE04E071ULL,
		0x739B5EA3B7C27298ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x946805F9C86E5FCEULL,
		0x095DA12226E9C117ULL,
		0x6543B0D50D516A53ULL,
		0xD0DC6A72218E56ABULL,
		0x7A7EC31B25E8045AULL,
		0xDA874E92C8FFE64CULL,
		0x2D6DCEDA7466BD5AULL,
		0x6C17B6F391D460F4ULL
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
		0xAF3519C394DB3CD5ULL,
		0xDAF3DA10BAE0F566ULL,
		0xF8E6F84CCB04D4CDULL,
		0x6EC5C02A62B6F6CBULL,
		0xA61E74CF12601619ULL,
		0x5D5267D17F71CAC2ULL,
		0x72587E2A03D801ACULL,
		0x09FC0078FDC07828ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9CE2E9967DAABCE1ULL,
		0xF412E0D173593FEBULL,
		0x75EF95B5CE1EDB94ULL,
		0xDCABAC6F76976A28ULL,
		0xF227995FFD915B5BULL,
		0x20E672F4CAB48C4DULL,
		0xFD4B075FF1DFC156ULL,
		0xCCDD890FFB79AE01ULL
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
		0x52E348D7E2F8B2A3ULL,
		0x11FC8304738D9979ULL,
		0x46608C8D1CD75568ULL,
		0xBC60C8E046558408ULL,
		0x7A28627B4C39232AULL,
		0xE0B88ACED8726F00ULL,
		0x37ECC8B96FAB6E3AULL,
		0xB0D95022A17728FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52E348D7E2F8B2A3ULL,
		0x11FC8304738D9979ULL,
		0x46608C8D1CD75568ULL,
		0xBC60C8E046558408ULL,
		0x7A28627B4C39232AULL,
		0xE0B88ACED8726F00ULL,
		0x37ECC8B96FAB6E3AULL,
		0xB0D95022A17728FEULL
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
		0x1D9BB8A12D90E8D6ULL,
		0xFCAC644E7E12A8CFULL,
		0xFB3C7C5E0887FCFBULL,
		0xCAC219C6E1F77752ULL,
		0x4BBA336AE566F334ULL,
		0x60BF947BF63142F0ULL,
		0x44D341597F39E510ULL,
		0x51E4F75FA817103BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE909E1B3026A9687ULL,
		0xADF1ABBE03DA7F4EULL,
		0x8325EFCCE747A491ULL,
		0xE0F7A011E6AD9663ULL,
		0x275AED31C1B45FE8ULL,
		0xE6AD1823954FF70BULL,
		0x547F81A10E837602ULL,
		0xE0FB1DA685BD0ECDULL
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
		0xEF8579EF0D923B05ULL,
		0xF86BD051906FFD20ULL,
		0x7B3E50BE3D545653ULL,
		0xED0042A023BD2FCEULL,
		0x0AC1B82F522491A3ULL,
		0x950EF1E6A728E116ULL,
		0x58927F516A917EF2ULL,
		0x746337DBC051A2F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D5614C7E587DE48ULL,
		0xDA7B0DA437CC4A43ULL,
		0xCB2C196F5716FA7DULL,
		0xABE56C95C80D29C7ULL,
		0xE7BA1A1E0910FC67ULL,
		0x67327F34E21A5204ULL,
		0x52894FAEC44A8B8BULL,
		0x3B86E7276EB5F02FULL
	}};
	t = 1;
	printf("Test Case 279\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDF4D0F64612505CAULL,
		0x8A02A18137C5AE9FULL,
		0x05DF760419ADDA7CULL,
		0x5BD114F145694588ULL,
		0xFF1D3BAE7F0EE742ULL,
		0x3E817B6F6E4DD59FULL,
		0x8C8A0E17B6A0DCD0ULL,
		0x8E9EAF27C81D16C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2F8D70627B69271ULL,
		0x1F4ECB7E1DFD3FCAULL,
		0x75406973D2EF8D96ULL,
		0xCE96280F011D7B59ULL,
		0x426884EF2A20F0C1ULL,
		0x2599890BDC9142FEULL,
		0xE2F7E82377642B71ULL,
		0x01E802A4F0FB3175ULL
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
		0x95D23B1850D5EFFBULL,
		0xCF73793A133AB2D5ULL,
		0x6CBB0F86C3D47C9DULL,
		0x5FE3C303246EF50CULL,
		0xA01449754D205273ULL,
		0xFF0FED705F05BA42ULL,
		0x2346C151A04502DDULL,
		0xAA19991326498161ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D23B1850D5EFFBULL,
		0xCF73793A133AB2D5ULL,
		0x6CBB0F86C3D47C9DULL,
		0x5FE3C303246EF50CULL,
		0xA01449754D205273ULL,
		0xFF0FED705F05BA42ULL,
		0x2346C151A04502DDULL,
		0xAA19991326498161ULL
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
		0x286A6EACB7D01EC8ULL,
		0xC310FE6F7BF71082ULL,
		0xDB7460C5961509F5ULL,
		0x303BCDE729398268ULL,
		0x56084666320C6441ULL,
		0x11DDF415218E3E07ULL,
		0xDBB34DE4CCEAD9F6ULL,
		0x0AA24A7453EED390ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CB8A6B572539EE8ULL,
		0x1F929F7F29A45834ULL,
		0x58A27195D764B899ULL,
		0x6AD3FE2F17695FDAULL,
		0x5A2CDA75600A9865ULL,
		0x0C452C2ADB46BB90ULL,
		0x528FB3D46E9E3AEDULL,
		0xA666D2BD6FEA75FBULL
	}};
	t = -1;
	printf("Test Case 282\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x97A131DC26DB2780ULL,
		0x85666C05B1FAC472ULL,
		0xD5AC0BD5C0D73448ULL,
		0xC7464B1DF1A743F4ULL,
		0xD3B1AF1E5D7161E1ULL,
		0xA48BC702A6C06119ULL,
		0x16A0A0898327DD34ULL,
		0x4283C041AE7426DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD53F52536BB942D2ULL,
		0xFA4570B4277224EBULL,
		0xD0E400B1E86493DDULL,
		0xEEE7956DFB3AA872ULL,
		0xB2B50F3F6EBF5B4FULL,
		0x633C40ACA7CBF1D0ULL,
		0xD752F6960ADE4701ULL,
		0xA316DA4E7430C40CULL
	}};
	t = -1;
	printf("Test Case 283\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0E475F8BE958ECFDULL,
		0x98ABEE1F343926CDULL,
		0xA9C27969845B8182ULL,
		0xD25D5AA867ACA32DULL,
		0x17F7663C9AF086DBULL,
		0x23F609C6F3B81DF6ULL,
		0x8EB9559BB5A29970ULL,
		0x3A162CAF61D2AF8CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC3C4F54B163E355ULL,
		0xF39FC12C239A6818ULL,
		0x9D06A9701C1F82F0ULL,
		0x63A0B6D1DA7E2129ULL,
		0xA34304AE140926B3ULL,
		0x5E0553D172A78F9DULL,
		0xD45B4709B05B0C29ULL,
		0xACECCC955A90F34BULL
	}};
	t = -1;
	printf("Test Case 284\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1B1DCFA02EF3F74CULL,
		0xF0750069538A7800ULL,
		0xEC6FFC60A7586FB7ULL,
		0x006501DF4F738052ULL,
		0x496A562D6FC60AD8ULL,
		0x908AD78F8FD221F7ULL,
		0x1EB1996E728D597FULL,
		0x6D493DCCB0E3B646ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B1DCFA02EF3F74CULL,
		0xF0750069538A7800ULL,
		0xEC6FFC60A7586FB7ULL,
		0x006501DF4F738052ULL,
		0x496A562D6FC60AD8ULL,
		0x908AD78F8FD221F7ULL,
		0x1EB1996E728D597FULL,
		0x6D493DCCB0E3B646ULL
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
		0xB04A23F59B665A6EULL,
		0x58A7F794F846CD1AULL,
		0x3FCBC2EB3CC4D14DULL,
		0xB4F923A06AF69E6EULL,
		0x4BAFAAB9B5FF6FCBULL,
		0xFACF357E4A8D4D5DULL,
		0x54A374A4EAF51E3CULL,
		0xC4A6236B66818951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD4EA8FAEBB1834DULL,
		0x3D9EC12EE09B4CE3ULL,
		0x112332643F65AC28ULL,
		0x9E9581B276F8DCAFULL,
		0xCE6119F5BD2776E1ULL,
		0x9D2D93E08707847BULL,
		0x06F0C22B0A82D009ULL,
		0xE74FBFC5F3734701ULL
	}};
	t = -1;
	printf("Test Case 286\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x10B00A52CF0C3709ULL,
		0xEB80069B68B35176ULL,
		0x9C29D5D2684B3A86ULL,
		0xA0883D2036225220ULL,
		0xC4A04BCAD8304F8BULL,
		0x27998A3D0D325788ULL,
		0xE65D9965A0E0D365ULL,
		0x9EFCD609BB46E89DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x896B3B2478967C34ULL,
		0x98874CDD06868A35ULL,
		0x1287BA006DEAF5B7ULL,
		0x316FEB2DC494E107ULL,
		0xB00D4E2A6AA20C01ULL,
		0x33CDE5DF29D3CB21ULL,
		0x279E1CC35A655A49ULL,
		0xE3BD107A06A65EBEULL
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
		0x6C1DB9E4EBE8E112ULL,
		0x6B0B47EBC3E9811FULL,
		0x47CA9D4D3EA70C2BULL,
		0xF41F5A22728975F9ULL,
		0xB5D0F782DAEEF38EULL,
		0x475128E58A13AC69ULL,
		0x2B2012A32EA72F15ULL,
		0x78F4014C0D33CDC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5089D2CD93A543ULL,
		0x33F6895F9A105B57ULL,
		0xE27BB01D454A77F9ULL,
		0x4FA4F0EB2530690EULL,
		0x817404B644F231B7ULL,
		0xA2B7EA9814585465ULL,
		0xFDC3E88D32E037A4ULL,
		0xE20C3F5710523C37ULL
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
		0xEBEC31DEAA911311ULL,
		0x517D5E0EC31E533CULL,
		0x6FFA4D15D490E57EULL,
		0x18C8076871EF65A8ULL,
		0x6D80DF9EFE36C129ULL,
		0x11A60FC907C54D13ULL,
		0x782710E56EBB5422ULL,
		0x887332049527A310ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBEC31DEAA911311ULL,
		0x517D5E0EC31E533CULL,
		0x6FFA4D15D490E57EULL,
		0x18C8076871EF65A8ULL,
		0x6D80DF9EFE36C129ULL,
		0x11A60FC907C54D13ULL,
		0x782710E56EBB5422ULL,
		0x887332049527A310ULL
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
		0xEA887ECE036ABA23ULL,
		0x8DB391374F2F4484ULL,
		0x557731CD143C35D3ULL,
		0x33601224AAC513A7ULL,
		0x6F5C1AFD0891E149ULL,
		0x9644AF01D851DDE9ULL,
		0xC2EF32450E222CA2ULL,
		0xE4182AAD644932F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5AC8839EEA5D7FC4ULL,
		0x9F44F6784F97BEE5ULL,
		0x67A64692B8C3479BULL,
		0x7000EFDAE25F092EULL,
		0x2F5B6F23677BC1CCULL,
		0xDDF03DC1510DA3D7ULL,
		0x6EB887E0A5F39F66ULL,
		0x8A2CF794B6604B07ULL
	}};
	t = 1;
	printf("Test Case 290\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x08FF26F1D85A9948ULL,
		0x381AFC635E72CB97ULL,
		0xFA8CDC27F1E1FDF1ULL,
		0xCC0FCAC8642833AEULL,
		0x373C10C027915E97ULL,
		0x1164548FC7DEB267ULL,
		0x9796510BA0169734ULL,
		0x407EA428D7B1B960ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25370A9B0BB78713ULL,
		0x9542EC4424F9E50BULL,
		0xDF76B98F41857706ULL,
		0xF86D17C5AECB62BBULL,
		0x879E1FB1A734163DULL,
		0x7F53EDE256BFDA66ULL,
		0xA8D9501251D62440ULL,
		0x63FFC6EED1CD7CD9ULL
	}};
	t = -1;
	printf("Test Case 291\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9CE1E973601AAA43ULL,
		0x3DC06679CB1EFE5BULL,
		0xDA17EB648B7F2956ULL,
		0x4595E56FC1E763EDULL,
		0xB1C6175B239A3EE3ULL,
		0xF5D76CC638F45921ULL,
		0xBB8C30B23295E6DEULL,
		0x4AA95D0DCC413DE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38DD7A07B40FC4A5ULL,
		0x43E8F685351F74A1ULL,
		0xB6D896121915B09FULL,
		0x5E880319731AC07DULL,
		0xA0724BB99B5E716BULL,
		0xF2531F6377DA31A5ULL,
		0x6EFF196A1BD017ECULL,
		0x124761675A24058CULL
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
		0xBD586E875471F58DULL,
		0xC5589EC28BE3BB32ULL,
		0x840B25D9325BD396ULL,
		0x2FD8848959F3C29BULL,
		0x9C3D3E9678A48CF3ULL,
		0x1D7F7E92328E1AF2ULL,
		0x6FA3AAB3ACABA5ADULL,
		0xD27B68C11894148FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD586E875471F58DULL,
		0xC5589EC28BE3BB32ULL,
		0x840B25D9325BD396ULL,
		0x2FD8848959F3C29BULL,
		0x9C3D3E9678A48CF3ULL,
		0x1D7F7E92328E1AF2ULL,
		0x6FA3AAB3ACABA5ADULL,
		0xD27B68C11894148FULL
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
		0xA597FA4D7560F8DAULL,
		0x6EDF72F89B27FAD6ULL,
		0x18287B61B90E7BDAULL,
		0xB9DC9AD25F7B95EEULL,
		0xD916EB43CED23A44ULL,
		0x524152FDBE433FF4ULL,
		0xF3342FF9459E35DFULL,
		0x2CD0D22DEE790C02ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA4A5C19FC574999ULL,
		0x4C961009C4A48EE4ULL,
		0x0FCD2457870F46C1ULL,
		0xCFEE70C1AAA55505ULL,
		0xCE95D6DD9398C859ULL,
		0x59A61B38771A641BULL,
		0x9EA0914906925B3BULL,
		0x8EED0CC12A1EA680ULL
	}};
	t = -1;
	printf("Test Case 294\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x05C9B3739755ED09ULL,
		0xFE94E447102E8064ULL,
		0xDE849920733F2BAEULL,
		0xD9517B46F5F1AB7EULL,
		0x1F1AB864F0E96A0EULL,
		0x3125A99DC792C618ULL,
		0xED5E42F3EAE99785ULL,
		0x8B28D247818DB229ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9693260B36F38D50ULL,
		0x7028F82BB1993908ULL,
		0x472FD7E27D86FBDDULL,
		0x34C5B7D3B1CA00DDULL,
		0x01621A5CF2791FF0ULL,
		0x42CDB15CC5233E01ULL,
		0x7B33ED5AE37D006AULL,
		0xF7FD17E67518FFB0ULL
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
		0x56E3D145DFEE7B98ULL,
		0x00010D828B0DCBF4ULL,
		0x99DB2404DFFE82F9ULL,
		0x8F2C8BBB1CAE2573ULL,
		0xE8A370D33BBD77E1ULL,
		0xEDD42B9013CC7F7DULL,
		0xA53EB332B67C7F29ULL,
		0xB2CDB54425BB3297ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19EDADF19426E858ULL,
		0xFEA209EF6885AF4FULL,
		0x562D7B48E2E3CB07ULL,
		0x64F31B7467CE7AA2ULL,
		0xDEFCC42D20261EC6ULL,
		0x7FD5C15AA929AE93ULL,
		0x8E02134141154315ULL,
		0xB56FD7D01037866BULL
	}};
	t = -1;
	printf("Test Case 296\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4227C542C7766849ULL,
		0xEFD0B54A60455F48ULL,
		0x2230BE92A66299BCULL,
		0x7F4CFF470FEA9A68ULL,
		0x95C7233F4655EA65ULL,
		0x5EA007557267E920ULL,
		0xB45EDF5544BBE4ADULL,
		0xF773E588E4ECDEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4227C542C7766849ULL,
		0xEFD0B54A60455F48ULL,
		0x2230BE92A66299BCULL,
		0x7F4CFF470FEA9A68ULL,
		0x95C7233F4655EA65ULL,
		0x5EA007557267E920ULL,
		0xB45EDF5544BBE4ADULL,
		0xF773E588E4ECDEDCULL
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
		0xF1BCDC658DB5DBD2ULL,
		0x555324AA948400DFULL,
		0x5E3E6C60FD469D5DULL,
		0x079763A719CA3101ULL,
		0x1AAC046A07675DA7ULL,
		0x32AF5CC0BFFEF3B9ULL,
		0x7D72639DDDDECDA7ULL,
		0x674D82924CADB531ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84F7F8A5F40DE96AULL,
		0xB74EC52E843E8794ULL,
		0xE6A8FB0682263827ULL,
		0x4EF77ECFC2E0BD5CULL,
		0xF558253196517349ULL,
		0x4021885331734690ULL,
		0x4441DB239E58503AULL,
		0xA32A5662808057B7ULL
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
		0xB9072933A813EC20ULL,
		0xE217911C320C038FULL,
		0x172B35B4C14482C8ULL,
		0x569549FD1CBC0159ULL,
		0xFF08799721E16D28ULL,
		0xCB315DC54D373D72ULL,
		0xA3ECEAA656061764ULL,
		0x4AFAE38D4CD747E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F5D4459D845B9DBULL,
		0xAABE08C295879E4FULL,
		0xCDCFD47C1BF6B5B4ULL,
		0xD09F2BB43E1149B9ULL,
		0xC70F0B7E3FD9DB6FULL,
		0x333A7FCEC6B98EB2ULL,
		0xC4B49FDF49A80A15ULL,
		0xB99C17B1678E5C54ULL
	}};
	t = -1;
	printf("Test Case 299\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9CFDA520BD1AEB06ULL,
		0x72AB6EB4487318FCULL,
		0x9115BE1004FB6200ULL,
		0x00EE538A63173754ULL,
		0xE936851854EC0267ULL,
		0xDA414910238A0DFFULL,
		0xDD1AC78C6063FFF0ULL,
		0x15C730EB83EE263BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE0DB3EC4D54B8C7ULL,
		0x20132519D22BC76CULL,
		0x5F611CAC4D4EC2A7ULL,
		0x1762DB9E697C7008ULL,
		0x886CE95BA2DB65BFULL,
		0xA15FB79BF15061F6ULL,
		0xAA8E3F7F0C7CB387ULL,
		0x8D15F4ECAB130D83ULL
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
		0x74CA451879EC1294ULL,
		0x09CC2B8EB59D4EA2ULL,
		0xABCC8DE47D7B9390ULL,
		0x1C6364FBFD1384DCULL,
		0x3DEB72E4F47F9F00ULL,
		0x59F16BEC7EEF6979ULL,
		0xB20D4E2B6349D567ULL,
		0x1C8954CA925838A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74CA451879EC1294ULL,
		0x09CC2B8EB59D4EA2ULL,
		0xABCC8DE47D7B9390ULL,
		0x1C6364FBFD1384DCULL,
		0x3DEB72E4F47F9F00ULL,
		0x59F16BEC7EEF6979ULL,
		0xB20D4E2B6349D567ULL,
		0x1C8954CA925838A9ULL
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
		0x5C5672354625622CULL,
		0x84C5FF4D2B7DB861ULL,
		0x9A880FCD802DEC94ULL,
		0xB15CB78CAABED289ULL,
		0xDE77423678DDEB49ULL,
		0xE1662E4898B2452AULL,
		0x817215A9EB3FFE5FULL,
		0xA64B1E36CAA5A3EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93CBC3BE208BF69CULL,
		0xCA0D0D11220C8BA0ULL,
		0x9E621D31A13A193EULL,
		0xB69CAA4C3ABF33A1ULL,
		0x30900C9F91A15338ULL,
		0x6EEA4E23C1A5A0D2ULL,
		0x1094A8C59E95D238ULL,
		0x782952E86B144B1AULL
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
		0xA1E1649CED393E56ULL,
		0xB550919CB6435C92ULL,
		0x1D925D44F0A1C291ULL,
		0x1F9EFFD8CB7A087FULL,
		0x0CB1C5E58162022AULL,
		0x4D3F251A24F8B5BFULL,
		0xE471BB5B156DABC8ULL,
		0xEF1FDFADF68754C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB25A070727C33900ULL,
		0xDE960FBEE93F6AE2ULL,
		0x4F00CA4DAC88CD64ULL,
		0xF9E2A434A25C5146ULL,
		0xF71E0A1AD2F96E94ULL,
		0x3753451741DC7E62ULL,
		0xBA548DB0BF329F4DULL,
		0x4790113B281ECD3DULL
	}};
	t = 1;
	printf("Test Case 303\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x388054F0B75A15FAULL,
		0x56C0C6D9D7E5B41EULL,
		0x363344B228179400ULL,
		0xF6385AF9786A43D1ULL,
		0xBC71162177F99BC9ULL,
		0x90324A328C3734EBULL,
		0x65AA9898C78BFDB5ULL,
		0xD9B81CF14D48F1C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46BA453EB9B41E67ULL,
		0x1A55620335E70D99ULL,
		0x791B660A4760E133ULL,
		0xBB4131FD88B8A4FFULL,
		0x887D4E67C97E799AULL,
		0xDBB92482BEA365AFULL,
		0x9BC780A01D90A671ULL,
		0x7ADBFC0473BF7B3DULL
	}};
	t = 1;
	printf("Test Case 304\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xDE6E88C4C8B410DFULL,
		0xA1508E0367833F3FULL,
		0x8416047E812BAE57ULL,
		0xCF7CA72B57DA8A8DULL,
		0x4AC14D2B7B0EC18FULL,
		0x509C05B3D8338FD8ULL,
		0x9C37B9F94C3F0FE7ULL,
		0xE81D0C72A9B2AB96ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE6E88C4C8B410DFULL,
		0xA1508E0367833F3FULL,
		0x8416047E812BAE57ULL,
		0xCF7CA72B57DA8A8DULL,
		0x4AC14D2B7B0EC18FULL,
		0x509C05B3D8338FD8ULL,
		0x9C37B9F94C3F0FE7ULL,
		0xE81D0C72A9B2AB96ULL
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
		0x7074C0A8E6F92550ULL,
		0xEC3AA5DBA24F015FULL,
		0xED5C30933C1F9A63ULL,
		0x3A7578D0D8B7BC36ULL,
		0x1D746A3F98976F64ULL,
		0x65381D0A8243AE5DULL,
		0x8431E79D30B2BB3BULL,
		0x9567C01057E46932ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78C76E8559641BF2ULL,
		0xA0D512B53D6CDC95ULL,
		0x6E3CE775ACD2609FULL,
		0x260A12811EB26FC0ULL,
		0x48B69A3BEAF5D843ULL,
		0x3111057A7A17943BULL,
		0x2934123E7775CB99ULL,
		0x10F8DC404501771BULL
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
		0x965A40EBB8CE51FEULL,
		0x5D7CB539B0709DB4ULL,
		0x3F4965A3B3ABACACULL,
		0xE002582A337605B1ULL,
		0x5953AC2F2F84DDA9ULL,
		0x9D6F7726703BF229ULL,
		0x501E5B519D78DB99ULL,
		0x110A2317092F3988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A845C9AFA5407EEULL,
		0x9D60B8C2D2C8C7FCULL,
		0x5B212543BB2FE13BULL,
		0x079CDFC9590234C6ULL,
		0xC8695332605196D2ULL,
		0x13AA23F4714BE785ULL,
		0x0DC46C9E51AEEBDEULL,
		0x54DB9234D9AC0F16ULL
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
		0x39F2965BF562912EULL,
		0x7C0B56B37736E035ULL,
		0xD27E01DB169D7908ULL,
		0x6BE37B01813ACAF9ULL,
		0x420D0E41C125BD28ULL,
		0x18494F4F2A2CDF15ULL,
		0xA8EB9A9E8DCF81FCULL,
		0xAD81ACC393F0FF80ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8532D89E81F500EULL,
		0x2FA19ABD0C8510DAULL,
		0xF18689A1003314B0ULL,
		0x0561F9285F75A8BDULL,
		0x346C2E47738C2AE8ULL,
		0x5AF0F49AE681B671ULL,
		0x4C6253CBFD4CB032ULL,
		0xF3B1F58AE909FA3EULL
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
		0x6F6C85B36D2F1588ULL,
		0x063F0716DFF938FEULL,
		0x0F2159E0B2CC7DB7ULL,
		0xECCC57FCE31DE062ULL,
		0xA680BC10A31B8F33ULL,
		0xC6EDCCB7C13F03A5ULL,
		0x56EA4932DB1A8A82ULL,
		0xC2FF134B2F8E1F6FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F6C85B36D2F1588ULL,
		0x063F0716DFF938FEULL,
		0x0F2159E0B2CC7DB7ULL,
		0xECCC57FCE31DE062ULL,
		0xA680BC10A31B8F33ULL,
		0xC6EDCCB7C13F03A5ULL,
		0x56EA4932DB1A8A82ULL,
		0xC2FF134B2F8E1F6FULL
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
		0x1AE214AE704E662CULL,
		0x0BAAFBE77904A77EULL,
		0x555765826DF404E4ULL,
		0xC0EA260A128B604EULL,
		0x667648BFE61D19D4ULL,
		0x30E8248CB541DD71ULL,
		0x1A2259CF0D194F61ULL,
		0x89AF8ED740D3FC67ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5CBCB9E26FF281FULL,
		0xD0B471105B2C679AULL,
		0x02186C793A82A03AULL,
		0x7F93FB92E3D47982ULL,
		0xA0277410B1C59ABBULL,
		0xE84453E368359DAAULL,
		0xBA17A7D642A3F1CBULL,
		0x38ABD49D8A911DBCULL
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
		0xCFD2FADD29A5886EULL,
		0x1E4620876E863AF4ULL,
		0x589D864D8DDD2A0EULL,
		0x4DB3EE91351EEA08ULL,
		0x06303EAA89A4B4B5ULL,
		0x008FB34EB9FB68DBULL,
		0x0B2C4CB1230E85ECULL,
		0x0DA07214D9F44642ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D48AA871D2F8415ULL,
		0x9FA9D26415CDAE61ULL,
		0x20B9C40439B43904ULL,
		0xA0A337C8E2E7A6AAULL,
		0x4A402F86DC321A55ULL,
		0x055A836E88C90C4FULL,
		0xEB221EFE9BA571F9ULL,
		0x2F543793A5090074ULL
	}};
	t = -1;
	printf("Test Case 311\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4BD3B055B02AE90AULL,
		0xA3FA7D6BD84A9A5FULL,
		0x9A8ACA18862B2907ULL,
		0xD0650DB0E839DF5CULL,
		0xACBC1C12C0FB105CULL,
		0xF23DC15ED96EEDF1ULL,
		0xD0DFDB680EBE547EULL,
		0x7F6D3EB2505585B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5BAF4F06459CFCA9ULL,
		0x63792006FCE2E211ULL,
		0x506E09F5F956EDD0ULL,
		0xB4F2E5021F6EFD9DULL,
		0xF1116605E634756CULL,
		0x602E8A2D34922907ULL,
		0xBD8A80CB97571E9FULL,
		0x828C1D0ADE8F1131ULL
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
		0x4B90A5E0224A6F97ULL,
		0x27576AF2FF54CAB2ULL,
		0xBAE2E52786911765ULL,
		0x1C92E13E49ADAEB0ULL,
		0x238524F60ED30504ULL,
		0x6C1912EDC423B07DULL,
		0xA6165DF55629D906ULL,
		0x97FF69FDF9C8EAC9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B90A5E0224A6F97ULL,
		0x27576AF2FF54CAB2ULL,
		0xBAE2E52786911765ULL,
		0x1C92E13E49ADAEB0ULL,
		0x238524F60ED30504ULL,
		0x6C1912EDC423B07DULL,
		0xA6165DF55629D906ULL,
		0x97FF69FDF9C8EAC9ULL
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
		0xEACF87071B7EF060ULL,
		0x00918CE8503284E4ULL,
		0x4809757C388D918CULL,
		0xCEA71D39A2C83280ULL,
		0x50DBA1BD2837CEC0ULL,
		0x56A53E27A24F3A51ULL,
		0x6FCF82170603F8CBULL,
		0x774AE532E95FA117ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x375698A80ECAB5A4ULL,
		0xDAC43973820212A4ULL,
		0xC4C7DCB7F35BECA4ULL,
		0x7DD1A3D756966836ULL,
		0xE3D1C9C5EF7E3F05ULL,
		0x15CDE5A3D284982CULL,
		0x39ED2C097AF2FF0FULL,
		0xC54637921B2F58D3ULL
	}};
	t = -1;
	printf("Test Case 314\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xEA29D0C0B16C8BA3ULL,
		0xBDB3090D0E700B87ULL,
		0xE338DAA1745A9B2CULL,
		0xA47F48CEDCA44E20ULL,
		0xCF312E9FC14C0915ULL,
		0xBCB4335694531893ULL,
		0x287A46326DC64CB1ULL,
		0xD4655C2E40363D55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC116923609882F5ULL,
		0x4496B56658FB77DCULL,
		0xC6562742F0E56F54ULL,
		0x9E291B78508E1807ULL,
		0x95671337B3BEF5DBULL,
		0x3DD73DA5003D3C04ULL,
		0xBA6DB5BF6B4449F3ULL,
		0x89F1BFF52BD979EBULL
	}};
	t = 1;
	printf("Test Case 315\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFD2A7C01D151148BULL,
		0x3D44B53430AE3AE7ULL,
		0x90CD761246D8125CULL,
		0x803EB97460775378ULL,
		0xC2E2B98C714E5B8DULL,
		0x020C5EF21D0C7B19ULL,
		0x4CCF3D8B5808ADBCULL,
		0x09172E78AE4EE5AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9AB45242982DBD8FULL,
		0xC6FBAE83D7ABA6CDULL,
		0x48EA5F60C399484AULL,
		0x3F26BA3475E56FCEULL,
		0x9DD4EEBB4BBCC48BULL,
		0xAE52BA89D26B407AULL,
		0xA1C3329E0BECB050ULL,
		0xF2991C61BA856CB0ULL
	}};
	t = -1;
	printf("Test Case 316\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x807B767B388421E3ULL,
		0xFA6A9A75C4FB78FDULL,
		0x23151EEDD3B8777CULL,
		0x76E6009CC6AFD537ULL,
		0xB0D012E0906659C6ULL,
		0xF3331627C693906EULL,
		0x860F71A98D245170ULL,
		0x1C1AE158D94F3708ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x807B767B388421E3ULL,
		0xFA6A9A75C4FB78FDULL,
		0x23151EEDD3B8777CULL,
		0x76E6009CC6AFD537ULL,
		0xB0D012E0906659C6ULL,
		0xF3331627C693906EULL,
		0x860F71A98D245170ULL,
		0x1C1AE158D94F3708ULL
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
		0xD0425C85B375F80BULL,
		0xB94D8983F09B8FAFULL,
		0x5A7ADD70471045F2ULL,
		0xA1574A4BDDE3FA57ULL,
		0xCB93948407FD712FULL,
		0x79A1DA6265D51C65ULL,
		0x95CE1DDDDBE9154CULL,
		0xE5BE5E52DBB892D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD96ED5AB3A6B9FD9ULL,
		0x8B1629DEBDBA1BD7ULL,
		0x14D6B09CA7180DACULL,
		0x71C718F9176A9F31ULL,
		0x0DAB27A679AF1162ULL,
		0x6C982E4DB939E66AULL,
		0xF7068DD4179B6C9EULL,
		0xE0420D2C08C39451ULL
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
		0x3CB66745F0E5D048ULL,
		0x8B61CE3C4005D178ULL,
		0xE8D8CD6CC3D50013ULL,
		0x34443ED943CC5B26ULL,
		0xDFDD9D629A358F60ULL,
		0x2C701A81F5687D73ULL,
		0xC95486E41AB85A6AULL,
		0x4A8337511C8C9399ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4141E9CB4ADC1927ULL,
		0xD6ABF132D9EDAB9DULL,
		0x8D58F8BE9F1A8641ULL,
		0x17B25D8E282D8202ULL,
		0x91A96CABC0420714ULL,
		0xE18DFF765C6FD5ACULL,
		0xFADD29F4E0C3FFDDULL,
		0x213CD70506396DE5ULL
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
		0xAFC45859A462A80FULL,
		0x5B123C2B381AC061ULL,
		0x535710812EB93BC2ULL,
		0x62E5412C5E24DA44ULL,
		0xCC63D1E382F41A2BULL,
		0x26D963FBA1257E26ULL,
		0x8ABE8E6E619ED2FAULL,
		0x981B98B64504E85EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FAB1ABA6E3C3449ULL,
		0xA409B15DFEC99ABFULL,
		0x98107AFE18864862ULL,
		0x03EA6A127E629BB9ULL,
		0xDCFB6E7B19C8F151ULL,
		0x2377DCA3DF47F864ULL,
		0x63DCED31E21930F6ULL,
		0x23B4DBD697960779ULL
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
		0xF4B452B2D0EB0207ULL,
		0xB514AD953A1F0459ULL,
		0xF339AE305A41EE9AULL,
		0x11D7A671A92C3CA4ULL,
		0x261E0417ED9BF1BCULL,
		0xE5F22EA75CF684D6ULL,
		0x98BF1381BB524D16ULL,
		0xE2700BF028511816ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4B452B2D0EB0207ULL,
		0xB514AD953A1F0459ULL,
		0xF339AE305A41EE9AULL,
		0x11D7A671A92C3CA4ULL,
		0x261E0417ED9BF1BCULL,
		0xE5F22EA75CF684D6ULL,
		0x98BF1381BB524D16ULL,
		0xE2700BF028511816ULL
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
		0x55C6B771AD267ED4ULL,
		0x457DF21FDA3ECB05ULL,
		0xC4733349A9B2D532ULL,
		0x8C964AB7DEB50AF9ULL,
		0xAE3A961AEE14D577ULL,
		0x661B9F4E9E29FD9EULL,
		0x89AC62C315697679ULL,
		0xFA5EAFDB49CA90F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB5032C4DD36315AULL,
		0x6C49A794F648EF88ULL,
		0x36E4794B89DD9009ULL,
		0xDE07BC1CD2BEC133ULL,
		0xCBF860DA091EE7B4ULL,
		0x314606EC81B467BCULL,
		0xB77B282C3B26C844ULL,
		0x3A11F9DE9AA8FECFULL
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
		0x19F7D476CAEEF817ULL,
		0xD1647625EB6C9F9FULL,
		0x97B67B894226AB0DULL,
		0xE9F69C025B16F086ULL,
		0xF601B1E6D9EF2AF4ULL,
		0x345F12C982650D43ULL,
		0x7BFF4DB8A0F199DAULL,
		0xDD2E99E33AA14576ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5062965F5DA120B8ULL,
		0x0A9D77618B5F1F1EULL,
		0x936CC9D98FE56B40ULL,
		0x6A188CF1F53D3940ULL,
		0x309859AB52527D59ULL,
		0x359608EA117F5E74ULL,
		0x1304D0E5AB4A0A2CULL,
		0x1D7EAD71E4766DC6ULL
	}};
	t = 1;
	printf("Test Case 323\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2FC6F190FAA5FF46ULL,
		0xD15E670660D6AF39ULL,
		0x138FCFA92321B3C7ULL,
		0x98931E1F1665C862ULL,
		0xE79B11622498E725ULL,
		0x6788CE58649AC238ULL,
		0x963B34A0F1E4DC28ULL,
		0x186D30098F396445ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3929D4F2363B688ULL,
		0x166F3D6B705ED4C1ULL,
		0x79E232B50F0F5F3AULL,
		0xDE919675F5EB99B0ULL,
		0xC8274AFF829C9156ULL,
		0xB518B340D0864761ULL,
		0x5FA5EC71464E357BULL,
		0x42959A2CEC9805A8ULL
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
		0x93BBB078FBE3654CULL,
		0xCFCD3102B6B3C5F2ULL,
		0x5217C1F1FF6C7D80ULL,
		0x13D1F47E502D9576ULL,
		0x1EC84B7FFC36E495ULL,
		0x3394E8EE0D5214FEULL,
		0xC1B1D6ED8DA7E0ADULL,
		0x9843017D428BA72DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93BBB078FBE3654CULL,
		0xCFCD3102B6B3C5F2ULL,
		0x5217C1F1FF6C7D80ULL,
		0x13D1F47E502D9576ULL,
		0x1EC84B7FFC36E495ULL,
		0x3394E8EE0D5214FEULL,
		0xC1B1D6ED8DA7E0ADULL,
		0x9843017D428BA72DULL
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
		0xEE34B58BD4C8107DULL,
		0x107E857B04855C14ULL,
		0x275030D24AEE382EULL,
		0xA2E2D4A1B9B6AFC8ULL,
		0xAB1089CE30F36FA4ULL,
		0xD021B28E3214231BULL,
		0xBA333C01C119AA2AULL,
		0xF36C0EB9E87B5A3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69ACBE05E1FCC330ULL,
		0xD9E8EC494FC3ABFBULL,
		0x3FD5CFA5277CAC75ULL,
		0x92E8FE193D7AF353ULL,
		0xCDDB65AC8998CD3AULL,
		0x9FA57F4E5188D97EULL,
		0x128DDE7CBFE6C05AULL,
		0x902856D3B7025976ULL
	}};
	t = 1;
	printf("Test Case 326\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB0B3BD29CF4CF404ULL,
		0x17731F33314D2D1DULL,
		0xB6FD0652393CA4E2ULL,
		0xE95529933530947DULL,
		0x115661B3A0E401B0ULL,
		0xF82BE34F06F50E27ULL,
		0x68EC2DAAF9F2B2B0ULL,
		0x8AC8A394C0C30C35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D19DCA5792B0211ULL,
		0x549E583FBF3FACAEULL,
		0x4F1C1B18ED82BCDBULL,
		0x9626D53A5AD3B71EULL,
		0x33AE52CCA56CCA40ULL,
		0xAB71D8315D56791AULL,
		0xF888C12986178992ULL,
		0x0D9C9E53C3F76F92ULL
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
		0xABB8DD4F2B5A379EULL,
		0x77923F16A6CE922BULL,
		0x6BAE98E7F5F3F6CCULL,
		0x895D472410013029ULL,
		0xF416CB50C6818963ULL,
		0x6E87986083D1E64EULL,
		0x0E57DFBA4A0D62B0ULL,
		0x27A8A46C52B01381ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76A9693D77E601ACULL,
		0x999024B70A39199AULL,
		0x993C471D74795A0AULL,
		0x0400FCA64B5E9B68ULL,
		0x0C411B73B62FD673ULL,
		0x8CEF594F62619A09ULL,
		0xB1C7CD30BD4CBFDBULL,
		0x29B02B46FE7ED6DBULL
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
		0x9E3F945AAA8FB3C9ULL,
		0x0EE24E2343289C40ULL,
		0x403B9C2B4E916B56ULL,
		0xC110F39AE62F575CULL,
		0xC43614C1DA90F70EULL,
		0x1AD16C94F79B5AE9ULL,
		0x58AC465ABD2A230DULL,
		0x01E93E27EE06CA62ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E3F945AAA8FB3C9ULL,
		0x0EE24E2343289C40ULL,
		0x403B9C2B4E916B56ULL,
		0xC110F39AE62F575CULL,
		0xC43614C1DA90F70EULL,
		0x1AD16C94F79B5AE9ULL,
		0x58AC465ABD2A230DULL,
		0x01E93E27EE06CA62ULL
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
		0xFEAD7E6FD217F101ULL,
		0x4D71AA3D9CD14AF9ULL,
		0xB7C3D5CF641B35FBULL,
		0x989C7646FE589251ULL,
		0x584D7A43D22BE0A2ULL,
		0x34C94C85572D2E84ULL,
		0x51B4377285F41D72ULL,
		0x8BC5A69DD7421FDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E0FE45802BAAD0ULL,
		0x9ACE3CD6135F293DULL,
		0x99A6CC8E724C4E61ULL,
		0x6DB5F8F3344C0E22ULL,
		0xC3E64BADC3A85EB2ULL,
		0x622E5E11F271DF54ULL,
		0xB7C0620490C79F48ULL,
		0xC930869DC0535025ULL
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
		0x92F6E16F1F32030BULL,
		0xBCF0586E417CF47FULL,
		0x3BCC877F1177C5E0ULL,
		0x2FA6D20ABCBD8B8EULL,
		0xFE818D6C8BE8B2BBULL,
		0x1C56069EF7059DAFULL,
		0x67C6CEBDDEC700AEULL,
		0xDB41F401E269E083ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB38C76A03CD1D84ULL,
		0x0C42ED0F81BAACBFULL,
		0xB43E43F06019E770ULL,
		0x012501485377F8B9ULL,
		0xD40141D6FD36B017ULL,
		0x2E77C5C47B06C0F1ULL,
		0xDDFCE46EFB38111EULL,
		0x47CB327D3ABE785DULL
	}};
	t = 1;
	printf("Test Case 331\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x08DCEF246356C3B2ULL,
		0x91F576BA4F80E44CULL,
		0xD58BD974803005C6ULL,
		0x8BBD1A3769D14573ULL,
		0xBDE81048BA9DE67AULL,
		0x370DE0058E4DDCD9ULL,
		0xC89F8A3A18B5A835ULL,
		0x72183256FEAB7AD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA6BDD916C83B6EFULL,
		0xA3A8071BD930A23AULL,
		0xCED4BBDAD080EAADULL,
		0x3E89E6B92838661FULL,
		0x5ED703FD3B25B269ULL,
		0xA1873D13BB73269AULL,
		0xB581727270A68CC5ULL,
		0xF60BAC84A4CF1F5AULL
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
		0xA76DECC41D5C7349ULL,
		0x7066B408EF3FFECBULL,
		0x8FE99A687AF554ECULL,
		0xFFFE69732405607AULL,
		0x65AD5C87C4EFBE27ULL,
		0xBC7B4C27C4C91FD6ULL,
		0x998D76DFEA380CEFULL,
		0x58F1725D0915CBDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA76DECC41D5C7349ULL,
		0x7066B408EF3FFECBULL,
		0x8FE99A687AF554ECULL,
		0xFFFE69732405607AULL,
		0x65AD5C87C4EFBE27ULL,
		0xBC7B4C27C4C91FD6ULL,
		0x998D76DFEA380CEFULL,
		0x58F1725D0915CBDBULL
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
		0x7E827B047793F0C5ULL,
		0x4482F7076BAFCA1AULL,
		0x48679C17948CF62CULL,
		0x827FBCDFA0D9E448ULL,
		0x3FE614872939B57BULL,
		0x5BDED62EB2BFFB01ULL,
		0x626B6945E47B0408ULL,
		0x4350B3E42DFF10D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF32F24D31150B38ULL,
		0xEE7DBD102816F51AULL,
		0xAE6FF43E477B7783ULL,
		0x3D6FC5C3098A7E9BULL,
		0xFF19416F41D2E2C2ULL,
		0xE82F82F00322C286ULL,
		0xA45CD0BDE70848F3ULL,
		0x138A2015D39BCA19ULL
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
		0x1B6291C6825E8206ULL,
		0xBB21C376D4B01FB0ULL,
		0xF49D5CE47FE123BBULL,
		0xA60C16E02DF88B75ULL,
		0xDD4DBDBF4B43C722ULL,
		0xA8E426A21202CC9BULL,
		0xFD3025389F035507ULL,
		0x1B5726008C752E58ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C1F03275954566ULL,
		0xB9FA4B5E13A61854ULL,
		0xEE1E292879CFEBB4ULL,
		0xF43B2C7534793FB0ULL,
		0x68116C5F09E26AB0ULL,
		0x627CD3385900F89EULL,
		0xC87E2F999F0751B7ULL,
		0x41492C1845FBD054ULL
	}};
	t = -1;
	printf("Test Case 335\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xCDCDAF2D38E4CCCFULL,
		0x9BC4D13D84E57784ULL,
		0x6AD3CF067C04B8AEULL,
		0x863481E202D8EE5EULL,
		0xDFFD71681E020A7FULL,
		0x2A997FBE282E5621ULL,
		0x32028A9514C06DE6ULL,
		0xECFFA7B05388E1D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FD8A375612C05E0ULL,
		0xB2E9C295DB896665ULL,
		0x54D37E5DA435404EULL,
		0x0DFC0C510A53A29BULL,
		0xB8AD80FB0AE9B40AULL,
		0x7AC5D97E46A15E96ULL,
		0x42657A58C48B32CAULL,
		0x151A6E60DAF121EDULL
	}};
	t = 1;
	printf("Test Case 336\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x528FA72B66220B9DULL,
		0x35F6A03C767F3E1BULL,
		0x65DA6E827F812DA3ULL,
		0xA29EF63D7A27652AULL,
		0x4F3D033F7ECF3E64ULL,
		0x8429B3098015211EULL,
		0x2E06435C7C6584D3ULL,
		0xB10A2F5A14E3C835ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x528FA72B66220B9DULL,
		0x35F6A03C767F3E1BULL,
		0x65DA6E827F812DA3ULL,
		0xA29EF63D7A27652AULL,
		0x4F3D033F7ECF3E64ULL,
		0x8429B3098015211EULL,
		0x2E06435C7C6584D3ULL,
		0xB10A2F5A14E3C835ULL
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
		0xC72A47E72CFB4932ULL,
		0x09F60C0FAB65FF45ULL,
		0x040BB0974E8A11ADULL,
		0x0A3A24F784A3F43EULL,
		0x8B85BE1B1037FBAEULL,
		0x0C24AEBD40257ED6ULL,
		0xABDC79E9F6202747ULL,
		0x98040E2F2D6D8807ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00D8919A14982B17ULL,
		0x675EA553B365F433ULL,
		0x9C63DB63A2BF276FULL,
		0xA49F8EAE74589AEDULL,
		0x28CBEE0293DF9A02ULL,
		0x39499E6A4CA78AEFULL,
		0x1F836A44C538C6C9ULL,
		0x84FFBA6EFF9A3F07ULL
	}};
	t = 1;
	printf("Test Case 338\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x868C356BC10A5B5EULL,
		0x921AEEE25785256BULL,
		0x58A405C1CAED1F15ULL,
		0xE40F93023D61BC67ULL,
		0xAAAC4C7E6CF29643ULL,
		0xCBFA95DC30C1676BULL,
		0x991B57F9B9D6EA26ULL,
		0x3C79844D247E0EB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F45145B2355E11CULL,
		0x3CD623CC73E5EBD7ULL,
		0xA5AE5FF226D2BCDCULL,
		0x231A3BC9A6E5EFC2ULL,
		0x9E740C3287A69172ULL,
		0xB0E225DFD1798C6AULL,
		0x209E192E37958AC4ULL,
		0xF5C3CBFFF014DA2FULL
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
		0x20928D8B234D5A20ULL,
		0x5ED9FC546E787377ULL,
		0xCDA0A6061E2EA18AULL,
		0xE31E859F6E606DCAULL,
		0x5EFF4BCCB4E36742ULL,
		0xBC50E8A82CE2AC03ULL,
		0x79FA0A1CCD2AD13FULL,
		0x6EE22FB880CD54F9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x693180DCF127CB06ULL,
		0x573979EF8D1401FEULL,
		0x41C5202F38EFC3FFULL,
		0x7C32E8A859DB53D7ULL,
		0x89663FEABE95DF57ULL,
		0xDE06749F3AF71A5AULL,
		0x6623997CF7C59F37ULL,
		0x1BD886C95EDAF16AULL
	}};
	t = 1;
	printf("Test Case 340\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xED223EA02BBFFF79ULL,
		0x2BA4F2F2F849E9CBULL,
		0x59D4F789D79E480CULL,
		0x743F30AB06D0D772ULL,
		0xEF367A7786E5C5D6ULL,
		0x652E3AAC2F6DE76EULL,
		0xA01F8B8C4570B2E8ULL,
		0xF4D1BF87D33640D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED223EA02BBFFF79ULL,
		0x2BA4F2F2F849E9CBULL,
		0x59D4F789D79E480CULL,
		0x743F30AB06D0D772ULL,
		0xEF367A7786E5C5D6ULL,
		0x652E3AAC2F6DE76EULL,
		0xA01F8B8C4570B2E8ULL,
		0xF4D1BF87D33640D9ULL
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
		0x955C636CA96F02B0ULL,
		0xA842997792622AE5ULL,
		0x2DFDEB645374853AULL,
		0x18BA1454D9328E35ULL,
		0x821ED72429E79EE1ULL,
		0x5641A264FF0008BDULL,
		0x00759D7428047E94ULL,
		0xD160DF80C4909292ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF075E7B3332BDF7BULL,
		0xEA155E44056FC8F9ULL,
		0x11528E41891E393EULL,
		0xD4DB4F7659FC1DA0ULL,
		0xECAA3EA0A4EA316FULL,
		0xF9CBF7C9FB740080ULL,
		0x6E37253CFC2F9133ULL,
		0xBB74620A1579B1ADULL
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
		0xE5F636F3B8BE434AULL,
		0xEE2851605BF9349EULL,
		0x02BD209CAA0980DDULL,
		0xE596FB6CDC2A6374ULL,
		0x773AA3BA57A6ABDDULL,
		0xC85212142816E96DULL,
		0xFC7688D3434E3556ULL,
		0x43CBC11339CD27FCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67DD23029FDC31DBULL,
		0x1AC7A75D2BDCCB90ULL,
		0xA9E5C0C3F37AE031ULL,
		0x6D1325C6307E52EDULL,
		0xB47E7056FCA5E102ULL,
		0x3137FE95A1E3F542ULL,
		0x224DA4A854717ADBULL,
		0x0494C9E5532899C5ULL
	}};
	t = 1;
	printf("Test Case 343\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x408683D2C86C42CFULL,
		0xE6BE9CD9A4043716ULL,
		0xBAA76CEF8BD32010ULL,
		0x5B6DD0B3387CDF33ULL,
		0x23D56AAF6B60F4E9ULL,
		0xB394018D78AFC233ULL,
		0x274F3F8994826407ULL,
		0x4799CBA53EF50BCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD48101937767C05ULL,
		0xC6B30229B41C71AFULL,
		0x0F446080BCBD7B39ULL,
		0x43C8FF49813AD3EAULL,
		0xA47E6FFB8A46230EULL,
		0xA598A63C6FBB8F26ULL,
		0x4BA871647AA1F14AULL,
		0x48A49C70739ABB28ULL
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
		0x1D2047CEE63AF95AULL,
		0xBD481169530DF016ULL,
		0x983FF7776C33D7A3ULL,
		0x4562CB5400163384ULL,
		0x9225D13D6083F55EULL,
		0x87EF9E7122499891ULL,
		0x0AD5F6ABA67345AAULL,
		0xEE32152529204E88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D2047CEE63AF95AULL,
		0xBD481169530DF016ULL,
		0x983FF7776C33D7A3ULL,
		0x4562CB5400163384ULL,
		0x9225D13D6083F55EULL,
		0x87EF9E7122499891ULL,
		0x0AD5F6ABA67345AAULL,
		0xEE32152529204E88ULL
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
		0x781E376A2F3C2DDCULL,
		0xBEEC7EF213FA0B3FULL,
		0x3B0CB446E8CD0F9AULL,
		0x0089DA6B4834BDF8ULL,
		0x9F0D623B21A5846CULL,
		0xCDDB81185139CE95ULL,
		0x9F328E0512224FBBULL,
		0xD9B2115DC0D2BA3AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x340E1EC71D640A6DULL,
		0x1C576783BB23312CULL,
		0x4A43C5660518D67AULL,
		0x5F8AF60EA30DFC59ULL,
		0x7C76EF625AEC2B51ULL,
		0xCD5B21E2E6AC9546ULL,
		0x901CF638FBB19F82ULL,
		0x45DE2CBB7F70CA61ULL
	}};
	t = 1;
	printf("Test Case 346\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x78A494BAF3D75D84ULL,
		0x644044FE508D5569ULL,
		0x2CC9DB8EE0EC7972ULL,
		0x20FCBB735A1689FEULL,
		0x3F97AA1986BCB212ULL,
		0x391FB5F659209E6FULL,
		0x9E4D8396DAD17582ULL,
		0x680DB6D2602E0964ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06A399E74636367FULL,
		0x80CF8BEDFF40F360ULL,
		0xB29369029A4FFC05ULL,
		0x727AC8B2F4DB9F6EULL,
		0x0D77892114F4AE40ULL,
		0xF8488F7036F96BBAULL,
		0x0E21A8F075391263ULL,
		0x2E3E476A768969FFULL
	}};
	t = 1;
	printf("Test Case 347\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC25ECB88D3020BBFULL,
		0xD281F0994D7486CBULL,
		0x2198C439F02F2153ULL,
		0x9E4DE37DFB8A3815ULL,
		0xA6F4DA9084BD82D1ULL,
		0xF160B8DA6C67B9C1ULL,
		0xFE790C1861B6908FULL,
		0x58B16BC87FE8B9BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x11A64636AF40FFBEULL,
		0x1A7F2F67E14D4BE0ULL,
		0x68BF630C3435EF04ULL,
		0x40D4B17516C36910ULL,
		0xB99FC3E2BDF41235ULL,
		0x907F2235865DB23FULL,
		0x105F513BE1864F16ULL,
		0xC54AD39A31A07995ULL
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
		0xFAC37AA0AE9DB265ULL,
		0x2D168683387D947EULL,
		0xDD00F9C19BECF9C3ULL,
		0x37BBF48303C4A109ULL,
		0x5739F276BD6A0767ULL,
		0x47D4E32EC65D7385ULL,
		0x085E284CD0BA90A2ULL,
		0x24EC56EE9897E1E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAC37AA0AE9DB265ULL,
		0x2D168683387D947EULL,
		0xDD00F9C19BECF9C3ULL,
		0x37BBF48303C4A109ULL,
		0x5739F276BD6A0767ULL,
		0x47D4E32EC65D7385ULL,
		0x085E284CD0BA90A2ULL,
		0x24EC56EE9897E1E1ULL
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
		0x03B38F233CFFE439ULL,
		0x18F47EA1921F896BULL,
		0x36CB420A5169A22EULL,
		0x615C446D882009E4ULL,
		0x541AC09CC3D1786DULL,
		0x56ECDF3AEEFA2B33ULL,
		0xC0BB4F1E2F6A3A1DULL,
		0x503E222938CE601BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6ED49D630AC1A317ULL,
		0x1D6569A247707A5DULL,
		0xE88A2155A7BFE395ULL,
		0x6EBEBF20DF517740ULL,
		0x4D9584203B2BD95FULL,
		0xEB1B1AA23947A59FULL,
		0xAC66EB2617B3B74AULL,
		0x535F5D223814DCBCULL
	}};
	t = -1;
	printf("Test Case 350\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF4E43757174F6F73ULL,
		0x33880B4436CD42F5ULL,
		0xCB04C3E467F975FBULL,
		0x6039DC8E79AB8E95ULL,
		0x2DDE6C0A2A551271ULL,
		0x27C284293967CE14ULL,
		0x5A8318086E0F7411ULL,
		0xB355ACC881070867ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4EA3D04775D8EC2CULL,
		0x3881C8D42A85BD08ULL,
		0x592851E8F0E525B0ULL,
		0x567365ED145B9EFFULL,
		0xA7667558ECFE0B77ULL,
		0xF7AD3A31FA055659ULL,
		0x55F58A00CB8E8D49ULL,
		0x02BCBD23CDAA9F58ULL
	}};
	t = 1;
	printf("Test Case 351\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x556FE52EF37DC414ULL,
		0x1B55CFC5D0C9249AULL,
		0x2A4D53B2E55C6802ULL,
		0xD41402C27C23D8A4ULL,
		0x1B2445DDDCA5C56FULL,
		0x0B09204EEE10E67EULL,
		0xF1F03EFDF2FBB4BDULL,
		0x9190C0161E1E348CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6564394D119097C2ULL,
		0xEA458D01C9B22533ULL,
		0xBCEFFD93D351417AULL,
		0xFD5E27DE445CBC8AULL,
		0xC32155F2BC199A3CULL,
		0xD2A457CE0BC9BF11ULL,
		0x1F09734B54C9EB6AULL,
		0x5C1791F5C3702A42ULL
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
		0xBC995110144562C3ULL,
		0x19D4D64FDB8D9E48ULL,
		0xE130DC1785D6F436ULL,
		0x38B36BCA85CA9FC4ULL,
		0x260C8A07EA77BD54ULL,
		0x931EC226D06E7492ULL,
		0xD7F05D874421D911ULL,
		0x71B996B7EA40E0F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC995110144562C3ULL,
		0x19D4D64FDB8D9E48ULL,
		0xE130DC1785D6F436ULL,
		0x38B36BCA85CA9FC4ULL,
		0x260C8A07EA77BD54ULL,
		0x931EC226D06E7492ULL,
		0xD7F05D874421D911ULL,
		0x71B996B7EA40E0F5ULL
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
		0x9294EB577C883CD4ULL,
		0x95EFC2640A3E288DULL,
		0xEA698CA559003A41ULL,
		0xDEC8222055E65C92ULL,
		0xC276DF41A3E89A1BULL,
		0xB3AB3EC63BBAA856ULL,
		0x8EAD9C7AE86C5EFBULL,
		0x6CE5D84E223FBC85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD441143118867962ULL,
		0xD40B6958DDDA00F8ULL,
		0xFEC493C45F956F8BULL,
		0x45225DA7F19BF0C9ULL,
		0xAF3CC95AEFB15775ULL,
		0x9D8424BFA56EFFFAULL,
		0xB24F683C427F5F90ULL,
		0x1DB184808CD1C235ULL
	}};
	t = 1;
	printf("Test Case 354\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD66A9790513343B5ULL,
		0xA4A3683DA0CCCB0FULL,
		0x9C39024F63B0E364ULL,
		0xDEEBFBCFBBDFCBFAULL,
		0xD14D704B3A4B9869ULL,
		0xDCE3327DDF28DF37ULL,
		0x15FDDAFBD8A77F0EULL,
		0xE081EC3945861B46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD538E05883F8C8D7ULL,
		0xAF0BE5BBE75A4ED4ULL,
		0x0EB4EA23D20BF084ULL,
		0xF944522EA583BC26ULL,
		0xAB91B5986CAB11CBULL,
		0x9A6CCF716E84446DULL,
		0xD2E5910C1CBC59A9ULL,
		0x9CEDC31023CBC15FULL
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
		0x181DDA7966F91213ULL,
		0x7EDDF4F7EEC2D2E6ULL,
		0x9D863618968C2FCFULL,
		0x3D9251557AF4F8B8ULL,
		0xF0807137975DBF20ULL,
		0x64A2632158473D84ULL,
		0x8BAC7269D2A12EFFULL,
		0x0824A0133168067BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE33CA88D52F824DAULL,
		0x6E1D82643233B019ULL,
		0x9F80C4FC396B0D2FULL,
		0x346014AE381D54A8ULL,
		0xE3579823CFF589C9ULL,
		0xEAABB0FC74A81650ULL,
		0xBAC9BB2C9668ED33ULL,
		0xDDA96AE5DB4399B0ULL
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
		0x9971C7BA0638B9A1ULL,
		0x10C250194C0B3E9DULL,
		0xF1DCF8FD565C0ECBULL,
		0x39E1A65A61738C92ULL,
		0x02AB37D8F21ED50DULL,
		0xA4CF374814B39A79ULL,
		0x2943E079C0B11E2FULL,
		0x96E9AC4496C5CD0BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9971C7BA0638B9A1ULL,
		0x10C250194C0B3E9DULL,
		0xF1DCF8FD565C0ECBULL,
		0x39E1A65A61738C92ULL,
		0x02AB37D8F21ED50DULL,
		0xA4CF374814B39A79ULL,
		0x2943E079C0B11E2FULL,
		0x96E9AC4496C5CD0BULL
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
		0x4273C3994B1BF32FULL,
		0xB8AAB36AD6FCD641ULL,
		0x1D32827E46A40C73ULL,
		0x2A99A4991F4793F3ULL,
		0x212325D46F4AC1A6ULL,
		0x20902AC39326F11CULL,
		0x1E02DFFD4DB4ABC2ULL,
		0x8C8AE9776594F81DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA227722FF62DE5DULL,
		0x474ACA96D97C1F39ULL,
		0x8F402026E0565F47ULL,
		0x84FCD680C03C03BBULL,
		0xD4EABAF7C94B53DAULL,
		0xFFF9595F31F1B255ULL,
		0x88C221BD8616881BULL,
		0x2B3E11C16E707866ULL
	}};
	t = 1;
	printf("Test Case 358\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA2BEE3C353BAB39FULL,
		0xEB2B15FC1D71B0ECULL,
		0x8BD7EDA0090CCD3AULL,
		0xFA4B334A199E6279ULL,
		0xCDB825D84A1C17B1ULL,
		0x1EC88B6DE78E5317ULL,
		0x0C6AA575156CFBC2ULL,
		0xC4B6D9DE14A6086BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD18307912700D0AULL,
		0x6BA82F45B5219102ULL,
		0x4049FDAD6ADD2994ULL,
		0x41FEDC6CC6F359C9ULL,
		0x6FD18934A1C1BD68ULL,
		0x32B620A4D27B22C9ULL,
		0xDBC701F75B83B422ULL,
		0x242CA87D85C28D5EULL
	}};
	t = 1;
	printf("Test Case 359\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x999621667E8F8262ULL,
		0xE56D08A16E890302ULL,
		0x14E2B149273EB66BULL,
		0x0CB256F14ED8B61FULL,
		0x3FBF121A12EB811FULL,
		0xA5DF7DAEA2C3FB98ULL,
		0x8FD8620DC4E7CDC4ULL,
		0xAC356CD6B2A73B4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4F8E6C96E975580ULL,
		0x19E8D2E87C182B37ULL,
		0xB204F9D598D7FDE9ULL,
		0x386D49F2A9F896FCULL,
		0x9DA6CE84BF0C4F19ULL,
		0x031E41BE39B001A0ULL,
		0x1C18F1D5584789A6ULL,
		0xC4A4B3320C1868ABULL
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
		0x8D06787C064FB19FULL,
		0xE2EA83834C3DF00BULL,
		0x73F54B0F8AD3D758ULL,
		0x0FFA95DC119A4D81ULL,
		0xD3994BFE10139B60ULL,
		0xB28E7F308C17C910ULL,
		0x85EC1EC8ECA3BA00ULL,
		0x7B76F44A39ADD910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D06787C064FB19FULL,
		0xE2EA83834C3DF00BULL,
		0x73F54B0F8AD3D758ULL,
		0x0FFA95DC119A4D81ULL,
		0xD3994BFE10139B60ULL,
		0xB28E7F308C17C910ULL,
		0x85EC1EC8ECA3BA00ULL,
		0x7B76F44A39ADD910ULL
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
		0x803B981781A135D9ULL,
		0xF82A180F2D8B2AAEULL,
		0x215DBB4433E31BF1ULL,
		0x90CD33980B5CEEE2ULL,
		0xE9ED205123039A8DULL,
		0xB565B5F714D8615EULL,
		0xAB47D1DCC26732D0ULL,
		0x30730AC95F262127ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02E556E738626292ULL,
		0xD6833D6617F7DC11ULL,
		0x149A459BE1A584EFULL,
		0x09E0412DB7FF778BULL,
		0x0730BD3ECE114D79ULL,
		0x9C3AAB24BB7287EAULL,
		0x9D01AD8B737BA9C5ULL,
		0x3FCC862A7B8E92F0ULL
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
		0x1B44D60FA5240CC6ULL,
		0x059F7D7D731F511AULL,
		0x148C2AC5AF36FB27ULL,
		0x79B4D3D413AE506AULL,
		0x0CF3472414A49FFDULL,
		0xC8164ED11B1240D0ULL,
		0x97A82938004F6290ULL,
		0x65BA0E536EEA35D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27352927142B40B1ULL,
		0xDDA8BF7C5C96BA04ULL,
		0x36AB45E023B6280CULL,
		0xBB6AA3BEB10C9BDDULL,
		0xED635EB2B6A9BE52ULL,
		0x09EA2454F437BF46ULL,
		0xCC49731998A3DC3AULL,
		0xF977BA18500543B6ULL
	}};
	t = -1;
	printf("Test Case 363\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x066FA8AFEEA81418ULL,
		0xEA1DD3DA4459941BULL,
		0x24B160CBECBF49C1ULL,
		0x9CA27E5B604AB4A1ULL,
		0xDEAF2BD7F2FFAB79ULL,
		0x68ECBBC335496D20ULL,
		0x692C8DD7E0CBA7D4ULL,
		0xDE2B5FD187427209ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F578C65BF8849D5ULL,
		0x89AFBF4FA3A99FD2ULL,
		0xC8E2AC7572709E66ULL,
		0x472190447E384BCFULL,
		0x08711B6816D1AADFULL,
		0x4C4DE4ADC7BEC4C9ULL,
		0x5429F97E7364308EULL,
		0xC5BE9F4F1C6FCDB4ULL
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
		0xC3C386280796B46EULL,
		0x9FB3C1B47BFC8C4EULL,
		0x73F6EA683530C1ADULL,
		0xB4BFAD3F1F2C01EBULL,
		0x1C61184850751C5EULL,
		0xF59C15B64F67F198ULL,
		0x4573EBF211665A79ULL,
		0xBCA3CD2C012BCC7AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC3C386280796B46EULL,
		0x9FB3C1B47BFC8C4EULL,
		0x73F6EA683530C1ADULL,
		0xB4BFAD3F1F2C01EBULL,
		0x1C61184850751C5EULL,
		0xF59C15B64F67F198ULL,
		0x4573EBF211665A79ULL,
		0xBCA3CD2C012BCC7AULL
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
		0x4A5A879E51EBBA5CULL,
		0x240388EF7AF09079ULL,
		0xB42C813FBD527243ULL,
		0xB99F5222DFF0C475ULL,
		0x4154EE34B301A66AULL,
		0x10AD882A98538F96ULL,
		0xD5BCAD4CAB4CADF3ULL,
		0x0D03312167032FB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B0FCCBD8E10497ULL,
		0x48064B73746277D5ULL,
		0x37DC82C03A71D4FDULL,
		0x598E21DE3568E51AULL,
		0x6D101EE29180B368ULL,
		0x166BA9D05F689F18ULL,
		0x7622AFE1BFC64E73ULL,
		0x77FB050C2C213060ULL
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
		0x15FB3641166DCF7AULL,
		0x1FF887BDBF0BFB92ULL,
		0x7BDF16325CA10E31ULL,
		0x66EC5BA825768EF8ULL,
		0x212ACAA84BF67EB2ULL,
		0x086C6968B869AEBFULL,
		0xB41DA40822164985ULL,
		0xCFB1AD6E40E4AE9BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB54815FABF87A31CULL,
		0xC79970262EC6577FULL,
		0x5B303C46A85BA60EULL,
		0xD64B97788A8F2DC6ULL,
		0x1D575EBB895FE7D5ULL,
		0x1105186AC4851409ULL,
		0x147C69B3CAE32316ULL,
		0x3809374B4A6D9410ULL
	}};
	t = 1;
	printf("Test Case 367\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBF556428B4911A51ULL,
		0x98EBE5F150B2AB82ULL,
		0x9759BCDB5972728DULL,
		0xE38BB44AA1FF6D1CULL,
		0xF27D85869FDC35DDULL,
		0x3A10B29D3A7BB7B4ULL,
		0xE65B03898C66A737ULL,
		0x8EE5A2B09868E945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2F765CFEED776A8EULL,
		0x52135D3564FB21E2ULL,
		0xEC2A042777606AA3ULL,
		0xDE12C4326FED1A7FULL,
		0x089444F7C356C55CULL,
		0x380A2EAF8E49CD84ULL,
		0x87C8EE07E262486FULL,
		0x03BF3DA6F4CFFA2FULL
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
		0x67BA80F628C2B253ULL,
		0xFE6440605FB9DD3CULL,
		0xE5DC8C6D15B94DA5ULL,
		0x527B0814237B2285ULL,
		0xBFB4A9D6A3C4B348ULL,
		0xC7DAD361F0841A74ULL,
		0xAA8FBC81E06CA238ULL,
		0xA2CDD1F23FE49140ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67BA80F628C2B253ULL,
		0xFE6440605FB9DD3CULL,
		0xE5DC8C6D15B94DA5ULL,
		0x527B0814237B2285ULL,
		0xBFB4A9D6A3C4B348ULL,
		0xC7DAD361F0841A74ULL,
		0xAA8FBC81E06CA238ULL,
		0xA2CDD1F23FE49140ULL
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
		0xE10CC1D0213EF46FULL,
		0x579A1C9DE0081A66ULL,
		0x0E92CB3346DEB112ULL,
		0xD43E4B6F2809259FULL,
		0x944900BDE3E878B7ULL,
		0x7D33A002C8B076A7ULL,
		0x410C334B5E251E4EULL,
		0xA9D500EF5B0693AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDFDFEFBD36911DC1ULL,
		0x524B13227698B581ULL,
		0x798E66FD8109C433ULL,
		0xC03070D6D52BAA55ULL,
		0xE51E5FBF86C92706ULL,
		0x6D485BE3020D9F4BULL,
		0x04E8CBAB5690DF1AULL,
		0x7BAC1D9D067DC2FFULL
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
		0x394FCA7040C1E80CULL,
		0xF1F0DF4A53AD9B9DULL,
		0xA4FE3986700C2B2FULL,
		0xB4DF82B4C3A05DCDULL,
		0xDA6E1A44A1B86F89ULL,
		0x68E2BAAB21977332ULL,
		0xE6EDD61975F566B6ULL,
		0x482F614890A9BA14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE816C988423E4269ULL,
		0x222B335731B7C4BEULL,
		0xC0A6D88E62E48E90ULL,
		0xCB53588D94C4F236ULL,
		0x27764FE1F26DC65CULL,
		0x86C1BF53A303CC43ULL,
		0x5AF64F978E3EEEB2ULL,
		0x3562D415D0F9AD39ULL
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
		0x6BFC7B7647093DF5ULL,
		0x8DE4CE8DD9802788ULL,
		0xA5AD558FB2A1E26CULL,
		0x45B0E0C8FA4BE9A1ULL,
		0xBE0E58F471935807ULL,
		0xE9E816F79C01D996ULL,
		0xA17B11EBD8AFF0CCULL,
		0x253396B7FCA474F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFEBAFAC0F47A0CC3ULL,
		0xD395CF516DC5298EULL,
		0x21E6D68FC38A5DADULL,
		0xFA7D71AAF7DBBCB4ULL,
		0x539D544D6745B4A3ULL,
		0xD53F3B7263AC7DACULL,
		0x0CE2ADBFCDA7B1BAULL,
		0xE828A3437C7B50B7ULL
	}};
	t = -1;
	printf("Test Case 372\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9641D328F0B0BF76ULL,
		0x79731AB3EF199FE8ULL,
		0xE1632EA0AAF12104ULL,
		0x131A4ADE411E277CULL,
		0x4DB651389FF77F6DULL,
		0x3496905DC3D2875FULL,
		0xC29762E2A6DF72F0ULL,
		0xC5471FB2C974026CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9641D328F0B0BF76ULL,
		0x79731AB3EF199FE8ULL,
		0xE1632EA0AAF12104ULL,
		0x131A4ADE411E277CULL,
		0x4DB651389FF77F6DULL,
		0x3496905DC3D2875FULL,
		0xC29762E2A6DF72F0ULL,
		0xC5471FB2C974026CULL
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
		0xAF3D6AE0221A423FULL,
		0xD26B8E85B9BF5979ULL,
		0xB98AC0EC04398C02ULL,
		0x9FD059A80D0D69FEULL,
		0xDEC6064D2154749AULL,
		0xF79D42A62CCCE806ULL,
		0xD62925EF926B98A6ULL,
		0x653BAFF207320700ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4028477F7E5F1254ULL,
		0x2455982C15FA8B7FULL,
		0x5D88D86AA7DB26F7ULL,
		0x8225AE651DD44886ULL,
		0x1D93B4760D155A8AULL,
		0xD3CF3C2244A34020ULL,
		0xE09531DE993D242AULL,
		0xB9A2B6DB0EF60493ULL
	}};
	t = -1;
	printf("Test Case 374\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x6B873222089D4180ULL,
		0x8B6DF62DF522DF7DULL,
		0xE8921EA9954C7BE9ULL,
		0x0C122FAC1F911A99ULL,
		0x799605E0D221EA72ULL,
		0xD5E92993A1687DCEULL,
		0x9B05327DCC9DC0EDULL,
		0xDF317F74F80E58CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08FEEC4B0DBD1F86ULL,
		0x11AD9CC717B92147ULL,
		0x94A04FB631B6FAFBULL,
		0x7089BBE25F545D3CULL,
		0x2961DB56A32554AFULL,
		0xA35165B676C9F340ULL,
		0x7D78095172B587F7ULL,
		0x6380BC6C327C79BFULL
	}};
	t = 1;
	printf("Test Case 375\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4EC6DAEE7B3E899BULL,
		0xA2A698A174646128ULL,
		0xF0C4901BB1CBEFBEULL,
		0xA8EBF070EAB1B893ULL,
		0xFBD111737C03FFCBULL,
		0x4074858F8F7BDD22ULL,
		0x03EF2004E98009DAULL,
		0x04722C309E602994ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9094A3125C8F0B2ULL,
		0xD10FD0B34C4E870EULL,
		0xC99B155CA28ECF28ULL,
		0xE16467964324ECF2ULL,
		0x3CD36CFF5F0DC2E4ULL,
		0xCDF56D7A5BC11760ULL,
		0xEEDA6E6CD13F13F5ULL,
		0xE903D5B4BE6D9A01ULL
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
		0x423D999EC69C9A6DULL,
		0x2CB5612526BDE8DCULL,
		0x5644AA6EF5A2EB3BULL,
		0x7F138B8FC978CF31ULL,
		0xF52D9DFE93A0AFB8ULL,
		0xC3CFB699461159EDULL,
		0x00F3B34874B82AA8ULL,
		0x2F2F25BE36A21D73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x423D999EC69C9A6DULL,
		0x2CB5612526BDE8DCULL,
		0x5644AA6EF5A2EB3BULL,
		0x7F138B8FC978CF31ULL,
		0xF52D9DFE93A0AFB8ULL,
		0xC3CFB699461159EDULL,
		0x00F3B34874B82AA8ULL,
		0x2F2F25BE36A21D73ULL
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
		0x9A80A8F3788E4BAEULL,
		0xA9A96036B5B212B8ULL,
		0x341123E15692ADFCULL,
		0xEB09DD2A71441C31ULL,
		0xFDFD704724080F1DULL,
		0x1D6471F16D84DABBULL,
		0xA7CB1FD84531A85CULL,
		0x000B817866212055ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x740534E7F09E3A7AULL,
		0xF99E777DA8EA562BULL,
		0xA1ADD73779CDAA5DULL,
		0xA0AFF119492F0E33ULL,
		0x25A4D61448900911ULL,
		0x27CD88380C703AEAULL,
		0x3F05682AB0B200E7ULL,
		0x5EEE6E849ADB05A5ULL
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
		0xF29CBE4C2425327CULL,
		0x8D3FFE29FBD7B4AFULL,
		0xC1E17DA33587D7F7ULL,
		0xA9FABF7F536A6EAEULL,
		0xC9A35BB018558391ULL,
		0xB6155D4E9571E2BCULL,
		0x000BA10316B37D91ULL,
		0xA5F5A473589B3790ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18DAE9B872F79300ULL,
		0x9D76205233F97778ULL,
		0xDD3ECA6DE67F9A89ULL,
		0x54E126AC7C799B04ULL,
		0x7D9DEAF8F801E605ULL,
		0x92A96AE64CB1377CULL,
		0x871F97B11592ECBAULL,
		0xE86736982D59F246ULL
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
		0x74F4B18507C19D4CULL,
		0x338CDC387290CB24ULL,
		0x6B9BE2BEEF07C187ULL,
		0x324CDB9B26719326ULL,
		0x40C7F902D88AE78AULL,
		0xA048F3B65FE285B7ULL,
		0x2520B7E213B86D83ULL,
		0xF9930FD2198EFC01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x055F65395CACC7D2ULL,
		0xAEA39DBD11B887F0ULL,
		0x0E1B3A8EDA726014ULL,
		0xA76BDD374B2C4D16ULL,
		0x93ECA019B0572A9CULL,
		0xD10A12B76C596B9AULL,
		0x8669AE4FF8365C01ULL,
		0xC3C667F99B257ADBULL
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
		0xD8D104575C8AFF0BULL,
		0x943EC3082D205AFFULL,
		0x24E4092B2FF2E1C0ULL,
		0xC37C12F130CC8B56ULL,
		0x6C37AB837A345410ULL,
		0x74B6F586A35396A6ULL,
		0x815E86E11D0CFDDEULL,
		0x6779D837FFC47443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8D104575C8AFF0BULL,
		0x943EC3082D205AFFULL,
		0x24E4092B2FF2E1C0ULL,
		0xC37C12F130CC8B56ULL,
		0x6C37AB837A345410ULL,
		0x74B6F586A35396A6ULL,
		0x815E86E11D0CFDDEULL,
		0x6779D837FFC47443ULL
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
		0x42115715972547D4ULL,
		0x6214A4E14B103F94ULL,
		0x224A5A9D667F1C42ULL,
		0xCEE41A7421908878ULL,
		0xFBCF3A95F85C7863ULL,
		0x146865ADF87A896AULL,
		0x1C59304B95CB3E1BULL,
		0xA666895467011585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56A15583CAEA7BE9ULL,
		0xA871B3497CBF3853ULL,
		0x9FDE295E72CB9CB5ULL,
		0xE7FBB70272FE7BC6ULL,
		0x40487CF12FDA122DULL,
		0xC66D2935D02598A3ULL,
		0x2BB11E237FCBFC15ULL,
		0x1F547292CA8ECC56ULL
	}};
	t = 1;
	printf("Test Case 382\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x36854651460D7A30ULL,
		0x3945913572A42CE7ULL,
		0xA828BD3DF1D694C6ULL,
		0xAD14883C82B08F16ULL,
		0xE6CD9F20F5955B3AULL,
		0x573BD9C5CF402644ULL,
		0xC40429E69EB588EFULL,
		0xA5A2618BE57E5FAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B758F17FA7F87FAULL,
		0xEBE99684445BBDD4ULL,
		0x77ADD36F96B561A4ULL,
		0xF62860622490BDADULL,
		0xE14BBD9911D46538ULL,
		0x7A24A894F30E4FF0ULL,
		0xDB4B9FA784C7B97DULL,
		0xEA29D6A2B626F363ULL
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
		0xC29512A31CE5FD3BULL,
		0xE01A5AAAF1E88155ULL,
		0x36A739951FCC3423ULL,
		0x8C2FE261DD01E741ULL,
		0x0826E4F0E05F302EULL,
		0xFE71C6900A782021ULL,
		0x3EFCFBFC0C53A810ULL,
		0xDEBE58C5DE004A55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E006684C509CEDCULL,
		0x3E5B0E8984E35559ULL,
		0xDE98FFF6057148F2ULL,
		0xB3EFD13804416687ULL,
		0x9812C0FB2220C48FULL,
		0x753D4132E3B8C592ULL,
		0x90853495AC0BEA80ULL,
		0x89B30FEF8FEFF40FULL
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
		0x96524A6B8DD1CA93ULL,
		0xF56FA50469C3023DULL,
		0xC695A1799EAB801FULL,
		0xF217657E75DADB0EULL,
		0x564368E0FBBA538BULL,
		0xD681F04C2ACB35C0ULL,
		0xF97D80914D00A8ECULL,
		0xAF3C42DA1B43F322ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x96524A6B8DD1CA93ULL,
		0xF56FA50469C3023DULL,
		0xC695A1799EAB801FULL,
		0xF217657E75DADB0EULL,
		0x564368E0FBBA538BULL,
		0xD681F04C2ACB35C0ULL,
		0xF97D80914D00A8ECULL,
		0xAF3C42DA1B43F322ULL
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
		0xF0513B218D3E43D7ULL,
		0x4EA028E47AACC2E4ULL,
		0xA259C6ECA59A549FULL,
		0x9A6FF789595D9DAFULL,
		0x0D13D8987B87ED20ULL,
		0x3A56DB50342D5EAFULL,
		0x19FCD1624D95CE80ULL,
		0x859FA46A3A811BDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9A2E9F673234996ULL,
		0x7CB1785D3471F0F3ULL,
		0x7854BA48AB9E504BULL,
		0x7CD86E8E2B4C0815ULL,
		0x1ADB9EF7FFFC4E65ULL,
		0x989A9EA3C80E9DA7ULL,
		0x5E0E914BC4E061E0ULL,
		0xAD49CCFBA22B8907ULL
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
		0xDF4E046D291E5D2CULL,
		0x034A5E62DB143FEDULL,
		0x1F4C2EA1851EB83AULL,
		0x98685E1D19793F70ULL,
		0xEA3B7AA0E644C1F7ULL,
		0x180A36FDFF9C4E3AULL,
		0x820BA401AD4D087FULL,
		0xD5726F82D85E0157ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0CFF7643B556F9ULL,
		0x9C3E0497B4A978F0ULL,
		0x6C8742CE80573CF4ULL,
		0xB943AC044BF44ABCULL,
		0x28FBC1F67684492CULL,
		0xDA1AAED1B25DA236ULL,
		0xF69D8A0DC489D846ULL,
		0xC9EE791762409EA1ULL
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
		0x55703569301AC082ULL,
		0xAF6F7E3F35E667A0ULL,
		0x26D42201CCDDC552ULL,
		0x8C075A9A2DA90337ULL,
		0x77B2C3A013AF1927ULL,
		0x499C22DE5AA0C149ULL,
		0xC52E51D9AD5AAB1BULL,
		0x78F3662010E01E87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92E53889638E92C3ULL,
		0x660C35CB0D36CBBFULL,
		0xDE51BE5308EDFAC0ULL,
		0x210F2A759D66F951ULL,
		0xB7DA59BD2AA40CC8ULL,
		0x15B69937188FFBE5ULL,
		0x50F4DA4DDA994709ULL,
		0x660852A742B8E6E9ULL
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
		0xD70431B6F816E418ULL,
		0x9A9BE3AEE775E16DULL,
		0xEA0B1A392CA8FFC3ULL,
		0x083E936E2A6361B4ULL,
		0x97D6600946041176ULL,
		0xC234293C851EF4D5ULL,
		0xD74F824E4AC62FD6ULL,
		0xD605B25D236674F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD70431B6F816E418ULL,
		0x9A9BE3AEE775E16DULL,
		0xEA0B1A392CA8FFC3ULL,
		0x083E936E2A6361B4ULL,
		0x97D6600946041176ULL,
		0xC234293C851EF4D5ULL,
		0xD74F824E4AC62FD6ULL,
		0xD605B25D236674F3ULL
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
		0xF8B1BD0A4DACFB01ULL,
		0x2E327B0E90C5BEAEULL,
		0xFECEA5B241AD4254ULL,
		0x708F1ACAE8A664E9ULL,
		0xFAA42EF7629C55A5ULL,
		0x9E920924771B47EEULL,
		0x9BD15F99F1A7FBF2ULL,
		0x34E2536441A08058ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98500F96994BF464ULL,
		0xEC70D0EFCFB0925DULL,
		0xDE88C4B2E3394451ULL,
		0xAA1814BCDF440CAEULL,
		0x04947DC75F7DDAF4ULL,
		0x18548A7DF602E1A8ULL,
		0x05A2658D10E0CBEBULL,
		0x94AE78DD5564BF6CULL
	}};
	t = -1;
	printf("Test Case 390\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9EB4DCA781D1B187ULL,
		0x3DAF963DB30CDD0CULL,
		0x98EB9156528A9E7EULL,
		0x32A9D3D939AA38E3ULL,
		0x04582396DF1EF8ACULL,
		0x90E727DEC605275AULL,
		0x6DE041CD408F92CFULL,
		0xA08838FD70F42D9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x756FC5330FAD5265ULL,
		0x51523DA816DCB46EULL,
		0x5D22E4706AFDF4C9ULL,
		0x99E7206F4E1DD603ULL,
		0x430EAD9F4ECD48D1ULL,
		0x83A6165D8938C88BULL,
		0x368DA0B0A5001E25ULL,
		0x4F044AA4A3FD32F6ULL
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
		0xC5FFB77DD2291F09ULL,
		0xB380379FCA7E8FC6ULL,
		0x48D89E0744641621ULL,
		0x47B5BEC4763DFCE8ULL,
		0x0A521AEAAC1D425FULL,
		0x7E303F6875656EF7ULL,
		0x35F1D061D8E5A1BAULL,
		0xBACCF3AB700701EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BEA1CF1D23A04BAULL,
		0xC9E7A481FA2E32EBULL,
		0xDB49E17C19385D93ULL,
		0x301D1FE40D3D3F24ULL,
		0xB9944BAE075CA369ULL,
		0xCA364E0B5963D350ULL,
		0x129866E67082F94CULL,
		0x5E3CB90EC1BAEE0BULL
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
		0xDD83DC1084B4EA2EULL,
		0xA9832DF18CCA8BB9ULL,
		0x4757816D4BA49BB0ULL,
		0xA84F7F18F346718EULL,
		0xD60F2B9FF582FCC3ULL,
		0xAA66881D371CB39FULL,
		0x68B952A58541DD2AULL,
		0x552593B08D05B8D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDD83DC1084B4EA2EULL,
		0xA9832DF18CCA8BB9ULL,
		0x4757816D4BA49BB0ULL,
		0xA84F7F18F346718EULL,
		0xD60F2B9FF582FCC3ULL,
		0xAA66881D371CB39FULL,
		0x68B952A58541DD2AULL,
		0x552593B08D05B8D3ULL
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
		0x41FB03FABC882A59ULL,
		0x77F6781F89576120ULL,
		0x69886873F927FF3AULL,
		0x9278958DDD4B9794ULL,
		0xC8B8E384BD619B23ULL,
		0xDD54A208F929D665ULL,
		0x34B9E3AD1D884A38ULL,
		0x0C72C8232D8AAE4DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40F5AE6E59B5C306ULL,
		0x26EA993A49899F47ULL,
		0x1576A37920ECD708ULL,
		0xA701E6DCC48D2CEFULL,
		0x6D6D0CD0D870F638ULL,
		0x8E152B241D951305ULL,
		0xF264651749D3ABABULL,
		0xA7EA83E335AC1D60ULL
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
		0x70BC000A7055C185ULL,
		0x1B9341E21223AAB2ULL,
		0xC17667B0D14704ABULL,
		0xF783B97F9BA405A4ULL,
		0xFB1C282A2B8A5D18ULL,
		0x790C4FEBF6F5BA17ULL,
		0xD61945BE5C57E39EULL,
		0xBB60B03F1FD29142ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4BCB3CB73D897BULL,
		0x00EA1AFC630838DAULL,
		0xC784C08531E54EDCULL,
		0xF7342593BA8BFF4FULL,
		0x74CBD40D0EDA5C72ULL,
		0xDB879094A0612467ULL,
		0x83B4DB2DCA5F1E2AULL,
		0x03E8A8FCED0CF88FULL
	}};
	t = 1;
	printf("Test Case 395\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB222B581E93E76C6ULL,
		0x952D6D3DF7946DF1ULL,
		0x5581E5E8165740D3ULL,
		0x167CDF5066D56463ULL,
		0xFE901C84A5E244E0ULL,
		0x6F87D96E4AB54D66ULL,
		0xBE2919C86CD93664ULL,
		0xE5525002B5895174ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x52023554499EE2F9ULL,
		0x82BF27D07BB88050ULL,
		0xFAAA21266DEE330DULL,
		0x6DDA01C81899F417ULL,
		0xC7D063B29401B2C0ULL,
		0x288B25C530CE8794ULL,
		0xC8ED5215D714B176ULL,
		0xDAD22EB6B7C7CD70ULL
	}};
	t = 1;
	printf("Test Case 396\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEECEC1699DE72DFDULL,
		0x0C3B4C5D46B62A96ULL,
		0x568579696BE46800ULL,
		0x0EFF8CA60663B4D6ULL,
		0x395DF40C07601954ULL,
		0xEA5CBA7D7C8A324CULL,
		0x0FA2C327322636B7ULL,
		0x5EAD3B5FF7B52DB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEECEC1699DE72DFDULL,
		0x0C3B4C5D46B62A96ULL,
		0x568579696BE46800ULL,
		0x0EFF8CA60663B4D6ULL,
		0x395DF40C07601954ULL,
		0xEA5CBA7D7C8A324CULL,
		0x0FA2C327322636B7ULL,
		0x5EAD3B5FF7B52DB8ULL
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
		0xB4084836C9DBBBE0ULL,
		0x5DC9805FE328D078ULL,
		0x648AAF9843CA941FULL,
		0x95DDCF716799F5E0ULL,
		0x267A8B25B11689D7ULL,
		0x293A16C97190867BULL,
		0xF7BCDE7D79AAD7DFULL,
		0xB08A4E34ECC8BCC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12F1E4B28CE62039ULL,
		0x15A99C2FE6734B39ULL,
		0xFEFEAE5CEFE911BFULL,
		0x43CE5D4771171F79ULL,
		0xBAA570DD9B5D1503ULL,
		0x9F13EDF84095BE96ULL,
		0x2117CA92132CDC1EULL,
		0xF9FC8384A43798BEULL
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
		0x79F50D7E7AB470B0ULL,
		0xA66C435AF566067BULL,
		0x9BB188716B0D7F99ULL,
		0xEB47F0AB31CDEBC6ULL,
		0xD26953D55C4B242CULL,
		0x801348332E6DC7DDULL,
		0x08F7C91B0838DCCBULL,
		0xA38589750EA9A54EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x91D0E716380A7C0AULL,
		0x8DDD2AA9695EBBE2ULL,
		0x95DF1D83D60606EFULL,
		0x286284580A6E6AAEULL,
		0xB93D6AC3E953A0EAULL,
		0x7E83F0E86DA5D911ULL,
		0x39C17B80375E1FC9ULL,
		0x16C894E236955131ULL
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
		0x82AC0FC82A791620ULL,
		0x57C07726BF47AA53ULL,
		0xD6CDBDBF70B63B85ULL,
		0x2D40ED547C547567ULL,
		0x862975C5CCCE3799ULL,
		0x011A1F19FA78105CULL,
		0xF24655B6C1D8EF78ULL,
		0x056B1A20075045F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407A67981FF179D0ULL,
		0x78840B89BDBCCEF1ULL,
		0xB75902FE0BA40A66ULL,
		0xCF2B6A76F0CD9450ULL,
		0xB9629FED445F945DULL,
		0x028B3C7A9EE66916ULL,
		0x6F8987965543BB8CULL,
		0x33A6ACC7D6860377ULL
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
		0xD19306AA338D05E8ULL,
		0xBCB8F8A207C458B5ULL,
		0x9E6CEFB090119290ULL,
		0xE9480E1220B3DD0AULL,
		0xF682F39FCBC7DA2FULL,
		0x9290C43DC9D715BBULL,
		0xA7068AC3505CED72ULL,
		0xFFFF0300A338B400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19306AA338D05E8ULL,
		0xBCB8F8A207C458B5ULL,
		0x9E6CEFB090119290ULL,
		0xE9480E1220B3DD0AULL,
		0xF682F39FCBC7DA2FULL,
		0x9290C43DC9D715BBULL,
		0xA7068AC3505CED72ULL,
		0xFFFF0300A338B400ULL
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
		0xA976F4E8F4EB3928ULL,
		0xDBC10AA3B07AEAA4ULL,
		0x8DD0C2B2BEF93C8FULL,
		0xEC4C53C4986E4E2AULL,
		0x6CECC6A374286456ULL,
		0x5E213D086959EE57ULL,
		0x6DB22BB575A59023ULL,
		0x6FB8C335D5EF2FB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20C19721217DA19FULL,
		0x0710FDE99FE92FAFULL,
		0x1A061DC4D4BD1B93ULL,
		0xE7F528FEC8C3D043ULL,
		0x7D1EA1600339F36AULL,
		0xDF7D3A734E4BCD09ULL,
		0x8572225B703515C8ULL,
		0xBB4472D7BC3B6083ULL
	}};
	t = -1;
	printf("Test Case 402\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3664FDFD1DCB8F9EULL,
		0x4CF308B8E0735BA5ULL,
		0x7ED415A54BF74DB6ULL,
		0xFABC3A0F84133F86ULL,
		0x9C09DAC4F0738BF8ULL,
		0xFC228FB65DC466B9ULL,
		0x9C642F27DE156816ULL,
		0x28D1DAE7BC36C6DFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49998C6ED62A934BULL,
		0xE544A4276269BCD3ULL,
		0xB98FADD403D4B63FULL,
		0x34C058533858B15CULL,
		0xEC5F00F0BE2D5F3BULL,
		0xAF8B28A03CD1A80CULL,
		0x4066255DD9C62ED6ULL,
		0xDFDF290B489187BFULL
	}};
	t = -1;
	printf("Test Case 403\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB13E4EBE5061D4FDULL,
		0x58231943742AE047ULL,
		0xE510FD97712E9C30ULL,
		0xF0A7FAF33C2BC3E1ULL,
		0x1BA0AF31A5510F4AULL,
		0x150F17507A551B35ULL,
		0x0D659DB67044AEB6ULL,
		0xAFA595015982F720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6402585FAB158C85ULL,
		0xDB403F95071F6FA0ULL,
		0x243C601EDCF233CDULL,
		0xE24514C7C6943B47ULL,
		0xAFE352FB800D3902ULL,
		0x1887107E4B29B9DDULL,
		0x9B8BB5100B805277ULL,
		0xC395A7E8B9B35D87ULL
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
		0x4CF5CB2BFF8932AAULL,
		0x400AA4F70F4EF82AULL,
		0x1B5C18C705A30ADBULL,
		0xF5BABE8BC5FDD17AULL,
		0x32B71A0A94F82C33ULL,
		0x2B1B5BE9DFEB94A5ULL,
		0x8C16AE82D47E65A5ULL,
		0x17602222C1FA8CCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CF5CB2BFF8932AAULL,
		0x400AA4F70F4EF82AULL,
		0x1B5C18C705A30ADBULL,
		0xF5BABE8BC5FDD17AULL,
		0x32B71A0A94F82C33ULL,
		0x2B1B5BE9DFEB94A5ULL,
		0x8C16AE82D47E65A5ULL,
		0x17602222C1FA8CCDULL
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
		0x8E5C3513A909E2DAULL,
		0xE4D8437DCD3F9405ULL,
		0xABB1212D17E27195ULL,
		0xEE9F02B0E1240654ULL,
		0xA951F33331F98BCAULL,
		0x271F2695041E4336ULL,
		0xC4F16CFCDD61F63AULL,
		0xD8E86EC3953823A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EBE3096CBAD8D92ULL,
		0x533A5738CD1944C3ULL,
		0xDBA942482C308057ULL,
		0xE15F6E8AB23DEDDBULL,
		0x1395017E75138C27ULL,
		0xF963A9397582969FULL,
		0xCE956F342AF88CB3ULL,
		0x81999472F24A1E7CULL
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
		0x7D3A48FE0D683DF0ULL,
		0x26F083325AF42768ULL,
		0xAE286721678B16FFULL,
		0xCDCD3FDDAB5B4963ULL,
		0x6178BD3C86A5E908ULL,
		0xA5265518CBBAAD01ULL,
		0x9F6C66417DA82D39ULL,
		0x1E5E9FDB487E71F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A15478F44E34545ULL,
		0x3ABEB2F12D7DC3D7ULL,
		0x6777492D81B8FA7BULL,
		0x3FC8F89B29EE3297ULL,
		0xF585A6B268A49E6EULL,
		0x0D4BF77EB7C96052ULL,
		0x54F95B0EE8864A14ULL,
		0xDEB101297265994FULL
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
		0x5CDB791974F50351ULL,
		0x05A908ADFD3D4C0CULL,
		0x734D72A47F83744AULL,
		0x1A8F2ADE7C8CFEDDULL,
		0x181A215976256EEBULL,
		0xB9E881F2803F9BDFULL,
		0x92C4A3D4BF403797ULL,
		0x2759E7DE806875F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA9EC36B1A1F8F0E5ULL,
		0xC917BD2D9D2276ADULL,
		0x816262E8EF598DABULL,
		0x8D7E654624FEB99AULL,
		0x6B76FF7525059535ULL,
		0x1BB90542A51D0A38ULL,
		0xD2561F1D94758916ULL,
		0x7DF0AE57FD020FC1ULL
	}};
	t = -1;
	printf("Test Case 408\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1CCAD576F383842AULL,
		0x6F71E38A88D63766ULL,
		0xE1182F73F58B1A7AULL,
		0x6D3E86BB23F76FE4ULL,
		0x5B4B84FC2F110D2EULL,
		0x193E52E6750E3B00ULL,
		0x6CB781AEAE628500ULL,
		0x82FA18A90D9B34E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1CCAD576F383842AULL,
		0x6F71E38A88D63766ULL,
		0xE1182F73F58B1A7AULL,
		0x6D3E86BB23F76FE4ULL,
		0x5B4B84FC2F110D2EULL,
		0x193E52E6750E3B00ULL,
		0x6CB781AEAE628500ULL,
		0x82FA18A90D9B34E4ULL
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
		0x63E74BEC5ABFB4A0ULL,
		0x18BFE005B8225B37ULL,
		0x0619D709A31CE52BULL,
		0xFFBC3BB8AB26F799ULL,
		0xD5379892F8F432DCULL,
		0x475D951A69B440F9ULL,
		0x55DEC9AC5861C0ECULL,
		0x0E2E1D681A92E561ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x81E1E08D92DBC4C4ULL,
		0x63F0CE53E67EA52EULL,
		0x2714B6880CD2CAC3ULL,
		0x91B98DD1C57E3F50ULL,
		0x033E2028B5939F93ULL,
		0x78644396EDC56368ULL,
		0x935C06B749900999ULL,
		0x44EE159224AA17C7ULL
	}};
	t = -1;
	printf("Test Case 410\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5B6C5AA5F563FC28ULL,
		0xE36012862956A81EULL,
		0x0ABAA96860134F69ULL,
		0xB81A5B4C798242E9ULL,
		0x01337DCC1DA71D5DULL,
		0x29579BF0145620DCULL,
		0x00267DA46C9000B4ULL,
		0x58A5A4C60E8E4442ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x759C0382C2EDB89CULL,
		0xC7BC0D7A9832E89BULL,
		0xB7FF1FA26DC7E53FULL,
		0x017D314B93A8927BULL,
		0x004FDAA6BFD2575AULL,
		0xF1A87B2331FBDC13ULL,
		0xB457857E6BAB3D6EULL,
		0xEE107E0922DF3464ULL
	}};
	t = -1;
	printf("Test Case 411\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB2B9943C923B45F0ULL,
		0x28480D05ADFA4B0FULL,
		0x40BEB688FDB5C540ULL,
		0x783B2FC29F6DE1E6ULL,
		0x023DC51B905C04F5ULL,
		0x63C567456064CCC5ULL,
		0x1075F6D61C660906ULL,
		0x365DB182E00E2B0EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0AA551981CB13538ULL,
		0x4A1B77AAF56D6FE4ULL,
		0x8CF2DE01141803B4ULL,
		0x97754D822312904DULL,
		0xB0125EB2859D25ECULL,
		0x799241D2972116D1ULL,
		0x96E8E39688442F01ULL,
		0xE6466C6A99E85EC4ULL
	}};
	t = -1;
	printf("Test Case 412\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB81EF417C4BD842DULL,
		0xF44DCB5A54FB07B6ULL,
		0xA56DBF3DEEE1CC80ULL,
		0xA5FC44D9A07A57A1ULL,
		0x16CA19316622B836ULL,
		0x7D162942F3C855C1ULL,
		0x342168E9780C3950ULL,
		0x40DDD106652A533DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB81EF417C4BD842DULL,
		0xF44DCB5A54FB07B6ULL,
		0xA56DBF3DEEE1CC80ULL,
		0xA5FC44D9A07A57A1ULL,
		0x16CA19316622B836ULL,
		0x7D162942F3C855C1ULL,
		0x342168E9780C3950ULL,
		0x40DDD106652A533DULL
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
		0xB7B5A0D1C0065230ULL,
		0x07EFE941D27CE8CBULL,
		0x0589CF5152B7CC46ULL,
		0x771DAE8179D0E33DULL,
		0x2C99FAA38261727FULL,
		0xC283712EE2726D6BULL,
		0x2BA3688B95BE1803ULL,
		0x4F1B7E1414F2DD68ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x331661F8E1215E80ULL,
		0xEEB4CB2D2346729EULL,
		0xBA2953ADEC80F9D5ULL,
		0x870E79E256B26E7DULL,
		0x70CC8F8A80D062F2ULL,
		0xA6C882399BF9440AULL,
		0xBEF504C603952F2AULL,
		0xD2926E829DB885F1ULL
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
		0x8AEDB361F580214EULL,
		0x01A9635D69A0C547ULL,
		0x4BE1D00D4E285C17ULL,
		0xFFDADFF7CDEBF65BULL,
		0x8E7CACD791581637ULL,
		0x1CA5EF55C86E2555ULL,
		0xA62757F6BFC2054FULL,
		0x72F2F7B6A377D2D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAEBF534BED6F90FAULL,
		0x399DF096490790BBULL,
		0xA0B067EB72BB0D69ULL,
		0x3D993E9EDB7AC511ULL,
		0x9441BFD9542A0E2AULL,
		0xA22776D47E64B907ULL,
		0x5E195A3B742A7303ULL,
		0x40E834B70ACF6034ULL
	}};
	t = 1;
	printf("Test Case 415\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5081467EF375A7F6ULL,
		0x9B7666D6ACEDB126ULL,
		0xEFF5A597B1FDCB66ULL,
		0xCD181FC7ED22A8F8ULL,
		0xB25DF96E9CFEF0F9ULL,
		0xC058C0B79BAF331BULL,
		0x3D03D70F510ACBADULL,
		0xA1F340C9E1A4FF8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6647B2774882D3F0ULL,
		0xF9D9A2708C66C303ULL,
		0xD9E3453C96218E95ULL,
		0xFA61DECD4FCA954BULL,
		0xBEE7E9EAD258BAB0ULL,
		0x5E442DA45C9DFBD7ULL,
		0x17888815A62199A4ULL,
		0x5ABDC93CEB3A4860ULL
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
		0xA448920E35CFAE32ULL,
		0x44207F0557FBA9CBULL,
		0xF456836E14E76758ULL,
		0x91120EB3E3651AF5ULL,
		0x79C978B2897205C5ULL,
		0x10464A35AA5059E1ULL,
		0xCF3AA1262F3BEB29ULL,
		0x04FC8E0B78FC773BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA448920E35CFAE32ULL,
		0x44207F0557FBA9CBULL,
		0xF456836E14E76758ULL,
		0x91120EB3E3651AF5ULL,
		0x79C978B2897205C5ULL,
		0x10464A35AA5059E1ULL,
		0xCF3AA1262F3BEB29ULL,
		0x04FC8E0B78FC773BULL
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
		0x31B577DB69C21CDEULL,
		0x2F1BBB9DE7098089ULL,
		0x71507281F14CB555ULL,
		0x4E80A8274AB7A660ULL,
		0x7B114C9D7360D06DULL,
		0xE0B18E7B9DB36F71ULL,
		0xB9819FB05E659EB2ULL,
		0xCAC53B6FF4EFAEA3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCCFF21CF4B84860DULL,
		0x87374FC7D9A9A1A5ULL,
		0x4556B41158D40F97ULL,
		0x84B0DE34BBE1EBD0ULL,
		0x4EED52897D82EF5AULL,
		0x4C4AC0D75CBBBFE1ULL,
		0x1829E95C62C76E17ULL,
		0xEE36250D21E82FB0ULL
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
		0x876AD5DA68505E07ULL,
		0x1DF12635BB164F6EULL,
		0x9CDD8B550676CD3CULL,
		0x715CD3EC25DB5941ULL,
		0xF1830761E096C88DULL,
		0xA3A9D1CE09574174ULL,
		0xBB097154E8F13950ULL,
		0x33BA74672C12BD51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E7DB6D3357990E4ULL,
		0xA0CDB4BA0BD8BA08ULL,
		0x8F1958C076E88B8DULL,
		0x728730C6EA15F8E2ULL,
		0xA7CB43D3AC38989DULL,
		0x85020BCC3D2F1D7BULL,
		0xA847E7D2DD65CDF5ULL,
		0x4BA7A9EF87E1AF73ULL
	}};
	t = -1;
	printf("Test Case 419\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x91EC9CC30A349EE2ULL,
		0x47D0304CD4ABD74CULL,
		0xE786E02B6EFB2C1CULL,
		0x4933A7F8A0D7119FULL,
		0x8CB7BDB4A96FCBE4ULL,
		0x6F0778601808F012ULL,
		0xF2148E72076FA7D0ULL,
		0x8145F58E621D2419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75F7916AD624A1F5ULL,
		0xEBBE2A861D15FFA8ULL,
		0xB980B0BFFBF24CA6ULL,
		0x407C4DA8E58E5830ULL,
		0xE1265A5100310F5CULL,
		0x28E65536534CB8EBULL,
		0x816E4871138DDAF6ULL,
		0x8298E3B0EE453EF8ULL
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
		0x5B0B814BE98F3A1AULL,
		0x4A4991828D32313EULL,
		0x1B60B186C5B75D33ULL,
		0x9E14599748EDC310ULL,
		0xAA368B1C85C683D3ULL,
		0xADF72AD77124F128ULL,
		0x7CE4E068D7B9AA7BULL,
		0xCBAE6C8DA5D52F1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B0B814BE98F3A1AULL,
		0x4A4991828D32313EULL,
		0x1B60B186C5B75D33ULL,
		0x9E14599748EDC310ULL,
		0xAA368B1C85C683D3ULL,
		0xADF72AD77124F128ULL,
		0x7CE4E068D7B9AA7BULL,
		0xCBAE6C8DA5D52F1AULL
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
		0x35CCCBCFA1347DB7ULL,
		0x80E186484D311E3CULL,
		0xCD25219F2975E765ULL,
		0x9B222CCEC50BBA34ULL,
		0x3C1021A8FB958AC3ULL,
		0xAFF619778FC8F96CULL,
		0x8A570614B81CC10CULL,
		0x472B134AC354F72AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD46DE7C542B3DAA8ULL,
		0xDDC196FDC9AFE0EAULL,
		0x5CF43A0607DB781AULL,
		0xEE1B88B3EB6C3B33ULL,
		0x87B09AC78FFFE35BULL,
		0xA5C10C10A2C2B9DEULL,
		0xC2B1965B4B3C8199ULL,
		0x8DB70E441484729CULL
	}};
	t = -1;
	printf("Test Case 422\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x28C38AD3046056E8ULL,
		0xB4CFDDFD0C2D34BDULL,
		0x04A394103B83D0A5ULL,
		0x9D50815C695E082DULL,
		0xB4F9F45BBB397497ULL,
		0xF0F6EE68B415D0A5ULL,
		0x4AAB8957DF707CCEULL,
		0x59BCE5FB189F91B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6B1AD2C7A220DDFFULL,
		0x447E797BE138A79EULL,
		0x2036C3EBDE9BEAE9ULL,
		0x255BE18D75D983D4ULL,
		0x55D0791DD8AA908BULL,
		0x99A42D9589ADBABEULL,
		0xC0E4FC69F5162DA1ULL,
		0xF2834FAC1C8CDA62ULL
	}};
	t = -1;
	printf("Test Case 423\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB876D240E0DB35E7ULL,
		0x2AC3C7E6F099431EULL,
		0x4411C78B6F060DD6ULL,
		0x299B33D7A48BF8F3ULL,
		0x1C0A27E6F4C11F69ULL,
		0xA6F3CE1C220156C5ULL,
		0xFBEBA36D00B92730ULL,
		0xB9844E28ADD39DCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8DEC0605412070EULL,
		0x10FE307E78447661ULL,
		0x32018890375D5321ULL,
		0x97A5ED09308D6261ULL,
		0x4F64EFE9DF1CF3E3ULL,
		0x50C90A61C9FD812AULL,
		0xB3868872C2F4C1CEULL,
		0x8062C312E67F5FE3ULL
	}};
	t = 1;
	printf("Test Case 424\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF0982C9B7F9E8475ULL,
		0x41F487E7427CC1EDULL,
		0xE02495889A9A34BFULL,
		0x263DBEF75AA781E8ULL,
		0xD0FD2906420AF5FCULL,
		0xC7DDACB58966CB21ULL,
		0x31C84A012D2841D1ULL,
		0x6627CCD33C08ECFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF0982C9B7F9E8475ULL,
		0x41F487E7427CC1EDULL,
		0xE02495889A9A34BFULL,
		0x263DBEF75AA781E8ULL,
		0xD0FD2906420AF5FCULL,
		0xC7DDACB58966CB21ULL,
		0x31C84A012D2841D1ULL,
		0x6627CCD33C08ECFBULL
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
		0x6B55C79DAAE8B630ULL,
		0x50366173D3D1A346ULL,
		0x9B3DF2CE5A41A508ULL,
		0x2A90A33D4D745973ULL,
		0xDD4AAA13A37B42B1ULL,
		0x22D39A5A3555711EULL,
		0xB58B46B468685E5AULL,
		0x9EA8C65AE9481C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ED209025BAFDBECULL,
		0x622367FC9A0EEF84ULL,
		0x5A5787B8B38C6673ULL,
		0x4D3FBC213DCFE964ULL,
		0x4F9C12FEF152982AULL,
		0x2A2F41B8309A2A29ULL,
		0x533FBA021819286AULL,
		0x349960F4138E7349ULL
	}};
	t = 1;
	printf("Test Case 426\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3CCA90B4911D1B81ULL,
		0x99CFF256AB800F00ULL,
		0x79700C05F9FB12BEULL,
		0xA947BB593B142C89ULL,
		0x348E2F101F9D924DULL,
		0x783E3FA33AB09D47ULL,
		0xCA6F73E025D53CF4ULL,
		0x641E293A9A76DF3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD35C1461AA2DD3E2ULL,
		0xC30779E8826DF52EULL,
		0x7F813F3B7489CE87ULL,
		0x71B08F07E166834EULL,
		0x5307DC7AEECF164AULL,
		0xBA55C96F0C0DBC39ULL,
		0x2811F54B17755D37ULL,
		0x552FA3D37578B555ULL
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
		0xCC6547C2E27DBB19ULL,
		0x1317FAF4332E8520ULL,
		0x667E837A9CC61DBCULL,
		0x61440A822CB74553ULL,
		0x17900B01B9EF4BE8ULL,
		0x43F0B79C9C76D6CFULL,
		0x1568DA1047CCAE50ULL,
		0xE76C44CEF1738E55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EC857793E44A8FULL,
		0xDCD49E58CC96E71AULL,
		0xCE9760EB02EC8324ULL,
		0xCBC5D8FA7DFCBBAAULL,
		0xC0E55E11A8967DEAULL,
		0x71134009F7FF2A97ULL,
		0xBABF0E9DA8341A9FULL,
		0xF8AA4D5A92D6C78DULL
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
		0xDE1F726E5E29FFC1ULL,
		0xBE3EFA7D578CECF6ULL,
		0xDA1D0BE756302DD5ULL,
		0xF5835ABCD5DD7658ULL,
		0x1F910E463B377590ULL,
		0xBDCA39ACB9239B12ULL,
		0x0B1AB30AF281FD26ULL,
		0xFE32952A86ABC632ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE1F726E5E29FFC1ULL,
		0xBE3EFA7D578CECF6ULL,
		0xDA1D0BE756302DD5ULL,
		0xF5835ABCD5DD7658ULL,
		0x1F910E463B377590ULL,
		0xBDCA39ACB9239B12ULL,
		0x0B1AB30AF281FD26ULL,
		0xFE32952A86ABC632ULL
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
		0xA33D1D6AA4CBA7B6ULL,
		0x7BD6703ED381AE17ULL,
		0x03D6C4CD9C7A891BULL,
		0x7787071FF8C382A8ULL,
		0xA02D677494DDB9BCULL,
		0x9F41F87ED211FD8BULL,
		0x86741F4296C820AEULL,
		0xB3EA0E1968B61725ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x98C4D042E84A9A50ULL,
		0x913FD6873E4BFCA9ULL,
		0x65D47DE8D994DA07ULL,
		0x6C50930869AB182BULL,
		0xE1CD313C0B0517E7ULL,
		0xDBDCF99EEEEE87BBULL,
		0x235AEBB342E7DE0FULL,
		0x3E8427DF65B7D226ULL
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
		0x29DD60F45A9E198CULL,
		0x55C3F606B1ED9134ULL,
		0xE74919E2351C5D74ULL,
		0x569BC32F6FE7DE6CULL,
		0xF3D73C5210A132BDULL,
		0x053A049C50D0AB28ULL,
		0xB588F98E6F4C028BULL,
		0xFE79F5BF30CA8814ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39AAB4AA39E96B24ULL,
		0xB3EBEAA6D9FD307DULL,
		0xF1D79A5B4548A596ULL,
		0x7A0B6885E3CD301DULL,
		0x1CB236006885CCB2ULL,
		0xB8671DBBE2F7F7CEULL,
		0x27FC0725AF99EB3AULL,
		0x00A96D536F4F2B83ULL
	}};
	t = 1;
	printf("Test Case 431\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF2232B22FB4F8AD1ULL,
		0x4FD0920798F63EA1ULL,
		0x4DE84239588C980CULL,
		0xFABBCC95D6007BD8ULL,
		0x31548C39A2A58132ULL,
		0x8FC68D3F689261F6ULL,
		0x7C57741AA46D86E6ULL,
		0xF8D74E54FAF355A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA3871D723E59EC89ULL,
		0x7BA348167D2EB716ULL,
		0x028E0856CEECBFF9ULL,
		0x993FEADC2E922F00ULL,
		0x5DB251C7C605503CULL,
		0x7ABCA7449AB59658ULL,
		0x76DF1578AB2A1E4FULL,
		0xE61EE91D6C71A6F5ULL
	}};
	t = 1;
	printf("Test Case 432\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x4A414F94F1E9097BULL,
		0x85B9CD95380EE267ULL,
		0xBA5B3C3C4F78F6B1ULL,
		0x105A2B7C7CCCE864ULL,
		0xC89C7642A40201AFULL,
		0xA2911E253700B6A0ULL,
		0x335453F0F2126125ULL,
		0x533E6C8EE844B34BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A414F94F1E9097BULL,
		0x85B9CD95380EE267ULL,
		0xBA5B3C3C4F78F6B1ULL,
		0x105A2B7C7CCCE864ULL,
		0xC89C7642A40201AFULL,
		0xA2911E253700B6A0ULL,
		0x335453F0F2126125ULL,
		0x533E6C8EE844B34BULL
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
		0x3B79A0DA7333E9DFULL,
		0x6B48592E7254FC4EULL,
		0x1BF89FFF9E956F70ULL,
		0x21F2345F88C2F245ULL,
		0x20C5A607DB85F46DULL,
		0x11AB82AE54619115ULL,
		0xE929FD2E2435170AULL,
		0xE1C9DF2D3A33DEFAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9ECDD8476145E547ULL,
		0xD3997A4820183129ULL,
		0xC0386F6B542E1CCEULL,
		0x2A3DF85AF24A25FBULL,
		0x830714B80795369AULL,
		0x79C92B14544ABA0EULL,
		0xE8CB8D8457DB5FB2ULL,
		0xC940F72AEFDEE908ULL
	}};
	t = 1;
	printf("Test Case 434\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x73B89C51BDED5546ULL,
		0x63C1425577609D31ULL,
		0x11DD70F24BD9C547ULL,
		0xEFC691A5C278FF1AULL,
		0xDDD00FC522544F54ULL,
		0xDD7845892DD883CBULL,
		0xBC7FBB07203C383DULL,
		0x319BC3D9923245A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8EADACA5E0755BF8ULL,
		0x273EF075EE1F4657ULL,
		0xB204082FB8744864ULL,
		0xB552B4A89FE54DDDULL,
		0x73089BA6553A25F5ULL,
		0x945F91A60F6E4C89ULL,
		0xE87C1744848792EEULL,
		0x9866D72A385DEB40ULL
	}};
	t = -1;
	printf("Test Case 435\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE08E7ADFD5D86C7EULL,
		0xE180DA94952599BAULL,
		0xE39F157F6C9D5ECAULL,
		0x6785225D8D606444ULL,
		0xE2A9675826D904E3ULL,
		0xD3C7E2EF54B873B9ULL,
		0x95EEC8F74CDFA09BULL,
		0x479858186932762FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFBF9C91E31CFAFEULL,
		0x99D98D8C769137D5ULL,
		0x442AFCC1AFA85AA2ULL,
		0xBEE68F7C06569656ULL,
		0x91CDA4C4A957FD22ULL,
		0x138558C9EF33D54BULL,
		0xE0C9023A3A91C6D4ULL,
		0x1BDE6691CF7D49FAULL
	}};
	t = 1;
	printf("Test Case 436\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBF408EBD70C1F2B4ULL,
		0x228FADE2590C0D04ULL,
		0x09993A7BF353E88DULL,
		0x75339A3437AB3668ULL,
		0x75F59E727BC73249ULL,
		0x29DA664CA6EA9A04ULL,
		0x72050D4D33867C0FULL,
		0x41AB78E36F56F09AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF408EBD70C1F2B4ULL,
		0x228FADE2590C0D04ULL,
		0x09993A7BF353E88DULL,
		0x75339A3437AB3668ULL,
		0x75F59E727BC73249ULL,
		0x29DA664CA6EA9A04ULL,
		0x72050D4D33867C0FULL,
		0x41AB78E36F56F09AULL
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
		0x342A5C66C8916439ULL,
		0xE81984355A525C26ULL,
		0x75BADFFC4040AC78ULL,
		0x942101A6553A18FDULL,
		0xADE6FE02DDF42E1DULL,
		0x3823AA4EF6B806CCULL,
		0xA754F5AC74236ACDULL,
		0x9D2838DBA49B03B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x43B9ECDDC41A4AA3ULL,
		0xA848215CC5911BA1ULL,
		0x8FD5A02CA7A65D98ULL,
		0x071C301E3C13E245ULL,
		0x44EED0052684524FULL,
		0x5D6BCC36EA732C40ULL,
		0xCAD446E5E659C2F1ULL,
		0xAFE49C31139FDE08ULL
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
		0x906BA0FCA67C7BAAULL,
		0x544EC7CAD1CD970EULL,
		0x48020726766B237AULL,
		0x30D49F1334402310ULL,
		0x491BD906E918231CULL,
		0xEF8B9366E489FF5FULL,
		0x6F28A79D1DA53124ULL,
		0x6C04C30BBA61C91CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8057A3BAC320FED2ULL,
		0xA7DC39B93603013DULL,
		0x3E2886CBFB861717ULL,
		0x5E19F3921B3832A3ULL,
		0xBCA27484EFCC2D43ULL,
		0x1F4A95AA850C1440ULL,
		0x34CC060977FD1FEFULL,
		0x0E1D603CFCDCECBAULL
	}};
	t = 1;
	printf("Test Case 439\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5D7F9AC96044265CULL,
		0xC354320363C62D56ULL,
		0xA5BDA6716DD5DE2EULL,
		0xC994EE36187A9B5AULL,
		0xB6BC88D79114F4E4ULL,
		0x8A5B325C6735D94DULL,
		0x6C6FA7FCE824C1A2ULL,
		0x367A4788F18FC027ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6E99153665866C5ULL,
		0x51EE032A36F73CBCULL,
		0x691B6C4269FFDC51ULL,
		0x986DED4B3790B679ULL,
		0x178394DB507940A3ULL,
		0x53FE6D122819240BULL,
		0x6572BA2DCFD733D1ULL,
		0xB2DE18238A7E0A48ULL
	}};
	t = -1;
	printf("Test Case 440\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4B32CD4BE1C2B14AULL,
		0xDCC970B8CF0ACEECULL,
		0xD7E541A49BB5B0BBULL,
		0xE085E277A554B631ULL,
		0x197E82B0C00B5131ULL,
		0xA0F10806373EC6DFULL,
		0x732A58A0B51B5E76ULL,
		0x59A66D66F67B7CF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B32CD4BE1C2B14AULL,
		0xDCC970B8CF0ACEECULL,
		0xD7E541A49BB5B0BBULL,
		0xE085E277A554B631ULL,
		0x197E82B0C00B5131ULL,
		0xA0F10806373EC6DFULL,
		0x732A58A0B51B5E76ULL,
		0x59A66D66F67B7CF1ULL
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
		0x0E91385B18B86D77ULL,
		0xB63C470DB436ACB8ULL,
		0xEEE6C3A41E0B2829ULL,
		0xD9A7288A42EE2B8DULL,
		0xD06F3FE1FE7F7E4FULL,
		0x6CAF40C1B5B998C3ULL,
		0x09A7FC4A6CCDED39ULL,
		0x982041C2B439A10DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13C646CCDC41AEF0ULL,
		0xA21F95003F3D0997ULL,
		0xBCEB921EAF502246ULL,
		0x3BE6F1EC0E297C7DULL,
		0x2DEDF78FBDC44B64ULL,
		0xDDDC66C5848CE4B5ULL,
		0x0E6337C81045C682ULL,
		0x996547A4E9134776ULL
	}};
	t = -1;
	printf("Test Case 442\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB7DFF348CE535A8FULL,
		0x8276E6F2FACAE2B3ULL,
		0xD60CBBE8DA5E6818ULL,
		0x1C4019ED63F31AA5ULL,
		0xE92E7134F1EACADFULL,
		0xFF74D6B3D66076DAULL,
		0xA6D451C24CE53EE3ULL,
		0x5514744115172BDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13F74E4BB6ED5E10ULL,
		0x6FD5224E790EE496ULL,
		0xCE40A5499AEE6F42ULL,
		0x86D4F591CE2D9DA0ULL,
		0xC85D3BB6E40928F2ULL,
		0xC44E306B171F3ED2ULL,
		0xF646244A8FFF2843ULL,
		0x9358E523A5D0A071ULL
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
		0xF7416FCD82DE8D1DULL,
		0xDA4FD86306314B8AULL,
		0xB4AAE322155A02D5ULL,
		0xCAC0DAB3ACE0F0BCULL,
		0x4FE40C2A6B21BF78ULL,
		0x6B0C59E2405D5277ULL,
		0x7202531B49E9BC91ULL,
		0xE2EA168914CF9447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1255B4264AA3F330ULL,
		0x913D8A5DE181F21DULL,
		0xCA21E5FB493A722EULL,
		0x6A55A96F18E42AB5ULL,
		0xB608858C6AA1572DULL,
		0x7390549535C3A375ULL,
		0x02AA1701DA8E99EEULL,
		0x7E9F460038F16A3CULL
	}};
	t = 1;
	printf("Test Case 444\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEB27B702BDC44DACULL,
		0x0026C66003EE7855ULL,
		0x24780F4CE598DA5CULL,
		0x8C470EDEBD91E1EFULL,
		0x5F6CA136625D70E7ULL,
		0x6637A50ADBA4F7C7ULL,
		0x3D09D6403FC40EA4ULL,
		0xFD65437D0EAC0176ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB27B702BDC44DACULL,
		0x0026C66003EE7855ULL,
		0x24780F4CE598DA5CULL,
		0x8C470EDEBD91E1EFULL,
		0x5F6CA136625D70E7ULL,
		0x6637A50ADBA4F7C7ULL,
		0x3D09D6403FC40EA4ULL,
		0xFD65437D0EAC0176ULL
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
		0xA873F5B036D59677ULL,
		0x3B945D9853F594C6ULL,
		0x46C7640709F1274CULL,
		0x61B0BC7A29AD83CCULL,
		0x1943CFDE3547A9F2ULL,
		0x1F8845C713055EBEULL,
		0xFD317F2D8D98FB49ULL,
		0x2550D17A54A97FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x230650FC6E095CDFULL,
		0x06F8BC8DA34A338AULL,
		0x2F880779A5FB97BDULL,
		0x7C8F41C9FB407353ULL,
		0xBF280A9255247498ULL,
		0xE899235FE4207183ULL,
		0xF0E53D2BF359BB07ULL,
		0x95C1A394DF4F45BCULL
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
		0xB6688CC416173364ULL,
		0xB819B0D91C14A86AULL,
		0x9115FCE0F5DB344DULL,
		0xB91421A26C63FDF2ULL,
		0x498DC973777FAF15ULL,
		0xFD53AE49A4FA7A10ULL,
		0xF9645F55D4D71E2AULL,
		0xBA4B757A40CF2AFCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B4D3FEB64B6DE2EULL,
		0x63907BB1E15FA119ULL,
		0x47E44F0E0F5DEB0CULL,
		0xF263D9F696BFFA1EULL,
		0xCC6F84EF076FBCA4ULL,
		0x5DD554D9712A09E3ULL,
		0xCF10E48DB545834FULL,
		0x06722B0374D0EA5AULL
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
		0xC04F8A526C1D9190ULL,
		0x30F509DA9110E86FULL,
		0xFDC58592B98B4AA6ULL,
		0x87892EA76AB799D4ULL,
		0xBD6B849B9B22F952ULL,
		0xC29654ACB5AC8309ULL,
		0x0EB13F0F10E14624ULL,
		0x9085F12B3108F4B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55162F9479381D37ULL,
		0xC3EEEA96DC90A3E5ULL,
		0xAF227CA3390144D0ULL,
		0x155105CFFF428DD1ULL,
		0x7B0FC4677CF47546ULL,
		0xB48D4E221510AB8AULL,
		0x9069000E6402C224ULL,
		0x0865B5CCECE72A48ULL
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
		0x382187F9A3180577ULL,
		0xF358063D74315D63ULL,
		0xB15D050A680EE36BULL,
		0x2074CF0A062B0CF2ULL,
		0x534AEE62D3BA53B5ULL,
		0xBD3AD99C7E92B3AFULL,
		0x2FC25DABABB0DCB7ULL,
		0x481F457C7A5E93DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x382187F9A3180577ULL,
		0xF358063D74315D63ULL,
		0xB15D050A680EE36BULL,
		0x2074CF0A062B0CF2ULL,
		0x534AEE62D3BA53B5ULL,
		0xBD3AD99C7E92B3AFULL,
		0x2FC25DABABB0DCB7ULL,
		0x481F457C7A5E93DDULL
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
		0x9FD2CF9B856D52F2ULL,
		0xCE7CE17CEFE54629ULL,
		0xFA1886AE619F249FULL,
		0x7A9D833B22718FFDULL,
		0xCC2E6F52A726878CULL,
		0x3EC1E687E613EDC4ULL,
		0x1D59D1715C2A5487ULL,
		0x807062931FE63261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6056537EC48F6E4ULL,
		0x07B0A3D7E1972013ULL,
		0x87F7A9EB40C813D5ULL,
		0x8A93F5578100F2FFULL,
		0x9A62923D8EDDE9B4ULL,
		0x6CA15274422A678EULL,
		0x2104AD8E630F975DULL,
		0x4CC12AEAC4CF2852ULL
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
		0xE0F1E7F13B097A79ULL,
		0xA063EED03D8FEDF1ULL,
		0x843303B4EFD46636ULL,
		0xE04CD0194114B13FULL,
		0x8FEAB64E977ABA40ULL,
		0xCB7F97483B0B1790ULL,
		0xDEE92CBBABFBD389ULL,
		0x1739A4EDDD56BE88ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE39C55944074699AULL,
		0x279E86A8D7D1D2B7ULL,
		0x6A08369A18E9EEE8ULL,
		0x5DB132480F1BAD40ULL,
		0x8D4346B5B23D7783ULL,
		0x5B90D1DF96F225E8ULL,
		0xE62D67001F7FAEDFULL,
		0xECCF0031CA73FA9DULL
	}};
	t = -1;
	printf("Test Case 451\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x03D1059AAE8DE201ULL,
		0xE6707BEFB23C369EULL,
		0x3662A44738F4C871ULL,
		0x49927D5F8E09BA5AULL,
		0xC174CCE84B0F1D4DULL,
		0x5B79F8DB66335BA7ULL,
		0x1D9F3B5C04BBB186ULL,
		0x91479F4AFADD4A97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6700547DD57D8B9FULL,
		0xF3809FE46D6C1DFDULL,
		0xCD54B800DF3B0193ULL,
		0x2CC3A54AD5CCBF5DULL,
		0x4A775BDFCB324FC8ULL,
		0xDAC7EC30F7FB4DD6ULL,
		0x52BC82538458DCEAULL,
		0xBF28D45FB226372FULL
	}};
	t = -1;
	printf("Test Case 452\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0148DB5B7FAE8988ULL,
		0x95E306462BD98E26ULL,
		0xE98E7441215FA9E3ULL,
		0x32A7A765B14472FAULL,
		0xC4499FD72385DEE1ULL,
		0x456DDE4954546CD4ULL,
		0x67CCA4C3B78DB209ULL,
		0xEB84063BF910A152ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0148DB5B7FAE8988ULL,
		0x95E306462BD98E26ULL,
		0xE98E7441215FA9E3ULL,
		0x32A7A765B14472FAULL,
		0xC4499FD72385DEE1ULL,
		0x456DDE4954546CD4ULL,
		0x67CCA4C3B78DB209ULL,
		0xEB84063BF910A152ULL
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
		0x65101E7CB1137AE5ULL,
		0xBC3C9905386E0628ULL,
		0xA13C269DAD7FDCF3ULL,
		0xAAD310B9EA124871ULL,
		0xFAE1CADCA89D81B7ULL,
		0xD70133284D2E0AD6ULL,
		0xB157DE8DD1355906ULL,
		0xFDB15164CE1849EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EE0B40A93F5086EULL,
		0xCFD186269A90D95EULL,
		0xCDF779B8C40D6A70ULL,
		0x99D0684686DC02C8ULL,
		0x0654973A222A4665ULL,
		0x1A3DAF69B0353081ULL,
		0x796D87EC7A6BB22BULL,
		0xC8D9A1D31D583BACULL
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
		0xA57914D8D5B2B16BULL,
		0xF42BB8E17C2B25C8ULL,
		0xD4F14505B9A37AB7ULL,
		0x0EFA73E7BE54CEC5ULL,
		0x85D6D1256C68BB4BULL,
		0xABA87D577EBD13BBULL,
		0x8CE70A30869C3D42ULL,
		0x1A1F281F61496802ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x174BEAD5CEC4C625ULL,
		0x2347F01E9ED76B8CULL,
		0x07A226EE9D67EF44ULL,
		0x2DED67488F130977ULL,
		0x996BA2D0F718B9D4ULL,
		0x3402D7AD82D01BE9ULL,
		0x3643ADAF34E41512ULL,
		0x39374D7CB9261437ULL
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
		0x12B1BCA50D53AB7FULL,
		0x5659C3EC9C40ECF1ULL,
		0x079E77B059CABDBBULL,
		0x0444BF6CD7DBE2A8ULL,
		0x551A4FA94FA542D9ULL,
		0x68B523105450810CULL,
		0x9F9D46F017FD2DE0ULL,
		0x949D831A2F48E2F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D6BDE134E8311C4ULL,
		0x0A938ADDB59243D6ULL,
		0x480932F8E5E8E616ULL,
		0x231B86028C05EAC3ULL,
		0x709E6760B45C60FBULL,
		0x6A840D921AA83721ULL,
		0xBF2FA45A3A7FAB29ULL,
		0x3044F94149B4A39AULL
	}};
	t = 1;
	printf("Test Case 456\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD9BEDF6738DDA9A6ULL,
		0x1C4A8CD07D0AAE14ULL,
		0x467396BA8683E596ULL,
		0x163852D9A846E6B4ULL,
		0xA7896B25BBE8B091ULL,
		0x127D243E526300C8ULL,
		0x8999E4AB78792D8EULL,
		0xD4261B4C2B8CDD7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9BEDF6738DDA9A6ULL,
		0x1C4A8CD07D0AAE14ULL,
		0x467396BA8683E596ULL,
		0x163852D9A846E6B4ULL,
		0xA7896B25BBE8B091ULL,
		0x127D243E526300C8ULL,
		0x8999E4AB78792D8EULL,
		0xD4261B4C2B8CDD7EULL
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
		0xCDB37B665DB6607BULL,
		0x01C1A7FAA2A64554ULL,
		0x522C70F9B780B2C8ULL,
		0x95FD2CCB15C98F16ULL,
		0x399011707E26C567ULL,
		0x79A2D0CCE04A64AEULL,
		0x4380284C51037A95ULL,
		0xFDC0C25DBE95A1D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x078524C25E05F773ULL,
		0x46641A271D150E03ULL,
		0x50F3E47F275427B5ULL,
		0xF8B45B9B300A5617ULL,
		0x9CED828A4BA05E19ULL,
		0x44693539B5E7FD1FULL,
		0x73CB8E6439A80064ULL,
		0xD6062A4580775EEAULL
	}};
	t = 1;
	printf("Test Case 458\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3B4298863E500C41ULL,
		0x63B9B83759F7E191ULL,
		0xC62EDDA5B7F71C73ULL,
		0x0E2EE29F1141B129ULL,
		0xDB4000004898FF2FULL,
		0x1F625817A10CC70DULL,
		0x56DBAA52AC549EBDULL,
		0xD9157DC2F6032E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C48F5682D604161ULL,
		0x09F32AD1FF90B014ULL,
		0x9CFA3E3AEE262172ULL,
		0xD2A162E54F2CEA26ULL,
		0x9DC9B855F42EB8E2ULL,
		0x68E5876164160F9AULL,
		0xA1106207BE83A151ULL,
		0x2AAD6977002DFA01ULL
	}};
	t = 1;
	printf("Test Case 459\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD2C5D7D74BCA423AULL,
		0xF1AB3534A843AE6DULL,
		0x5E28999DD4933780ULL,
		0x35380160D408141FULL,
		0x1964AC57D854C951ULL,
		0x8BEAC52C21C08028ULL,
		0xEB08047FAF955F43ULL,
		0x835A4D9A41B1385CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45FBEB7B0D984ACCULL,
		0x13E770AB702B939FULL,
		0x9AA0ECAF6488D3ECULL,
		0x186A212A31B576D1ULL,
		0x4F566F8CBB240EE9ULL,
		0x287FE1948AA3E34AULL,
		0x61151E9B124D5CE2ULL,
		0x37829A171DA63F6BULL
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
		0xA1865F927EE7F817ULL,
		0x9A85006E28CD71FAULL,
		0x4728BE2B0EAB381FULL,
		0xC296BF3E0177F777ULL,
		0xE309882BB0A94ADBULL,
		0x66AB7989446D8A5CULL,
		0x695BE01B5E6D56E5ULL,
		0xC7CEFCFB49D22DBEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1865F927EE7F817ULL,
		0x9A85006E28CD71FAULL,
		0x4728BE2B0EAB381FULL,
		0xC296BF3E0177F777ULL,
		0xE309882BB0A94ADBULL,
		0x66AB7989446D8A5CULL,
		0x695BE01B5E6D56E5ULL,
		0xC7CEFCFB49D22DBEULL
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
		0x4ECAB864F40BA8EBULL,
		0x9FFB16F91B82DF4FULL,
		0x64DF148744A7BB3DULL,
		0xA84469847BE85492ULL,
		0x27C83AA0289F6C2DULL,
		0xC989A2F31570315CULL,
		0xCB7D199BACFC800EULL,
		0x31E41598ADB04426ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2319E39F86D7EA23ULL,
		0xF218E79515C5711EULL,
		0xF4BAC47B313F9CBDULL,
		0xC1945F232340E221ULL,
		0xB6ECA3604CF26C45ULL,
		0x8C83901631244D4DULL,
		0xD3E5BCE836D15D8CULL,
		0x2B7536AAA79182CBULL
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
		0x3DA1887555C8E8DFULL,
		0x3F92DF73E1B3AB40ULL,
		0xF22408BDC20202ECULL,
		0xE96DB0236A9D7A86ULL,
		0x32C323244792AB23ULL,
		0x517A78F922783F16ULL,
		0x0D1467D647DF1335ULL,
		0x01D7C376E19BE9A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC394A80FE130D515ULL,
		0x9C51B338D5AB8D66ULL,
		0xAE769CA4CB1B41C2ULL,
		0x16FBB143180E0FF2ULL,
		0x1FACA250479D6A34ULL,
		0x50EA96635D0A051FULL,
		0x97F5548551F6D97EULL,
		0xCE3DD7BC7AB8E70DULL
	}};
	t = -1;
	printf("Test Case 463\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE55350DD83D6AAB4ULL,
		0xF75E6A4A4A2BE11AULL,
		0xBBA1EC351F60B4C1ULL,
		0x7FFD7C15E21E303FULL,
		0xA0844675263A09D1ULL,
		0x3E6F31128F936871ULL,
		0x4E51D3DC2A6CFAB0ULL,
		0x754C534CA7B8634FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD905B990C2DE9D06ULL,
		0x2C8E6CA0963DEE09ULL,
		0x14E7BC21FCE635B5ULL,
		0x46C84EC7A7FC4B1FULL,
		0x0C44C67A6A22BBA0ULL,
		0x081E0CE403F7C878ULL,
		0x2C48FFFEA3B7818CULL,
		0x4E39D179C5124781ULL
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
		0x0713636A59A57D5AULL,
		0x1C6EEC38249075BEULL,
		0x431741D95F03E5B8ULL,
		0x88A0039038D95203ULL,
		0x66CFD359960E85CEULL,
		0x9B0F2FE519EEBED6ULL,
		0xE51F905E42E2F830ULL,
		0x0D360EE496BA641AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0713636A59A57D5AULL,
		0x1C6EEC38249075BEULL,
		0x431741D95F03E5B8ULL,
		0x88A0039038D95203ULL,
		0x66CFD359960E85CEULL,
		0x9B0F2FE519EEBED6ULL,
		0xE51F905E42E2F830ULL,
		0x0D360EE496BA641AULL
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
		0xEF5C1C8CB5CFBEBBULL,
		0x696FD62F1693FD70ULL,
		0x112D95A68277610FULL,
		0xFE596AB0161432A9ULL,
		0xD9BC72DABCBE85ADULL,
		0xE7A79601127C1577ULL,
		0x48627DA16EE13C28ULL,
		0x32F73A255F9BB25BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF720AB3C61D5E05ULL,
		0x1FCC70DE61C95C13ULL,
		0x9A61629D2E46C9B0ULL,
		0x9541D64E918587B6ULL,
		0xC01F7CB4309569E0ULL,
		0x1B0DA62C99B5DDEEULL,
		0x41928A5CB7F51615ULL,
		0x43AF4812F5F5A098ULL
	}};
	t = -1;
	printf("Test Case 466\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4D697477362D441DULL,
		0xD932862997FFD780ULL,
		0xFD15CDE96B48CB0FULL,
		0x5C4C638151F4635DULL,
		0x9F354444998A0E8FULL,
		0x9D910AAFEDF3FF84ULL,
		0x844E5E35BB5B4A75ULL,
		0xF74B5CB60634F6D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF5B5133A10A2ED6ULL,
		0x296B15DB0AD66183ULL,
		0xD35BD3F67B5B2162ULL,
		0x8DD7E2F6BB30AC7CULL,
		0x119EE42363975742ULL,
		0x8ADE73D01B36E6F0ULL,
		0xADE75E69ABF3157DULL,
		0xFF52CF10D24D751DULL
	}};
	t = -1;
	printf("Test Case 467\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xE9EE585921AFD2D4ULL,
		0xC4BFF61D27411F18ULL,
		0x1791833B0E37F8F9ULL,
		0x0B4C563182F7F973ULL,
		0xF04DC11CADE3F1ABULL,
		0x26F0784B56F0EF89ULL,
		0xD49FB2069102E037ULL,
		0x37B129D2912C21A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C8CF51AF33B0C7FULL,
		0x50323368F9A28B5CULL,
		0xD2364FDF75A4B6EBULL,
		0x0317F51F6EB06AC8ULL,
		0x2FA16DC40F8AC707ULL,
		0x3AFA66A5611E69B1ULL,
		0xDC47538A01D9D642ULL,
		0xCA50FC3BCACE8519ULL
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
		0x10F374D7BCE89CC0ULL,
		0xE7AE50013315B1DCULL,
		0x3EC5C02E2EA861AEULL,
		0x261FFF173C417FCDULL,
		0xCEF1236D8D23C071ULL,
		0x455E0EA809042115ULL,
		0x966B1A52BA296282ULL,
		0x852DBF41E7557F2DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10F374D7BCE89CC0ULL,
		0xE7AE50013315B1DCULL,
		0x3EC5C02E2EA861AEULL,
		0x261FFF173C417FCDULL,
		0xCEF1236D8D23C071ULL,
		0x455E0EA809042115ULL,
		0x966B1A52BA296282ULL,
		0x852DBF41E7557F2DULL
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
		0x670AF61FCD1DE9C4ULL,
		0x275A79011F4E9330ULL,
		0x226EFF28E8B57CBBULL,
		0xFD911D80D40F52ADULL,
		0x331116674D0BA12DULL,
		0x03CA187A9FB58972ULL,
		0x0412173556003933ULL,
		0x532FA094A9F37BFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC807E34F477FCBEAULL,
		0xECA8A8524866027EULL,
		0xD5458160E2A6C856ULL,
		0x5CE69B3BE70DD96AULL,
		0x94D221A5C91EA2A4ULL,
		0x09182DA7E41ECFB8ULL,
		0x1C2E04F87F5D82E5ULL,
		0xCFBF83EF4999FD27ULL
	}};
	t = -1;
	printf("Test Case 470\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3138768CD47D0E1EULL,
		0x247396FDF601EFD4ULL,
		0x127501CE62C6B67DULL,
		0xCDF2B9AAF78FB1ECULL,
		0xCD75FB86B126D06FULL,
		0x57278116DDCE8E8DULL,
		0x559F4FFB6C770F85ULL,
		0xD9684A20B4CACEBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78B87DC74A67DCAFULL,
		0x280200DECA30616AULL,
		0x6B2F69A160FB96C0ULL,
		0xEA92D66F308130FEULL,
		0x7DB221106A42D092ULL,
		0x497096691AC05ACEULL,
		0xCB1E9D1B4B5D6561ULL,
		0xF38CAFAB03DC6210ULL
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
		0xF2DD60A145685B61ULL,
		0x29C8F4F41BD8D483ULL,
		0xCF8FDF0C2D05F9E1ULL,
		0x5DC1375112898514ULL,
		0x6CFB1ECE8B4A89C2ULL,
		0x8DB006D63B49D4C2ULL,
		0xEF5A5CFB05B60129ULL,
		0xD347BC84D4C577F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD29318FA9BA99BABULL,
		0xF1745412B6A56E4EULL,
		0xF9A3DCD6FCC20EB6ULL,
		0xBC9C9490C4E7D56DULL,
		0x94FA2300311FF13DULL,
		0x03ACFDA5804203DCULL,
		0xF4AF13E447B16AAFULL,
		0x085A4C2671CF3502ULL
	}};
	t = 1;
	printf("Test Case 472\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x2FE553D49BE606DCULL,
		0x2E2BF6DEE089553FULL,
		0x967545C653921A62ULL,
		0x0216736C2AA1148AULL,
		0x3A223198DDBF4511ULL,
		0xED4D98F35B6E8BF8ULL,
		0x6CBBE5D9483893D1ULL,
		0xF069957B0358C274ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FE553D49BE606DCULL,
		0x2E2BF6DEE089553FULL,
		0x967545C653921A62ULL,
		0x0216736C2AA1148AULL,
		0x3A223198DDBF4511ULL,
		0xED4D98F35B6E8BF8ULL,
		0x6CBBE5D9483893D1ULL,
		0xF069957B0358C274ULL
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
		0x9AFBB82628BEA74EULL,
		0x286D92F40013F694ULL,
		0xA6C4B7B17729CEC5ULL,
		0xC839082D108C9FDFULL,
		0x1ED5DFD3C0E1554AULL,
		0x6B31E8396101C1A1ULL,
		0xD9B6052143CCF261ULL,
		0xEFE4E9D0ED635368ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDD361CC011E556BULL,
		0x342EB430F09EC776ULL,
		0x4C5F81C0FE27CD30ULL,
		0x195B5D8A6D9A088BULL,
		0xFEF6EB4EAA9374E5ULL,
		0x006D8DC73D36A850ULL,
		0xD311AD9814E8C4F3ULL,
		0x71943C2E5A67F4B2ULL
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
		0xA637371637363BD7ULL,
		0x9624EB317922032BULL,
		0x87B97BF686FE119EULL,
		0x35DFB08AA698A104ULL,
		0x491F762E58F47227ULL,
		0x185C2D58AB49CF6FULL,
		0xF33B130D32990C76ULL,
		0xB3CEC1187570743AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE416015E57FD6E9AULL,
		0x795C2B42AF7E2D15ULL,
		0x472DCF998611041FULL,
		0xA5626642BBB8BEBDULL,
		0x2B2BE0EB08DF989BULL,
		0xA7B4898ED8523210ULL,
		0xDF887A84E3BD5EC1ULL,
		0xE8197400C4167209ULL
	}};
	t = -1;
	printf("Test Case 475\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x99E18A0B0D5AF729ULL,
		0xEE15BA8F83AF1638ULL,
		0x5648494E9FF32D3CULL,
		0x807635D38737B3BBULL,
		0x5C90786D040A9B3BULL,
		0x988910D8CAA8B88AULL,
		0xD915EA4B5DDD7F1BULL,
		0xA0F3F215913D2300ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA1E1CCB0DC764C9ULL,
		0x1EFBA1DD7156941BULL,
		0xEF6D80E44C09F2A8ULL,
		0x5E3EC87C52A658BCULL,
		0xD939A01A775B931FULL,
		0x6B90296F3E3F8DEBULL,
		0x28E52499CD4DADFCULL,
		0xB1DC22BE764FFBE0ULL
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
		0x6780F6940C8E64DEULL,
		0xC60A396AFA9739BFULL,
		0x9FA1EBBDB245D366ULL,
		0x547EB117FEF69056ULL,
		0xFD1809F8561D3E75ULL,
		0xD8BFD1AFA3BCEABFULL,
		0xB32A218CED210A8FULL,
		0x2B848E63A544C42FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6780F6940C8E64DEULL,
		0xC60A396AFA9739BFULL,
		0x9FA1EBBDB245D366ULL,
		0x547EB117FEF69056ULL,
		0xFD1809F8561D3E75ULL,
		0xD8BFD1AFA3BCEABFULL,
		0xB32A218CED210A8FULL,
		0x2B848E63A544C42FULL
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
		0x55CFFA58CA2B1E61ULL,
		0xD1DD0046736511CFULL,
		0xF98BE47CDBA984C9ULL,
		0xB0BF6D928FDB3605ULL,
		0x5A12BE7149905CE6ULL,
		0x11262BA1739E2CE0ULL,
		0x4B0A098776453981ULL,
		0xA7EDBC80029FEA9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68B07B52AE4CFAEDULL,
		0xBF6D18AA7DB0A73AULL,
		0x71A4E973F8C3F707ULL,
		0xFE9DA79D96A81AFEULL,
		0xA9E3E5C842BB4CACULL,
		0xD478CDC8DFD0A518ULL,
		0x404581E38BDB6F31ULL,
		0xE374937E7F16AABAULL
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
		0x4102495F3AD9119EULL,
		0x9702AB0FFDD6312BULL,
		0xA1CA0AF88D2332DCULL,
		0x2B92E2F0250EB8EAULL,
		0xF067B3204C878CD4ULL,
		0xF31299A5D0958EA8ULL,
		0xD8BAC4F26139085FULL,
		0x7DFB075E02543488ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D51BAED5FD60DA2ULL,
		0x59C6D62B79CA9241ULL,
		0xCB2BD1AA38F840ABULL,
		0xF6DB2292113CB6DEULL,
		0x8E2197F02C7ABD27ULL,
		0x5123AFA8C9A48FB5ULL,
		0x13036A5DC3C6F198ULL,
		0x61172F53209A92CEULL
	}};
	t = 1;
	printf("Test Case 479\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x02C27E02216E2F9FULL,
		0x830905B13AEA3B6AULL,
		0x17609179D379C7C1ULL,
		0xA344ED4206D3A577ULL,
		0x54A13082C7F9319AULL,
		0x4FBD01116B68054DULL,
		0x421F2F60DE640FB3ULL,
		0xA0A4C1B9B9262585ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA9F58E4DE621796ULL,
		0x207AF990D5FB2032ULL,
		0x8A547A7CE23CEFA2ULL,
		0xB0C63EE826B026A6ULL,
		0x8DBE85A82A8E24E2ULL,
		0x6668CD85CED9BA12ULL,
		0x078EED1E680B7DE7ULL,
		0x4D8A08EA11193875ULL
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
		0xFAE6A6D7E19BFE08ULL,
		0xD37D64B058C03D5AULL,
		0x4178D63B479D74CEULL,
		0xF0B07D1069A61291ULL,
		0x07B5DD4957681F6DULL,
		0x384CBCC32F9B9C32ULL,
		0x25231C39AD4B3B03ULL,
		0x5BD3823F74BDC443ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAE6A6D7E19BFE08ULL,
		0xD37D64B058C03D5AULL,
		0x4178D63B479D74CEULL,
		0xF0B07D1069A61291ULL,
		0x07B5DD4957681F6DULL,
		0x384CBCC32F9B9C32ULL,
		0x25231C39AD4B3B03ULL,
		0x5BD3823F74BDC443ULL
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
		0x54CC74EF72B3041CULL,
		0x08E21592BFF606FFULL,
		0xB9945A3EEFC52C80ULL,
		0x789EB8B3782263DAULL,
		0x0F1BEAE695892CD7ULL,
		0x3A1F1BC8597B3FB8ULL,
		0x96FA7C540C4C527BULL,
		0x626E2FDD652E44B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2008E1F270494056ULL,
		0xB77D568C28DA8A56ULL,
		0xBDA764BA52093BC3ULL,
		0xC8848E5056C4F998ULL,
		0x87B4CA7ACB64CB08ULL,
		0x24C8227F50246480ULL,
		0x3FC947D8A2D5F41DULL,
		0x610B7C8002B7218FULL
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
		0x5CF75C7E63102157ULL,
		0x944629EC0D875B38ULL,
		0x8F9998C4346E96B4ULL,
		0xE0D40E951E7294E1ULL,
		0x18B87D7F27D24B35ULL,
		0xF284759031B76CCFULL,
		0xE23153F44BE94C46ULL,
		0xBA13E6C11E6C3AF1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x243B46C013062C4BULL,
		0xFF4365A4177E6431ULL,
		0x13E7A4EBF8D3FC56ULL,
		0x6C5E1A1BD1655B4FULL,
		0x0C477AC717AF49B7ULL,
		0xA80DF41F8CAB63DDULL,
		0x16467FACCDBE8056ULL,
		0x06A4859EEEE6DFB4ULL
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
		0x1F1265F400F6687CULL,
		0x3AC621BB8C635ED0ULL,
		0x189B717448E0C167ULL,
		0xD2F49CAEAE55993EULL,
		0xFDF4218A75BCFCEBULL,
		0x4CBAF8CEF7D61327ULL,
		0x23284D559A004939ULL,
		0x3A74B9C1764AAE8EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x56EB676C50A6AA30ULL,
		0xC7EDFEBA3CCB584FULL,
		0x80A29E24F75F117BULL,
		0x947917660E5A54F6ULL,
		0x7466EECDCA60D3B4ULL,
		0xBBE7766CE0390A84ULL,
		0x0FDE10FC07EAB78DULL,
		0xB9B5C6F369CCE3CDULL
	}};
	t = -1;
	printf("Test Case 484\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x885901410CF87F16ULL,
		0xD89B231119E56838ULL,
		0x9EBBCD6EDE27C741ULL,
		0x3C46B3E79C8F2608ULL,
		0x75AE52CB1A4FDC93ULL,
		0x5BFFBD353EDC3879ULL,
		0x8F902E96B16C9877ULL,
		0x82BFBA2901B747F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x885901410CF87F16ULL,
		0xD89B231119E56838ULL,
		0x9EBBCD6EDE27C741ULL,
		0x3C46B3E79C8F2608ULL,
		0x75AE52CB1A4FDC93ULL,
		0x5BFFBD353EDC3879ULL,
		0x8F902E96B16C9877ULL,
		0x82BFBA2901B747F7ULL
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
		0x83F20FF3E1B81BA2ULL,
		0x6E524DEC4693E8D1ULL,
		0x46599BE3883BF853ULL,
		0xB058DE20CA48D51BULL,
		0xF911E7A53DAC5231ULL,
		0x08D8AD7E76553C36ULL,
		0xC2641DA6AC973049ULL,
		0x5E40C6CA65ECD96FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD46C3B393070CCBULL,
		0xAFF0D94CAB4C86C8ULL,
		0x46B73B47154DBDF5ULL,
		0xDE01A16AEC8CE5B0ULL,
		0x7A41727D2C8919C6ULL,
		0x57B0CC0DF2E630F1ULL,
		0x000D677A22DDCADCULL,
		0xFD610D3230888B39ULL
	}};
	t = -1;
	printf("Test Case 486\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x72B32F16D2882544ULL,
		0x8BE322AF5008EC94ULL,
		0x0DF18EBD79400E3BULL,
		0x7EDED7F2CEAD6390ULL,
		0x297226884C16E686ULL,
		0x79AAC18E49EA869AULL,
		0x3427D3D991512A3FULL,
		0x71FB1182A6957239ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5BE89C741AFC354ULL,
		0xD15161A9B1076AC8ULL,
		0xD1D469171A12BA68ULL,
		0x6D1B35C23EB4ECD2ULL,
		0xB8788407658E0B84ULL,
		0x0475A5EE6F5CB97CULL,
		0x7A2FCD1A3CD6D76BULL,
		0x4932E1B1B4F566BDULL
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
		0xC76D1A7288EE9D9AULL,
		0x1D04ABCEC71260FEULL,
		0x6E0351F4855EB231ULL,
		0x39A6313A7303EF56ULL,
		0xAF82F5791E062D5BULL,
		0xFE0E52E44265A92AULL,
		0xD684714FFA1EAF95ULL,
		0xC2B0C73B8C6E0088ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBEC52DDE5923E13ULL,
		0xAFC80B2D7CCCD81FULL,
		0x68937BE8E651DE57ULL,
		0x772AF473B3F439C3ULL,
		0xDB443FF3CDF6620EULL,
		0x24F1981456A10343ULL,
		0xC7EFB37499ED97C4ULL,
		0xD26B01B61AB6DFC2ULL
	}};
	t = -1;
	printf("Test Case 488\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x1BDEDCF27B77B0D0ULL,
		0xBDE920BC19A1C9CCULL,
		0x14AB8A547274173DULL,
		0x8DE23987E11B3E2EULL,
		0x3CC6E4DECFDA28FDULL,
		0x039D36E6734C59AFULL,
		0x48BA5FEF7DBE06E9ULL,
		0xBF52E66FB1353DA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BDEDCF27B77B0D0ULL,
		0xBDE920BC19A1C9CCULL,
		0x14AB8A547274173DULL,
		0x8DE23987E11B3E2EULL,
		0x3CC6E4DECFDA28FDULL,
		0x039D36E6734C59AFULL,
		0x48BA5FEF7DBE06E9ULL,
		0xBF52E66FB1353DA6ULL
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
		0x3B551E042533F841ULL,
		0xD09668097A7B6FE0ULL,
		0xB2198CCBE9698741ULL,
		0xCF21F8D6EAD770C9ULL,
		0xA0A0CDCA3DCB6711ULL,
		0x6C1ADBDEAFE587A0ULL,
		0xE259DFD4A94B0C3AULL,
		0xE3524EE1D8FBA70FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D59DE16BFCF496AULL,
		0x9D69BCFFC1A06F9DULL,
		0x2F4A8DFB1655BC32ULL,
		0xC62451316CFAE4E8ULL,
		0x60C283106A034A3FULL,
		0x6120FA581F08D961ULL,
		0x6D464A626127E9D1ULL,
		0xAC7A72BC44EFED9AULL
	}};
	t = 1;
	printf("Test Case 490\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x590877750B2A1143ULL,
		0x44C356C74852A6CCULL,
		0xC45CE7305C5D9412ULL,
		0x7C33A9D271C28096ULL,
		0x296A8B4E5E5AB7B3ULL,
		0xAD7F1C80A671EED5ULL,
		0x5DD6C45DEDEC0762ULL,
		0x046DB2369D5CD513ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3783EA86DC19D912ULL,
		0xB5BB976E894C1E85ULL,
		0xF945113E8A606AB0ULL,
		0xCB540FF1B7155AD4ULL,
		0xD4C08B58D86B76EEULL,
		0xC532C1429542BC3CULL,
		0xA9B57D0D2E42A292ULL,
		0x2B041256B26C502DULL
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
		0x1DEF06F6DEC7725CULL,
		0x95451CCAFADB0686ULL,
		0x689764DCB0E9D21FULL,
		0x5737601CEA883627ULL,
		0x33B6F1AFF3BEBC3CULL,
		0xFD23208BA2BAD4CCULL,
		0x978241B69B8C35E8ULL,
		0xA99ABADC894FC6C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x86AB0A2060C59E4BULL,
		0x60CD4A1ABD0A213FULL,
		0xB7D4D37D94C14CCEULL,
		0x2DD3819BA68BCD5CULL,
		0x27310F79FE9299A2ULL,
		0xF570E50A3327364DULL,
		0xC3777198AA6A2AEFULL,
		0x230685BF048FC8A9ULL
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
		0xD7F6FFE8B7103EFEULL,
		0x27657CDDC13D34A2ULL,
		0x1E1D9B62CC068CE3ULL,
		0x6BFE9929C0BE774EULL,
		0x4F89AC8805AEDE32ULL,
		0x94236225AD8459B1ULL,
		0x4DC1A720701B384DULL,
		0xD4C394CDE06AA0AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7F6FFE8B7103EFEULL,
		0x27657CDDC13D34A2ULL,
		0x1E1D9B62CC068CE3ULL,
		0x6BFE9929C0BE774EULL,
		0x4F89AC8805AEDE32ULL,
		0x94236225AD8459B1ULL,
		0x4DC1A720701B384DULL,
		0xD4C394CDE06AA0AFULL
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
		0xFA69B0695ED524D9ULL,
		0xE70FDD390A880095ULL,
		0x5964BE79E1CE022BULL,
		0xF383B3EB07760C2DULL,
		0x841C92BB53C93AC3ULL,
		0x83E53097E96894B8ULL,
		0x2E3946BB964A45A1ULL,
		0x42060167FFAF15A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB7D600184C459305ULL,
		0x5D48F43D7FEF595BULL,
		0x3311269CCAE3FE55ULL,
		0x42A34F806A39CCCDULL,
		0x6E92920C5B4C148CULL,
		0x5E69645C2CF99494ULL,
		0xB6B7E235CC988B57ULL,
		0xCBBCFB0AAC40A1D6ULL
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
		0x29BA720BC9FAC902ULL,
		0xF08A558E4E819F97ULL,
		0xEA25C2134412144DULL,
		0x3835AC742D63C4DAULL,
		0x35342890263C9EABULL,
		0xF789ADAF179B870DULL,
		0x14F7DC0883825403ULL,
		0x7D56C9B867C6075CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E55ABAFB19D5739ULL,
		0x5946710F51D263E6ULL,
		0xF4BA2EB9E4789F1FULL,
		0x24EA8FA5010A5BFAULL,
		0xA91DA720F2D91A9EULL,
		0x6603E5C5548D8E2EULL,
		0xCEF102791E223464ULL,
		0xE3A2568B4AB59398ULL
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
		0x3FF68335D269BC33ULL,
		0xF3EE116A49EECCA6ULL,
		0x363AD67AF0573AA3ULL,
		0x4DDE0780B93D31C4ULL,
		0xBC48EA8BA8C5A57EULL,
		0x89BAD9C324CF0FD2ULL,
		0x4B1D2995BB727DBDULL,
		0xB4E830F5F7D45029ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x420CA89179828C9AULL,
		0x6C83B9E7B6579AB9ULL,
		0x55672F0EE5B3C2D1ULL,
		0x359234052D4F7E00ULL,
		0x903F8DB034C5D0A1ULL,
		0x2BA364E13F0F2E66ULL,
		0xF98C89A3DB41B977ULL,
		0xD94C416B5B2DF0DFULL
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
		0x170657FB1FCBAAACULL,
		0xE6FC7BBE56A0D5C5ULL,
		0xD43E698AEDFCC7F9ULL,
		0xB3FF9299E3834EDBULL,
		0x26731AC0695B000CULL,
		0xB4BA3ED0B90D210FULL,
		0xC1E83687A8DCCDF5ULL,
		0xE0EB29D40AAA56C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x170657FB1FCBAAACULL,
		0xE6FC7BBE56A0D5C5ULL,
		0xD43E698AEDFCC7F9ULL,
		0xB3FF9299E3834EDBULL,
		0x26731AC0695B000CULL,
		0xB4BA3ED0B90D210FULL,
		0xC1E83687A8DCCDF5ULL,
		0xE0EB29D40AAA56C7ULL
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
		0x41C77032E84B061EULL,
		0xAC3B6495C6D08FEEULL,
		0x5E9E3C9CDDAE6851ULL,
		0x5245EC5C0474533EULL,
		0x1733E95C5FB49F5BULL,
		0x244C5E153BD72489ULL,
		0x0190351B261C3CEAULL,
		0xC28ACB2F728F366DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7870FEF749988801ULL,
		0x14AAD3BDA9B81AADULL,
		0x25432512E896EC86ULL,
		0xE83B35D5C1522E17ULL,
		0xBAC350EE4A57436FULL,
		0x107C3DEAAEFAE923ULL,
		0x087DA43D0587262EULL,
		0x23E14C586C4D6F0DULL
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
		0x67E8DADC4913D7B8ULL,
		0xD38C53047384A592ULL,
		0xAD414E6848CABA0FULL,
		0xFF60B6A1DDA3C861ULL,
		0xFB4D19B828ABB2EFULL,
		0xF8F5A61ACE34E3ACULL,
		0x686D930DCE1FA982ULL,
		0x6C8A6ACB206DC9D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x328E86DCF79A9F20ULL,
		0x621402B070D5B7BFULL,
		0xC4342898378CB130ULL,
		0x15AB20EFBCAC8E42ULL,
		0x7058B2E39863F78CULL,
		0x48E2A0ABECE7D060ULL,
		0x120F4AE1CA4A275DULL,
		0xA205EC3A8F2CEB55ULL
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
		0x2D6CCC3EF0FAF89AULL,
		0x5A5E9C654EFA8787ULL,
		0xDD075168D1E49419ULL,
		0x9951AAD6B3DAE19CULL,
		0xB70962957908F74CULL,
		0x98E5C83F026831B7ULL,
		0x6A3CE3B0515DBEB1ULL,
		0xE295EBD136822811ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x728C7B788667CAA1ULL,
		0x04E10872BD5A375AULL,
		0xB0F88746500C2770ULL,
		0xC935AFB5E6150A13ULL,
		0xE7D7898933F7DCF3ULL,
		0x67A8D6575EF8A6A3ULL,
		0xF31A186EC3726F10ULL,
		0x9D27F9B507C92205ULL
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