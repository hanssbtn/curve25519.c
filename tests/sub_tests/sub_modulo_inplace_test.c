#include "../tests.h"

int32_t curve25519_key_sub_modulo_inplace_test(void) {
	printf("Inplace Modular Key Subtraction Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x86DB8646CA0E09F0ULL,
		0xDA6BD73B6A01E53DULL,
		0x5E9E5F0E13E470A2ULL,
		0x07253EBE22FDEED2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0x37B6CEDC47B6C734ULL,
		0x1825C48D4013B5ABULL,
		0xF105C5A815D3C39BULL,
		0x38E367852A913DA7ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x4F24B76A825742A9ULL,
		0xC24612AE29EE2F92ULL,
		0x6D989965FE10AD07ULL,
		0x4E41D738F86CB12AULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	int32_t res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 1 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -1;
	} else {
		printf("Test Case 1 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x48022C7002AB79DDULL,
		0x0B022EDADC9DC23DULL,
		0x608A04CE23CE40FEULL,
		0x74E952DE66CAA73CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E432CF3CDB588B9ULL,
		0x02DEC8B0C5AA918BULL,
		0xD80E67612ED02BAFULL,
		0x56546992E6F018FEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19BEFF7C34F5F124ULL,
		0x0823662A16F330B2ULL,
		0x887B9D6CF4FE154FULL,
		0x1E94E94B7FDA8E3DULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 2 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -2;
	} else {
		printf("Test Case 2 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC93840D498AE9ECEULL,
		0x103D536CAE77997BULL,
		0xD17282618A2A8DE2ULL,
		0x7CA8071CBDF83A3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9603A458FE3CED02ULL,
		0xD1FBCE95EC785AD2ULL,
		0xCF013EE004C1871AULL,
		0x6A7D78F4D8A73B01ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33349C7B9A71B1CCULL,
		0x3E4184D6C1FF3EA9ULL,
		0x02714381856906C7ULL,
		0x122A8E27E550FF3DULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 3 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -3;
	} else {
		printf("Test Case 3 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE5F3E2DEF7AE246FULL,
		0xC1F68640F0FE34E1ULL,
		0xA41364384CD8E5A4ULL,
		0x25EFB96C1B5F34FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x04497FDCB7282963ULL,
		0x18E0FDB92F033509ULL,
		0xA7CC153D6F24D44EULL,
		0x3E9AF28CB703A7DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE1AA63024085FAF9ULL,
		0xA9158887C1FAFFD8ULL,
		0xFC474EFADDB41156ULL,
		0x6754C6DF645B8D20ULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 4 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -4;
	} else {
		printf("Test Case 4 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEB32F10EC784830EULL,
		0x043B5A361829368EULL,
		0x647C07702DD013BBULL,
		0x1770B5AD515297EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEB9F61A371586C4ULL,
		0x7B802615CBD78477ULL,
		0x6D65999D4209A74CULL,
		0x05C14F352CE7885DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C78FAF4906EFC4AULL,
		0x88BB34204C51B217ULL,
		0xF7166DD2EBC66C6EULL,
		0x11AF6678246B0F8FULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 5 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -5;
	} else {
		printf("Test Case 5 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36CF494E2830FED5ULL,
		0xC18879513495D149ULL,
		0xCBC2AABB05969DF7ULL,
		0x0AB46EEB6F22A49CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18CF6FD140F99E0CULL,
		0xCEC7BD26FEB66BA3ULL,
		0xEF8C9FC612C81E97ULL,
		0x1D3B07091DC4252FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DFFD97CE73760B6ULL,
		0xF2C0BC2A35DF65A6ULL,
		0xDC360AF4F2CE7F5FULL,
		0x6D7967E2515E7F6CULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 6 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -6;
	} else {
		printf("Test Case 6 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5A11EFB1A833484AULL,
		0x1C26F7300D6FC339ULL,
		0x48FFC79367C582FDULL,
		0x0C60C4BEFA6BC360ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42D5D21B37A773BEULL,
		0x71D3379CDB93B83CULL,
		0xBAA80F221EF3C9A6ULL,
		0x2CD83AE2589122A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x173C1D96708BD479ULL,
		0xAA53BF9331DC0AFDULL,
		0x8E57B87148D1B956ULL,
		0x5F8889DCA1DAA0B7ULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 7 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -7;
	} else {
		printf("Test Case 7 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x367025727E76B077ULL,
		0x05A8EF2A4A930813ULL,
		0xE5642A1303235B89ULL,
		0x062774C36767803AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7DEB72FD01F302FULL,
		0xBD1409CCD0A1C62CULL,
		0x9379A3EDAD80E382ULL,
		0x62DC6BE818743DACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E916E42AE578035ULL,
		0x4894E55D79F141E6ULL,
		0x51EA862555A27806ULL,
		0x234B08DB4EF3428EULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 8 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -8;
	} else {
		printf("Test Case 8 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB191BF6FF89B892ULL,
		0xD873F1DE19B088F6ULL,
		0x6AF220493C7C2B7EULL,
		0x163E4A7A79AE7F33ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2984AF7D7969D51ULL,
		0xA2629A0E469B6882ULL,
		0xB372379A880AB286ULL,
		0x4EC753FDE0DEB201ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2880D0FF27F31B2EULL,
		0x361157CFD3152074ULL,
		0xB77FE8AEB47178F8ULL,
		0x4776F67C98CFCD31ULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 9 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -9;
	} else {
		printf("Test Case 9 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4AAB45D0A155834ULL,
		0x40D9320E51E19940ULL,
		0xBA734BB02E9DC4B6ULL,
		0x6B16B69C33B3B48FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x849AD8C02BFEC068ULL,
		0x9F878D847DEC0996ULL,
		0x9A0F669D0C9FDAFEULL,
		0x091B6CA5F523E985ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x500FDB9CDE1697CCULL,
		0xA151A489D3F58FAAULL,
		0x2063E51321FDE9B7ULL,
		0x61FB49F63E8FCB0AULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 10 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -10;
	} else {
		printf("Test Case 10 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35F7DEB0BC6C670BULL,
		0x4CD47A45E2953611ULL,
		0xD54A1DEC9742392EULL,
		0x085B7CB4E8FEA8ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC8B7E077783FD1BULL,
		0xB43C2E390D6636B1ULL,
		0xA0F5D53FD491EE4AULL,
		0x36CE600D292ED6DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x496C60A944E869DDULL,
		0x98984C0CD52EFF5FULL,
		0x345448ACC2B04AE3ULL,
		0x518D1CA7BFCFD1CFULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 11 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -11;
	} else {
		printf("Test Case 11 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF7F443E2D428B1BDULL,
		0x590C47D83C7E25FAULL,
		0x1E35EF65B30536EDULL,
		0x27E3BE2C748FB9E6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10DD69EEE7125316ULL,
		0x0B99331A67EFF32BULL,
		0x96840950E435E526ULL,
		0x6D7497E91666419DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE716D9F3ED165E94ULL,
		0x4D7314BDD48E32CFULL,
		0x87B1E614CECF51C7ULL,
		0x3A6F26435E297848ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 12 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -12;
	} else {
		printf("Test Case 12 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x010CFBE232F0980AULL,
		0xAC2B47915B5B0057ULL,
		0x1CF5B943970E4E95ULL,
		0x66DBA7FAE8B74350ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1D7CB88DE3A6CA6ULL,
		0xF55D40AA773A00AFULL,
		0xDEFEC9E772C76544ULL,
		0x6AC86CDE732B7906ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F35305954B62B51ULL,
		0xB6CE06E6E420FFA7ULL,
		0x3DF6EF5C2446E950ULL,
		0x7C133B1C758BCA49ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 13 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -13;
	} else {
		printf("Test Case 13 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB3C33D85B3E6EE39ULL,
		0x316EC71BD6909D07ULL,
		0x3A134DABF30F7381ULL,
		0x5F32A6C49EE33E14ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF30B19848FB17738ULL,
		0x550C8B120952A195ULL,
		0x96BF78D62D42022EULL,
		0x3B5E25B2C2F65F6AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0B8240124357701ULL,
		0xDC623C09CD3DFB71ULL,
		0xA353D4D5C5CD7152ULL,
		0x23D48111DBECDEA9ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 14 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -14;
	} else {
		printf("Test Case 14 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D5114AC7E97F99AULL,
		0xFB32045DDD34C628ULL,
		0x5E9C4BC62795C927ULL,
		0x6C30DA7C2B0144E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE4E22D7E0B2A0B8ULL,
		0xA1D7287E4DF66578ULL,
		0xEF2126F449A1AC50ULL,
		0x450986228882E010ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8F02F1D49DE558E2ULL,
		0x595ADBDF8F3E60AFULL,
		0x6F7B24D1DDF41CD7ULL,
		0x27275459A27E64CFULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 15 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -15;
	} else {
		printf("Test Case 15 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1EA5870DBAB677B6ULL,
		0xF5026099A8F58317ULL,
		0xE45D2087A3B8AC8AULL,
		0x68C750D50188EBB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88F301BA5AFFCD2DULL,
		0xC6CFF9609F265608ULL,
		0x83219F4A56C37610ULL,
		0x7D8F9AAFB3BF31C2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x95B285535FB6AA76ULL,
		0x2E32673909CF2D0EULL,
		0x613B813D4CF5367AULL,
		0x6B37B6254DC9B9F7ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 16 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -16;
	} else {
		printf("Test Case 16 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x415DD49128F9ED80ULL,
		0xF4AADA2288FC97B6ULL,
		0x8EF11EAEABF0A343ULL,
		0x161556402BA407ECULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA06325B361A20CB9ULL,
		0x1035E8E161484969ULL,
		0x160296EA85C8C187ULL,
		0x1B6CFE2A83E1876AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0FAAEDDC757E0B4ULL,
		0xE474F14127B44E4CULL,
		0x78EE87C42627E1BCULL,
		0x7AA85815A7C28082ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 17 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -17;
	} else {
		printf("Test Case 17 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x644BD471176615B1ULL,
		0x00BB561F5CE8DD0CULL,
		0x47D266D7196E805EULL,
		0x3761E8C0C4E06196ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEA13EB7FCD19E7AULL,
		0xB3C16E4966467E19ULL,
		0xD7AF1A9004B6E2A3ULL,
		0x2977F01807C79329ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5AA95B91A947737ULL,
		0x4CF9E7D5F6A25EF2ULL,
		0x70234C4714B79DBAULL,
		0x0DE9F8A8BD18CE6CULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 18 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -18;
	} else {
		printf("Test Case 18 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCF26FBEB314B0692ULL,
		0x914D6F97446696CBULL,
		0x1CEA2DEEEE241ADCULL,
		0x35610AE6AAE2DA1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A7EC19891170DB1ULL,
		0x199C48772597ED63ULL,
		0x68D48978E705E1D5ULL,
		0x474354C730826EB5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54A83A52A033F8CEULL,
		0x77B127201ECEA968ULL,
		0xB415A476071E3907ULL,
		0x6E1DB61F7A606B67ULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 19 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -19;
	} else {
		printf("Test Case 19 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x975F84ADA0C86F39ULL,
		0x52E2CD1099C718D4ULL,
		0x2D3B99568485B030ULL,
		0x67D3D31CBCFEAA27ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59B92D6FC104B11FULL,
		0x82DDCB1B102628E2ULL,
		0x4F45BF9D40227222ULL,
		0x63E89DCE86A855A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3DA6573DDFC3BE1AULL,
		0xD00501F589A0EFF2ULL,
		0xDDF5D9B944633E0DULL,
		0x03EB354E3656547DULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 20 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -20;
	} else {
		printf("Test Case 20 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE6022F88FDB15B09ULL,
		0x42C2A930DD683090ULL,
		0x9D6748795A4EFA77ULL,
		0x17B65A05C08A34C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x23B3E588638A1146ULL,
		0xAC21ECDF719D64BDULL,
		0x27612ECE89C4EC37ULL,
		0x73D69C756436C981ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC24E4A009A2749B0ULL,
		0x96A0BC516BCACBD3ULL,
		0x760619AAD08A0E3FULL,
		0x23DFBD905C536B46ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 21 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -21;
	} else {
		printf("Test Case 21 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x138FA82945454910ULL,
		0x6A3D025E0D3589EEULL,
		0xF7DE7639D6C57C2AULL,
		0x7069758822FDC8BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2DD1A4896AFE0025ULL,
		0x9913FED1D311989DULL,
		0x0AD72C009C4AE6AEULL,
		0x56670FD1008C80DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE5BE039FDA4748EBULL,
		0xD129038C3A23F150ULL,
		0xED074A393A7A957BULL,
		0x1A0265B7227147DFULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 22 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -22;
	} else {
		printf("Test Case 22 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x905C07275019D106ULL,
		0xC43126A64E27D36EULL,
		0x8CDA88C719F3508EULL,
		0x1AD80EF171A1829AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB66B7B15EB3AB33ULL,
		0x2DEB65C54A9A33D9ULL,
		0xF348CCF248587EE3ULL,
		0x27BD34EA41889D7FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94F54F75F16625C0ULL,
		0x9645C0E1038D9F94ULL,
		0x9991BBD4D19AD1ABULL,
		0x731ADA073018E51AULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 23 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -23;
	} else {
		printf("Test Case 23 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBC8A511922E87492ULL,
		0xB49D96B468423F69ULL,
		0x0C58ABB6E4EABF62ULL,
		0x025F23D0B21E44E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD080B56DA76DA87ULL,
		0x35383856C5A45AA2ULL,
		0x4979A4190669A779ULL,
		0x7C30F1C5AD79041DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEF8245C2487199F8ULL,
		0x7F655E5DA29DE4C6ULL,
		0xC2DF079DDE8117E9ULL,
		0x062E320B04A540C7ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 24 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -24;
	} else {
		printf("Test Case 24 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1EAE37EBDC5C138ULL,
		0x52F46EA3D794BC38ULL,
		0x8409545D6D05FE3CULL,
		0x4F8127145D4B5B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573916F286F174E8ULL,
		0x9C3F13E3D51EDAC0ULL,
		0xA79EA535AAF2C411ULL,
		0x3AB757AD9FF183E8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8AB1CC8C36D44C50ULL,
		0xB6B55AC00275E178ULL,
		0xDC6AAF27C2133A2AULL,
		0x14C9CF66BD59D71BULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 25 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -25;
	} else {
		printf("Test Case 25 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3AC52B696E3B8E29ULL,
		0x749CD3568496989FULL,
		0x4BE83914B47647FBULL,
		0x045C7C8954BD2104ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x526A3B6E0BDD4C39ULL,
		0xA92353D76FC35774ULL,
		0x3BD11B3B78B6688AULL,
		0x66755143AED265DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE85AEFFB625E41DDULL,
		0xCB797F7F14D3412AULL,
		0x10171DD93BBFDF70ULL,
		0x1DE72B45A5EABB29ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 26 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -26;
	} else {
		printf("Test Case 26 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EC7FE2C1857481BULL,
		0x5BC8A466A3ACCD63ULL,
		0x443B43348A26FEF1ULL,
		0x5D31DDA99CD07B92ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC588B070249D3D69ULL,
		0xEE2106DA2CA3574FULL,
		0x0B1172A98C1786FCULL,
		0x28F97CF039AC491EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x693F4DBBF3BA0AB2ULL,
		0x6DA79D8C77097613ULL,
		0x3929D08AFE0F77F4ULL,
		0x343860B963243274ULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 27 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -27;
	} else {
		printf("Test Case 27 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2BBA9E4A41B0CB27ULL,
		0xCC62195F61BD99BCULL,
		0xFA20381F9A253C4BULL,
		0x201F253BCF5D596CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x009C9E01C06A247EULL,
		0x6A400A300D801B11ULL,
		0xE9F389B273802DA7ULL,
		0x6B420F2F10E1D2D5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2B1E00488146A696ULL,
		0x62220F2F543D7EABULL,
		0x102CAE6D26A50EA4ULL,
		0x34DD160CBE7B8697ULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 28 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -28;
	} else {
		printf("Test Case 28 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C6E8FC496BD18A4ULL,
		0x77B85E8A244FC81CULL,
		0xF9D63499090F5CA8ULL,
		0x4B70FDFE690A0E98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1BD3F59CF7595181ULL,
		0x77D93A355907D651ULL,
		0x75D24FC28AE7A7FAULL,
		0x661F74000F7C93CCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x209A9A279F63C710ULL,
		0xFFDF2454CB47F1CBULL,
		0x8403E4D67E27B4ADULL,
		0x655189FE598D7ACCULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 29 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -29;
	} else {
		printf("Test Case 29 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA3299F57BE5870CAULL,
		0x8B4897BE610D4729ULL,
		0xA9EDAC9CC3852DCEULL,
		0x33C2D2EDF3D47BD3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A08169B6DC32A92ULL,
		0x6D88355356CC182AULL,
		0x47A940DC1183D61CULL,
		0x6F8171E9F825C682ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x792188BC50954625ULL,
		0x1DC0626B0A412EFFULL,
		0x62446BC0B20157B2ULL,
		0x44416103FBAEB551ULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 30 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -30;
	} else {
		printf("Test Case 30 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8AF6AFE11FDB8A44ULL,
		0x62598DC134494E91ULL,
		0x95AF5B8A1C6B2F14ULL,
		0x3926F48A0C3BC3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x062670AC7D28C393ULL,
		0xF5F4BE5ADB6A857FULL,
		0xCC04A2040E13A598ULL,
		0x7C82505CD2A8CECFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x84D03F34A2B2C69EULL,
		0x6C64CF6658DEC912ULL,
		0xC9AAB9860E57897BULL,
		0x3CA4A42D3992F52EULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 31 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -31;
	} else {
		printf("Test Case 31 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99E56E0500CC0620ULL,
		0x13FC431A93F5FE73ULL,
		0x04B1E5631F013135ULL,
		0x3C5419C971FE6C03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3FBBCD65ED6F79CULL,
		0x81BD48ED75444166ULL,
		0x7F906886DB422F55ULL,
		0x608E98DDC9B06EC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA5E9B12EA1F50E71ULL,
		0x923EFA2D1EB1BD0CULL,
		0x85217CDC43BF01DFULL,
		0x5BC580EBA84DFD41ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 32 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -32;
	} else {
		printf("Test Case 32 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x45E8424102C72A14ULL,
		0xD60EB5C0A4318950ULL,
		0x22754ED62877CAACULL,
		0x6AFB33B71361E173ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E801223BFF9C004ULL,
		0x9845BBC11A730D92ULL,
		0xBC4ACBFD16951C17ULL,
		0x09D1BFA81B75CB0EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA768301D42CD6A10ULL,
		0x3DC8F9FF89BE7BBDULL,
		0x662A82D911E2AE95ULL,
		0x6129740EF7EC1664ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 33 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -33;
	} else {
		printf("Test Case 33 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4839BC6756AA0C86ULL,
		0x04BA7786E8370E41ULL,
		0x7CBAF4852FD561ACULL,
		0x77E3C95E56771AD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5130FEEB2DEC2F03ULL,
		0x0851DE260164CDF3ULL,
		0x569F3F1711600156ULL,
		0x09D9EC0FAB9FAE03ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF708BD7C28BDDD83ULL,
		0xFC689960E6D2404DULL,
		0x261BB56E1E756055ULL,
		0x6E09DD4EAAD76CD2ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 34 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -34;
	} else {
		printf("Test Case 34 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DBB33C0B5391C63ULL,
		0x47CB00BFD9D574C0ULL,
		0x8A7B8622EE7ABE28ULL,
		0x42F7CDCDA9B3BF6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99F35392001CDE3EULL,
		0xE1976E08A6BA7DC9ULL,
		0xDEA4127B6CA13959ULL,
		0x53EF8C27883BF2B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC3C7E02EB51C3E12ULL,
		0x663392B7331AF6F6ULL,
		0xABD773A781D984CEULL,
		0x6F0841A62177CCBCULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 35 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -35;
	} else {
		printf("Test Case 35 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1A6982D9E5B215ULL,
		0xCE565F8D42250717ULL,
		0x00E112A57DCCC83FULL,
		0x203AA3564B54261BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF921A6933022D50AULL,
		0x6D5FAF301CCCB69CULL,
		0xB64A27CA089A5E09ULL,
		0x26C8B3ECFFE494DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x82F8C2EFA9C2DCF8ULL,
		0x60F6B05D2558507AULL,
		0x4A96EADB75326A36ULL,
		0x7971EF694B6F913FULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 36 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -36;
	} else {
		printf("Test Case 36 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x77A6A71DA8C3A639ULL,
		0x5C030DA2888AF933ULL,
		0xD027ED9772A110DAULL,
		0x08318FE1C3FFC3B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15463B02FBF4157BULL,
		0x1FE44CD7AA1979CDULL,
		0xE2FE53AD9053BC29ULL,
		0x106FC7CF7BC7BD5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x62606C1AACCF90ABULL,
		0x3C1EC0CADE717F66ULL,
		0xED2999E9E24D54B1ULL,
		0x77C1C81248380659ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 37 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -37;
	} else {
		printf("Test Case 37 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B981038A3618E83ULL,
		0xA2EC10201E40CBC8ULL,
		0xE5ECDFBCA6F14516ULL,
		0x2676996915799C76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB98F15F1AF3422DBULL,
		0x791FB3747E3E6CF1ULL,
		0x3785F5E06F5CEF3DULL,
		0x39972AEEA5EEBF93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE208FA46F42D6B95ULL,
		0x29CC5CABA0025ED6ULL,
		0xAE66E9DC379455D9ULL,
		0x6CDF6E7A6F8ADCE3ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 38 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -38;
	} else {
		printf("Test Case 38 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xABF5C4667E3BDE81ULL,
		0x1040A59ACFE5BA49ULL,
		0x8D876C05225DF462ULL,
		0x328BBBE669A78E01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB880594CB02863A2ULL,
		0x1F050BEA12791100ULL,
		0x4262EFF7DF942A30ULL,
		0x2F23A41C1846F276ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF3756B19CE137ADFULL,
		0xF13B99B0BD6CA948ULL,
		0x4B247C0D42C9CA31ULL,
		0x036817CA51609B8BULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 39 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -39;
	} else {
		printf("Test Case 39 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBE71EC5F066722B3ULL,
		0x27859294D58D01BAULL,
		0x11C177BCAEAFF72EULL,
		0x1B311306D559195CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCB7D9DE3DB00C5D2ULL,
		0x60727933F7D87563ULL,
		0xAA4C481FB1657250ULL,
		0x34E66A67CDE5B378ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF2F44E7B2B665CCEULL,
		0xC7131960DDB48C56ULL,
		0x67752F9CFD4A84DDULL,
		0x664AA89F077365E3ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 40 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -40;
	} else {
		printf("Test Case 40 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7AE0EEDAE6C9FA0CULL,
		0x70AC822A97AD8AF1ULL,
		0x628D56A5C439F3E5ULL,
		0x58EB62A8AE0882ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A8D0E35E5C2803BULL,
		0xA8A92A9664224367ULL,
		0x550CDC4C565FE4B4ULL,
		0x5ED6CA04F1D7CBADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1053E0A5010779BEULL,
		0xC8035794338B478AULL,
		0x0D807A596DDA0F30ULL,
		0x7A1498A3BC30B700ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 41 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -41;
	} else {
		printf("Test Case 41 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAB4E8D55DE7E8F76ULL,
		0x1A900712E53869B8ULL,
		0x7DDE114DDCBED5D5ULL,
		0x1A0B2DF081EECEEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E4028CD702A7B4BULL,
		0xAFF52150DA30FE05ULL,
		0xF8C63D9DBA81AB5FULL,
		0x3CEC73BED33EBD9AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9D0E64886E541418ULL,
		0x6A9AE5C20B076BB3ULL,
		0x8517D3B0223D2A75ULL,
		0x5D1EBA31AEB01153ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 42 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -42;
	} else {
		printf("Test Case 42 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9FFE15B4D457D6D6ULL,
		0x6A9D7865150446E0ULL,
		0x77786D85606FA613ULL,
		0x7D7892313EB2B103ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16BE4B1851064503ULL,
		0xDE0FA8717812CCA6ULL,
		0xC439115037D90430ULL,
		0x0541991E20F1DCA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x893FCA9C835191D3ULL,
		0x8C8DCFF39CF17A3AULL,
		0xB33F5C352896A1E2ULL,
		0x7836F9131DC0D45FULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 43 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -43;
	} else {
		printf("Test Case 43 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25C6F5692D814CB7ULL,
		0x66DB5B4DEA0B43D0ULL,
		0x16BF821070D34817ULL,
		0x3C35B7E25ACCD7A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DE7AB9E5E23CA0FULL,
		0x47015F0CA3B22282ULL,
		0xC189700091A3C813ULL,
		0x04879D71D8FC5B25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC7DF49CACF5D82A8ULL,
		0x1FD9FC414659214DULL,
		0x5536120FDF2F8004ULL,
		0x37AE1A7081D07C81ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 44 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -44;
	} else {
		printf("Test Case 44 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x05C3DB84F8E40578ULL,
		0x0DC6E47F78033C50ULL,
		0x98E8BA5A4F7A372EULL,
		0x135CBBFA0DC764CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25B9E21993B54334ULL,
		0xD9C01BA19C823F68ULL,
		0xF9525C174646CEAFULL,
		0x7D59F1DE0727F644ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE009F96B652EC231ULL,
		0x3406C8DDDB80FCE7ULL,
		0x9F965E430933687EULL,
		0x1602CA1C069F6E87ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 45 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -45;
	} else {
		printf("Test Case 45 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE370EF419E232757ULL,
		0x04058BB9D2AADAC3ULL,
		0xE499B49C4F13D86EULL,
		0x6C9757386B854757ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6A1B2B87792317CULL,
		0x97512670D8983847ULL,
		0xB8AA1C12EB001F65ULL,
		0x41F702443DE41A11ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1CCF3C892690F5DBULL,
		0x6CB46548FA12A27CULL,
		0x2BEF98896413B908ULL,
		0x2AA054F42DA12D46ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 46 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -46;
	} else {
		printf("Test Case 46 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8181291F984CA9CFULL,
		0x78D4E9650FF7316AULL,
		0xBB401ABDB785F2B6ULL,
		0x04F84B9B6FCD6195ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE10825EBCD060266ULL,
		0xE2738B9768510019ULL,
		0x3C6F558DE148A288ULL,
		0x477597D7CF6EE264ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0790333CB46A756ULL,
		0x96615DCDA7A63150ULL,
		0x7ED0C52FD63D502DULL,
		0x3D82B3C3A05E7F31ULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 47 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -47;
	} else {
		printf("Test Case 47 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1F39E620457EA3EULL,
		0xDD8C04CA5D2839F7ULL,
		0x207458FDFEE791EAULL,
		0x5C892421DB8DEFB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x703E339C8B6D1B51ULL,
		0xC3E7A9792A0782ECULL,
		0x63E49DC8B34A9A56ULL,
		0x68C36B6F1D3CBF12ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51B56AC578EACEDAULL,
		0x19A45B513320B70BULL,
		0xBC8FBB354B9CF794ULL,
		0x73C5B8B2BE5130A5ULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 48 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -48;
	} else {
		printf("Test Case 48 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x334102A8A8A0E8AAULL,
		0xD2518671082E8427ULL,
		0x81FE863BD18C3E12ULL,
		0x14D8181CB5F65E5CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27F35B82EFFD9A30ULL,
		0x1352B71DCF8702E3ULL,
		0x53B2BBAD4421C169ULL,
		0x0EE55DF9167F390AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0B4DA725B8A34E7AULL,
		0xBEFECF5338A78144ULL,
		0x2E4BCA8E8D6A7CA9ULL,
		0x05F2BA239F772552ULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 49 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -49;
	} else {
		printf("Test Case 49 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x294E70B70059483EULL,
		0x22246A53D19BE402ULL,
		0x0F018C9EA6D7B3A7ULL,
		0x7B1AF4B727063741ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x695F4C6D78BA1228ULL,
		0x5C86AEA09969C119ULL,
		0x8E94D9C103212612ULL,
		0x70C30F84FF4815A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBFEF2449879F3616ULL,
		0xC59DBBB3383222E8ULL,
		0x806CB2DDA3B68D94ULL,
		0x0A57E53227BE219DULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 50 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -50;
	} else {
		printf("Test Case 50 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1789F4EFA68FB44ULL,
		0x4AD5CFFCE83ACC5DULL,
		0x21441062FFB6496DULL,
		0x7E44E2096F6FAF93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A19E1ED6977216FULL,
		0x5884FB72025F9DCDULL,
		0x1A24A389F0B5DD0FULL,
		0x4F7EEC39DFDED2CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC75EBD6190F1D9D5ULL,
		0xF250D48AE5DB2E90ULL,
		0x071F6CD90F006C5DULL,
		0x2EC5F5CF8F90DCC9ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 51 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -51;
	} else {
		printf("Test Case 51 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x685DE7F476FD9674ULL,
		0xA6AE3A92B41B8916ULL,
		0x199C0BC1828DD4C2ULL,
		0x3B6B2ABEC12AC6F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8176CF85F70DA0F3ULL,
		0x64E0F18769E76933ULL,
		0x9E9D4276554E45EDULL,
		0x2B27AF4339F54431ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE6E7186E7FEFF581ULL,
		0x41CD490B4A341FE2ULL,
		0x7AFEC94B2D3F8ED5ULL,
		0x10437B7B873582C5ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 52 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -52;
	} else {
		printf("Test Case 52 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xAF7B34EED4F938C5ULL,
		0x03F9E3764B9223CFULL,
		0xDAB08F83FBA2CD6DULL,
		0x1337B21B1471BC12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73115C45D2C3B8F7ULL,
		0x9E46312B5633F9A0ULL,
		0x45F566C80E59A606ULL,
		0x42A506EA48A6A7B9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3C69D8A902357FBBULL,
		0x65B3B24AF55E2A2FULL,
		0x94BB28BBED492766ULL,
		0x5092AB30CBCB1459ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 53 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -53;
	} else {
		printf("Test Case 53 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3D622F846263C955ULL,
		0x227A2E1C318B4FF7ULL,
		0x6D8055E08F3DF67CULL,
		0x72E3797069A1BDA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C233940FDF8C26CULL,
		0xCB61C7F2DB0A83CDULL,
		0x63253D44A07591F6ULL,
		0x6572DF1BE0D6DAAAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x013EF643646B06E9ULL,
		0x571866295680CC2AULL,
		0x0A5B189BEEC86485ULL,
		0x0D709A5488CAE2FBULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 54 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -54;
	} else {
		printf("Test Case 54 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA6F535A948904CB3ULL,
		0x3B3496415C4EFFA8ULL,
		0x49A049169067E9FAULL,
		0x251797AEE8FBFD04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC223F1074E0DADD9ULL,
		0xF00B5C99635A9CEDULL,
		0x1E66BA20544FBEC4ULL,
		0x224F5ED9D660538BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4D144A1FA829EDAULL,
		0x4B2939A7F8F462BAULL,
		0x2B398EF63C182B35ULL,
		0x02C838D5129BA979ULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 55 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -55;
	} else {
		printf("Test Case 55 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE33600D82AEB1069ULL,
		0xAFC19A061F3BE9FBULL,
		0x50F9230A917059D3ULL,
		0x0D012F1472A3F5BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD40E9FCB4B0DD2ECULL,
		0x1E4CD8D21112E040ULL,
		0xB19C53A76CA92142ULL,
		0x5325544B3E557500ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F27610CDFDD3D6AULL,
		0x9174C1340E2909BBULL,
		0x9F5CCF6324C73891ULL,
		0x39DBDAC9344E80BBULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 56 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -56;
	} else {
		printf("Test Case 56 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7A3DFF4159965EF1ULL,
		0x0F59824212AA0A3EULL,
		0xE61D7BF114D7642FULL,
		0x55F1FF1AE4863826ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF131D127B7EA65A7ULL,
		0x810BB40ECF3BE6F4ULL,
		0x776D32159AB78367ULL,
		0x5E517E7B72809A79ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x890C2E19A1ABF937ULL,
		0x8E4DCE33436E2349ULL,
		0x6EB049DB7A1FE0C7ULL,
		0x77A0809F72059DADULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 57 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -57;
	} else {
		printf("Test Case 57 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D1EF8B10FC79A77ULL,
		0x8311D7B00D5B9AB3ULL,
		0xDD74EA54D0933D1FULL,
		0x08EFBFE25D16BBE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD5F607EAB5F471C8ULL,
		0xC301D2F75E7A5930ULL,
		0xB5461335D3BCB0EEULL,
		0x2287A79F426D991CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9728F0C659D3289CULL,
		0xC01004B8AEE14182ULL,
		0x282ED71EFCD68C30ULL,
		0x666818431AA922C5ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 58 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -58;
	} else {
		printf("Test Case 58 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x18B4FD25425D0994ULL,
		0x210D4A8363EB7537ULL,
		0xA84FDB86D0FA23C6ULL,
		0x419501BA9E3AC8BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACA9976B9D2E46FEULL,
		0x2C7C5553D5A6C3DBULL,
		0x3909D982D738199FULL,
		0x5000B505E48ECE21ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C0B65B9A52EC283ULL,
		0xF490F52F8E44B15BULL,
		0x6F460203F9C20A26ULL,
		0x71944CB4B9ABFA9CULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 59 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -59;
	} else {
		printf("Test Case 59 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC2E3B4504DDB7A44ULL,
		0x1D109DA0C935354CULL,
		0x2E4EFEC8875109D9ULL,
		0x7DEF7130E27CE5D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1025D1527C6CE86DULL,
		0x7B0344FB10D2FE02ULL,
		0x169597CBD1CBB420ULL,
		0x021615BFA32A5B2EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB2BDE2FDD16E91D7ULL,
		0xA20D58A5B862374AULL,
		0x17B966FCB58555B8ULL,
		0x7BD95B713F528AA5ULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 60 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -60;
	} else {
		printf("Test Case 60 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD3AB395A22B7DC70ULL,
		0x04506EC510585B4EULL,
		0x19A0F5BDFB12B695ULL,
		0x7F9B3C35CF11D194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00739816C9A78CBAULL,
		0xB4A611D0F7714B3AULL,
		0x8894911DECC4BC82ULL,
		0x7B74268796CA0B9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD337A14359104FB6ULL,
		0x4FAA5CF418E71014ULL,
		0x910C64A00E4DFA12ULL,
		0x042715AE3847C5F6ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 61 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -61;
	} else {
		printf("Test Case 61 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x23A420E5B1D2FE33ULL,
		0x124278572E8ABBB4ULL,
		0xFAAEE3EF6418BEA0ULL,
		0x37E6AD6C7524CE4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE382598D626554E0ULL,
		0xF87E2CAF108BADBEULL,
		0x2AF4A11E7D3D9585ULL,
		0x682CBA9B3C2A6948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4021C7584F6DA940ULL,
		0x19C44BA81DFF0DF5ULL,
		0xCFBA42D0E6DB291AULL,
		0x4FB9F2D138FA6502ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 62 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -62;
	} else {
		printf("Test Case 62 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C81C18165678FB5ULL,
		0x3DE64F9EB654108AULL,
		0xFB6C410F82E887DBULL,
		0x6B2D7E8E20A75AAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08C9C17FD6EA5FBDULL,
		0x121EBBB0E5487AF4ULL,
		0xD4F636175336AC50ULL,
		0x657EDB135BCF0757ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53B800018E7D2FF8ULL,
		0x2BC793EDD10B9596ULL,
		0x26760AF82FB1DB8BULL,
		0x05AEA37AC4D85358ULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 63 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -63;
	} else {
		printf("Test Case 63 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB825D67B46FC928FULL,
		0xB8693C906AC87C7DULL,
		0x72E17F77E6905966ULL,
		0x732D8C3A29461AB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5DCDCAB907904224ULL,
		0x73586EC699239A06ULL,
		0xF623D888E64E1D40ULL,
		0x393F5310CDD8B33EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5A580BC23F6C506BULL,
		0x4510CDC9D1A4E277ULL,
		0x7CBDA6EF00423C26ULL,
		0x39EE39295B6D6779ULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 64 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -64;
	} else {
		printf("Test Case 64 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x06D51B99F5C2220BULL,
		0x4C270F6DD0A37CE4ULL,
		0xB2ABBD651A6818B4ULL,
		0x2666EC31C103730FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B2CAAF915983D6ULL,
		0x98D52F94F8B5EFF3ULL,
		0xA16A7EBE5207FD84ULL,
		0x794559F4C24E8966ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x532250EA64689E22ULL,
		0xB351DFD8D7ED8CF0ULL,
		0x11413EA6C8601B2FULL,
		0x2D21923CFEB4E9A9ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 65 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -65;
	} else {
		printf("Test Case 65 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E9F35178F45EC29ULL,
		0x56C7390F6C8F988FULL,
		0x158F73E99B9C7E99ULL,
		0x2F40AC80B9B2142EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0EB062E25F341E62ULL,
		0x818233ECD7AA0EEEULL,
		0xF4A3C5D16F60A03FULL,
		0x4FF45E266DF56925ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FEED2353011CDB4ULL,
		0xD545052294E589A1ULL,
		0x20EBAE182C3BDE59ULL,
		0x5F4C4E5A4BBCAB08ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 66 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -66;
	} else {
		printf("Test Case 66 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3467D37C674ECA2CULL,
		0x0791B1FEE25A6CB6ULL,
		0xF74AB564400E09B8ULL,
		0x030BE53F06E6ECE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19AF8F1D220A2277ULL,
		0x37CD3D9EE62FAF0DULL,
		0xF9CDF5202431E1EAULL,
		0x6C5D40C236958969ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1AB8445F4544A7A2ULL,
		0xCFC4745FFC2ABDA9ULL,
		0xFD7CC0441BDC27CDULL,
		0x16AEA47CD051637CULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 67 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -67;
	} else {
		printf("Test Case 67 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3C683BCDAD90DC37ULL,
		0x938997C405686FABULL,
		0xA4658128F4A5F4CAULL,
		0x10209EAE28B813BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x929E6762BF4E15AEULL,
		0x417B5F1815F056DCULL,
		0x4BC8CB345427279AULL,
		0x1146C7142002CF60ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9C9D46AEE42C676ULL,
		0x520E38ABEF7818CEULL,
		0x589CB5F4A07ECD30ULL,
		0x7ED9D79A08B5445DULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 68 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -68;
	} else {
		printf("Test Case 68 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9195E486C9BC896CULL,
		0xC8098BC2E9680AE2ULL,
		0x786A49FB05DD1299ULL,
		0x46763C0FDCE530B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE2BBBD181ABA779CULL,
		0x1D714D279CCD8280ULL,
		0xAE8D8654D5A211FCULL,
		0x746921EE1BC9F32DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAEDA276EAF0211BDULL,
		0xAA983E9B4C9A8861ULL,
		0xC9DCC3A6303B009DULL,
		0x520D1A21C11B3D84ULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 69 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -69;
	} else {
		printf("Test Case 69 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x04AB537124B2A73BULL,
		0x7A1D91EC6916D364ULL,
		0x6D3DFC4B11CC4E1FULL,
		0x23AE2B81C71728DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B002E0F54FCA6A3ULL,
		0x07A917CB44823527ULL,
		0x2B65AAAFAFAA7DA9ULL,
		0x041DC0B92E0D6B35ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF9AB2561CFB60098ULL,
		0x72747A2124949E3CULL,
		0x41D8519B6221D076ULL,
		0x1F906AC89909BDA6ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 70 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -70;
	} else {
		printf("Test Case 70 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9E7344877079DAE0ULL,
		0xC433FFA2597DF926ULL,
		0xD457CBF6D79BC286ULL,
		0x7514240B514EBBA9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26F4DE2830DF531CULL,
		0x7DE01AA71B4D7874ULL,
		0x154F2236FAA1B0F2ULL,
		0x2DF5C2A6150639BBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x777E665F3F9A87C4ULL,
		0x4653E4FB3E3080B2ULL,
		0xBF08A9BFDCFA1194ULL,
		0x471E61653C4881EEULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 71 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -71;
	} else {
		printf("Test Case 71 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA7BD6A1834D567A6ULL,
		0x30FFACE8C439FD49ULL,
		0x8524D7F034647D0AULL,
		0x03BE57E03E61C961ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4E4519AEC54BC1DULL,
		0x4CC0AFDC124CD6EBULL,
		0x6D9EE7E0E09DB44EULL,
		0x7CD816D25D698BCAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2D9187D4880AB76ULL,
		0xE43EFD0CB1ED265DULL,
		0x1785F00F53C6C8BBULL,
		0x06E6410DE0F83D97ULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 72 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -72;
	} else {
		printf("Test Case 72 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB4FF2F9E1168D55DULL,
		0x6C26563AD1E55D5AULL,
		0xB55A973F30AC1F7FULL,
		0x52F3A4080635909EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x975D11F8B11B741CULL,
		0x1E40F07E42CBC3F4ULL,
		0x236FD052DD50324DULL,
		0x5C2A3FC45C294773ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1DA21DA5604D612EULL,
		0x4DE565BC8F199966ULL,
		0x91EAC6EC535BED32ULL,
		0x76C96443AA0C492BULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 73 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -73;
	} else {
		printf("Test Case 73 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE7CEB7A234BAB470ULL,
		0x583B50124E7C6B7CULL,
		0x41CB68FACC4B48A4ULL,
		0x6EFB80ECD2DD1CEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51770FABD35602F9ULL,
		0xF0B7B35DAB3A23BAULL,
		0xEB95D045F6945BDEULL,
		0x1987884C6BF47CE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9657A7F66164B177ULL,
		0x67839CB4A34247C2ULL,
		0x563598B4D5B6ECC5ULL,
		0x5573F8A066E8A009ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 74 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -74;
	} else {
		printf("Test Case 74 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCCDA7BD45AAE4BCEULL,
		0xCEFF088D6AAB1D9CULL,
		0xF383485FAC697FEDULL,
		0x134328774A74A9A9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1A9126487E9DFCBULL,
		0x5B29AFCEDAC5F691ULL,
		0x36E9664D07D888D0ULL,
		0x6F4A5FEAFDA55B3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB31696FD2C46BF0ULL,
		0x73D558BE8FE5270AULL,
		0xBC99E212A490F71DULL,
		0x23F8C88C4CCF4E6AULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 75 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -75;
	} else {
		printf("Test Case 75 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x25212EAF25D8DA47ULL,
		0x7B538363C087ADAAULL,
		0x9512E93E2E78AADDULL,
		0x4B06346DDEC61189ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27FFD6D01A4C2577ULL,
		0x866459DA5F47DB53ULL,
		0x07B81127FE2B2FEEULL,
		0x3FF162DB89CCA429ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFD2157DF0B8CB4D0ULL,
		0xF4EF2989613FD256ULL,
		0x8D5AD816304D7AEEULL,
		0x0B14D19254F96D60ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 76 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -76;
	} else {
		printf("Test Case 76 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x393C1A214AD242C4ULL,
		0x92EAF9CA763C8592ULL,
		0xCACA8B3983B941A5ULL,
		0x3169EEF9A1481DCFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB650C605D5591DBULL,
		0xB70C0531795CC04BULL,
		0xF92F0E998D293C47ULL,
		0x7E3CCAAB5E352A3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4DD70DC0ED7CB0D6ULL,
		0xDBDEF498FCDFC546ULL,
		0xD19B7C9FF690055DULL,
		0x332D244E4312F38FULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 77 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -77;
	} else {
		printf("Test Case 77 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x62B474989A52D633ULL,
		0x83CD400A000EF20AULL,
		0x16B3B157BEE2FC31ULL,
		0x6320CBC1898DAA4BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8707DE671BB80797ULL,
		0x6AE2D79BBBFD30DBULL,
		0x54E1EA85E6803754ULL,
		0x612A30C51F5EC72DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDBAC96317E9ACE9CULL,
		0x18EA686E4411C12EULL,
		0xC1D1C6D1D862C4DDULL,
		0x01F69AFC6A2EE31DULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 78 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -78;
	} else {
		printf("Test Case 78 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x75321328AFDCAAB2ULL,
		0x5C9131E700C2ED95ULL,
		0x244DD75AFD1CED8DULL,
		0x7E12F09C8050135CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABD848B36C32105DULL,
		0xB47ED092FD9EA398ULL,
		0xCF770243B8B5D828ULL,
		0x162660D392EC8E7CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC959CA7543AA9A55ULL,
		0xA8126154032449FCULL,
		0x54D6D51744671564ULL,
		0x67EC8FC8ED6384DFULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 79 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -79;
	} else {
		printf("Test Case 79 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5E61E829E6F5DAB4ULL,
		0xA0091E70C52919AFULL,
		0x13F8BA05031D51BDULL,
		0x61189914205EBA60ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x93680A6F49231E40ULL,
		0x5FFB8E00D2B6CBEAULL,
		0x9BC59219975541DCULL,
		0x03DDFF24587F270BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCAF9DDBA9DD2BC74ULL,
		0x400D906FF2724DC4ULL,
		0x783327EB6BC80FE1ULL,
		0x5D3A99EFC7DF9354ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 80 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -80;
	} else {
		printf("Test Case 80 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6D9BA98CCED5F90FULL,
		0x714A572CC85EC7DEULL,
		0x3A3228A65D4EC2ABULL,
		0x02CF6611D3CD9899ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5173484E3CE23229ULL,
		0x820F954993D26D1FULL,
		0x6707BEAD4775F07DULL,
		0x79DF72FA3988110DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1C28613E91F3C6D3ULL,
		0xEF3AC1E3348C5ABFULL,
		0xD32A69F915D8D22DULL,
		0x08EFF3179A45878BULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 81 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -81;
	} else {
		printf("Test Case 81 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1B27EB95A2E2CA0EULL,
		0xC005185664EC1646ULL,
		0xB86DC334C498091CULL,
		0x23FEB93D27D940EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2AEE87B053524337ULL,
		0x354E1704C3F11923ULL,
		0xEE4252F631CFCA19ULL,
		0x6C9ADF9E9DB0B58DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF03963E54F9086C4ULL,
		0x8AB70151A0FAFD22ULL,
		0xCA2B703E92C83F03ULL,
		0x3763D99E8A288B60ULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 82 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -82;
	} else {
		printf("Test Case 82 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C46DD115095B802ULL,
		0xF11D0595C3489B63ULL,
		0x1FA4C792EC0F75FFULL,
		0x0BEC1666B9C7874FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB960E02D9252B4C6ULL,
		0x4685AA6EE9DD8183ULL,
		0x59EDC1C59A271B8EULL,
		0x61558468E10B6D58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2E5FCE3BE430329ULL,
		0xAA975B26D96B19DFULL,
		0xC5B705CD51E85A71ULL,
		0x2A9691FDD8BC19F6ULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 83 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -83;
	} else {
		printf("Test Case 83 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA54459A60974AA99ULL,
		0x85B3A10360ECC381ULL,
		0x2DDFE98193F52096ULL,
		0x3E22A248721F7073ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD43FF23888E4D5CULL,
		0x542084B8AC604ADAULL,
		0x298094E1F36911F4ULL,
		0x3F56CC395D98034AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE8005A8280E65D2AULL,
		0x31931C4AB48C78A6ULL,
		0x045F549FA08C0EA2ULL,
		0x7ECBD60F14876D29ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 84 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -84;
	} else {
		printf("Test Case 84 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x97FA0A3C555F4EE6ULL,
		0x313247E797012D22ULL,
		0x8ED00F965A69DFDCULL,
		0x32E4C99561FF559FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB418BD8C112B7F21ULL,
		0xFB763A641C85D6BDULL,
		0x0728F890F72DFF42ULL,
		0x250F60BECF879362ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE3E14CB04433CFC5ULL,
		0x35BC0D837A7B5664ULL,
		0x87A71705633BE099ULL,
		0x0DD568D69277C23DULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 85 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -85;
	} else {
		printf("Test Case 85 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x218F7D5BBDD0F181ULL,
		0x9770D5240E3430B7ULL,
		0xF18C54976F047B40ULL,
		0x41A9E463A7B0A529ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x22C5B747FD155A34ULL,
		0x2C3920A20D77ED17ULL,
		0x7FB93DC012AB318BULL,
		0x4B4106A6C5859B41ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFEC9C613C0BB973AULL,
		0x6B37B48200BC439FULL,
		0x71D316D75C5949B5ULL,
		0x7668DDBCE22B09E8ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 86 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -86;
	} else {
		printf("Test Case 86 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x974D761497880BEAULL,
		0x467AF62E2C36537DULL,
		0x034DF19DB9E53CA8ULL,
		0x62F722E59CA55612ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD88D5A460F343FE4ULL,
		0xA42F0B062B0DE3FEULL,
		0x8B6298F0D39B2E11ULL,
		0x73DF8D664FE42978ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBEC01BCE8853CBF3ULL,
		0xA24BEB2801286F7EULL,
		0x77EB58ACE64A0E96ULL,
		0x6F17957F4CC12C99ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 87 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -87;
	} else {
		printf("Test Case 87 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9C9F3D4862C15B05ULL,
		0x166285BE0B941F50ULL,
		0xBD070672CA0F2BB9ULL,
		0x676B3602E415390CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDADEC6EA677800B3ULL,
		0x13F137E9BE45682EULL,
		0xAAAAB8D499141A53ULL,
		0x4E2809E6F9DF0E27ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC1C0765DFB495A52ULL,
		0x02714DD44D4EB721ULL,
		0x125C4D9E30FB1166ULL,
		0x19432C1BEA362AE5ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 88 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -88;
	} else {
		printf("Test Case 88 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1980914E170E3E6BULL,
		0x5D2B83A6346E5392ULL,
		0xE79A0190DFAA386EULL,
		0x6D60BD65A8DC487DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4A8117F7D6F1943ULL,
		0x6B9296717D15FA2BULL,
		0xCCE80F2B7C4F8866ULL,
		0x03A9BEA341F54DA3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74D87FCE999F2528ULL,
		0xF198ED34B7585966ULL,
		0x1AB1F265635AB007ULL,
		0x69B6FEC266E6FADAULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 89 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -89;
	} else {
		printf("Test Case 89 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x65C3E78644E6B822ULL,
		0x2B3417869F952870ULL,
		0x990FA4A5D94AE425ULL,
		0x640D4959C7E063CAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x240FB51613E196BEULL,
		0x5D6E8CAE552A118FULL,
		0x5E05C4DD03C5CD5EULL,
		0x2E178EC46987B118ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x41B4327031052164ULL,
		0xCDC58AD84A6B16E1ULL,
		0x3B09DFC8D58516C6ULL,
		0x35F5BA955E58B2B2ULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 90 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -90;
	} else {
		printf("Test Case 90 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9B6D7689C1C48689ULL,
		0xA6236EB4B6A5F01BULL,
		0xDF3CD9CC01817B5DULL,
		0x26863F3B61499B59ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89F42B8C43607FF6ULL,
		0x23178B871B4EBDEFULL,
		0xACB54117C11FE056ULL,
		0x0D3BC67EA0D867C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11794AFD7E640693ULL,
		0x830BE32D9B57322CULL,
		0x328798B440619B07ULL,
		0x194A78BCC0713391ULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 91 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -91;
	} else {
		printf("Test Case 91 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECBBA3801F1CF48DULL,
		0x4D1ADB6300C064D0ULL,
		0xF05D5319279F5085ULL,
		0x74EFEC182114531EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x06B0A3DBEF0B2F4CULL,
		0x3488BA93AAF7DE69ULL,
		0x5CADE28E605FC462ULL,
		0x2E75B904BA7F8D14ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE60AFFA43011C541ULL,
		0x189220CF55C88667ULL,
		0x93AF708AC73F8C23ULL,
		0x467A33136694C60AULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 92 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -92;
	} else {
		printf("Test Case 92 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x272E2DBB4DE5C9AAULL,
		0xC91E1536BEE734F7ULL,
		0x451B7E4586D82892ULL,
		0x521C04579848D235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EB3D2EA39D45B18ULL,
		0x5D4A98364C45BB55ULL,
		0x6DB72654666BA859ULL,
		0x271500020226BFE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE87A5AD114116E92ULL,
		0x6BD37D0072A179A1ULL,
		0xD76457F1206C8039ULL,
		0x2B0704559622124DULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 93 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -93;
	} else {
		printf("Test Case 93 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6315CA9F0802B8A7ULL,
		0x941C782A5CA71F35ULL,
		0x2C3F59BE7A71445BULL,
		0x6028871211D730FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8607FD2B97303A43ULL,
		0x47C39DD314E910E5ULL,
		0xB7C2C57E37DD31DEULL,
		0x320429B77093FB36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0DCD7370D27E64ULL,
		0x4C58DA5747BE0E4FULL,
		0x747C94404294127DULL,
		0x2E245D5AA14335C4ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 94 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -94;
	} else {
		printf("Test Case 94 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0C45E85F22C18525ULL,
		0xF81E8BBA36685732ULL,
		0xB427BC03877D90E6ULL,
		0x5636FCEB86522C89ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03FDDF97C3AF73A5ULL,
		0xF62350E49B5C8ADCULL,
		0x94C7D4D0ED9F2895ULL,
		0x6D11FBAED062D45AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x084808C75F12116DULL,
		0x01FB3AD59B0BCC56ULL,
		0x1F5FE73299DE6851ULL,
		0x6925013CB5EF582FULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 95 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -95;
	} else {
		printf("Test Case 95 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2562347D82CFD404ULL,
		0xF8CAFDC05E66DEDEULL,
		0x8DE1980F777C4C38ULL,
		0x297DD642698EDE87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1B8C36B72977FFFULL,
		0x104624DEEED25150ULL,
		0xE5BD479C48BCAC0AULL,
		0x2A68B4FA2815FD65ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73A97112103853F2ULL,
		0xE884D8E16F948D8DULL,
		0xA82450732EBFA02EULL,
		0x7F1521484178E121ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 96 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -96;
	} else {
		printf("Test Case 96 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF49E3A740197B044ULL,
		0xDC0A7C959F2745CBULL,
		0x7750C937AB410B5DULL,
		0x64CA54D4D2EC87C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C8E7D8382252943ULL,
		0x022327D348962F2AULL,
		0xEEA0055F3340C497ULL,
		0x494EC65FC4BEC5B6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB80FBCF07F728701ULL,
		0xD9E754C2569116A1ULL,
		0x88B0C3D8780046C6ULL,
		0x1B7B8E750E2DC20EULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 97 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -97;
	} else {
		printf("Test Case 97 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE64D8B2F94121A8AULL,
		0x4CBDCC17C06CE80FULL,
		0xD417F5E67061042CULL,
		0x4A55BB67111C4907ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA997C401BEB92338ULL,
		0xA20C6594210F9BA5ULL,
		0xE7DF6334B358B20CULL,
		0x48D82F32668E7C98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3CB5C72DD558F752ULL,
		0xAAB166839F5D4C6AULL,
		0xEC3892B1BD08521FULL,
		0x017D8C34AA8DCC6EULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 98 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -98;
	} else {
		printf("Test Case 98 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x228D2A06C3695442ULL,
		0xB47316A2A8C59DAFULL,
		0x4B04258526392821ULL,
		0x0577E3FBBE9826A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x266934E1C031571DULL,
		0x1FBD7D641DAB439BULL,
		0x152E416CF73B7DF3ULL,
		0x2AEB171D10B9568AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC23F5250337FD12ULL,
		0x94B5993E8B1A5A13ULL,
		0x35D5E4182EFDAA2EULL,
		0x5A8CCCDEADDED017ULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 99 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -99;
	} else {
		printf("Test Case 99 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x69B5C1429D4334E5ULL,
		0xCBEF9C89D4193F53ULL,
		0xBF88F9F0CD426AC2ULL,
		0x61864600D85103C5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C691D2C675FBDA6ULL,
		0x90A49B1D76CB1ECEULL,
		0xE45E3CC308A3A842ULL,
		0x40A37DEA84C50230ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D4CA41635E3773FULL,
		0x3B4B016C5D4E2085ULL,
		0xDB2ABD2DC49EC280ULL,
		0x20E2C816538C0194ULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 100 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -100;
	} else {
		printf("Test Case 100 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x582DE1A0DDFFD51EULL,
		0x674AD8C0D19B2FB3ULL,
		0x9F5BA3AE6836A321ULL,
		0x06C8A0492C9B6CD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE877FAE87B927315ULL,
		0x2AF8C3729B7C39DFULL,
		0x63C8D26E23BD799BULL,
		0x6DB9F3EF7BB28DE0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6FB5E6B8626D61F6ULL,
		0x3C52154E361EF5D3ULL,
		0x3B92D14044792986ULL,
		0x190EAC59B0E8DEF5ULL
	}};
	printf("Test Case 101\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 101 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -101;
	} else {
		printf("Test Case 101 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x13069046253A5089ULL,
		0x13856CA488425F7BULL,
		0xA6B16993ED91BEA8ULL,
		0x502EECBB0A62D495ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26D841EC564AAC5AULL,
		0x69FB8F4746930C27ULL,
		0x301BAA6BF8F2523DULL,
		0x6BB5C293D568A320ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC2E4E59CEEFA41CULL,
		0xA989DD5D41AF5353ULL,
		0x7695BF27F49F6C6AULL,
		0x64792A2734FA3175ULL
	}};
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 102 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -102;
	} else {
		printf("Test Case 102 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA155EFEB5A59B12BULL,
		0x1AB9E89D9764B670ULL,
		0x16F29E48EF1E9987ULL,
		0x4EDDB89AB5B97DBAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C395FAACEA94103ULL,
		0x3133D9C7E44F576FULL,
		0xFA465E9263099217ULL,
		0x3E8343D88CCA74C8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x051C90408BB07028ULL,
		0xE9860ED5B3155F01ULL,
		0x1CAC3FB68C15076FULL,
		0x105A74C228EF08F1ULL
	}};
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 103 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -103;
	} else {
		printf("Test Case 103 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x650FD1FBDA818EA7ULL,
		0x9B99894793A6F8DBULL,
		0x384204AB85574684ULL,
		0x3BFE6F488E87343EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE960204CEEA92FF7ULL,
		0xC6413614CA4D8E59ULL,
		0x9082215FEA1B94E1ULL,
		0x783C4583AC628F36ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7BAFB1AEEBD85E9DULL,
		0xD5585332C9596A81ULL,
		0xA7BFE34B9B3BB1A2ULL,
		0x43C229C4E224A507ULL
	}};
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 104 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -104;
	} else {
		printf("Test Case 104 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x91CEF29590619F68ULL,
		0x6FCA49FCB214C752ULL,
		0xD721309263DD0629ULL,
		0x23E7CB9A71389993ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5D801DA0ED35B47CULL,
		0x119B6F7BAB61A1CDULL,
		0xD33FF796CBAC0E6FULL,
		0x0A78EBEA7F9BEE89ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x344ED4F4A32BEAECULL,
		0x5E2EDA8106B32585ULL,
		0x03E138FB9830F7BAULL,
		0x196EDFAFF19CAB0AULL
	}};
	printf("Test Case 105\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 105 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -105;
	} else {
		printf("Test Case 105 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE9F282DBC0BA592FULL,
		0x70627A06C79F285AULL,
		0xDECB8574EA561EA9ULL,
		0x1FA283F927027E5BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB94D4A8228F22940ULL,
		0x7E50C69C79104E11ULL,
		0x973BF735ACA7CD7EULL,
		0x786C184EFC99703DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30A5385997C82FDCULL,
		0xF211B36A4E8EDA49ULL,
		0x478F8E3F3DAE512AULL,
		0x27366BAA2A690E1EULL
	}};
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 106 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -106;
	} else {
		printf("Test Case 106 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6BFD924CFE6310F2ULL,
		0xA37A9B75CDD031FEULL,
		0x674A9FDC97B52C8CULL,
		0x767FC18C545D56B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6909C53A3ED375AULL,
		0x8A2BEA6E9D7AC1ADULL,
		0x62F48B49988B334EULL,
		0x6EC797337C488094ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC56CF5F95A75D998ULL,
		0x194EB10730557050ULL,
		0x04561492FF29F93EULL,
		0x07B82A58D814D621ULL
	}};
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 107 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -107;
	} else {
		printf("Test Case 107 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FA694DB6A2DDF03ULL,
		0xE49D73C4720BB9A5ULL,
		0x682A045A9F075362ULL,
		0x0BF02C22A34ED2FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E6A7C44D1281CFCULL,
		0x9DC3DA8F5849E5BEULL,
		0x54C77A889D91A5BCULL,
		0x2A73647E8257DA85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x713C18969905C1F4ULL,
		0x46D9993519C1D3E7ULL,
		0x136289D20175ADA6ULL,
		0x617CC7A420F6F879ULL
	}};
	printf("Test Case 108\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 108 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -108;
	} else {
		printf("Test Case 108 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB6B2C66ED0C4942EULL,
		0xA33C995BE27882DDULL,
		0x0EBB454005EA58B6ULL,
		0x39D55A128D01DFC8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD25DDF00DF5B7445ULL,
		0xF625B06F696DA524ULL,
		0x79A8FAF3B9BDE9F5ULL,
		0x4AE6FFB4E0FF1D45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE454E76DF1691FD6ULL,
		0xAD16E8EC790ADDB8ULL,
		0x95124A4C4C2C6EC0ULL,
		0x6EEE5A5DAC02C282ULL
	}};
	printf("Test Case 109\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 109 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -109;
	} else {
		printf("Test Case 109 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE16D86ACB43A09B5ULL,
		0x1FBA571CC9CB1C4FULL,
		0xAB801D931F9BDD72ULL,
		0x724E7F68DB946D79ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA535CE3951165F0ULL,
		0xFF3E5A71427F6EE4ULL,
		0xB7A765F00E860656ULL,
		0x08A80D867DEA8F98ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x271A29C91F28A3C5ULL,
		0x207BFCAB874BAD6BULL,
		0xF3D8B7A31115D71BULL,
		0x69A671E25DA9DDE0ULL
	}};
	printf("Test Case 110\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 110 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -110;
	} else {
		printf("Test Case 110 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x116A24D99D1EA5A2ULL,
		0x56E1B925CD4D9DD1ULL,
		0x679C51907C186F49ULL,
		0x53DCC3B71383D079ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE96929515F50FFB9ULL,
		0x3B51F9197826C1D0ULL,
		0x1FAB05E47805C66BULL,
		0x275718536BE39518ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2800FB883DCDA5E9ULL,
		0x1B8FC00C5526DC00ULL,
		0x47F14BAC0412A8DEULL,
		0x2C85AB63A7A03B61ULL
	}};
	printf("Test Case 111\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 111 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -111;
	} else {
		printf("Test Case 111 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7899E3A78BE04056ULL,
		0x63497B0B8B9B9CB3ULL,
		0xD89D973394CD27B2ULL,
		0x342788DAE75903B4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x261F29AD45E8624EULL,
		0x2305629B703C978AULL,
		0xEC88E9F1EDBA390EULL,
		0x31754EE1D6EA4D4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x527AB9FA45F7DE08ULL,
		0x404418701B5F0529ULL,
		0xEC14AD41A712EEA4ULL,
		0x02B239F9106EB669ULL
	}};
	printf("Test Case 112\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 112 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -112;
	} else {
		printf("Test Case 112 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD7CA7478B219D077ULL,
		0x623C7968B550B65EULL,
		0x90A41299645572BDULL,
		0x2D8CCD93B8E88CADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE1DAA73B3DF3E94ULL,
		0x11A0B9DA2F1D8790ULL,
		0x58D3B182DDA9D741ULL,
		0x20E73FF694CDB1EEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19ACCA04FE3A91E3ULL,
		0x509BBF8E86332ECEULL,
		0x37D0611686AB9B7CULL,
		0x0CA58D9D241ADABFULL
	}};
	printf("Test Case 113\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 113 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -113;
	} else {
		printf("Test Case 113 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x43298C7550369992ULL,
		0x2D9D7A17F15AD0E8ULL,
		0x8B04380E5F897B52ULL,
		0x7D0F40C08DA51288ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x889C2AAFD81D72A5ULL,
		0x15D8AC145FA62143ULL,
		0x5F4CB304246AEF17ULL,
		0x4CA87528DE0273E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA8D61C5781926EDULL,
		0x17C4CE0391B4AFA4ULL,
		0x2BB7850A3B1E8C3BULL,
		0x3066CB97AFA29EA7ULL
	}};
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 114 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -114;
	} else {
		printf("Test Case 114 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2DDB733B80A7EFCEULL,
		0x78BBDC2E5EC5F968ULL,
		0xDCE3E6B8B4CD756CULL,
		0x0421D0D6EAEF04B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6D6D6F2011D8D323ULL,
		0xCE0ECF403927761AULL,
		0xB969B3BE7683C571ULL,
		0x405D482164DCDAE1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC06E041B6ECF1C98ULL,
		0xAAAD0CEE259E834DULL,
		0x237A32FA3E49AFFAULL,
		0x43C488B5861229D5ULL
	}};
	printf("Test Case 115\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 115 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -115;
	} else {
		printf("Test Case 115 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4793EBA67117C56EULL,
		0x2D3147588D72F965ULL,
		0x4954E5F95AA19E2AULL,
		0x7FA98961E5FE6DE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x31F3B07F23B80A97ULL,
		0x34C55A2219DEF63EULL,
		0x13FFEB25732C2D31ULL,
		0x139DEC3CADD48DDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x15A03B274D5FBAD7ULL,
		0xF86BED3673940327ULL,
		0x3554FAD3E77570F8ULL,
		0x6C0B9D253829E004ULL
	}};
	printf("Test Case 116\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 116 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -116;
	} else {
		printf("Test Case 116 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF75827A1DD4E8A77ULL,
		0xC82F6948C6F0B0B7ULL,
		0x2C1F81F339C80F71ULL,
		0x3749262722963A1BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A4CC8553DB202CBULL,
		0x20DE4117E2D96883ULL,
		0xB12C1ECA8856E82FULL,
		0x72585BBEE1D22D31ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D0B5F4C9F9C8799ULL,
		0xA7512830E4174834ULL,
		0x7AF36328B1712742ULL,
		0x44F0CA6840C40CE9ULL
	}};
	printf("Test Case 117\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 117 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -117;
	} else {
		printf("Test Case 117 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x333064A4B1CB870AULL,
		0x16D0311F40A3FFF1ULL,
		0x5E11575B0494C3B0ULL,
		0x5CD0010DECB9624AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD318A5AF2FA70130ULL,
		0x13451F949C527925ULL,
		0x8170D835222EEFD0ULL,
		0x09C3CDD03F8E6E4AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6017BEF5822485DAULL,
		0x038B118AA45186CBULL,
		0xDCA07F25E265D3E0ULL,
		0x530C333DAD2AF3FFULL
	}};
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 118 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -118;
	} else {
		printf("Test Case 118 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA54AD507C0AC86DFULL,
		0x29B3451C287CF62AULL,
		0xB3CEA3DF9C7CB244ULL,
		0x7D5172C73B2258EFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A88911C15B21A3FULL,
		0xAA9F37C79E5AA0C3ULL,
		0x42449347547AFDAAULL,
		0x071701D5222BC8BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3AC243EBAAFA6CA0ULL,
		0x7F140D548A225567ULL,
		0x718A10984801B499ULL,
		0x763A70F218F69031ULL
	}};
	printf("Test Case 119\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 119 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -119;
	} else {
		printf("Test Case 119 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x95BB2BEC88B5D5C8ULL,
		0xD2994B5B9C0A9649ULL,
		0xBF1BF8CE7B23BDFAULL,
		0x732E9776ECEDC6F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50191FA8F7A425A6ULL,
		0xB04897BE50EAEF07ULL,
		0x0B8724C3E86FD47CULL,
		0x211BB2CADD0C594DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x45A20C439111B022ULL,
		0x2250B39D4B1FA742ULL,
		0xB394D40A92B3E97EULL,
		0x5212E4AC0FE16DA7ULL
	}};
	printf("Test Case 120\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 120 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -120;
	} else {
		printf("Test Case 120 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0F6FE3771780A20FULL,
		0x6EF6F12E9E398030ULL,
		0x7A22FC8EA437EBA0ULL,
		0x78739105935DBF1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53C2967D7F586AD4ULL,
		0x096D330608981397ULL,
		0xCFA2842B3262D45CULL,
		0x7A067FC1057552ACULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBAD4CF998283728ULL,
		0x6589BE2895A16C98ULL,
		0xAA80786371D51744ULL,
		0x7E6D11448DE86C70ULL
	}};
	printf("Test Case 121\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 121 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -121;
	} else {
		printf("Test Case 121 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB2E2AAA6E265D66DULL,
		0xD38D6B1564377DE6ULL,
		0x530728F952871627ULL,
		0x3455F056D5D1B5D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8920ADD6872AB0BCULL,
		0xF2E8EB5AE56E4EEBULL,
		0x1B181B6756D9EC37ULL,
		0x23AF1A1800C1CBD8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29C1FCD05B3B25B1ULL,
		0xE0A47FBA7EC92EFBULL,
		0x37EF0D91FBAD29EFULL,
		0x10A6D63ED50FE9F8ULL
	}};
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 122 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -122;
	} else {
		printf("Test Case 122 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x39F020782B8795BDULL,
		0xC76E2B0459CC742FULL,
		0xDDD8064FB7900ADDULL,
		0x726A2F294DB78419ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF51973DDEFEA5A8ULL,
		0x1AA49A5A1F4E8225ULL,
		0x40A0AC41AB085B1CULL,
		0x67A43FEB570F80D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A9E893A4C88F015ULL,
		0xACC990AA3A7DF209ULL,
		0x9D375A0E0C87AFC1ULL,
		0x0AC5EF3DF6A80346ULL
	}};
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 123 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -123;
	} else {
		printf("Test Case 123 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3005958A2F385D92ULL,
		0xB675BC12CA1A47D7ULL,
		0x3B012B44FD479F37ULL,
		0x25CC36921E6EA9B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8F4C20C85A439C82ULL,
		0x289FAB97B1CEB4DDULL,
		0x787CB0E5F126B35AULL,
		0x14104B7E7491446DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0B974C1D4F4C110ULL,
		0x8DD6107B184B92F9ULL,
		0xC2847A5F0C20EBDDULL,
		0x11BBEB13A9DD6548ULL
	}};
	printf("Test Case 124\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 124 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -124;
	} else {
		printf("Test Case 124 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x94BCE0D09BFC987AULL,
		0x27ACBB23D0147FD5ULL,
		0xF90112A9EF831219ULL,
		0x7183879D1982B5F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10CA370E6A3E25DDULL,
		0x0202CF6B3DF304EAULL,
		0xEA59ED169BFCAD63ULL,
		0x03543AF2362BA8B5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83F2A9C231BE729DULL,
		0x25A9EBB892217AEBULL,
		0x0EA72593538664B6ULL,
		0x6E2F4CAAE3570D3BULL
	}};
	printf("Test Case 125\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 125 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -125;
	} else {
		printf("Test Case 125 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DF97DEFD3EB1BB1ULL,
		0x20A122E77EEE31E5ULL,
		0x411AAF07E3D9B919ULL,
		0x5E4D034607B4EB18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCDF090C0E0D01652ULL,
		0x0B5D3411D23ED453ULL,
		0xDDE4A1FC3F047AFFULL,
		0x16783E2D83F11367ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9008ED2EF31B055FULL,
		0x1543EED5ACAF5D91ULL,
		0x63360D0BA4D53E1AULL,
		0x47D4C51883C3D7B0ULL
	}};
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 126 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -126;
	} else {
		printf("Test Case 126 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDF98D9C5ED145D61ULL,
		0x0847EBA75232CAEAULL,
		0x39DDE070619FA1B4ULL,
		0x6BAE207C4FA044AAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE920A3893B6E7505ULL,
		0x4D85CFD5DC692D20ULL,
		0x3EE9DA8C62A5C9E2ULL,
		0x535778BACA205E45ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF678363CB1A5E85CULL,
		0xBAC21BD175C99DC9ULL,
		0xFAF405E3FEF9D7D1ULL,
		0x1856A7C1857FE664ULL
	}};
	printf("Test Case 127\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 127 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -127;
	} else {
		printf("Test Case 127 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB408D093172A9FDULL,
		0x4858F94BAF741A2DULL,
		0x19FB1E2C4FB45BA0ULL,
		0x3DEED83E0E181CA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC15EAA811A4F3536ULL,
		0x5F87E58EE5D6F0B5ULL,
		0xB8AC16A7CF69D453ULL,
		0x3AF6F1AB1836500BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x19E1E288172374C7ULL,
		0xE8D113BCC99D2978ULL,
		0x614F0784804A874CULL,
		0x02F7E692F5E1CC9CULL
	}};
	printf("Test Case 128\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 128 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -128;
	} else {
		printf("Test Case 128 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9D7874FC40FDA35AULL,
		0xE0E7A325B26014FFULL,
		0x01FE1E76C6126473ULL,
		0x19CB53C75CE97997ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1ADB2B9900532AF1ULL,
		0xE36140A94219D1E2ULL,
		0xAC52FABB7A5AD643ULL,
		0x54758AB0CE22A8E2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x829D496340AA7856ULL,
		0xFD86627C7046431DULL,
		0x55AB23BB4BB78E2FULL,
		0x4555C9168EC6D0B4ULL
	}};
	printf("Test Case 129\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 129 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -129;
	} else {
		printf("Test Case 129 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5DC056FFC11CC456ULL,
		0xCBD03B01A2D1BE1CULL,
		0x8EA658D5766FB018ULL,
		0x5142C2C51C11A194ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x55F6517E2580A687ULL,
		0x2E0410EA07C2065AULL,
		0x89425D2F8068F0CDULL,
		0x08D23AEB04ECF8B0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x07CA05819B9C1DCFULL,
		0x9DCC2A179B0FB7C2ULL,
		0x0563FBA5F606BF4BULL,
		0x487087DA1724A8E4ULL
	}};
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 130 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -130;
	} else {
		printf("Test Case 130 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3B9CA23C737116E4ULL,
		0x0EC49FFEA4BBACA7ULL,
		0xEF3CE3A9E025D479ULL,
		0x53A9A3541DB0CC7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6660E44CD5AD0640ULL,
		0x7FAD147F1509192FULL,
		0x6BB90E977F0B7A96ULL,
		0x36F21E2F0D7F523AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD53BBDEF9DC410A4ULL,
		0x8F178B7F8FB29377ULL,
		0x8383D512611A59E2ULL,
		0x1CB7852510317A44ULL
	}};
	printf("Test Case 131\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 131 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -131;
	} else {
		printf("Test Case 131 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x016AC938613F24F6ULL,
		0x87A4C703CBD4CF6CULL,
		0x42EEACB16A77A5B4ULL,
		0x347F9C7C5A7DCB15ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EB88BE8C0241ABCULL,
		0x82CD7702CFD63B7EULL,
		0x063D8CC08E554020ULL,
		0x7FB080FDC63B2AA1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA2B23D4FA11B0A27ULL,
		0x04D75000FBFE93EDULL,
		0x3CB11FF0DC226594ULL,
		0x34CF1B7E9442A074ULL
	}};
	printf("Test Case 132\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 132 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -132;
	} else {
		printf("Test Case 132 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xECCD0EDD288E0FE7ULL,
		0xA2EF22FF70C69447ULL,
		0xAE666C6B36E154F5ULL,
		0x29D3EDD14D1E92F2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0AC646A710755CBULL,
		0xEBD946ABF3DD4AFCULL,
		0xD8E7066517350EFDULL,
		0x58D7A59952D046CFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C20AA72B786BA09ULL,
		0xB715DC537CE9494BULL,
		0xD57F66061FAC45F7ULL,
		0x50FC4837FA4E4C22ULL
	}};
	printf("Test Case 133\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 133 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -133;
	} else {
		printf("Test Case 133 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x11AA1443E51D1EC9ULL,
		0x37374EF44795266BULL,
		0x132303042D488DD5ULL,
		0x642D6A1EF9E6A9FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40A64E6AD5DF55CBULL,
		0xC60009FFC033814EULL,
		0x42BC5E7A11757A0AULL,
		0x76678F963F1FA9D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD103C5D90F3DC8EBULL,
		0x713744F48761A51CULL,
		0xD066A48A1BD313CAULL,
		0x6DC5DA88BAC70026ULL
	}};
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 134 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -134;
	} else {
		printf("Test Case 134 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE04396345E329348ULL,
		0xA9D02A12A7B28E19ULL,
		0x99E80FFF047F9481ULL,
		0x6BA81D6A8BF8C66AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD0871B31DDDF3B3ULL,
		0x553D161F0E2E787CULL,
		0xE9AA886B5BF5E280ULL,
		0x370C182D0F7B75B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x133B248140549F95ULL,
		0x549313F39984159DULL,
		0xB03D8793A889B201ULL,
		0x349C053D7C7D50B6ULL
	}};
	printf("Test Case 135\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 135 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -135;
	} else {
		printf("Test Case 135 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x133EE6BF26A61C4AULL,
		0x607BF225CF6BE7D8ULL,
		0xC7BB84736F853A07ULL,
		0x1C2C1858EA94FF69ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A41E9733C7FF73EULL,
		0x2D761A942C07C466ULL,
		0x89A52BD5D3806C8CULL,
		0x7F068539A06151B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8FCFD4BEA2624F9ULL,
		0x3305D791A3642371ULL,
		0x3E16589D9C04CD7BULL,
		0x1D25931F4A33ADB2ULL
	}};
	printf("Test Case 136\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 136 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -136;
	} else {
		printf("Test Case 136 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA2C08A52202BE1F5ULL,
		0xC4B02F7D8E5067B2ULL,
		0x55C7D4C4D823E0BDULL,
		0x7DB39B9EB48D5ACCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD87EC451A5372322ULL,
		0x379B315517235530ULL,
		0x2C5205F6844C205BULL,
		0x661E322A47C3D281ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCA41C6007AF4BED3ULL,
		0x8D14FE28772D1281ULL,
		0x2975CECE53D7C062ULL,
		0x179569746CC9884BULL
	}};
	printf("Test Case 137\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 137 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -137;
	} else {
		printf("Test Case 137 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x6F38309108C7265DULL,
		0x05458EF7E9FD396BULL,
		0xB20D3C91B286FF88ULL,
		0x25067B24E30F619FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0F1796A6F43B0DULL,
		0x08CCD0DBDDFF4052ULL,
		0xC124FDFCAE8DF622ULL,
		0x197F600D16097321ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x512918FA61D2EB50ULL,
		0xFC78BE1C0BFDF919ULL,
		0xF0E83E9503F90965ULL,
		0x0B871B17CD05EE7DULL
	}};
	printf("Test Case 138\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 138 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -138;
	} else {
		printf("Test Case 138 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x978ACCC1FDCD15DEULL,
		0xB22C0F0E6301BD03ULL,
		0xA68F7992D90C9C35ULL,
		0x0F98C46703E5B541ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67FDA398C872946EULL,
		0x1612223DAD617776ULL,
		0x0689FBF4CB507602ULL,
		0x74A35FC407B10866ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2F8D2929355A815DULL,
		0x9C19ECD0B5A0458DULL,
		0xA0057D9E0DBC2633ULL,
		0x1AF564A2FC34ACDBULL
	}};
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 139 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -139;
	} else {
		printf("Test Case 139 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x9BD68E296C1F7FA5ULL,
		0x34CCE2886E92F0C3ULL,
		0x0A57C3F273677D3DULL,
		0x05391F503E16FC3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E00AAF5D623A2BAULL,
		0xC413FAD84FA5E793ULL,
		0x084EEA495284221AULL,
		0x6798D90D880C358CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5DD5E33395FBDCD8ULL,
		0x70B8E7B01EED0930ULL,
		0x0208D9A920E35B22ULL,
		0x1DA04642B60AC6B2ULL
	}};
	printf("Test Case 140\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 140 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -140;
	} else {
		printf("Test Case 140 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1985A6C6C3AEEE00ULL,
		0x1852069F4BB9AC3FULL,
		0x14A29108631AAE73ULL,
		0x69358A34E0DE91D9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x619C546DA2E7F626ULL,
		0xB40295D72EEF97F0ULL,
		0x9126BC87CA03947EULL,
		0x20D84B3A95BFCD2DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB7E9525920C6F7DAULL,
		0x644F70C81CCA144EULL,
		0x837BD480991719F4ULL,
		0x485D3EFA4B1EC4ABULL
	}};
	printf("Test Case 141\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 141 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -141;
	} else {
		printf("Test Case 141 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xDB058ED11A065DFBULL,
		0x0555E5D4456DA6EDULL,
		0xC512489785317F26ULL,
		0x1FB4828DE492ABE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBA09BF898CCAB46ULL,
		0xC85304D206A77CE9ULL,
		0xDA5FA82AF5B5B77AULL,
		0x6952201E2ACF87A9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1F64F2D88139B2A2ULL,
		0x3D02E1023EC62A04ULL,
		0xEAB2A06C8F7BC7ABULL,
		0x3662626FB9C3243CULL
	}};
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 142 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -142;
	} else {
		printf("Test Case 142 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3984EFB70DADF3BBULL,
		0xCB75B359F0AF89E4ULL,
		0xC1CEC61B41B74A52ULL,
		0x7807D051FC720C52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC6026481E0412E13ULL,
		0x74ADD912DADA81C1ULL,
		0x755652EF01D8876FULL,
		0x3ACEBFC936542922ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x73828B352D6CC5A8ULL,
		0x56C7DA4715D50822ULL,
		0x4C78732C3FDEC2E3ULL,
		0x3D391088C61DE330ULL
	}};
	printf("Test Case 143\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 143 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -143;
	} else {
		printf("Test Case 143 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4BE07CF03F7C8C96ULL,
		0xC512AAE6D8DE7454ULL,
		0xE740B8D6191C91E5ULL,
		0x1841D048B9C3AEF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8009F311FD5C714BULL,
		0xD86DA64DE1001E1BULL,
		0x75794ECABA5A2A30ULL,
		0x1BBF82F8040F23D2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCBD689DE42201B38ULL,
		0xECA50498F7DE5638ULL,
		0x71C76A0B5EC267B4ULL,
		0x7C824D50B5B48B22ULL
	}};
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 144 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -144;
	} else {
		printf("Test Case 144 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x281BE75AB07006F0ULL,
		0xE440F94A85A9DA73ULL,
		0x5EC6ED3594206130ULL,
		0x3B4E7B54393E2101ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03A203D99C318C1EULL,
		0xEA8C1A474EB3A896ULL,
		0x9B03F9E060291063ULL,
		0x4B7E64A11E863A5FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2479E381143E7ABFULL,
		0xF9B4DF0336F631DDULL,
		0xC3C2F35533F750CCULL,
		0x6FD016B31AB7E6A1ULL
	}};
	printf("Test Case 145\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 145 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -145;
	} else {
		printf("Test Case 145 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2EEF7B1BDC09EBE2ULL,
		0x80FFE0763218FB49ULL,
		0x949A11EE9BB17840ULL,
		0x59AB6ED38CEACA50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC8B4858E7EB82CBULL,
		0x23E0F1FBFCE9732BULL,
		0x2E36F80C40D7B889ULL,
		0x23DC3CCF8BEB46C3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x726432C2F41E6917ULL,
		0x5D1EEE7A352F881DULL,
		0x666319E25AD9BFB7ULL,
		0x35CF320400FF838DULL
	}};
	printf("Test Case 146\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 146 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -146;
	} else {
		printf("Test Case 146 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2D507E61A39F7A0BULL,
		0xAEFD9CEABF1BD82FULL,
		0x14550C7C2DC9F0FDULL,
		0x3980BEF59BFFDB1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3326EF6123C0AFULL,
		0x9E444E4D91ED60E1ULL,
		0xFE40B093B3798B03ULL,
		0x5BA0B004DF950100ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4F1D5772427BB949ULL,
		0x10B94E9D2D2E774DULL,
		0x16145BE87A5065FAULL,
		0x5DE00EF0BC6ADA1CULL
	}};
	printf("Test Case 147\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 147 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -147;
	} else {
		printf("Test Case 147 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x4809F8D1A2741DB3ULL,
		0x61DCB72908CB791DULL,
		0x8F17CA0FE18967F5ULL,
		0x7E4461E42A9CCA6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x46B8F11F4252A753ULL,
		0x93DA164E2564E53FULL,
		0x3817A433F1661416ULL,
		0x28469A597C47F5E1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x015107B260217660ULL,
		0xCE02A0DAE36693DEULL,
		0x570025DBF02353DEULL,
		0x55FDC78AAE54D48CULL
	}};
	printf("Test Case 148\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 148 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -148;
	} else {
		printf("Test Case 148 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7FFAD6F9764591FFULL,
		0x9670696F8BC9714DULL,
		0xEF57D4EE6D480746ULL,
		0x704DD19E549CBD35ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD19E86474604BCFFULL,
		0x277BA2214045BD87ULL,
		0xBE0B2484855DE3EAULL,
		0x317D5C0F655A74D0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE5C50B23040D500ULL,
		0x6EF4C74E4B83B3C5ULL,
		0x314CB069E7EA235CULL,
		0x3ED0758EEF424865ULL
	}};
	printf("Test Case 149\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 149 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -149;
	} else {
		printf("Test Case 149 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x1D1053A1956052A4ULL,
		0x737CD592D673F37CULL,
		0x03363AC37ABFE524ULL,
		0x0553680BD63A215CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x01862B48C6576D60ULL,
		0xA790F0390C0A63BEULL,
		0x4CFBB6E0D6554AF1ULL,
		0x0D1163FFD12CDCC1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1B8A2858CF08E531ULL,
		0xCBEBE559CA698FBEULL,
		0xB63A83E2A46A9A32ULL,
		0x7842040C050D449AULL
	}};
	printf("Test Case 150\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 150 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -150;
	} else {
		printf("Test Case 150 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA21BBB43A66C4C01ULL,
		0xD7FA88484501BB5DULL,
		0x2EBECA3827A33E80ULL,
		0x2C555C73A567A121ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00796254E084AB5ULL,
		0x5B6205AA45F0E16AULL,
		0xD76FB012E46EB6FCULL,
		0x5A0AF13BFB048E2CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE214251E58640139ULL,
		0x7C98829DFF10D9F2ULL,
		0x574F1A2543348784ULL,
		0x524A6B37AA6312F4ULL
	}};
	printf("Test Case 151\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 151 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -151;
	} else {
		printf("Test Case 151 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x2F09C5B6305F42C3ULL,
		0xFF581330B2794E00ULL,
		0x875BA30006C1C8FEULL,
		0x4C33A1D72A181F11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7CF6B58AA8895096ULL,
		0x6BDF05DB5288749EULL,
		0x6703648A9AB388E2ULL,
		0x0FCE28344CC9CEB4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB213102B87D5F22DULL,
		0x93790D555FF0D961ULL,
		0x20583E756C0E401CULL,
		0x3C6579A2DD4E505DULL
	}};
	printf("Test Case 152\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 152 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -152;
	} else {
		printf("Test Case 152 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0AF4FA88CE68E90CULL,
		0x9D2797BC7AAD9C41ULL,
		0x14F3604F77FC3D32ULL,
		0x303F217356C60C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E5950B2F1F3481CULL,
		0x11EEF04F701ED7B7ULL,
		0xE277AB8A73893467ULL,
		0x5F4F187FA2162CBDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC9BA9D5DC75A0DDULL,
		0x8B38A76D0A8EC489ULL,
		0x327BB4C5047308CBULL,
		0x50F008F3B4AFDFBEULL
	}};
	printf("Test Case 153\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 153 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -153;
	} else {
		printf("Test Case 153 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BCDF455EA7098F8ULL,
		0x03A928D99E46847DULL,
		0xBCE9AF52072721D5ULL,
		0x2F65AD476506BEDCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF64346C2BCA568C6ULL,
		0x5A63ACCB987BA3E8ULL,
		0xC48ED132B330EB02ULL,
		0x5FED85152C6A715DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x858AAD932DCB301FULL,
		0xA9457C0E05CAE094ULL,
		0xF85ADE1F53F636D2ULL,
		0x4F782832389C4D7EULL
	}};
	printf("Test Case 154\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 154 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -154;
	} else {
		printf("Test Case 154 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF684BE3BC2E2E01DULL,
		0x7FAC262CD888808AULL,
		0x516C50CD4126A238ULL,
		0x3B8E81E372CED7BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2891EBAEAD3E94FAULL,
		0xD5925AFA12137BB4ULL,
		0x4CD201A3233212E2ULL,
		0x62C4785DCA0DAFB0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDF2D28D15A44B10ULL,
		0xAA19CB32C67504D6ULL,
		0x049A4F2A1DF48F55ULL,
		0x58CA0985A8C1280DULL
	}};
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 155 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -155;
	} else {
		printf("Test Case 155 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x03BFC8E8494A6F41ULL,
		0x30BA37063805B06CULL,
		0x30445A31D795758FULL,
		0x129CE09731D6304EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95F332E4257D2A6FULL,
		0x5911F2D96B49D322ULL,
		0xC8D73497FA1E9297ULL,
		0x5BFE15542EF083A7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6DCC960423CD44BFULL,
		0xD7A8442CCCBBDD49ULL,
		0x676D2599DD76E2F7ULL,
		0x369ECB4302E5ACA6ULL
	}};
	printf("Test Case 156\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 156 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -156;
	} else {
		printf("Test Case 156 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD697CE5AEB4A5D25ULL,
		0x8CF2B7E655CDC8E5ULL,
		0xC37FA5EB5DF94307ULL,
		0x375D338D3209AA5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F42E68FB9E53DACULL,
		0xBF2DEBECB129CBB1ULL,
		0xE9A5F58A3C07CB3DULL,
		0x32CFC919F959A0F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC754E7CB31651F79ULL,
		0xCDC4CBF9A4A3FD34ULL,
		0xD9D9B06121F177C9ULL,
		0x048D6A7338B00963ULL
	}};
	printf("Test Case 157\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 157 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -157;
	} else {
		printf("Test Case 157 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xD4DA97925EC3C63CULL,
		0x8F3E9EFEE91EA5CCULL,
		0x6B118F3D27A46977ULL,
		0x06D03CFF0CC47A9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E5B95F8A05B8162ULL,
		0x7271DE939913D3E5ULL,
		0x22A8C3EB8A7EC5E7ULL,
		0x5B1990D2D4623146ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x467F0199BE6844C7ULL,
		0x1CCCC06B500AD1E7ULL,
		0x4868CB519D25A390ULL,
		0x2BB6AC2C38624954ULL
	}};
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 158 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -158;
	} else {
		printf("Test Case 158 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x116DDBA6285EFE55ULL,
		0xE10D8FB6285BB9F6ULL,
		0x8284749FC22E7653ULL,
		0x20A951F5D0CF29BEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8373CA05C2B92690ULL,
		0xD27A842333E698E1ULL,
		0x85F9798A8DA1BBC8ULL,
		0x24CC7654A692F506ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8DFA11A065A5D7B2ULL,
		0x0E930B92F4752114ULL,
		0xFC8AFB15348CBA8BULL,
		0x7BDCDBA12A3C34B7ULL
	}};
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 159 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -159;
	} else {
		printf("Test Case 159 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x105052FC403D1679ULL,
		0x8C8B17D4E6DB1E41ULL,
		0x687B85FDCB0732E2ULL,
		0x76DAEC5238EFA8F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC8282D28665801EULL,
		0xDFC604EBAB08BF95ULL,
		0x7BF8721E2992663FULL,
		0x1F75B0526F7B827DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53CDD029B9D7965BULL,
		0xACC512E93BD25EABULL,
		0xEC8313DFA174CCA2ULL,
		0x57653BFFC9742679ULL
	}};
	printf("Test Case 160\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 160 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -160;
	} else {
		printf("Test Case 160 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFF08F14EDA3556DDULL,
		0xE1B21CF9E275DEDEULL,
		0x17EA1B4131C23E10ULL,
		0x3E3B3139AC22C775ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94E48F03669A3280ULL,
		0xB75D4983BEF4ACD8ULL,
		0x551019635A0A9438ULL,
		0x09401AE8DE77DBF8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6A24624B739B245DULL,
		0x2A54D37623813206ULL,
		0xC2DA01DDD7B7A9D8ULL,
		0x34FB1650CDAAEB7CULL
	}};
	printf("Test Case 161\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 161 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -161;
	} else {
		printf("Test Case 161 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xCDF9F4FCFFBBA6EFULL,
		0x2A37952533F092BFULL,
		0xC5BDDCFA1FF199F3ULL,
		0x190B351EC29A0FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AEEED0AD8BD19E4ULL,
		0x8E240C6857CFCC76ULL,
		0xE94F58BDA6DAAF73ULL,
		0x62CE37E4ED481A6BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x830B07F226FE8CF8ULL,
		0x9C1388BCDC20C649ULL,
		0xDC6E843C7916EA7FULL,
		0x363CFD39D551F53CULL
	}};
	printf("Test Case 162\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 162 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -162;
	} else {
		printf("Test Case 162 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x51596507A9C8D91BULL,
		0xA198B8F2ABA2E6EEULL,
		0x27D2F15424D4E6B9ULL,
		0x48A6F6826AB401EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF13724C15CAD9D5DULL,
		0x5C61992F6509BD5EULL,
		0x400F61719061288CULL,
		0x00A89C9503B255E7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x602240464D1B3BBEULL,
		0x45371FC34699298FULL,
		0xE7C38FE29473BE2DULL,
		0x47FE59ED6701AC06ULL
	}};
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 163 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -163;
	} else {
		printf("Test Case 163 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x677625B39A0012B9ULL,
		0x2898601A4C24FF74ULL,
		0xDCB9194F0D250CD1ULL,
		0x2F3B9EA78BADAE51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x15A324B8884999DEULL,
		0x1429AC55901F8724ULL,
		0xC6753B3740A2B0C1ULL,
		0x0A2B935C08F62A7AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x51D300FB11B678DBULL,
		0x146EB3C4BC057850ULL,
		0x1643DE17CC825C10ULL,
		0x25100B4B82B783D7ULL
	}};
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 164 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -164;
	} else {
		printf("Test Case 164 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xBF94C5C03F311B1AULL,
		0x405E3E1CF3BD2DBAULL,
		0xFC53287AA72495ECULL,
		0x408029FB8566C68CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF66A25C5E153C530ULL,
		0xEFD715CA2C8AD6A7ULL,
		0x53F3ECAE13633DB7ULL,
		0x09F59788F9387C25ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC92A9FFA5DDD55EAULL,
		0x50872852C7325712ULL,
		0xA85F3BCC93C15834ULL,
		0x368A92728C2E4A67ULL
	}};
	printf("Test Case 165\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 165 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -165;
	} else {
		printf("Test Case 165 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x71790F49E1C1E268ULL,
		0x4CC900F51C718CB7ULL,
		0xAFF93241C313FD3AULL,
		0x560E41EBAEF7CA99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54628112765E56A8ULL,
		0xDD2C00C6ECF66ABCULL,
		0x0934901E3D68D7BFULL,
		0x52157512FB287B58ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1D168E376B638BC0ULL,
		0x6F9D002E2F7B21FBULL,
		0xA6C4A22385AB257AULL,
		0x03F8CCD8B3CF4F41ULL
	}};
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 166 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -166;
	} else {
		printf("Test Case 166 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB847976FEEA54F4FULL,
		0xF0B1F229F55AE336ULL,
		0x617D09EBD9C756EDULL,
		0x6BE53FEF2A71A08BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6238C0EAC414F9E7ULL,
		0x17C01748F58225A2ULL,
		0xEBDCDBC48B344CAFULL,
		0x64CEB144646AD725ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x560ED6852A905568ULL,
		0xD8F1DAE0FFD8BD94ULL,
		0x75A02E274E930A3EULL,
		0x07168EAAC606C965ULL
	}};
	printf("Test Case 167\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 167 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -167;
	} else {
		printf("Test Case 167 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x14E2F1BA9AABF4ECULL,
		0xA78CFCA19A938186ULL,
		0xAC0936F8D43725A6ULL,
		0x3D6B5FEA41660AB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C33012373C8B697ULL,
		0x5C1721B5A344FB7EULL,
		0x2D1F4ECD2F2484C5ULL,
		0x0E8F9F6F595A3A93ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98AFF09726E33E55ULL,
		0x4B75DAEBF74E8607ULL,
		0x7EE9E82BA512A0E1ULL,
		0x2EDBC07AE80BD026ULL
	}};
	printf("Test Case 168\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 168 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -168;
	} else {
		printf("Test Case 168 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7C1A8615E1806C52ULL,
		0x571753769722CE9CULL,
		0xF20BA82BB8DF185AULL,
		0x465E4425350F9FC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2D794EE3E5F49D3ULL,
		0x8DC0343A41DECA02ULL,
		0x6D37587870606AA4ULL,
		0x70065720DD144174ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA942F127A321226CULL,
		0xC9571F3C55440499ULL,
		0x84D44FB3487EADB5ULL,
		0x5657ED0457FB5E53ULL
	}};
	printf("Test Case 169\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 169 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -169;
	} else {
		printf("Test Case 169 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEBD02543BACDABC0ULL,
		0x17F947F3C042DA52ULL,
		0xBF3465E0D0CD5CCEULL,
		0x5C0A9F4B16A44D97ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3541861D0CEC8BB8ULL,
		0x6A65DE03997502A7ULL,
		0x0277189F13AC7046ULL,
		0x29B8E12B901B48DBULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB68E9F26ADE12008ULL,
		0xAD9369F026CDD7ABULL,
		0xBCBD4D41BD20EC87ULL,
		0x3251BE1F868904BCULL
	}};
	printf("Test Case 170\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 170 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -170;
	} else {
		printf("Test Case 170 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x3204BE16219832F5ULL,
		0x9D5C220AA4FBB429ULL,
		0xB726AB532E0AAEF8ULL,
		0x1B5B9FFC2D352FE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5400B75DDBD7292BULL,
		0x796D245D7D9833EDULL,
		0x70EF1F97E72F6BF3ULL,
		0x6D6679CEE5CBD69DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE0406B845C109B7ULL,
		0x23EEFDAD2763803BULL,
		0x46378BBB46DB4305ULL,
		0x2DF5262D47695949ULL
	}};
	printf("Test Case 171\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 171 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -171;
	} else {
		printf("Test Case 171 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x99D5E16EBDB203F8ULL,
		0x952FFC7DFD336EC4ULL,
		0xB814BC147A05E35CULL,
		0x4C065E6ADBD9E41CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x396AEC348345AB48ULL,
		0xB55898DE8FA46085ULL,
		0x3B37EE91483AFC07ULL,
		0x0BD42A357A8B7C7BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x606AF53A3A6C58B0ULL,
		0xDFD7639F6D8F0E3FULL,
		0x7CDCCD8331CAE754ULL,
		0x40323435614E67A1ULL
	}};
	printf("Test Case 172\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 172 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -172;
	} else {
		printf("Test Case 172 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF3461781537A2A95ULL,
		0xC62452164A91AC25ULL,
		0x09FE6ED5DFDACFA4ULL,
		0x3264F71F9A8188D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16369021FC1D74D8ULL,
		0x74DB5447C1FE685FULL,
		0xE5C57A61D48D3899ULL,
		0x3334DA713BB85694ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDD0F875F575CB5AAULL,
		0x5148FDCE889343C6ULL,
		0x2438F4740B4D970BULL,
		0x7F301CAE5EC93241ULL
	}};
	printf("Test Case 173\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 173 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -173;
	} else {
		printf("Test Case 173 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1C6E2692A738C8DULL,
		0xE0D7910C90F2B7A1ULL,
		0x3B2A7E77F78F3E89ULL,
		0x54E0FE793DF09D03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x25901ADA00CBA2FCULL,
		0x2DB26D957540391CULL,
		0xEF342CECBA702F67ULL,
		0x03291EA0C0AEA50FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C36C78F29A7E991ULL,
		0xB32523771BB27E85ULL,
		0x4BF6518B3D1F0F22ULL,
		0x51B7DFD87D41F7F3ULL
	}};
	printf("Test Case 174\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 174 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -174;
	} else {
		printf("Test Case 174 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x32A1AAC325DB08AEULL,
		0x2419557B1B39BDD5ULL,
		0xC5A11184E75868D4ULL,
		0x5BC8258B41FA4F82ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44C2633E4F90AA81ULL,
		0xA9D6E12CFCB7AC77ULL,
		0x56B763DF21094BA6ULL,
		0x1257DA59D74820FAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEDDF4784D64A5E2DULL,
		0x7A42744E1E82115DULL,
		0x6EE9ADA5C64F1D2DULL,
		0x49704B316AB22E88ULL
	}};
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 175 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -175;
	} else {
		printf("Test Case 175 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xA1993AD98620445EULL,
		0x11377B56A20E0B53ULL,
		0x4FCF6F872810B555ULL,
		0x7B3FC028B2A598B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C30613753E44495ULL,
		0x5E0CBD9061BF6CE3ULL,
		0x188A425FE9AA2F63ULL,
		0x766515A1F61F8BB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2568D9A2323BFFC9ULL,
		0xB32ABDC6404E9E70ULL,
		0x37452D273E6685F1ULL,
		0x04DAAA86BC860CF8ULL
	}};
	printf("Test Case 176\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 176 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -176;
	} else {
		printf("Test Case 176 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x96241573FA843C33ULL,
		0x7EB4384A3CA07B65ULL,
		0x9B2DC62ACF13CE1CULL,
		0x7492F7F0100D51ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEECAF22711DF84D4ULL,
		0x9166D5E6D6C8A06DULL,
		0x647D0E920F2DE594ULL,
		0x67A4896BEF95C732ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA759234CE8A4B75FULL,
		0xED4D626365D7DAF7ULL,
		0x36B0B798BFE5E887ULL,
		0x0CEE6E8420778A7AULL
	}};
	printf("Test Case 177\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 177 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -177;
	} else {
		printf("Test Case 177 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x0672D6B6362060BEULL,
		0x8A768B56269FC59AULL,
		0x67C24351DB2A5BB5ULL,
		0x476FA4B30D444AEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD94E1D7E03A31F46ULL,
		0x338CA0D1999EEC92ULL,
		0x27BD4E89FB0F22F1ULL,
		0x3B1839259F4EC3B3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2D24B938327D4178ULL,
		0x56E9EA848D00D907ULL,
		0x4004F4C7E01B38C4ULL,
		0x0C576B8D6DF5873AULL
	}};
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 178 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -178;
	} else {
		printf("Test Case 178 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8C5C0723F29E822AULL,
		0xB523F06C6F13910FULL,
		0x866205D051566703ULL,
		0x2ED9308AF2125D49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0C02D58BDF1C2B4ULL,
		0x967DCF4B0C06AA34ULL,
		0x58ED81B933B3741EULL,
		0x38D8ED13114B52D8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDB9BD9CB34ACBF63ULL,
		0x1EA62121630CE6DAULL,
		0x2D7484171DA2F2E5ULL,
		0x76004377E0C70A71ULL
	}};
	printf("Test Case 179\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 179 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -179;
	} else {
		printf("Test Case 179 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x317D5055847000F0ULL,
		0x88C9AE30BAAB4E93ULL,
		0xB7525E417B804FE7ULL,
		0x3D3DF02D80F802CCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDAEDFC33F6FAD7CDULL,
		0xB8155E8CA75FE15DULL,
		0xCA4452F8032AE927ULL,
		0x49E19F699CC6B573ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x568F54218D752910ULL,
		0xD0B44FA4134B6D35ULL,
		0xED0E0B49785566BFULL,
		0x735C50C3E4314D58ULL
	}};
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 180 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -180;
	} else {
		printf("Test Case 180 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF0CBCFFB16079A93ULL,
		0xCEF825A477305B12ULL,
		0xE3544A1DC1AF3475ULL,
		0x638B7EFE9C4BE3A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x252F98B510890B1EULL,
		0x7CB93734893DADBAULL,
		0x550B8F8D4A9008DEULL,
		0x30797B5DB9AB2177ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCB9C3746057E8F75ULL,
		0x523EEE6FEDF2AD58ULL,
		0x8E48BA90771F2B97ULL,
		0x331203A0E2A0C230ULL
	}};
	printf("Test Case 181\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 181 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -181;
	} else {
		printf("Test Case 181 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xACF46E25AAC41BA0ULL,
		0xE9BF68F6A06501ACULL,
		0x69F42031882260F7ULL,
		0x7647A6FB3BA6FDCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x58F62AA68717A3C9ULL,
		0x8618AC3C2B864144ULL,
		0x8B943B9889E1A243ULL,
		0x36286361CB0BD506ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x53FE437F23AC77D7ULL,
		0x63A6BCBA74DEC068ULL,
		0xDE5FE498FE40BEB4ULL,
		0x401F4399709B28C3ULL
	}};
	printf("Test Case 182\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 182 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -182;
	} else {
		printf("Test Case 182 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFCFD0A0B44FD63C4ULL,
		0xA4C98B755DDC8EEAULL,
		0x8B5228C285446C08ULL,
		0x436E24B8249C75F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38446E317AF4D214ULL,
		0x678374648F9A5EB6ULL,
		0x967D7AC25E467B00ULL,
		0x14FC8ABC7B753B15ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC4B89BD9CA0891B0ULL,
		0x3D461710CE423034ULL,
		0xF4D4AE0026FDF108ULL,
		0x2E7199FBA9273ADBULL
	}};
	printf("Test Case 183\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 183 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -183;
	} else {
		printf("Test Case 183 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xE1E6D78437123816ULL,
		0x65C9B21D33CDC636ULL,
		0xC589484EE0AFAE97ULL,
		0x73A6C057C938DE09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE184340B60EEEA9AULL,
		0x74E229CFC6EA45C8ULL,
		0xE5C17EF573E5E56DULL,
		0x36A28F75B9900908ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0062A378D6234D7CULL,
		0xF0E7884D6CE3806EULL,
		0xDFC7C9596CC9C929ULL,
		0x3D0430E20FA8D500ULL
	}};
	printf("Test Case 184\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 184 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -184;
	} else {
		printf("Test Case 184 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x284E4CE94AA89B0BULL,
		0xA86396DDE76F02FAULL,
		0x0674B0BF936E6961ULL,
		0x5ED6F65E87A841E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CD0789E9AB74F1DULL,
		0x08B431E45B5E46F5ULL,
		0xB7E19F2F2C8B90FFULL,
		0x3AB264928E10DAD7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB7DD44AAFF14BEEULL,
		0x9FAF64F98C10BC04ULL,
		0x4E93119066E2D862ULL,
		0x242491CBF997670AULL
	}};
	printf("Test Case 185\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 185 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -185;
	} else {
		printf("Test Case 185 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x19D64A2E0C425766ULL,
		0x530D8450CD2DFF36ULL,
		0xBC992D961672EB3AULL,
		0x471B35711DE29344ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x434B44F50142B78CULL,
		0x816BF824CA94EB69ULL,
		0x714FDD0D8DA7330FULL,
		0x671DA010BD0635F6ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD68B05390AFF9FC7ULL,
		0xD1A18C2C029913CCULL,
		0x4B49508888CBB82AULL,
		0x5FFD956060DC5D4EULL
	}};
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 186 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -186;
	} else {
		printf("Test Case 186 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xEEB2586BA0FAFC82ULL,
		0xBE5E2E890E5D2978ULL,
		0x2B0831EFD10F9B76ULL,
		0x62AD3F938D9E87CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E48E257E0B6289FULL,
		0x2BE2B189B635C357ULL,
		0xD1CC7062B845B66FULL,
		0x74C4CF3C44CFD52FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x60697613C044D3D0ULL,
		0x927B7CFF58276621ULL,
		0x593BC18D18C9E507ULL,
		0x6DE8705748CEB29BULL
	}};
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 187 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -187;
	} else {
		printf("Test Case 187 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xF5BE54438344B3DEULL,
		0x4BD89F1A657AF55BULL,
		0x084D144EE11CA44BULL,
		0x0B7DFFC3ABE22447ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x891AD63BD84517CFULL,
		0x6AE78135259A4A18ULL,
		0x4291B6E267C11B04ULL,
		0x7967814FC4873EB9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CA37E07AAFF9BFCULL,
		0xE0F11DE53FE0AB43ULL,
		0xC5BB5D6C795B8946ULL,
		0x12167E73E75AE58DULL
	}};
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 188 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -188;
	} else {
		printf("Test Case 188 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x35174311A9850E85ULL,
		0x8BC14B646F23E50DULL,
		0x544745AA026E6F3EULL,
		0x234236F7B6E875E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF2CDAB582AF85786ULL,
		0xC4A96E129A88F93CULL,
		0x9B63E147876AF4BBULL,
		0x753252D2EE225C4CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x424997B97E8CB6ECULL,
		0xC717DD51D49AEBD0ULL,
		0xB8E364627B037A82ULL,
		0x2E0FE424C8C61994ULL
	}};
	printf("Test Case 189\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 189 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -189;
	} else {
		printf("Test Case 189 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x7BFFFB99FF3BD11EULL,
		0x7079BA7C6AE20266ULL,
		0x6D1BE0AA17133270ULL,
		0x46911F2C9CD36F55ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA2BF3475A46D8F7DULL,
		0x89186C0E92D57A22ULL,
		0x4C3C26B543902932ULL,
		0x617EA3C5949DA0A8ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD940C7245ACE418EULL,
		0xE7614E6DD80C8843ULL,
		0x20DFB9F4D383093DULL,
		0x65127B670835CEADULL
	}};
	printf("Test Case 190\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 190 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -190;
	} else {
		printf("Test Case 190 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB64E0F622EAE60A5ULL,
		0xD59F82C1B62DFF09ULL,
		0x9FC11CB65D5CD346ULL,
		0x6EF2863DC561CB12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x66547124E999821CULL,
		0xE2FAABF3F6FE31FDULL,
		0x3B70C1099106D6B8ULL,
		0x3DE4291E386AAB86ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4FF99E3D4514DE89ULL,
		0xF2A4D6CDBF2FCD0CULL,
		0x64505BACCC55FC8DULL,
		0x310E5D1F8CF71F8CULL
	}};
	printf("Test Case 191\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 191 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -191;
	} else {
		printf("Test Case 191 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xB40CFD6895B7B6F3ULL,
		0xB56894163AB25B14ULL,
		0xA65FB80C68C70362ULL,
		0x2156E250837987E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD7C57595B8684160ULL,
		0xDFDB6866B8BA1915ULL,
		0x4819D6EF59809106ULL,
		0x5B0B678C8F07A46CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC4787D2DD4F7580ULL,
		0xD58D2BAF81F841FEULL,
		0x5E45E11D0F46725BULL,
		0x464B7AC3F471E376ULL
	}};
	printf("Test Case 192\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 192 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -192;
	} else {
		printf("Test Case 192 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x36F4C12BB88760DDULL,
		0x3B8025637592B25EULL,
		0xE71DA582319F252EULL,
		0x13F765AF64CC22D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10FADA889895EB44ULL,
		0xB7B7071EA8892DBEULL,
		0xE16748C6F5BCBD06ULL,
		0x400E2C28BFD225D7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x25F9E6A31FF17586ULL,
		0x83C91E44CD0984A0ULL,
		0x05B65CBB3BE26827ULL,
		0x53E93986A4F9FD01ULL
	}};
	printf("Test Case 193\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 193 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -193;
	} else {
		printf("Test Case 193 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5C80E7B72F6C6C5DULL,
		0xD9C0A78049F24933ULL,
		0x24374D334CA648E8ULL,
		0x52857272853B6F85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8F8361D30CD3ABDULL,
		0xD93F0DE27D1B926BULL,
		0xA227425A06FE12F5ULL,
		0x0718AB9597564C2AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9388B199FE9F31A0ULL,
		0x0081999DCCD6B6C7ULL,
		0x82100AD945A835F3ULL,
		0x4B6CC6DCEDE5235AULL
	}};
	printf("Test Case 194\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 194 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -194;
	} else {
		printf("Test Case 194 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xC1F744495D70B2F6ULL,
		0xE7951E4245A91CA6ULL,
		0xCA9A93ECD36E314BULL,
		0x128A086DD48A4D20ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEC76B219C819AF15ULL,
		0x1FB78F9000169117ULL,
		0xF2A406D846B42B82ULL,
		0x09957BFF8F399788ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD580922F955703E1ULL,
		0xC7DD8EB245928B8EULL,
		0xD7F68D148CBA05C9ULL,
		0x08F48C6E4550B597ULL
	}};
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 195 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -195;
	} else {
		printf("Test Case 195 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x5F9D46F86300F78CULL,
		0x493CB5227BDC1759ULL,
		0x52E20F2802711757ULL,
		0x076A6AC6A957E361ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80667C070DB83E4DULL,
		0x49A97F074227B579ULL,
		0x2EAF721738E958D9ULL,
		0x2983F39E6BBF1D00ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDF36CAF15548B92CULL,
		0xFF93361B39B461DFULL,
		0x24329D10C987BE7DULL,
		0x5DE677283D98C661ULL
	}};
	printf("Test Case 196\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 196 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -196;
	} else {
		printf("Test Case 196 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x30D131BCAD604A8AULL,
		0xE7DD8BFF19017A73ULL,
		0x66C4F439B6718E14ULL,
		0x5B400E2C676C10B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0085CE67650104BBULL,
		0x67E02FA4BF3FFB6BULL,
		0x80F99F88D232414CULL,
		0x0DCC0088C2228B06ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x304B6355485F45CFULL,
		0x7FFD5C5A59C17F08ULL,
		0xE5CB54B0E43F4CC8ULL,
		0x4D740DA3A54985A9ULL
	}};
	printf("Test Case 197\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 197 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -197;
	} else {
		printf("Test Case 197 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x8DC8A74AE3DCD527ULL,
		0x2036FFFA11770D64ULL,
		0xFA093BC132F9C4DCULL,
		0x5B973FF06D7D8C56ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFAF049BED6AEADABULL,
		0x732C0A272D89578BULL,
		0x506126BB84C06969ULL,
		0x5CBE7000B2589B5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92D85D8C0D2E2769ULL,
		0xAD0AF5D2E3EDB5D8ULL,
		0xA9A81505AE395B72ULL,
		0x7ED8CFEFBB24F0FBULL
	}};
	printf("Test Case 198\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 198 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -198;
	} else {
		printf("Test Case 198 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0x528728BF30C958C3ULL,
		0xD66CC051DE85E7CEULL,
		0x7D89C62577B9CC25ULL,
		0x038A09122587B456ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC2C6BA9B69E38136ULL,
		0x9CB04C6673665576ULL,
		0x4B21C6FBFE999735ULL,
		0x2A47E5E657D86971ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8FC06E23C6E5D77AULL,
		0x39BC73EB6B1F9257ULL,
		0x3267FF29792034F0ULL,
		0x5942232BCDAF4AE5ULL
	}};
	printf("Test Case 199\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
		printf("Test Case 199 FAILED\n");
		curve25519_key_printf(&k1, COMPLETE);
		curve25519_key_printf(&k2, COMPLETE);
		return -199;
	} else {
		printf("Test Case 199 PASSED\n");
	}
	printf("---\n\n");
	k1 = (curve25519_key_t){.key64 = {
		0xFA4A04204E6EE70AULL,
		0x7AB49EA254CE4807ULL,
		0x0F9384E7D6C57A77ULL,
		0x36636A64A760EE99ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A1A2A6EF8D60E1ULL,
		0xC5043EFC27375F19ULL,
		0x5D93D4936E906050ULL,
		0x17C0995679623333ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0A861795EE18629ULL,
		0xB5B05FA62D96E8EEULL,
		0xB1FFB05468351A26ULL,
		0x1EA2D10E2DFEBB65ULL
	}};
	printf("Test Case 200\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: \n");
	curve25519_key_printf(&k3, COMPLETE);
	curve25519_key_sub_modulo_inplace(&k1, &k2);
	res = curve25519_key_cmp(&k1, &k3);
	if (res) {
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