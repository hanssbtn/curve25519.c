#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0xC1A5A112D865C960ULL,
		0xDB25AA6B4979FB67ULL,
		0x2423D4E58A17B571ULL,
		0xE1C23252B27AF0BBULL,
		0x471EF73B5CF4C84BULL,
		0x05A4FBCA3FE2EBB0ULL,
		0xEB4F04C2C6396C5DULL,
		0x8AE2EC0141C439E2ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xFAC7B8F512D02818ULL,
		0xA8B28F305353194AULL,
		0xBC40A307281D7A5EULL,
		0x425051A23A73E6C1ULL,
		0xABEEC9D9BFE93015ULL,
		0x2FE35669ABD9675BULL,
		0x8459AA1FAAAC7EBDULL,
		0x6AB3608AD76CB968ULL
	}};
	int t = 1;
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA459859E78218DB7ULL,
		0xBB6E8F3258557909ULL,
		0xF4C3FE79AD01DE0FULL,
		0x009B7EC1CAF32C7EULL,
		0x41F415DC3E499D32ULL,
		0x745E8AF46FD7790AULL,
		0xDE1A89908D479116ULL,
		0xB939A2EEBF14196FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7FA377B20D0944C9ULL,
		0xDE3417A0C02C7B3FULL,
		0x89E7DA66D77B4D1CULL,
		0xB6D0C87EA0780809ULL,
		0xE77A24A4CF08CF38ULL,
		0xBE7B202535D976ABULL,
		0x1822D7BA359EC706ULL,
		0x527594562BC68E09ULL
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
		0x53992038CD30D0C0ULL,
		0x1EF51D62E2B2BC45ULL,
		0x9D48149B06E08282ULL,
		0xDF1264F4DE5E657EULL,
		0x1E5227AC2799319CULL,
		0x97893A91826EEC89ULL,
		0xC60B4E45F293F5D5ULL,
		0x03C20EC229CCB544ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x464F33191589CDDBULL,
		0x1521208F86D992CFULL,
		0x31E300DFF7ABA71BULL,
		0x054A07F6904CFECEULL,
		0xEDCCFFCB01404377ULL,
		0xA031A587FACC24F9ULL,
		0xA1B423A82B8C8FCFULL,
		0xEFCC6AEEA0D09C5AULL
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
		0x2C8FF2F960D79C59ULL,
		0x96C9ED495B93DFAFULL,
		0x8A05B85DBCB2D19FULL,
		0x3A7AF67D9BA88CCDULL,
		0xA31CFDE5C07F30E0ULL,
		0xFFCAB5F0F12B34FAULL,
		0x51E20723FC31677AULL,
		0xFF3280FBE2BE89DEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF4471B2948BADB64ULL,
		0xE979A1FCF0D88498ULL,
		0xD11D48F218C85C4AULL,
		0x336EF57205CF7194ULL,
		0xE749A529C44D89EEULL,
		0x9D86EE4BC517A878ULL,
		0x968647CEE386DCDDULL,
		0xE21E6586E017B284ULL
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
		0x696D4F0071147AC3ULL,
		0x930D99EF61CB1F1EULL,
		0x6F05A7751E3477B3ULL,
		0x44173A8D8BB5EEAFULL,
		0x27A452D91F50D223ULL,
		0xA7A21D6C1605DC04ULL,
		0x44054378D52DFAB2ULL,
		0x8EACD41843BE8C6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x696D4F0071147AC3ULL,
		0x930D99EF61CB1F1EULL,
		0x6F05A7751E3477B3ULL,
		0x44173A8D8BB5EEAFULL,
		0x27A452D91F50D223ULL,
		0xA7A21D6C1605DC04ULL,
		0x44054378D52DFAB2ULL,
		0x8EACD41843BE8C6AULL
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
		0x8D9EDFB43E8E3EDBULL,
		0xE474CBC202DE0F66ULL,
		0x0D74CFD2BA8F3990ULL,
		0xC1B2649017FA1972ULL,
		0x40D3E8112675C0A0ULL,
		0xF59C43922173CE46ULL,
		0xF03148AC9333E1F3ULL,
		0x5662B4AB24F06B03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0741E309A5E0783CULL,
		0xA17DE8A37F89984BULL,
		0x772FE1EDA1025009ULL,
		0x2990FF1DF2298B3AULL,
		0x06A140B110ACB6D5ULL,
		0x354DC873206ACD15ULL,
		0x9447A974430205AEULL,
		0xD6D398536AC24976ULL
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
		0x055A057A5BC2931EULL,
		0x8138A54F1E34CFB1ULL,
		0x0E43BFFB69B25249ULL,
		0x9A49F7F47BF5CAEDULL,
		0x28E4916160C8803FULL,
		0xAD60FF56924D4227ULL,
		0x7F94B68436913933ULL,
		0x73F9F4D2F54392A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF739C5C267036692ULL,
		0xD03827338ED38E5DULL,
		0x702D717C2FBC40A4ULL,
		0xF7B869C57545B374ULL,
		0x7D26EE7A1FCDD48CULL,
		0x12AC83FF7FF4DFAFULL,
		0xF4F6C2BC698DCCA2ULL,
		0x804A3252FA48E3F7ULL
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
		0x700553C0840291D7ULL,
		0xB10222FA078CD260ULL,
		0xE1D322DD37E77102ULL,
		0x33C6F3E0092586FFULL,
		0xA8ABD7444BEB5061ULL,
		0x17205BB207320A96ULL,
		0xFF48FA4774267B9CULL,
		0x04FB6FC0C51D617EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x40CFCF4C27B3E1A8ULL,
		0x21FD3253144A8385ULL,
		0x452965EC75DFC86FULL,
		0xFB2F7B312CF68A05ULL,
		0x57BA6B81893A7CA8ULL,
		0xF983C5BB515451F8ULL,
		0x4ACB35ACACF05972ULL,
		0x7E33200409484F74ULL
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
		0x97F485D18CEE199DULL,
		0x983F95799D568E56ULL,
		0xF7216028D3E5CDDDULL,
		0x793FADC71BDDB62CULL,
		0x6B6B488CAE3A8CB2ULL,
		0x72AFE91EE582AA5EULL,
		0xFE6644B427213CA2ULL,
		0xB4233228A89E4BA6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97F485D18CEE199DULL,
		0x983F95799D568E56ULL,
		0xF7216028D3E5CDDDULL,
		0x793FADC71BDDB62CULL,
		0x6B6B488CAE3A8CB2ULL,
		0x72AFE91EE582AA5EULL,
		0xFE6644B427213CA2ULL,
		0xB4233228A89E4BA6ULL
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
		0x7F1C02568D52BAF6ULL,
		0x4F1E33FDE8AC0DF2ULL,
		0x3063A6540488EB3FULL,
		0xC7F932096956192DULL,
		0xF8A405DEF27C87C1ULL,
		0x3954683EBF8FE295ULL,
		0x5B2FCDCDF15A5A9FULL,
		0x4DD2DFB4A0B2BFADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53ACE625F740367EULL,
		0x14C51E0C4A06741AULL,
		0xC9E948BB6D23012BULL,
		0x51DCD53B724D7353ULL,
		0x2C8063829FB298A0ULL,
		0x7913219529F7BA8CULL,
		0xC4E3BBED523F83BFULL,
		0x67ACF1B94713299BULL
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
		0x941CFBCED29CFBD0ULL,
		0xB17E2A89896487DDULL,
		0xD538F65D67C9A642ULL,
		0x75679E4D43B217D6ULL,
		0xC07C807D99457F53ULL,
		0xF56E2C2BE939463CULL,
		0x56C7EEA960D720C3ULL,
		0x9E4840410E070BE6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x80EEE0268BE9E270ULL,
		0x6C5523FAB68EE195ULL,
		0x295B5C186F7B4885ULL,
		0x506B6AF580D11501ULL,
		0x4993DF0159C14911ULL,
		0xF1F5F25869A82B5EULL,
		0x071E23191AD2B496ULL,
		0x75CEAAAABF7BB6EAULL
	}};
	t = 1;
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xEFB20A83F2322CBAULL,
		0x4C57FB01F1E64BCEULL,
		0x1201B480BE666A3BULL,
		0x54257BFF5F59CA8DULL,
		0x610343D0B8DAAE80ULL,
		0x1095E95505E92FC9ULL,
		0xE4ACE141134B0157ULL,
		0x2566817590331BD7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x51C5D94C538649D9ULL,
		0x4056BEA2DB975119ULL,
		0xAB364FFD55170CE0ULL,
		0xAB991BFEA2277A3BULL,
		0xE84A125C82AD61D3ULL,
		0x2E947634B0B36936ULL,
		0xB5FED9C118755338ULL,
		0x699F4ACF44D1AE6DULL
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
		0x97AE2FDAE6E6D949ULL,
		0x180DB0758ED61E21ULL,
		0xF24490DF1636B068ULL,
		0x332F002612D7FFC8ULL,
		0x6302DBA250DB6647ULL,
		0xF1DB60EE2E4CE127ULL,
		0x74DDC0E0DA3F24D3ULL,
		0x87C828CCCB9DC9CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x97AE2FDAE6E6D949ULL,
		0x180DB0758ED61E21ULL,
		0xF24490DF1636B068ULL,
		0x332F002612D7FFC8ULL,
		0x6302DBA250DB6647ULL,
		0xF1DB60EE2E4CE127ULL,
		0x74DDC0E0DA3F24D3ULL,
		0x87C828CCCB9DC9CEULL
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
		0xC89C2D76610AD9F6ULL,
		0x158AE64B46881B07ULL,
		0x3658AB2927A44043ULL,
		0x751294A2BA64169BULL,
		0x8455D9F40B8932D0ULL,
		0x3066C487DE99D54EULL,
		0x5D61DC38132D3E29ULL,
		0x7B719ADFB5151728ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD68BD2D048E9443ULL,
		0x8267F83EDCB142F6ULL,
		0x20F87332A252F6C6ULL,
		0x2F4A56959AA978A2ULL,
		0xE41FC8AE7BDB5208ULL,
		0x608CA24B7B4DFC3AULL,
		0x9C6AA39A08FB87F7ULL,
		0x6A856BD0A0C1C050ULL
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
		0x67391A842C3BCB6DULL,
		0xD928B4F0FB786D59ULL,
		0x7EAC82BF94E2A7E2ULL,
		0xAA5BCB3AD8C56F0BULL,
		0x98BE6DCA66670A26ULL,
		0x201D4EE329D67F89ULL,
		0x6E841D89B86102E2ULL,
		0xB7F12009C8CEC622ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F57CE68A1722937ULL,
		0xA4ACD12BBDFEEFFDULL,
		0x6675FE452261F946ULL,
		0x97FE55CD8EDC5326ULL,
		0x7DF29F8FDC718089ULL,
		0xBA3034994C559531ULL,
		0xACA48B3F128E0310ULL,
		0x588C82B1A61C1ECEULL
	}};
	t = 1;
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xBAD51D0C95F5E01AULL,
		0xBF6F4B3B20C89C12ULL,
		0xF98B613B2FD60307ULL,
		0x9FBF4ACB62457379ULL,
		0x8D4F0653D5CFC40FULL,
		0xBA78882FBF178EC8ULL,
		0xE8D6089CCBCED32EULL,
		0x7931DDBB0E2B993FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6208B91D8447BD95ULL,
		0x59A6D80B41B7D77EULL,
		0xCAC9F7B66BDB2619ULL,
		0xCE18E1EE23B8BACFULL,
		0xFE2174FD83D55677ULL,
		0x623EF297382D460DULL,
		0x425D7D16706457C4ULL,
		0x06C99AF1F2C7FF66ULL
	}};
	t = 1;
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xAF06D50780238AA1ULL,
		0x9E5341B3CA35D6B8ULL,
		0x02BA4BD75C8126DAULL,
		0x8C6A77F372245D42ULL,
		0xD315BFEC3831D644ULL,
		0x6847455E526B8B5EULL,
		0x58DA31B06601A5A3ULL,
		0x0849680968EE94CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF06D50780238AA1ULL,
		0x9E5341B3CA35D6B8ULL,
		0x02BA4BD75C8126DAULL,
		0x8C6A77F372245D42ULL,
		0xD315BFEC3831D644ULL,
		0x6847455E526B8B5EULL,
		0x58DA31B06601A5A3ULL,
		0x0849680968EE94CBULL
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
		0x80B5C6A84FDACA02ULL,
		0x2EAF2831EA2B66A4ULL,
		0xF74591BAC4369913ULL,
		0x49EA588C2C7E6DFAULL,
		0x8E0C45A472F3BAC7ULL,
		0xFBAF703EEC675B18ULL,
		0x55C47E5C88118EA1ULL,
		0xF8D6880E7E859FDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41F2681128B96A1AULL,
		0x22DE89D0C9A8C413ULL,
		0x2580A6F23E745BEAULL,
		0x358FC936964FC069ULL,
		0x77200D1DB572FF1DULL,
		0x391C12B880E26A82ULL,
		0x153CFB88242EFFE5ULL,
		0xA4568E72A222908EULL
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
		0xD9A4B9841EA8F6C9ULL,
		0x8C8D7F6D42738577ULL,
		0xFB6EE921350F2D56ULL,
		0xE2D7E47220629E90ULL,
		0xE058D992837D1081ULL,
		0xB3BA4B2C1999B6E7ULL,
		0x32D9CEB34138D68DULL,
		0xA8CD24C1A6930910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD004DAB2E78824CCULL,
		0xEAFAC04B84F6F012ULL,
		0x0743A810530D6215ULL,
		0xB34BBC1C7D0FED35ULL,
		0x3C9730F6DECA85E3ULL,
		0x667AAE27FA61E156ULL,
		0x8D79977F37E8E662ULL,
		0xC2BF05C0E03CE2F0ULL
	}};
	t = -1;
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x2489095720A86177ULL,
		0x88FC5941C4540669ULL,
		0xB030E02E7030E4FDULL,
		0x2D099A3373BBD0A2ULL,
		0x24B4E2FC6B53BA61ULL,
		0xCABAB60788E528AFULL,
		0x5EC85AB747EEB633ULL,
		0x89CC2C756BEE636EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA158CCD9EDD8FE0ULL,
		0x22EF8BF8AC0C535FULL,
		0x2EDFA438D7BB5D20ULL,
		0x163B8250FB26852EULL,
		0x7209509229D13D0DULL,
		0xE6266498C3309CF9ULL,
		0x64C0A38D76A4B0CAULL,
		0xE3FBC0BD203C3F8BULL
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
		0xF628F5693FC8E79FULL,
		0xDBF8FDB0FCD966C8ULL,
		0xCCAD2C592EA91839ULL,
		0x7B6621DBBB46858CULL,
		0xC72816345DBDF3BAULL,
		0x2E81AFBD803ABB31ULL,
		0x822024FD3E6A71F1ULL,
		0xAD0F4D8FE9026E78ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF628F5693FC8E79FULL,
		0xDBF8FDB0FCD966C8ULL,
		0xCCAD2C592EA91839ULL,
		0x7B6621DBBB46858CULL,
		0xC72816345DBDF3BAULL,
		0x2E81AFBD803ABB31ULL,
		0x822024FD3E6A71F1ULL,
		0xAD0F4D8FE9026E78ULL
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
		0x885777A64FF2E298ULL,
		0xA8FBB3F5F119A128ULL,
		0x37116B88D0BA3BE2ULL,
		0xF320FCEFF700BD1FULL,
		0x741EAC93F5DFF25EULL,
		0xE40277CF53803E51ULL,
		0xF4A936AA8CFCB9CAULL,
		0x8D6FCA2E3BF84DF6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x221FA6A26EAA6724ULL,
		0xA9F1F343F5E4A823ULL,
		0x32F628429E4C76C3ULL,
		0x0B74A6F7F9B9A3F6ULL,
		0x4B1500DD8E4F0D1EULL,
		0x9C960848F16CBF10ULL,
		0xDA5B57A0819B9BFFULL,
		0xE4C303D66E170A09ULL
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
		0x104C96A6C173218FULL,
		0x4D31D25A62754F2CULL,
		0xB7F1C1F221CFB459ULL,
		0x8D3F63EE7D7351EEULL,
		0xC66147D51D61165DULL,
		0x6428E3E081721E34ULL,
		0x448126D3DB219223ULL,
		0x9B93C946AB93C19BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5F0819125957AC91ULL,
		0x6F5F2183E80B0148ULL,
		0x4118AB867A154774ULL,
		0xBF9E5BFE5749BF01ULL,
		0xCC9B295FEC37DC18ULL,
		0x98053471E21FAF6EULL,
		0x96519C232F043DD9ULL,
		0x505CBEA67650C5D7ULL
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
		0xBA674DD09E6D004FULL,
		0xE7F55525ABB0C1B7ULL,
		0xA32C7FC12CB7A8CEULL,
		0x0CFE1F6C53C32B6CULL,
		0x50345BFA323BBA9DULL,
		0x72D52FEA9F2AAC65ULL,
		0xB78905A154CD7B18ULL,
		0x876B6202D0818CCAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x100F49A2620CD36CULL,
		0x4F2B32C98836FED3ULL,
		0x1CA4D6ED8F87DAFCULL,
		0xB8044B25DF72A7C5ULL,
		0xD7C5DF77B7697A1BULL,
		0x2CC45307A51EC17BULL,
		0x06F03A55430D4E53ULL,
		0xAD7D50F69AF7A870ULL
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
		0x9344F703EF42EF1DULL,
		0x6AB54889A02E27D6ULL,
		0x38790268561B0A6CULL,
		0xB6FE255F373D4E9FULL,
		0x7F9DC8D9B2DD833EULL,
		0x339184B3F5E90E5CULL,
		0x1FD75190398F59AFULL,
		0x225852932AD92A10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9344F703EF42EF1DULL,
		0x6AB54889A02E27D6ULL,
		0x38790268561B0A6CULL,
		0xB6FE255F373D4E9FULL,
		0x7F9DC8D9B2DD833EULL,
		0x339184B3F5E90E5CULL,
		0x1FD75190398F59AFULL,
		0x225852932AD92A10ULL
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
		0xA8E619AB7B17D067ULL,
		0x98ABDB2D2EE571A0ULL,
		0xFDE4C8030657ACA2ULL,
		0x139B954591FEAB84ULL,
		0xD7BEA020F1A5FA16ULL,
		0x8B3541A4E3D69BEBULL,
		0x9211CC668E57E82AULL,
		0x4700EC74BB10C635ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02299C691B621A82ULL,
		0xC0DA204AB0FED544ULL,
		0x06AFEBC5B940F35FULL,
		0x4DCDDDAA73308243ULL,
		0xEF0C57EF6A17AAE9ULL,
		0x59E73BA35C153905ULL,
		0xE54E6D25A16F3B78ULL,
		0x4F28C63253BD5E40ULL
	}};
	t = -1;
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x05D7553E1049987CULL,
		0xC83C0E37F121B8B0ULL,
		0x5E5A0BF16AD0D1BAULL,
		0x13B368625AF7BA5FULL,
		0x3DAA62C6CFD83EC4ULL,
		0x928D7F36C972B587ULL,
		0xA07DE0326455CD44ULL,
		0x1522EF2BA88062E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC97862CA346762F5ULL,
		0x56D81F5C85BB04B5ULL,
		0x435C52196E5E24CBULL,
		0x19251E432D35468FULL,
		0x28E635BA32E6D148ULL,
		0x9C77266EB9624F72ULL,
		0x0B2DFFEB432FAE18ULL,
		0x4A518F9C882B20ADULL
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
		0x5043B05657D7E87EULL,
		0x0C4CA26A68067654ULL,
		0x207CCF7AE836B1B8ULL,
		0xF0228328F073AFB9ULL,
		0x4E6CF63F1A9F1ED2ULL,
		0x9F7E90D6B0B3CFD5ULL,
		0xB6AA21D7BD8CFBB1ULL,
		0x2D485F920829E277ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BAEA85BD3DE3756ULL,
		0x3FD35BC9B61692E0ULL,
		0xC145E082F70FF2B0ULL,
		0x69EE00B3E0FBF7F0ULL,
		0x9B54AFF352B1CCF9ULL,
		0x8D12A15903B325C9ULL,
		0x6AC9891C7B4FBED5ULL,
		0xC871ADEDC7418001ULL
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
		0xF98A32C6479685A4ULL,
		0xF4C111F0A42CDCE3ULL,
		0x87543C7A6A8570A2ULL,
		0xD41D6C785AFFC6F2ULL,
		0x261EFA6D065CB01AULL,
		0x5BCDCE13D59E9AB8ULL,
		0x93B5AC266CEE7069ULL,
		0x62DF1A301962AA1CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF98A32C6479685A4ULL,
		0xF4C111F0A42CDCE3ULL,
		0x87543C7A6A8570A2ULL,
		0xD41D6C785AFFC6F2ULL,
		0x261EFA6D065CB01AULL,
		0x5BCDCE13D59E9AB8ULL,
		0x93B5AC266CEE7069ULL,
		0x62DF1A301962AA1CULL
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
		0x85E00779095BFECEULL,
		0x7E38BBACE32937BBULL,
		0xD7EE70E3658226F5ULL,
		0xF6225A4D317929A7ULL,
		0x549B4AE5EAD3CA6BULL,
		0xD5D2A3E97A8740E1ULL,
		0x262C9E0CEF979D82ULL,
		0x0C08BD923D1F404DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8230F8317D0282DEULL,
		0xB93AF21B4AD9CBFFULL,
		0x2C167F52FB67E009ULL,
		0x54E5A0C998DE4DA0ULL,
		0x081CDF24C8D91C0EULL,
		0x24349AAA863AD466ULL,
		0x6BCF30E9CE469064ULL,
		0xFDB8C9B31DC2A760ULL
	}};
	t = -1;
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC57757CCD683C959ULL,
		0xC214CA3CE71516C3ULL,
		0x95C539F09D842BC6ULL,
		0x17CAA4A85D33DD23ULL,
		0xCB1A58C03C4EC7EBULL,
		0x9925148288B82566ULL,
		0x7138167B3DD1B125ULL,
		0xAB114174D429DCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAD1030FC9F16BBB8ULL,
		0x8ED7A20BABFF982DULL,
		0x77638E22D72FA06AULL,
		0xD53FA189255EA2AFULL,
		0x16E00E38898B3A6EULL,
		0x66F258B6FAE7246CULL,
		0x6776EF85007E4B65ULL,
		0x67C7F0B42DDC1E57ULL
	}};
	t = 1;
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x690E8F39B1AA4914ULL,
		0x2697E09505912056ULL,
		0xB8135650F31AC351ULL,
		0x9262CDFBA05D18F0ULL,
		0x9E9317F72BF2709DULL,
		0xC52DEA234ABFF702ULL,
		0x92D4FEED3DCA4683ULL,
		0xFF5F784F41148DD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B0BA3BF29145411ULL,
		0x7663E2E35BB34F9BULL,
		0x36A46B2C95B4CADBULL,
		0xE375DC1C73903097ULL,
		0xD3217A4BE9F78275ULL,
		0x3A0C01935CD1BF51ULL,
		0x43F80D765E160983ULL,
		0x1F701C681870C04DULL
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
		0x73E02D525841851AULL,
		0xEFD26BFB0AF23395ULL,
		0x338EE9192CD71C00ULL,
		0x34C044A685800C6FULL,
		0x63EB9A48509F1A79ULL,
		0xB1F339E1FCA66576ULL,
		0xC384BA97EE8EEA3FULL,
		0x888023B37027D312ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73E02D525841851AULL,
		0xEFD26BFB0AF23395ULL,
		0x338EE9192CD71C00ULL,
		0x34C044A685800C6FULL,
		0x63EB9A48509F1A79ULL,
		0xB1F339E1FCA66576ULL,
		0xC384BA97EE8EEA3FULL,
		0x888023B37027D312ULL
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
		0x621E490C018728ECULL,
		0x8C9EC4E09AC816D9ULL,
		0x56F8EB0BF9B816A3ULL,
		0xB345A96948CDA421ULL,
		0x0DDE93E886C58D42ULL,
		0x1ABA4C719A48DA61ULL,
		0x9E284C61310F03AFULL,
		0x1437DCE4AA5C60B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FD2F27E7CA90622ULL,
		0xF5C22771D47D67E8ULL,
		0x8A87E767EA9EB4F0ULL,
		0x451F3F4DBE7CBCA3ULL,
		0x8B7B28E29D27CC7CULL,
		0x5037B648FA9D6996ULL,
		0xD2A10BCA1DAC33FCULL,
		0xE84EFCB56AA8C063ULL
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
		0x011C42213D1959F8ULL,
		0x73A26C0CFEAA0BEBULL,
		0x0ECB86A6117527F7ULL,
		0x149CC551B4F86D97ULL,
		0x7BE792076CD655A0ULL,
		0xE0346F61AC2DBC61ULL,
		0x7D324218D35384FBULL,
		0xD81779A4DEFB3B37ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34F27A18BF732374ULL,
		0x3654E384E757E765ULL,
		0xCA81957849E56325ULL,
		0x07C2BE74B6085364ULL,
		0xED56901406F5D6A7ULL,
		0x395C26E5C041A089ULL,
		0x6BBE2A99D9087B39ULL,
		0x45688B575DDF2951ULL
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
		0x2EE1E86966889F03ULL,
		0x5A62190500CF353AULL,
		0xA1866E8FDC0EF4F8ULL,
		0x806F3899F60F0841ULL,
		0xA2B9AD22C6336DFCULL,
		0xB1EB537A3E3CBA98ULL,
		0x9BCB302DFD384D0EULL,
		0x435DF72E878644D5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAFF5E1809A003C8ULL,
		0xA14DFEAD58653870ULL,
		0x568ABF1EE20FAFF0ULL,
		0xBADED2D4FDFB3607ULL,
		0x3F6196590A26D6E5ULL,
		0x10D6982662E33252ULL,
		0x089955C0FDEDB871ULL,
		0x08EA61352B335514ULL
	}};
	t = 1;
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA04E15C72B676F5CULL,
		0xEA6123C0993CB8DBULL,
		0x77C83BC0507FF71EULL,
		0x13EA35D738B71FCAULL,
		0x2765F20E08CEB9FEULL,
		0x69453E329B1AF455ULL,
		0x351C241233625864ULL,
		0x400F0EEC46A3F5D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA04E15C72B676F5CULL,
		0xEA6123C0993CB8DBULL,
		0x77C83BC0507FF71EULL,
		0x13EA35D738B71FCAULL,
		0x2765F20E08CEB9FEULL,
		0x69453E329B1AF455ULL,
		0x351C241233625864ULL,
		0x400F0EEC46A3F5D2ULL
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
		0x12AD368EB522D76DULL,
		0x42F4FBBF152ECAE5ULL,
		0x1EF6A6C628E15FE0ULL,
		0x0D9D56A0BBE9D660ULL,
		0x333B1A35B6702C37ULL,
		0x520F4BC5ACBC4C83ULL,
		0xACD5A4B77F48CE3EULL,
		0x7A7A75F778FF0687ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE64797579C7EE6D5ULL,
		0x7693E1DA0E9B02F8ULL,
		0xB85EF7812C6307DDULL,
		0x7A4BD3D5E56F4746ULL,
		0x719A6F9EFD46BD69ULL,
		0x2347637C909D26C9ULL,
		0x8F8C512549A5D9ABULL,
		0x2B6ED3FF467D3E25ULL
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
		0x0F4E17A479B546E5ULL,
		0xA5D617A9832DA9B4ULL,
		0x2EEBCE33F1AAD8B9ULL,
		0x8EC3B14FB6E33D6FULL,
		0xDDB14CA568217C3CULL,
		0x769FA343F2441727ULL,
		0x49615203421FD284ULL,
		0x99992E793834E35BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAFAC258FF41A8F6DULL,
		0xAC8DC0061E7E2038ULL,
		0x82425B88FEFE051AULL,
		0x9207C364F244A25BULL,
		0x0F0A5A33FC7FAD7BULL,
		0x6C9080C853A8BA3FULL,
		0x9399F509E1D1E47CULL,
		0xFB98144268A113BBULL
	}};
	t = -1;
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x27F633CB134F0136ULL,
		0xBBA0D43271FFB6AAULL,
		0x58F45BF9C73E29EDULL,
		0xE753AA1DC9DA9C40ULL,
		0xCEAFFF89E83362E3ULL,
		0xAFBDCBD5292368CFULL,
		0x50F775109E27757FULL,
		0xC4C45F8B9CB764D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x72B215823FE8E32EULL,
		0xC1ADA34842161EE8ULL,
		0x091BB75B51528A3FULL,
		0xEBC011766ED3147CULL,
		0x54E00549C2418EE9ULL,
		0x4CDE405F9C38F84DULL,
		0x5E34C87013F2BB7FULL,
		0x4FDE5A54D9C461D2ULL
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
		0x462C19D153604C63ULL,
		0xAA4F457DEC807EECULL,
		0xF0B03B74D54362FCULL,
		0x0B44D61B64A49FB2ULL,
		0xF405626C318A2127ULL,
		0x1356BFDA017ACDBAULL,
		0xFEEEDC47821DCF7BULL,
		0x661A32D6CAB0CC5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x462C19D153604C63ULL,
		0xAA4F457DEC807EECULL,
		0xF0B03B74D54362FCULL,
		0x0B44D61B64A49FB2ULL,
		0xF405626C318A2127ULL,
		0x1356BFDA017ACDBAULL,
		0xFEEEDC47821DCF7BULL,
		0x661A32D6CAB0CC5AULL
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
		0x16A914078F15E2F5ULL,
		0x63B4E7B2E446ABA1ULL,
		0x34689397A615B115ULL,
		0x1DF9B2D2D6E7CA81ULL,
		0xF63E4C43AB4522C9ULL,
		0x6C0A1952F94490D1ULL,
		0x93088F270288A40EULL,
		0xA191912B29392C98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x666227C00E86CFA6ULL,
		0xB07EF62208F2E896ULL,
		0x729F9C87A379A87DULL,
		0xB14CB4CDF57B7B5FULL,
		0xA23B515C6EB03612ULL,
		0x3C2D12A43794F794ULL,
		0x216710BF7D727324ULL,
		0x09AF763BDF578036ULL
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
		0x77873BAB1904055FULL,
		0x0B23A198A4403B37ULL,
		0xEE2DCF2B7B7FD0EEULL,
		0xAF2FABB361B6DCF5ULL,
		0x3980A8160F55F447ULL,
		0x9DB56411C761BC62ULL,
		0x34E93185C2D62422ULL,
		0x573B816493C302E8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x24386D57E670EEA7ULL,
		0xA833A29D9D1E979BULL,
		0xA7AC28058B392D6CULL,
		0x8F799E2D03733982ULL,
		0xBC32FF2BE8783FD0ULL,
		0x57958B15B3E93CF6ULL,
		0x5AF1D8A3E3F7059DULL,
		0x5B2778BD6ECF524CULL
	}};
	t = -1;
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA2E72C8E9ABB4A91ULL,
		0x3C9950C0FB3078CBULL,
		0x1D32F35444067BFDULL,
		0x632049DC89E39446ULL,
		0x2E85E4A9FB7D4001ULL,
		0x7EFE7C3B4D0A2421ULL,
		0xD3AD8E26681A11E0ULL,
		0xEDDAE78ABD2DDCD1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB03E8E3D0B95869AULL,
		0x409E2A8DB5428171ULL,
		0x5946F66A82A7531EULL,
		0xD182F7BC86D004DAULL,
		0xF7B8E337FC771FB8ULL,
		0xC7CC1DB71CC4A692ULL,
		0x70E7034C595A556DULL,
		0xA5CDD3A0829D81C1ULL
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
		0x1C1C53BA1552F79FULL,
		0x1935A9958FC4D7DBULL,
		0x6DAA0109C05E6CA5ULL,
		0xF6433AE30D967F0AULL,
		0x94F69A66EF48F963ULL,
		0x0BB228CB3346DD2BULL,
		0xF69C8238FBD081FDULL,
		0xDCD2E65BAFC85385ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C1C53BA1552F79FULL,
		0x1935A9958FC4D7DBULL,
		0x6DAA0109C05E6CA5ULL,
		0xF6433AE30D967F0AULL,
		0x94F69A66EF48F963ULL,
		0x0BB228CB3346DD2BULL,
		0xF69C8238FBD081FDULL,
		0xDCD2E65BAFC85385ULL
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
		0x4173EAD22B457BEFULL,
		0xF9E1BCFEEC192255ULL,
		0xD269262B637D3556ULL,
		0x400835E71A26CB79ULL,
		0xEA7C68013AE1216EULL,
		0xCF46B4B43B51AB0FULL,
		0x607E4A77D85CAF2CULL,
		0x505001A086905CF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6327DEAA0542DBEEULL,
		0xA509BF2E8E1EECCDULL,
		0x0B481ECD61C5F4AFULL,
		0xEE544B29EDBF478DULL,
		0x47A64D47343429C3ULL,
		0x03794CD207E1DBDEULL,
		0x0ECAB907648058CEULL,
		0xB6D6EA02B1EBFA67ULL
	}};
	t = -1;
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5F98D8582108D4E7ULL,
		0x57EF5AB0A619EB9EULL,
		0xCB0F4E775C393DDFULL,
		0x64D333AE0AE7A1AFULL,
		0x802C236122651A5CULL,
		0xA1F56E7254BC7A9FULL,
		0x7DDFF5634B94BD1EULL,
		0x0E16EF76B8B74093ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E335F1F16A8726DULL,
		0xC1E3017FF4DE7F71ULL,
		0xE43162BA4FAD0037ULL,
		0xD08A1B336A814B5AULL,
		0xD71E97B3D3249A06ULL,
		0xA9541F8C5CC70773ULL,
		0xF59EFA13452A3A45ULL,
		0xA5220A12C652789CULL
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
		0xA27C59CE4175B6F8ULL,
		0x4E34AB7A17B2CB11ULL,
		0xBF2E5951CBDAD03BULL,
		0x66E69728E7653470ULL,
		0x9E38B1D3B582E5BFULL,
		0x245F485E29D87496ULL,
		0xEC94C57B3A1A389CULL,
		0x1D98315F6A93F753ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FBF33ED88043B3FULL,
		0xC566D883D9B387C9ULL,
		0x3FD334526AF9A568ULL,
		0x1358E864348E3EE4ULL,
		0xD47B10524625B1F8ULL,
		0xC85D72DEF7D3FFF9ULL,
		0x59B1254ABE2724F5ULL,
		0xD4F175E9277E0B2FULL
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
		0x33B3D1C249E08ADDULL,
		0x7B7F5D1B92E5C767ULL,
		0x4DFDE220179E887AULL,
		0xB95A9613ABD6926AULL,
		0xAC3D0767CBBF98A7ULL,
		0xA41D3B03A4B72AF4ULL,
		0xA45EE12A006C73CAULL,
		0xB3246BFEA53F4FA8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x33B3D1C249E08ADDULL,
		0x7B7F5D1B92E5C767ULL,
		0x4DFDE220179E887AULL,
		0xB95A9613ABD6926AULL,
		0xAC3D0767CBBF98A7ULL,
		0xA41D3B03A4B72AF4ULL,
		0xA45EE12A006C73CAULL,
		0xB3246BFEA53F4FA8ULL
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
		0xE886C46F9CF78B8CULL,
		0x06AE0C94CA9D1D9DULL,
		0x90D046184ADEEE5FULL,
		0xC11D656AC2453539ULL,
		0x3BB41DC81849F4E3ULL,
		0x736C32BA08748276ULL,
		0xADBB279555A92291ULL,
		0xD5961687A074054FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF69518F7F3796220ULL,
		0x044E0CF243B02013ULL,
		0xAD644772ACF8C167ULL,
		0xF007BE9628A553DCULL,
		0xE82750F3A76DC9FFULL,
		0xDD310CA3D1830036ULL,
		0xB3BBA4BF43B9E893ULL,
		0xE3CB76ECAF336CE4ULL
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
		0x78ECBA2D7E47B052ULL,
		0x46ACFF04FC91FC0FULL,
		0xB49E9795F6828CEAULL,
		0xBED71D0671406D1CULL,
		0x3C37211909E746E8ULL,
		0x109C03C4CF1ED79FULL,
		0x5273B426671D4CAAULL,
		0xC712551D172936E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3A91B69CBCE9E03ULL,
		0xE35853EB7CB8AE03ULL,
		0x989ADEFD4737CF9CULL,
		0x684BB99CD4DAD6A4ULL,
		0x8F16BD3DA844B38AULL,
		0x5D244F5436B9AE8FULL,
		0x7697634677E4BA0CULL,
		0xEB50968C48C7F9B9ULL
	}};
	t = -1;
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x148B753F24407ED2ULL,
		0xE36F16BC828D8C44ULL,
		0x1CD29330C7E76066ULL,
		0xBE875A3BFEE80583ULL,
		0xE862001865D951B8ULL,
		0x021ADC28991272D9ULL,
		0xD93EC50B3A9248E9ULL,
		0x4795C7B26A99A131ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBBF14B6EC9DB825BULL,
		0x3217BC5D8A664B65ULL,
		0xFBECCD6D7CBC35C5ULL,
		0xC076BB4AEDB1B153ULL,
		0xE2695F6FB1BE0F78ULL,
		0xD63C594CA3D6B6EEULL,
		0x1259089E610859B5ULL,
		0x5A07F5C4D3448B29ULL
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
		0x5CAC4A8F7589270FULL,
		0x512A1E9BB1CE1BE4ULL,
		0x8F83E66A914C902AULL,
		0x62E13EDFDCB70F9DULL,
		0xB5C5332AF5FDB9A6ULL,
		0x9100FE78D569A000ULL,
		0x12D4F2815657F147ULL,
		0xC04968315E6F3A6AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CAC4A8F7589270FULL,
		0x512A1E9BB1CE1BE4ULL,
		0x8F83E66A914C902AULL,
		0x62E13EDFDCB70F9DULL,
		0xB5C5332AF5FDB9A6ULL,
		0x9100FE78D569A000ULL,
		0x12D4F2815657F147ULL,
		0xC04968315E6F3A6AULL
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
		0xB83799E2FEE39F48ULL,
		0x1CB0A962E13207F2ULL,
		0x779D0E28CD8DBAF7ULL,
		0x2E05B98A84352C8AULL,
		0xB8329F8B1835F2A7ULL,
		0x37DE00B9B7EE324AULL,
		0x576DD20636A91CB8ULL,
		0xEEEAC7D7441B1DDAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBDE5BEEEE408EBA5ULL,
		0x306A828849F12AB4ULL,
		0x4505AE5AB7643F89ULL,
		0xAB711B0A14D8498AULL,
		0x96FFE7702E8A7EA2ULL,
		0x677446C59C817A87ULL,
		0xF118AA00EE873736ULL,
		0x62B648BF5972195CULL
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
		0x9DE87863B9E14ED7ULL,
		0x3B0D90810AB1A7F7ULL,
		0xCBDDFAF94AB71159ULL,
		0x56438D19DCD16448ULL,
		0x78D60AD9C7A8B7D9ULL,
		0x63488A708EA940ABULL,
		0x99FCCE0C2A22996EULL,
		0x5D5E6A5D284FF255ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x126C13A8B367A266ULL,
		0x48D7363616067136ULL,
		0xADDBA5FB7F0AF47EULL,
		0x28E1D29FBB34BE9FULL,
		0x3E7AD65B630955EBULL,
		0x28A1837922371BBFULL,
		0xC98D8FF428E46493ULL,
		0x3250BA7165702360ULL
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
		0x22C1707D8BA87F16ULL,
		0x31F4A2E39C1AB12CULL,
		0x5D2B628635E35C6DULL,
		0xADCA0EFE070FC68AULL,
		0x79E948E6BD2AE81CULL,
		0xCD392FB395AFCEB4ULL,
		0xEDB5541427CA2696ULL,
		0x25E4470416583CE0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21B453945D4A981BULL,
		0xEAD995E4D9D84740ULL,
		0x5D2A75B22D013CC4ULL,
		0x942D38B9B7C70C00ULL,
		0x970633EB030FC235ULL,
		0x3C0A538AB44317D2ULL,
		0x3B1315181165EC49ULL,
		0xD6F960A435091B2CULL
	}};
	t = -1;
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4B2831CF55637CB8ULL,
		0x5E2D9799589E00C4ULL,
		0x3A9D33DC8D122A6BULL,
		0xAE375C882BF1FC3EULL,
		0xE84DEC792D15F0D3ULL,
		0xA7C8D8201B4CAF2EULL,
		0x92D565F6E48021D2ULL,
		0xF746D5C93A11ADD6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B2831CF55637CB8ULL,
		0x5E2D9799589E00C4ULL,
		0x3A9D33DC8D122A6BULL,
		0xAE375C882BF1FC3EULL,
		0xE84DEC792D15F0D3ULL,
		0xA7C8D8201B4CAF2EULL,
		0x92D565F6E48021D2ULL,
		0xF746D5C93A11ADD6ULL
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
		0x01BB92693ADCB54CULL,
		0xE1D5009430EA74D2ULL,
		0xBF36A3E1E8934230ULL,
		0xE61A1099EAF59638ULL,
		0x1FE01B0AD3601EDFULL,
		0x0577D0AD54C7DB14ULL,
		0x7DC9D53E8007D3BFULL,
		0x5CEDCE12A7900B95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DC085204C098443ULL,
		0xB3C7E6A8AED9B048ULL,
		0x51BBEDA18DD37B3AULL,
		0x6F3A7B85D1635E93ULL,
		0x3B1840466EE7DB8FULL,
		0x2034851E41975599ULL,
		0xE2436DD3A4EA232FULL,
		0x308E1F6AD5B7CCBFULL
	}};
	t = 1;
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x908E40F157DDA06FULL,
		0x959446B5453521C7ULL,
		0x0A6204D3393C07DEULL,
		0x18EE52DF89FDA6AAULL,
		0xBCAC82718C7E12EAULL,
		0x930B820870D45D59ULL,
		0x24BB48F3CAF7B98AULL,
		0xA00360B666E5F945ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16E17E05540AF6DDULL,
		0x521175719A0BB938ULL,
		0x71642F3E113FE376ULL,
		0xBEC965A6D4A9C91FULL,
		0xF1D906CAF2D6F4FBULL,
		0xCFDF515249D465BFULL,
		0x053162EBE49B8705ULL,
		0x1164D38D97A787BEULL
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
		0xF9D4BFFB73548883ULL,
		0xA8D84740A73EBE92ULL,
		0x09B6F86882864285ULL,
		0x8D6E34D46CBF2DC1ULL,
		0x590F1FA6B2E676D5ULL,
		0x0373E0B54E02DD12ULL,
		0x20C6814B07203320ULL,
		0x14992A0D46A18AE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19C3E78F425ABAD6ULL,
		0x33B5C1BD5AE68946ULL,
		0xA8712521200CC641ULL,
		0xCEFBE5C603CCB411ULL,
		0x2AADAC04C9BED8CAULL,
		0x6F6F5E1D0774A95DULL,
		0xD6D252167234F661ULL,
		0xED99FF29E2902F9EULL
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
		0xF5A454ED6F101D8FULL,
		0x631C22282E5FFD95ULL,
		0x8D3CA81BA7D2F665ULL,
		0x31C09E2C55872825ULL,
		0x1EF7E90860243BBDULL,
		0x4848C90D51F83080ULL,
		0x26F727B810EF1F0FULL,
		0xF927751D95C7D70EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF5A454ED6F101D8FULL,
		0x631C22282E5FFD95ULL,
		0x8D3CA81BA7D2F665ULL,
		0x31C09E2C55872825ULL,
		0x1EF7E90860243BBDULL,
		0x4848C90D51F83080ULL,
		0x26F727B810EF1F0FULL,
		0xF927751D95C7D70EULL
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
		0x3D5688C952A789C3ULL,
		0x968258D781B9E56BULL,
		0x76843BBAA50FBE4AULL,
		0x819058CF1E6B255EULL,
		0x153D174BF92E3E2CULL,
		0xFD8F936CC1A1BABFULL,
		0xBE551AECDA0142D6ULL,
		0xC4E5E6D07403218AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA36F21826FF6269ULL,
		0xB6E9BD147E6BE738ULL,
		0xDACED10194E53513ULL,
		0x05E4758C11E4FC46ULL,
		0x4245FFD7F576FD6BULL,
		0xFD10A8AF9A2E0292ULL,
		0x0AC553C62C694140ULL,
		0x78B077DB6A7BA453ULL
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
		0x87F5A3E6B40A43B0ULL,
		0xBF4E9D7E0F50A070ULL,
		0x2964555CF7F9E90DULL,
		0x6EA639DB570E3964ULL,
		0xF565A65FAD4CCA05ULL,
		0x3C530EF2DC1EE1F3ULL,
		0x1D3F15AF6C695A00ULL,
		0x3050B8AF0AA26126ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4516FFB9A913EAE6ULL,
		0x3AE6898E50C38C3EULL,
		0xFC534DF472993953ULL,
		0x394F6671EB5CF80FULL,
		0x4D05848889CD2246ULL,
		0x4AF1AC3950FB594EULL,
		0x7A066C47514C1B16ULL,
		0x2245CA3768F7C082ULL
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
		0x8E859ED6ECE07D7DULL,
		0x06FF833A2D446B9EULL,
		0x34A40CCC1BF9568EULL,
		0xBCBC57EAA2B3D47AULL,
		0x6B77AB6C647A4972ULL,
		0x7C5C984D9AD7D1D9ULL,
		0x42C8665DB16763CBULL,
		0xA4CE99AB16E519BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x213E27EE782A0452ULL,
		0xC8C4BFD7BAFB9FBFULL,
		0x950ECB34C02ADAC5ULL,
		0x442617DD2D567F69ULL,
		0x2FC1A624F36D5A09ULL,
		0x0A2AEE516BEB3EB4ULL,
		0x7331921EAAF22E29ULL,
		0x876E85C5A7D77A79ULL
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
		0xBEC2F5A8B92CED89ULL,
		0x52955560A44410FBULL,
		0x4F4C92D52A4FD092ULL,
		0xCD4B5C3EE7EAB811ULL,
		0x15183CE936E0F8B8ULL,
		0xC928076873204671ULL,
		0x77D912E23F28A537ULL,
		0x0A139D076E29F143ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC2F5A8B92CED89ULL,
		0x52955560A44410FBULL,
		0x4F4C92D52A4FD092ULL,
		0xCD4B5C3EE7EAB811ULL,
		0x15183CE936E0F8B8ULL,
		0xC928076873204671ULL,
		0x77D912E23F28A537ULL,
		0x0A139D076E29F143ULL
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
		0x93D53F4BF2A76752ULL,
		0x8AE781872D2BCA35ULL,
		0x3500BB3BBDE2B52CULL,
		0xC9C0CD4FBC9359AAULL,
		0x8B76429B6C521A88ULL,
		0xAFC89639DF49C430ULL,
		0xEF8CB4C17646E0D1ULL,
		0x23F7319143224D50ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4DD3CC7A93861CCULL,
		0xD5AF82D5DAA97C30ULL,
		0xDE0AE97A7BC1F617ULL,
		0xF5BB973C50191177ULL,
		0x54D1B2D9193A6C1CULL,
		0x58CD0009AE72E34FULL,
		0xD860DB0D8381EA56ULL,
		0x0BBED6EFF29DE1F2ULL
	}};
	t = 1;
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x588E519E78DCD919ULL,
		0x942898FB4F443D46ULL,
		0x8785B7882CAB4AFFULL,
		0x80C0D1FAE90324FEULL,
		0x238373E6A19C9E58ULL,
		0xBAA80081C77FBDB5ULL,
		0x09B1A87AD87D0140ULL,
		0x96041832B22E89CFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB700AEB96FCE02DULL,
		0x4AB90D81DF538C0DULL,
		0x0A7E53F4362726F2ULL,
		0xCE8D5907C648BFCAULL,
		0x3A95687ED6C791ABULL,
		0x5F7FE2F736540B09ULL,
		0xE975ECAFF7072488ULL,
		0x2FE675435620B25BULL
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
		0xF2C0BA1836CDF890ULL,
		0x6AAF5659C27321F7ULL,
		0x31B40753F31CB683ULL,
		0x73D2C586CD9EDED1ULL,
		0xB91A1AAB2607675DULL,
		0x7C9FD7E9B65AA68DULL,
		0x3EC969CF470D06ECULL,
		0xDA4FC43DB0EE320CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3B34D25773B3A5C3ULL,
		0xA4482884FC2534BBULL,
		0x882B4B18780727EEULL,
		0x81EB03BA1C1C774EULL,
		0xA3434A9EC6CFBB48ULL,
		0x542886AEFBA72124ULL,
		0x9E86195B4A8D350EULL,
		0xB11C72615EC70473ULL
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
		0xC49C03F9A372A64BULL,
		0x6E85E34AA46D95ADULL,
		0x7D710D2A93D0113EULL,
		0x324A2CC91EF1818DULL,
		0x4FA69323189A540FULL,
		0x2EC60CBAD6DFBB7BULL,
		0x3C526924B0E18C8AULL,
		0x332D0127DABC1D7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC49C03F9A372A64BULL,
		0x6E85E34AA46D95ADULL,
		0x7D710D2A93D0113EULL,
		0x324A2CC91EF1818DULL,
		0x4FA69323189A540FULL,
		0x2EC60CBAD6DFBB7BULL,
		0x3C526924B0E18C8AULL,
		0x332D0127DABC1D7CULL
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
		0x5CCEAC4116CB92ECULL,
		0x18C7FCA6523D23C8ULL,
		0x0BA285BFE09A71A1ULL,
		0x13E9FC52D0804206ULL,
		0xBB0A8DCED899E0DEULL,
		0x98BF06070AC231BCULL,
		0x381F3367E106532FULL,
		0xB788EBD90969A133ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD1D00D586B3B18EULL,
		0xB1BAE4E924C21655ULL,
		0x71E53898C78FAEC6ULL,
		0xDF41616494F6E2DAULL,
		0x5867B2ED92581135ULL,
		0xFAD5383FCC61000BULL,
		0xCAA15AC66DE8706EULL,
		0x4CA2A35CEECCA31AULL
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
		0x030D3EE392275407ULL,
		0x17DD98DA87796EEFULL,
		0xBBED5B7DFE813F33ULL,
		0x2A9552D81D0B3580ULL,
		0xAB40BA9FE8B148B5ULL,
		0x001A8B9903297141ULL,
		0xF9A9898B2A51C9DDULL,
		0x152701BA1FD2C282ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D7F19A3AD97158DULL,
		0x51B336727B3DD5EDULL,
		0xE7066CD50769B030ULL,
		0x96328FEDC5F4B79FULL,
		0xE462622A7AB5EDDAULL,
		0x0D3AA2B343E851F9ULL,
		0x9B7F4FD372E799CFULL,
		0xD5AEC0A84A1AF5FFULL
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
		0xA9DCE54C54A54DB2ULL,
		0xF7C2765874668022ULL,
		0xFA6D9DB0C9A72AACULL,
		0x77291B3E14D98C7FULL,
		0x1CA27E349E7C6373ULL,
		0xE0DD370460472BBCULL,
		0xDC33D475D6BC0B53ULL,
		0x3D32CB9D48188727ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7A934F3EB89A6D69ULL,
		0x13AF3B74A0349C5EULL,
		0x514D87FB788F2378ULL,
		0xDED1CA01B0F4B446ULL,
		0x7DCD49895EE74CB9ULL,
		0xA5F0EACA8A2A9747ULL,
		0xBABF99E9C8A4E804ULL,
		0xC3F73E7693D57524ULL
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
		0x8D440C96475E1CC2ULL,
		0x7FE9F5B2975B8F54ULL,
		0x524F4C43A772F40BULL,
		0x410CFF38B24AB7A0ULL,
		0xAB406C39B8DAE9CDULL,
		0xA02A8E51D19FC912ULL,
		0x50C06F8D3DEDCB71ULL,
		0x77D4B7D0D784B1E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D440C96475E1CC2ULL,
		0x7FE9F5B2975B8F54ULL,
		0x524F4C43A772F40BULL,
		0x410CFF38B24AB7A0ULL,
		0xAB406C39B8DAE9CDULL,
		0xA02A8E51D19FC912ULL,
		0x50C06F8D3DEDCB71ULL,
		0x77D4B7D0D784B1E4ULL
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
		0x6AC8BECA9D489205ULL,
		0x00F50F72ECCA59B2ULL,
		0xED98CBE6D372C82CULL,
		0x877E1A8AA5E579E3ULL,
		0x3CA723CDE8BC89A8ULL,
		0x3AAFEE56D664AFDFULL,
		0xDE4CFC79136E257EULL,
		0xA16B73DBDA27342BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A9DCCC75FDC2364ULL,
		0xF48DD1027D772806ULL,
		0xE0B9A2009DEDF6CBULL,
		0xE918ABAD231ADBEDULL,
		0xC18BBAB3FEAC5DB6ULL,
		0x859860463D710429ULL,
		0x6680F29F8A9AD9CDULL,
		0xAB73F90A1C028C2DULL
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
		0x16D695FDD11F85ECULL,
		0xA7C7C40C5255D8EEULL,
		0x568D586126AE4905ULL,
		0xB69A6936AB8C8382ULL,
		0xBF49077D971A135AULL,
		0x1388A0A24CB47AB7ULL,
		0x1EE59CBC5D0C6DECULL,
		0xEAF67E6C5B21497DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBD0B72E0399AC53DULL,
		0x4DCF6796777D48F7ULL,
		0xFB9573FA0A9FC092ULL,
		0xDA6F395F19147415ULL,
		0x8983274FA3F2CFA0ULL,
		0xE0A1FC6105C764C6ULL,
		0xC1CC6E856097B197ULL,
		0xE00DFD03F54A61C1ULL
	}};
	t = 1;
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x24E9BAAA1BF59CF2ULL,
		0x636C6B0BB51EF048ULL,
		0xFFE1BDBFBD5E8172ULL,
		0x8D1820072818A3F2ULL,
		0x424FAD6792DEBBA8ULL,
		0x198B8B0C234A81F2ULL,
		0x435272CA17A20A6EULL,
		0xD36324048604A243ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE97DEFC8624DBB2ULL,
		0xFF40DBC17EC9064DULL,
		0xCCBEA9AD4AA1FF32ULL,
		0x9829D703EEEDAAF7ULL,
		0x809AF9B003FD0ED9ULL,
		0xFE7DC51139AE486EULL,
		0x7CB0B7A61B3AD1A6ULL,
		0xD36D8DD02833F493ULL
	}};
	t = -1;
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x39217C1CC6A43143ULL,
		0x51FAE81F834862D9ULL,
		0xDDBBFF091BB2A321ULL,
		0x4DFB6DD16A68A352ULL,
		0xC2A9EC568BFCE1AEULL,
		0x420164352676CBD1ULL,
		0xA12AE368E8B86AFCULL,
		0x194303ED0D165452ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39217C1CC6A43143ULL,
		0x51FAE81F834862D9ULL,
		0xDDBBFF091BB2A321ULL,
		0x4DFB6DD16A68A352ULL,
		0xC2A9EC568BFCE1AEULL,
		0x420164352676CBD1ULL,
		0xA12AE368E8B86AFCULL,
		0x194303ED0D165452ULL
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
		0x6B60E747CF670A9FULL,
		0x9E1DEAAEE4788D4FULL,
		0x7B3AF45AF1947A2BULL,
		0xF69805E789176AC4ULL,
		0x2FF23389E14B4A94ULL,
		0x15C482EB98F95C0AULL,
		0x8D34DAAF74A95704ULL,
		0x6BA3676D4E5A34A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x99A78E930E9567E4ULL,
		0x3FB8A4C7C65EA5C5ULL,
		0xC851FB55A5961C7CULL,
		0xDE641680C26501F5ULL,
		0xED18115BE6A9BBDAULL,
		0x15AE8B0EF2F8A073ULL,
		0x609F945ADF8A997EULL,
		0x7D37BE1458DC3E11ULL
	}};
	t = -1;
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF7C179D4AE30B21EULL,
		0xDC01250E989B3E5FULL,
		0x431D5EA6203FA747ULL,
		0x7D37722FEDB9D0CCULL,
		0xC653F3B8B029EA36ULL,
		0xE3CB8BCF73E87755ULL,
		0x56FE17B0F043BD1FULL,
		0xCCEC8725D5622481ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA54D6F4480D31EULL,
		0x264072CD4A09BD68ULL,
		0xBE05EC6C64E314E0ULL,
		0xA86723744F66B308ULL,
		0x1433DEBEFFFEA4ACULL,
		0x72D0B3899CC812F3ULL,
		0xF8C7C315D4407BD7ULL,
		0xFA23A18543E62C1AULL
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
		0x956966B43D14C075ULL,
		0x0B4FE8FD1A846FCBULL,
		0x070138D3B904705DULL,
		0x5998F38F7A63016AULL,
		0x18F9AEFA50D9BF86ULL,
		0x723A8827F9D17426ULL,
		0x3BE5028E0655672EULL,
		0x7A98E5124387D13AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x142678DDD7E459C5ULL,
		0x5003D9F4C9184EA4ULL,
		0x91B52933F39C03F9ULL,
		0xD78B33A0217F08ACULL,
		0xFA333C35C7B047A2ULL,
		0xAA971AEB509E043FULL,
		0x7ABDE6CD0DE2BBB4ULL,
		0xB9AA0CCCFDF72763ULL
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
		0x564D41BA6272F5B8ULL,
		0x937C6EC199ED3E81ULL,
		0xF4F3AA05E5140DA1ULL,
		0x523C298506A80C57ULL,
		0x2212DE4D2B2618E5ULL,
		0x43F1DD4A5C247125ULL,
		0x5D8AA2D2ECB55700ULL,
		0xD395DAACA1650F84ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x564D41BA6272F5B8ULL,
		0x937C6EC199ED3E81ULL,
		0xF4F3AA05E5140DA1ULL,
		0x523C298506A80C57ULL,
		0x2212DE4D2B2618E5ULL,
		0x43F1DD4A5C247125ULL,
		0x5D8AA2D2ECB55700ULL,
		0xD395DAACA1650F84ULL
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
		0xC662BB2D09935518ULL,
		0x35B2E91BF35E0ED6ULL,
		0x6F5753388075AF0CULL,
		0xE777C1A14C9F0CA9ULL,
		0x94986F4293DCCF16ULL,
		0x8D70A46D315A5BF3ULL,
		0x3902A9FCD56EC88FULL,
		0x08E7634F7030043EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x76987AC18B635C10ULL,
		0xE0A5D082C54FF0DDULL,
		0xFE86A053352DCB62ULL,
		0x47DB23A13B58778AULL,
		0x0001F1637344DDCDULL,
		0x4A05C499AEBFDD18ULL,
		0x53E0F441E233599AULL,
		0x4C49A738CD5A74CBULL
	}};
	t = -1;
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8BC0B3E466C80D3AULL,
		0x909C7192888BC979ULL,
		0x1CBC8F4CCE68017AULL,
		0x2AA509D6F311F385ULL,
		0x2BFB59B2276B1039ULL,
		0x3EFC330B6763C49BULL,
		0x04EE6884423270D2ULL,
		0x69D307905BE05345ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBA4059BCE26FF9FEULL,
		0xB95BB51CED0A3ED5ULL,
		0x6A57C8817FECAF10ULL,
		0x899A2B839FB23B96ULL,
		0x39A8E8D96C16C056ULL,
		0xD73F2DE9A0F41B50ULL,
		0xE09FF1A18C180D6EULL,
		0x533E0FC266869F63ULL
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
		0x0DF64522AA1A08D5ULL,
		0x5111661163C34BC1ULL,
		0xFFF614CF357B7FC7ULL,
		0x0C04DDE775A80440ULL,
		0x1661A66A5BED9CFEULL,
		0xA2205B6025036F68ULL,
		0x170339C79CEFAB4AULL,
		0xB3D259F7146A61DDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BFFD7689AC2661BULL,
		0x173CFE1753A1704EULL,
		0x2DCF9BFD9C8CDA71ULL,
		0xDCB8ABE7ED92432EULL,
		0xDBC221970DE8AB61ULL,
		0xE8CAFDB9263A62ADULL,
		0x684FEC95B93B7A39ULL,
		0x25F19D86DA3ED3CEULL
	}};
	t = 1;
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x9DB548691936CAB9ULL,
		0x49C32E1B68A22EFBULL,
		0xE961E184BEC435FFULL,
		0xB00A7CD58FA84FD5ULL,
		0x1B89B6FFB2A41102ULL,
		0x7B38B21EE9CA154EULL,
		0x37C7DBF0402BE04FULL,
		0xEC7CD0C2F1DE77A4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DB548691936CAB9ULL,
		0x49C32E1B68A22EFBULL,
		0xE961E184BEC435FFULL,
		0xB00A7CD58FA84FD5ULL,
		0x1B89B6FFB2A41102ULL,
		0x7B38B21EE9CA154EULL,
		0x37C7DBF0402BE04FULL,
		0xEC7CD0C2F1DE77A4ULL
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
		0xB1E68592F9CD4CF6ULL,
		0xC083440111A2C627ULL,
		0xE0140BCD14421248ULL,
		0x03EB5B5299A52087ULL,
		0xA55EB25CB0EB3DA4ULL,
		0xF0A632CE7B822156ULL,
		0xB489DD677BD31A5BULL,
		0x16CB7BE333ACD5D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38AF0D79D8045A90ULL,
		0x7A60290CCD6150B7ULL,
		0xA87F272A3AC85609ULL,
		0xC2CF9EFD11607760ULL,
		0xF5334328AE80C107ULL,
		0xA19D5D5BB96918E2ULL,
		0xA27E1EFC2513D734ULL,
		0xAE7A6310F92B1627ULL
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
		0x4CC1A67F1B22CC37ULL,
		0x03D926BB792C6711ULL,
		0x658E2325FE962C3EULL,
		0xB214715D60226E74ULL,
		0xE37C01631C3F99B1ULL,
		0x44C0466462009AB4ULL,
		0xE485745AF30743FCULL,
		0x325BF87C44B04311ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1B663777419D7744ULL,
		0x1ADEEBE0C5215005ULL,
		0x051066FD5324F44BULL,
		0xA33095BC461CEC4AULL,
		0xF03BC8F91A9108CCULL,
		0xB8F86F6EE207EB24ULL,
		0x66A1FE2226528553ULL,
		0x9CC82AA95D71F7C5ULL
	}};
	t = -1;
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xF793CCA36269AA35ULL,
		0x754623504FF35411ULL,
		0x4B3FB439F498B2ABULL,
		0x124FBCB59D7A5861ULL,
		0xC348BD15F4FA30BBULL,
		0x631BC8CA8650816CULL,
		0xFB3921FC52D9482EULL,
		0x632C9880200E88C4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8F35F791D95B39DULL,
		0x76FE6922324F02DCULL,
		0x50D9BB62A9D59099ULL,
		0x62DF1E290E38066BULL,
		0x617FE5B6FB818A6DULL,
		0xF7C14C1517B2C525ULL,
		0x755685B7606B92A8ULL,
		0xBECB01145AEC9DAAULL
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
		0x42E837A2A38B8E67ULL,
		0x6242D61218539FE9ULL,
		0xF55ECE4AE323BC8DULL,
		0x2EFACFA28DC4CAC7ULL,
		0x3B27FA5A08AA8D5EULL,
		0xCA8B4AC0C70C9B80ULL,
		0xDB3B698DC01BD29CULL,
		0xE58A98E5F8327280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x42E837A2A38B8E67ULL,
		0x6242D61218539FE9ULL,
		0xF55ECE4AE323BC8DULL,
		0x2EFACFA28DC4CAC7ULL,
		0x3B27FA5A08AA8D5EULL,
		0xCA8B4AC0C70C9B80ULL,
		0xDB3B698DC01BD29CULL,
		0xE58A98E5F8327280ULL
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
		0x9837C22BD3182F36ULL,
		0x23BCBAB5EDD83F96ULL,
		0xC3B634CC8A8DECCEULL,
		0x57BBA0566D11C8ABULL,
		0xED7D0957B5124A5DULL,
		0xF880574917BFA555ULL,
		0x9707BC96E667122BULL,
		0x7F5F33075A086F0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85C57A5DB1FD0799ULL,
		0x4B43573C6F91749FULL,
		0xCDE04A475EDFBBD8ULL,
		0x06800C47F31636F1ULL,
		0x3356E8AA2486A2D2ULL,
		0xD4167FB243CFCC50ULL,
		0x7977C742F37459DEULL,
		0x8F69AAC6C048B68DULL
	}};
	t = -1;
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x11FDFAE5509563DDULL,
		0x0AFE8099702A9388ULL,
		0xCA611A580FE02A2DULL,
		0xC1DB13DD1DB21849ULL,
		0xB61C74EC2A1140AFULL,
		0xA1ECE80C7D14CC1DULL,
		0x0D3DBFD2B0457A65ULL,
		0x495CE3E2AD277280ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA738BA1D1A1CE494ULL,
		0x1E2D0F4B040EEC9DULL,
		0x9D682251AAB14E6EULL,
		0x0F93E5C0480282EBULL,
		0x4F8F6E76E596052CULL,
		0xF389B687E01F9ADEULL,
		0x5A918A1EBAE86168ULL,
		0x6020C951FCC78E92ULL
	}};
	t = -1;
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB1C77290CA75DD1FULL,
		0xE56C7118E95EA1EBULL,
		0xA4AB7881CE677466ULL,
		0xC8D9F663F00AAED7ULL,
		0x6CB73314A250C644ULL,
		0x84330F90DCFE92E3ULL,
		0x320D4F32F4900BD3ULL,
		0xD0A8DB36B25644A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3A1244B0ECA39EEULL,
		0x37E69E9D8975464DULL,
		0x51EE750E9C9F1970ULL,
		0x28993C8ED1BAA8DDULL,
		0xD102A54A7F6A773AULL,
		0xC245DCB95DEE0C1FULL,
		0xA7B0C439E4A7C119ULL,
		0xED847DA7D86D5E57ULL
	}};
	t = -1;
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x9B69EEA72C5E6027ULL,
		0xD8A4CD89D1756922ULL,
		0x8BFFCDDDBCF4A166ULL,
		0xF7DF7D4F75D79742ULL,
		0x603137972097AA62ULL,
		0xB4094B7E59055531ULL,
		0x3D1D4567DDC8812AULL,
		0xBF063A7144928998ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B69EEA72C5E6027ULL,
		0xD8A4CD89D1756922ULL,
		0x8BFFCDDDBCF4A166ULL,
		0xF7DF7D4F75D79742ULL,
		0x603137972097AA62ULL,
		0xB4094B7E59055531ULL,
		0x3D1D4567DDC8812AULL,
		0xBF063A7144928998ULL
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
		0xB74CEAD38C08E651ULL,
		0x64D85711481684DBULL,
		0xA5DE84310061A489ULL,
		0x2352DA484C1D257FULL,
		0x3912558B225A36B1ULL,
		0x2B90912F84C8147AULL,
		0x4EBABD4CA85B0BF5ULL,
		0x2540E678EDB4F052ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E6B7A130FD1C3E2ULL,
		0x6CB4A09014275A5DULL,
		0x30D541885E4AF05DULL,
		0xB98B25E77FA021BEULL,
		0x4B28BF4A12D7FE9BULL,
		0x05FBEEC8ACD4D465ULL,
		0x923FC0F933ED8187ULL,
		0x8671BC36E8A09819ULL
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
		0xFE48E8D65BCE3728ULL,
		0x4E14B83993015F20ULL,
		0x52657E5C391E3C4FULL,
		0x784B6278C85D2FBDULL,
		0xD8FB635316B89D46ULL,
		0x386FBBC705A8BE61ULL,
		0xAB0BA0B3015E4A22ULL,
		0xF2C759A7E4254B85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B62AD588351822EULL,
		0x651E06A4E1B6F5CEULL,
		0xD15C13E2CF72A67AULL,
		0x29D24F9EE4F5E909ULL,
		0x6E3712F8EFFEE218ULL,
		0xC1A3E2A67C6E53FBULL,
		0x5377303C359C1148ULL,
		0xB81FF56813CDC878ULL
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
		0x4DE749572DBB1360ULL,
		0x1838D8558B475A3FULL,
		0x6EDA88ECB716414BULL,
		0x0DB546B9A8A85ABEULL,
		0x0C8A14B38F90F7F6ULL,
		0x18E6D8CC39C55CF3ULL,
		0x269DBD58B4F66559ULL,
		0xF7DD6596EDA3455CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD54A052E39259C74ULL,
		0x6EB42526BA1F4571ULL,
		0xAA1859BC226DF850ULL,
		0x35C9C46BF5E86A1EULL,
		0x7C63C9C7C2601849ULL,
		0x8EA03963B51EEF52ULL,
		0x87C8AAA332DA5F3EULL,
		0xC3AE3FCD14D67CBEULL
	}};
	t = 1;
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFE0028665EE0B5E0ULL,
		0x91663D18417BB25AULL,
		0x553F0B7D31D70713ULL,
		0x7A9B3A2AF51D54CBULL,
		0x767DA7B1B719A0CAULL,
		0x301EDE2AAE360127ULL,
		0x24B95FDD558EF56DULL,
		0x5FA925C074EB7D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE0028665EE0B5E0ULL,
		0x91663D18417BB25AULL,
		0x553F0B7D31D70713ULL,
		0x7A9B3A2AF51D54CBULL,
		0x767DA7B1B719A0CAULL,
		0x301EDE2AAE360127ULL,
		0x24B95FDD558EF56DULL,
		0x5FA925C074EB7D46ULL
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
		0x86142CFAE47208FEULL,
		0x905DF86A3C8FBBEBULL,
		0xDF8EAC9EE66886A9ULL,
		0xB290D849DFD0C11EULL,
		0xACCD6B3030FA14B0ULL,
		0x19433E3547BF4C36ULL,
		0x8D31ED8709E4A06CULL,
		0x560B6BBFC35C8105ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69F4F3C84A53D052ULL,
		0x93369433E0154137ULL,
		0x1B90762B9AB42A0EULL,
		0xA198A2BAACF31884ULL,
		0x0D8DEF9F836F188FULL,
		0xAC46B61F87C3730AULL,
		0xDD9D1C5BF22961D8ULL,
		0x0DDD203A750D1DE0ULL
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
		0xE99124B2B3202EB1ULL,
		0x6C25D32EAD986798ULL,
		0x33F60620C0D4D662ULL,
		0x35F9A6A1705B7CEAULL,
		0xE0D135084D7CC3ADULL,
		0x950BFD31F7111606ULL,
		0x79E7BD14F867A1B2ULL,
		0xE4B3F10ADF99B7BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D1FDFCC1D0ABB2ULL,
		0xB9C0EB6B1CFC14B4ULL,
		0xA12D6A6B597FE6B5ULL,
		0x61724A9AFE32865CULL,
		0xA604049B601E4959ULL,
		0x9AA3249C820C543FULL,
		0x56F9BAF7EA38C536ULL,
		0x4642D2BE960ED971ULL
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
		0x7B8B705F4904B47EULL,
		0x7D1800222C0AD63EULL,
		0x74765A14D63C58B2ULL,
		0xC879FC7336AED7A4ULL,
		0xBDA05C3851D45A3FULL,
		0xAAE64F235EEE6330ULL,
		0x83A940695076A0F1ULL,
		0x904E65796849D1DAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x835A3B4E3107C1DAULL,
		0xB546E7259BCD02D1ULL,
		0x28029C6B27214540ULL,
		0xDC2B4DD5C6059850ULL,
		0x6071008BD059488FULL,
		0x5E04CBF153FC0889ULL,
		0xAC664F66FDBA33E9ULL,
		0xC34AB9184F0685D8ULL
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
		0xCD83C11FAC04CDF9ULL,
		0x434AA64551EB61E0ULL,
		0xC39B81F5327BEC21ULL,
		0xA3BEE2909CB87DADULL,
		0x6B239345191DA281ULL,
		0x307028910F0F279EULL,
		0x6D1D31C714A3433FULL,
		0x5A61C1C99ECAF076ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD83C11FAC04CDF9ULL,
		0x434AA64551EB61E0ULL,
		0xC39B81F5327BEC21ULL,
		0xA3BEE2909CB87DADULL,
		0x6B239345191DA281ULL,
		0x307028910F0F279EULL,
		0x6D1D31C714A3433FULL,
		0x5A61C1C99ECAF076ULL
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
		0xBCCE0C45A7A552A5ULL,
		0x6FE7243F43E6A48FULL,
		0xE8BA28603FDDEBCAULL,
		0x9816E4CABB2C299CULL,
		0xD2DFDF86DC9208D9ULL,
		0xDD7C5ABC4975813BULL,
		0x2C2707C59688D99AULL,
		0x77027DF17FB4ADEDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5486E6C064514BA6ULL,
		0x225D8B1DDFBC3563ULL,
		0xA11C7204894ED122ULL,
		0xF3257D5EE6860F74ULL,
		0x8231BB9093A72EB3ULL,
		0x1932FA040404A2F8ULL,
		0x1A3CF0B853BF6485ULL,
		0xE90ABF9FE66EC9EEULL
	}};
	t = -1;
	printf("Test Case 102\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xD1A5BFE919D1854AULL,
		0x2A9287565858505CULL,
		0xF0C7832B03E66394ULL,
		0x39FB7B999BC97052ULL,
		0x08C31252FC52D3D7ULL,
		0xB70923AD5E7E0291ULL,
		0x6DC1EF5A5E068553ULL,
		0x5BB8AE2A90EA9609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBAC6955DEEAB99BAULL,
		0x06B3FBD4F1CF3D31ULL,
		0x5C16EDAFD67F5CFAULL,
		0xA33FE90F20FD6047ULL,
		0xB8F1C24C4574CF1EULL,
		0x683E1DEF7F66427DULL,
		0xD345002E78317710ULL,
		0x92D48AE139894EE8ULL
	}};
	t = -1;
	printf("Test Case 103\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x09F0356DE0E01862ULL,
		0x1519094F2F360D07ULL,
		0x2ECEC0E16CE0BFB6ULL,
		0x0B149E94E389ABD9ULL,
		0xB56D74C79359ABE8ULL,
		0x102A91E79B7D0B16ULL,
		0x9CAEF220E1EA9439ULL,
		0x6F05DC4FAC197342ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4279E9A6956AC537ULL,
		0x37CC3B48F5703AAAULL,
		0x34837B2B687D8D66ULL,
		0x050FDA8961809422ULL,
		0x89216AECA1B35D34ULL,
		0xDF598F2CCD22AC5CULL,
		0x4BB8222D4B5C6CDCULL,
		0xD19A8F12D41691CCULL
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
		0x68F32E407208DE7CULL,
		0xC36978F9D05D0D33ULL,
		0x482904869551704CULL,
		0xE134D9A15EFEB7DCULL,
		0xAECD6A50465A9955ULL,
		0x07F06776F9BF7F49ULL,
		0xEF3A68EA3D7FFF88ULL,
		0xEA8280B39E32E4A3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68F32E407208DE7CULL,
		0xC36978F9D05D0D33ULL,
		0x482904869551704CULL,
		0xE134D9A15EFEB7DCULL,
		0xAECD6A50465A9955ULL,
		0x07F06776F9BF7F49ULL,
		0xEF3A68EA3D7FFF88ULL,
		0xEA8280B39E32E4A3ULL
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
		0x1A533B49680EE416ULL,
		0x3A322C68DCD86AB1ULL,
		0x74A3F103F5AE1D2EULL,
		0x6658561B1AA10828ULL,
		0xA1D3FFD4666B603CULL,
		0xFED4C936592A4A0BULL,
		0xCF1FB573623E3642ULL,
		0xC3BE02B2AE42236DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2ACE378D2CFE0335ULL,
		0xCA77E456724E76D3ULL,
		0xBF781A6B3A420632ULL,
		0xC6BF239AC9ECAD8CULL,
		0x8F1FD60D4733F77BULL,
		0x26128A049590DC41ULL,
		0xC9C697DA6900ED27ULL,
		0xCD21C2E85446D5D0ULL
	}};
	t = -1;
	printf("Test Case 106\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xFF08D79FB7B3F3F2ULL,
		0x1341276795553059ULL,
		0x548032F39037352CULL,
		0x6BE13DB8F131F4D9ULL,
		0xE634431088B6829FULL,
		0x0F361A2442867F2DULL,
		0xD5DD60B9192F3317ULL,
		0x909C951500EC27ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E96C792F41E01AEULL,
		0x87DF3FA30EE0A8DBULL,
		0x872882FE4F8F33C9ULL,
		0xFEFF34B5228A1745ULL,
		0x0031C5A1E2E5B9F1ULL,
		0x518C37FF781F8DDEULL,
		0x583A5BDB82342E4AULL,
		0x9FF3184E1F7D7E03ULL
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
		0xF365C96E7896B9B8ULL,
		0x7F5DE69C1C1F648AULL,
		0x08DA6CBBA2C65713ULL,
		0x5840ADCA64B68C8AULL,
		0x9852935B4CD7ADA8ULL,
		0x323BE67C203D9873ULL,
		0x6AAD62A470F0B1EAULL,
		0x16034B1CE702F32BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC7FD9A83FD4B3DD3ULL,
		0x7B63EC43CE141E14ULL,
		0x9A8697F6A524C1DAULL,
		0x3E2FBC9D9AD5A9EDULL,
		0x157FAB49A6CF8EB0ULL,
		0x9162288D09D55ADFULL,
		0xA99AA398C3D3DC92ULL,
		0x1BE792EC3194DF31ULL
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
		0xC568B92ABBCDD9ACULL,
		0xBC34A3C9E4B014B0ULL,
		0x406DA2A008520EECULL,
		0x12D475410E83E3BFULL,
		0x491A0D07313D1A41ULL,
		0x76F53BF7B96F2338ULL,
		0x416BEEE4654D3B24ULL,
		0x11AD4D3B58B49D44ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC568B92ABBCDD9ACULL,
		0xBC34A3C9E4B014B0ULL,
		0x406DA2A008520EECULL,
		0x12D475410E83E3BFULL,
		0x491A0D07313D1A41ULL,
		0x76F53BF7B96F2338ULL,
		0x416BEEE4654D3B24ULL,
		0x11AD4D3B58B49D44ULL
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
		0xE5E80272BDCD3DD2ULL,
		0x99DA9FF6F70263EBULL,
		0x5BC38DE9E78D3675ULL,
		0x1FF4B8E028260D81ULL,
		0x2CFCBB0EE989CA87ULL,
		0xECA085AAAD98A353ULL,
		0x8580A7A8AB0866A6ULL,
		0x6EF79BDA8492AEC5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF25A2BB44EEEB95ULL,
		0x8E7CC02531B92970ULL,
		0x5A857131A05BE2D3ULL,
		0x513DF0FF3129FA6EULL,
		0x624B4D46FC5291CBULL,
		0xA8DC970738A49212ULL,
		0x38D87A7F1FFFE5C8ULL,
		0x16CCEC2F0F1AE4F5ULL
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
		0xD64966573A9D2771ULL,
		0x0F4F742143F80ACAULL,
		0x92FF72C0B4147851ULL,
		0x1DB18D860C69F501ULL,
		0x030A56D5D929D3DBULL,
		0x0DD40A6B7BEB7ED9ULL,
		0xF6415501CA7B89DFULL,
		0x4605FFCAA38174A8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03B6AD3E98FF4404ULL,
		0x3433C617ED6E3D7DULL,
		0x93F87F22F7DC24DAULL,
		0xD0C435695F8DF632ULL,
		0xEB6A9176CF46FD86ULL,
		0xCD9640869DA94EEEULL,
		0x5C9EB129331BA9FAULL,
		0x9EB6518871A54354ULL
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
		0xA527EEC13B9D67FCULL,
		0x2477D6CECD574DDAULL,
		0x1289D2E45F2C34E4ULL,
		0x20BC91CED1B87F36ULL,
		0x96D190D06A7DBD8DULL,
		0x31929A4F12DFC6CCULL,
		0x713F2FEC1BEA5C6DULL,
		0x9FE5EC2B7BEDDDF4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1082D29ED5FB58E3ULL,
		0xB930AE57FD9A3D6FULL,
		0xBD7BFCD462A54DB7ULL,
		0xE6581A5D88E05D8DULL,
		0x0F18C36A87796591ULL,
		0x8E5ACE96E6160A89ULL,
		0x2952658C18B54E50ULL,
		0x85CEA83CF3C63E99ULL
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
		0xAC0B8859491E623AULL,
		0x1C5D0C5C4E0EFA44ULL,
		0x904CC96FCEC209ADULL,
		0xCE2BD8B24A5B8813ULL,
		0x801F201D339D903CULL,
		0x4D69E895D3AAEEB3ULL,
		0x162DF4F17990845FULL,
		0xD602F2259A889AB6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC0B8859491E623AULL,
		0x1C5D0C5C4E0EFA44ULL,
		0x904CC96FCEC209ADULL,
		0xCE2BD8B24A5B8813ULL,
		0x801F201D339D903CULL,
		0x4D69E895D3AAEEB3ULL,
		0x162DF4F17990845FULL,
		0xD602F2259A889AB6ULL
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
		0x1C5DE835764156BFULL,
		0x51D03D04BAE31ACFULL,
		0xD155FEBBD65D3654ULL,
		0x54A7F09FC6B803D2ULL,
		0x036DE3E64E060292ULL,
		0x2E6730956C4C7341ULL,
		0x847DE682FCDEAA11ULL,
		0xEAB39E9496CB4F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA84EC874B8579430ULL,
		0x64113CA98A89AB4EULL,
		0x772385B7B79F6DF2ULL,
		0xDAC162EEFD2087A9ULL,
		0x882402AB44D461F7ULL,
		0x565259EF045DA5F3ULL,
		0x3ABBD0785E0A2B57ULL,
		0x46C0F28AFDA53EB7ULL
	}};
	t = 1;
	printf("Test Case 114\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF3EBBE7E028EBFFFULL,
		0x3FF68B332D09B688ULL,
		0x13CF572D0A717CF8ULL,
		0x2BEA406B105CA729ULL,
		0xF8B460B3D75EA2A0ULL,
		0x514A8D1889CF9407ULL,
		0x3E8179598CDEC901ULL,
		0x9C71D20455DF6BF2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89DDB8220D85DFF9ULL,
		0xAB233F8EC079256FULL,
		0xAEFACE2C35E36E60ULL,
		0xF690BBBEEC03CB38ULL,
		0xD15F32CEAE67D546ULL,
		0xF227A6B8ECCBFA1EULL,
		0x1E0C387A96744C34ULL,
		0xA3EBF58B9E116A68ULL
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
		0xCE7C28B068254380ULL,
		0xF003A9A989407C89ULL,
		0xAA6FC8B9503C2768ULL,
		0x4ADA2D26A04F20F1ULL,
		0x320510031AA7552BULL,
		0x5438B00D491DF165ULL,
		0xA58FE6511A9D80B0ULL,
		0xA368C837344FA930ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6A471969FB53060ULL,
		0x67F9F2426ADD8EDCULL,
		0x96C01B0AFEE8ED65ULL,
		0xD34DA6447D8C3F25ULL,
		0x1BA31A6F53D46847ULL,
		0x6CDE295849976DC4ULL,
		0x9F9C2B92F3088716ULL,
		0x238EBAF1A6E2F8FAULL
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
		0x34DABDFA2BDDF740ULL,
		0xF03B20B0D161B208ULL,
		0x4B19742D595DB3DBULL,
		0x464223DB56259505ULL,
		0x03DFD9360FA3E4B9ULL,
		0x6795C370B298B82DULL,
		0xBA569EC7161E72BFULL,
		0xE2170A51DF5618BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34DABDFA2BDDF740ULL,
		0xF03B20B0D161B208ULL,
		0x4B19742D595DB3DBULL,
		0x464223DB56259505ULL,
		0x03DFD9360FA3E4B9ULL,
		0x6795C370B298B82DULL,
		0xBA569EC7161E72BFULL,
		0xE2170A51DF5618BBULL
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
		0xBFD9ED95B03D61DCULL,
		0xDB3AC4C0771D44EDULL,
		0xBA3DC1679CF05D5EULL,
		0x6324C4B787942679ULL,
		0x106C67FD9336B9CCULL,
		0x21F4C28CF871BBF1ULL,
		0x5005FCB3385455D5ULL,
		0xA4607A6CF923D7B0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2A797DDBFEE485ULL,
		0xBFF00B2CE27C1B07ULL,
		0x86E6AAE1D5E28885ULL,
		0xC82E7FDF8A886996ULL,
		0xD17730ED9797B5A7ULL,
		0x96B76CEF07A7D048ULL,
		0x3B01B3E9A5282A10ULL,
		0x46375D9B12A34F91ULL
	}};
	t = 1;
	printf("Test Case 118\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xA524EA385051DFF7ULL,
		0xC5E29896653A6926ULL,
		0xC3D06693A4A947B2ULL,
		0x55F64B7D0E2FC4BBULL,
		0xE60CB0CCD05A6514ULL,
		0x3767B917ED602EA3ULL,
		0x9D16A7C73100CB89ULL,
		0x8D82D2614FDD7882ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C02D28BCD273C0ULL,
		0x05E2373B74F55514ULL,
		0x732652070A3997F4ULL,
		0xC31D527C6BB091C8ULL,
		0x81F8B00797BF9BCDULL,
		0x2BDB2DCF0DCF76F5ULL,
		0x12AF770AC0BC4002ULL,
		0x997F1966D43A7572ULL
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
		0x59F75BCDB0D6FF68ULL,
		0x4584C836D3DAC583ULL,
		0xC541CB72C03E53AAULL,
		0x4144289185E0042FULL,
		0xA6C894B1FD0CD6DDULL,
		0x13EB3C5F952897D4ULL,
		0x76E9460CD9C9CAB5ULL,
		0x9CE1A4B294DC27D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB529899F1936AB6ULL,
		0xEDE81B202A5BA6CFULL,
		0x6478BFE507FB53B8ULL,
		0xA60E356662BA152FULL,
		0x36AE25A0DF131046ULL,
		0xEA18EFF213859668ULL,
		0x4E65EE57318DC3A7ULL,
		0x5101144EE6D489DDULL
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
		0x5A4AEE9517485B3DULL,
		0x29946F1E012C9F59ULL,
		0xC0DD1AF9D1DACEB6ULL,
		0xD1EEE39960CB4D38ULL,
		0xDA6CCB00CE75E773ULL,
		0xA931FDDB40052A6EULL,
		0xF4A7C0CD07849625ULL,
		0x3A46B79D8FC8A698ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A4AEE9517485B3DULL,
		0x29946F1E012C9F59ULL,
		0xC0DD1AF9D1DACEB6ULL,
		0xD1EEE39960CB4D38ULL,
		0xDA6CCB00CE75E773ULL,
		0xA931FDDB40052A6EULL,
		0xF4A7C0CD07849625ULL,
		0x3A46B79D8FC8A698ULL
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
		0x3EDDFB66B560D23EULL,
		0xA3859245B5BE6F10ULL,
		0x4BEFA11BFF2FA0AEULL,
		0xB2FB163E65117881ULL,
		0x225AA614C86F3C02ULL,
		0xAC511CD68F56D229ULL,
		0x3B5DFDD9D258E99AULL,
		0x8BC491919842A8F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x083C9A666641CAA9ULL,
		0xEEF7AFD374EED25AULL,
		0x9BBDB0CEC850334CULL,
		0x1A10033DBFB00CD0ULL,
		0x0D6A6D2C88CC8259ULL,
		0x222F5EF4254F31BEULL,
		0x7C4AABE7D4501451ULL,
		0xE98D86C28AE8D5E9ULL
	}};
	t = -1;
	printf("Test Case 122\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA3A1606C5863D85EULL,
		0x1D0E46710C93EA20ULL,
		0xDA28C06F6DBD5595ULL,
		0x0673B8533083DC20ULL,
		0x51C08E09732914D0ULL,
		0x22377FC8F9EAAF53ULL,
		0xE82E8CA5235D46A3ULL,
		0x8736763ECB75D5F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x41BB52E15D63A7A2ULL,
		0xA4944D6F2FFE4D56ULL,
		0x40FAF4419D3D5E59ULL,
		0x412348886E4D8A47ULL,
		0x1710E326C5CE134EULL,
		0x8A44ED8B20D18915ULL,
		0x7C1708CF9F8BE469ULL,
		0xFC14CDA701826501ULL
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
		0xF42792305696A94CULL,
		0xB487C359CA934262ULL,
		0x1A2E659A2721C966ULL,
		0x506B976E34A85EDDULL,
		0x78181E4AE5143FFAULL,
		0xADE5AE7BF1D8549BULL,
		0xD1465C77D17B06A2ULL,
		0x52A030F56E4A4F03ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D443844F07BEE76ULL,
		0xE17C04CD66E40707ULL,
		0x6BE5CC8B6827988EULL,
		0x475E642FA5144745ULL,
		0x2FA5C1673CF4F7A5ULL,
		0xFB1AECF645947D75ULL,
		0xF347B4FFB0BADF97ULL,
		0xDEC8C93C09233FBBULL
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
		0xA234AE767D833C7CULL,
		0x582F305AD55F9B18ULL,
		0xBE1EAB5F9F91BE86ULL,
		0xE3A3850F3EEF4DEDULL,
		0xFB976BB1A28F202BULL,
		0x4FBC50C2128BE7BEULL,
		0x9829EE951BF2395FULL,
		0x60951FFA8B6292BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA234AE767D833C7CULL,
		0x582F305AD55F9B18ULL,
		0xBE1EAB5F9F91BE86ULL,
		0xE3A3850F3EEF4DEDULL,
		0xFB976BB1A28F202BULL,
		0x4FBC50C2128BE7BEULL,
		0x9829EE951BF2395FULL,
		0x60951FFA8B6292BDULL
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
		0x291E645E57A1FBDEULL,
		0xB01D1E7C474B7328ULL,
		0x29836833A8226BAAULL,
		0x8BEDB2F8D9B7EE90ULL,
		0xBDC4FD939E082EC9ULL,
		0x2A2C8CB3CCF099B5ULL,
		0xE044888352B052BFULL,
		0xC0B1C823C368C18DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DE956C0B6B5EC41ULL,
		0xABC6439C16D8FDE5ULL,
		0x35E57113BBEC5C0AULL,
		0x292136A2BA850E0BULL,
		0x2358D534B39C8F6EULL,
		0x79A56FE543BBF3A8ULL,
		0xDA43C054D3777FC3ULL,
		0x5F86A4910AF1319CULL
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
		0xDAA78EEDF296C596ULL,
		0xDFD17C3C841F8414ULL,
		0x07E373F730465D3BULL,
		0xF7FB1BB64D310F1EULL,
		0x4763A923A2487926ULL,
		0xDAE21CCC6F28828DULL,
		0x1326AAF099FD3D9FULL,
		0x1F0FED8A4D7B0DEBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06ACE730A993B42ULL,
		0xA685FD6BBCB2F58AULL,
		0xE9C995387584992AULL,
		0xAC17A34D1B09DABCULL,
		0xFA89E61DDFA0BA74ULL,
		0x7AA3CF08FCD5EA29ULL,
		0xD0410E651EBBB262ULL,
		0x37179648A3BE7FD5ULL
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
		0x456726F05AB463DDULL,
		0x7FCD5AFF8FF30B36ULL,
		0x71B9C3A59BB8BC95ULL,
		0x056C3438FACCC141ULL,
		0x30F72C2E9D023974ULL,
		0xCCC246A2B40B0B41ULL,
		0x1ADE19E411277D6DULL,
		0x0100E6163443A0CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7417B9873518490ULL,
		0x7287E4DB8F4ED869ULL,
		0xEF6177037FBFC2DAULL,
		0xBFFB329D2EB70AB1ULL,
		0x9DA69371F1D80A63ULL,
		0x8935F88B5D817637ULL,
		0x2104E11769BCF0ADULL,
		0xB80F37A815B6E41AULL
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
		0x730995F335ABA3E0ULL,
		0xE5F0080ED42C6FE2ULL,
		0xAEDA525AEFF4DF11ULL,
		0x7E85FFCBA2AD5342ULL,
		0x2A4340F690FFC646ULL,
		0xFAC474A0F31246BCULL,
		0xA613DB90282DC250ULL,
		0x577BB5058AA58D25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x730995F335ABA3E0ULL,
		0xE5F0080ED42C6FE2ULL,
		0xAEDA525AEFF4DF11ULL,
		0x7E85FFCBA2AD5342ULL,
		0x2A4340F690FFC646ULL,
		0xFAC474A0F31246BCULL,
		0xA613DB90282DC250ULL,
		0x577BB5058AA58D25ULL
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
		0xBB790E827CBC3DE3ULL,
		0x17D53F9114F7A4C1ULL,
		0x4A3E09995F505DD1ULL,
		0xD15B3803040B4B21ULL,
		0xEFAF893695A00C67ULL,
		0xF33BE80FAA3B81D9ULL,
		0xBA1475BC88ACB236ULL,
		0x0A64AD86AEC99870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB86D9D245AC8A2EULL,
		0x7E7CD0CF31759CD7ULL,
		0xA6AEB0CF0009D472ULL,
		0x19B5C9F3F016A5BAULL,
		0x1B780FDBE92505B4ULL,
		0x6FDE4163B08635EEULL,
		0x919CCE2BF70E6B29ULL,
		0x5D384918BC2427F6ULL
	}};
	t = -1;
	printf("Test Case 130\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x586BACA13195CCCFULL,
		0xE4FC354954EB66D5ULL,
		0x0449D57C7D633DC6ULL,
		0xB4F26A305C7E7882ULL,
		0x955FA3623D9785EBULL,
		0x9334BDECD358D693ULL,
		0xFA0594B2D8B664E6ULL,
		0x35FBEFCF41A05271ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD712DFD259CA28D9ULL,
		0x4D236C3E3C459065ULL,
		0xC8B988758C71E6AAULL,
		0xDAE2F67F75BFE004ULL,
		0xA29F9B5A6E3B9B07ULL,
		0xE6FEE9ACE4F0FA58ULL,
		0x1A03EAD7E8D221ABULL,
		0x66F0198BF039AA1EULL
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
		0x0EE1CA46C2542B2DULL,
		0x623A15A43FB340E6ULL,
		0xC3392918A2065B38ULL,
		0xBC9601AECFCDD189ULL,
		0x6ABC6C98F18091A4ULL,
		0x3BE9551458880E61ULL,
		0xA0402BD6160A7DA8ULL,
		0x0EB14B91E7407C1DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFE487E0CC966D1AULL,
		0xC8B56157A39F5C3CULL,
		0x2E6E8BC1AE903815ULL,
		0x07CC012F4A8BE7C4ULL,
		0x09802966A1351909ULL,
		0x2E6D08AFD065A8DFULL,
		0x5F7E47832AA1F1FAULL,
		0xD16FDBCFCECBDF29ULL
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
		0x88C4749D46181E05ULL,
		0xC86CF79FD95F86E0ULL,
		0x7089E04FC4974D21ULL,
		0x03ACCB1AD2CF17CCULL,
		0x8CFD233C1E76E729ULL,
		0xC08D45F0C599D10AULL,
		0x9B696DA6EBEC94DEULL,
		0x2D706159C1509FC4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x88C4749D46181E05ULL,
		0xC86CF79FD95F86E0ULL,
		0x7089E04FC4974D21ULL,
		0x03ACCB1AD2CF17CCULL,
		0x8CFD233C1E76E729ULL,
		0xC08D45F0C599D10AULL,
		0x9B696DA6EBEC94DEULL,
		0x2D706159C1509FC4ULL
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
		0x77AE933D8F859DD6ULL,
		0xC24399A056AF7D4DULL,
		0x5112202E6BC95349ULL,
		0x454C4898C17B1170ULL,
		0x4E0EE4A3E616A612ULL,
		0x247D86C8AA8BC35EULL,
		0x5518AC2711F9666EULL,
		0x0582C567AE61E9B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABA59A39AC4A6569ULL,
		0x8ABABD780C2D9AA5ULL,
		0xB06E3FEB43683EDCULL,
		0x23DEBAC7A6CEDC71ULL,
		0x70DCD33A94F480B8ULL,
		0xD730C0CB3C509B79ULL,
		0x0A8969BCA2F5573EULL,
		0xD97F49DF2738B3ABULL
	}};
	t = -1;
	printf("Test Case 134\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x3B9EAF25F4072A57ULL,
		0x114651E44C4F53BDULL,
		0x6246C447EAD61B55ULL,
		0xD95C468303E9027BULL,
		0x138787CCA725A447ULL,
		0x2D0A69E27AC9CA89ULL,
		0x1520FCFDB4489BF4ULL,
		0xBC986FCF8A0E10A0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE8D5ACC2B4248344ULL,
		0x46893CDC0C8167E2ULL,
		0xA904B84301197ED6ULL,
		0xEB93FBD946CB4749ULL,
		0x3741B5DDE411DB1EULL,
		0xC77C34488500DB2BULL,
		0x5E568C134700DB88ULL,
		0xD447155577077B78ULL
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
		0x7AA00D2A4319F04FULL,
		0x538318DA4F6347E4ULL,
		0x81C0EFBD382E1E3BULL,
		0x612B2BDFD71C3C56ULL,
		0x6B24C74E772005FBULL,
		0x0C6BE7F0C74604C4ULL,
		0xA440A8143A3A7F09ULL,
		0xBED24B6233B7F386ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAB17D4DA7A50C844ULL,
		0x0C92EF429022BBDDULL,
		0x4A30332B614ED89DULL,
		0xD1D896DD0CA8E8B4ULL,
		0x6F01F5A831B108A7ULL,
		0xA9A1ABD59DBE5F34ULL,
		0xFD533767805B5798ULL,
		0x819C5B2767A435FBULL
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
		0x9C82A5BE699898AEULL,
		0x0A86BC55BA08F91AULL,
		0x3A152D88879A4921ULL,
		0xAF28D17A2E0E6225ULL,
		0x59B0C12C5FF9C6E9ULL,
		0x35B2BA385151A2F2ULL,
		0x2C919A173F34DE11ULL,
		0x6C9AED382964F13EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C82A5BE699898AEULL,
		0x0A86BC55BA08F91AULL,
		0x3A152D88879A4921ULL,
		0xAF28D17A2E0E6225ULL,
		0x59B0C12C5FF9C6E9ULL,
		0x35B2BA385151A2F2ULL,
		0x2C919A173F34DE11ULL,
		0x6C9AED382964F13EULL
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
		0x612E65788EF4A7EAULL,
		0xBDEBEC6E40FC6801ULL,
		0xD82FF83764B6B23AULL,
		0x7940E46F284C558FULL,
		0x3E35C08069466067ULL,
		0x4647CE3279EC781FULL,
		0xAA870138A0ED18DAULL,
		0xCBC4DD0B5C6FF8F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0AD4A062F2C6949ULL,
		0x87B88C09CF46295EULL,
		0xC8EE02D73EB3F749ULL,
		0xBE13577A254A5924ULL,
		0x12FC7AA0D0CCBB0FULL,
		0xDFAB84C783880BC2ULL,
		0x1F8ED934C75B37A3ULL,
		0xD78BE84EA0083598ULL
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
		0x33D6C3F84ADF900CULL,
		0xEA2CB70E36D92660ULL,
		0xD7D7A3247A99C1BFULL,
		0x9DAC560AC9C082C7ULL,
		0x30C335099AF94B14ULL,
		0xB140458B56E7C4EEULL,
		0x2D002E3D085B85B1ULL,
		0x62CC7C77F45F406CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E084BB502821CF7ULL,
		0xC13016E194147453ULL,
		0x973A367EA03E6987ULL,
		0x79591CA854BABF7DULL,
		0x61DD4497BAE745EBULL,
		0xDC8AE9C5C192A5AAULL,
		0xE8FD6B07BD0C1157ULL,
		0xE41B88F4014DA222ULL
	}};
	t = -1;
	printf("Test Case 139\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB1C7F7CF996E1E61ULL,
		0xE4FCEC6E08403C60ULL,
		0xD71681FFFBCEE408ULL,
		0x6FE17857A5FBE834ULL,
		0x8CE3B492F368A6E7ULL,
		0x9F8557DDD90C4FBFULL,
		0x00DFA96E8422FAB7ULL,
		0xF07BDEEE0D77EA4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x309AEA3679536ABBULL,
		0xDC9E267CB2E71E08ULL,
		0x714100A9FBBE03DCULL,
		0xBA5EE28A0F65F1E0ULL,
		0x3A77E05E6BC0A739ULL,
		0xE49B4FEC549E7BDEULL,
		0xB6B926B0F396FCF7ULL,
		0x7A33861E1F54E16BULL
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
		0x14EC0EADE3F5BAFDULL,
		0xB966D6D0085B3243ULL,
		0xDA944EA9E9CA2B52ULL,
		0xC85E6A1460E2EFE7ULL,
		0x17E8F5C6D40E847BULL,
		0x59E39C7BD3866DB0ULL,
		0x41752F0BFB9C9CA4ULL,
		0x32F9F6E19D6506A7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14EC0EADE3F5BAFDULL,
		0xB966D6D0085B3243ULL,
		0xDA944EA9E9CA2B52ULL,
		0xC85E6A1460E2EFE7ULL,
		0x17E8F5C6D40E847BULL,
		0x59E39C7BD3866DB0ULL,
		0x41752F0BFB9C9CA4ULL,
		0x32F9F6E19D6506A7ULL
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
		0xCF7A430201A51F03ULL,
		0x11B492DE4C726A62ULL,
		0x7E9A0396CBEFA520ULL,
		0x0047BC0D296A1173ULL,
		0x56E5920EA724DFA4ULL,
		0x3D14E3296A1929E4ULL,
		0x5DD1CC2657B804B0ULL,
		0x158245253D596EAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0F63513045D36D83ULL,
		0x499427D541C33C80ULL,
		0x8278AC5C03D8F433ULL,
		0x42543BC1A3738885ULL,
		0xC986444E61452E66ULL,
		0x3BA856CA339ED271ULL,
		0xCE92521B63180755ULL,
		0xAA65042C6B13686AULL
	}};
	t = -1;
	printf("Test Case 142\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x4ADF8A537D7A245FULL,
		0x0D47CF9A16550774ULL,
		0x1350ED02DD306B31ULL,
		0x44543D7BBCB8BF74ULL,
		0xB54C8C12369F5CD2ULL,
		0x1F3DBEF903771045ULL,
		0x4B90B8489148D7F9ULL,
		0x7E64FD63C1BE501DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2A80A961B7E51721ULL,
		0xD41EFF490FB8594DULL,
		0x2603E26E251377DAULL,
		0x47A1DFB9A4958CB0ULL,
		0xE07FFEB7F9350ECCULL,
		0x18B9A69B88DDD7D4ULL,
		0xC2B0B3B64979C1A5ULL,
		0xCD4960A1BD7B5CC4ULL
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
		0x693EC1CB3171ABECULL,
		0x9C3D7CFEC5CBA5B2ULL,
		0x8F96C2A806BF8EB2ULL,
		0x626E1E77ED08ECB4ULL,
		0x6567ED9983FA71CAULL,
		0x8682B38A398B73DEULL,
		0xD5F1131AE247F5A0ULL,
		0xEFDF1DD12B8BDFFFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4B2FC687AF2EEEBULL,
		0xE5063C3F6D0592B7ULL,
		0xE3AE21226DABD5D9ULL,
		0xCF53CB129CF4CB21ULL,
		0x69118DB6E910BA87ULL,
		0x15DF5D932716AC0DULL,
		0x5CCBE14194DA1786ULL,
		0x2A780FCCB8B4F93CULL
	}};
	t = 1;
	printf("Test Case 144\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x6C2E7915A38E1036ULL,
		0x2742F64A6D09840CULL,
		0x56952B5D98371480ULL,
		0xDBE5BA79133E41E9ULL,
		0x4F3016BE8B4C43CEULL,
		0x554748EDA9291DA8ULL,
		0xC051165F6B821836ULL,
		0x0C9749EF6598778CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C2E7915A38E1036ULL,
		0x2742F64A6D09840CULL,
		0x56952B5D98371480ULL,
		0xDBE5BA79133E41E9ULL,
		0x4F3016BE8B4C43CEULL,
		0x554748EDA9291DA8ULL,
		0xC051165F6B821836ULL,
		0x0C9749EF6598778CULL
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
		0x9295A49FA416218FULL,
		0x388A7CE89B7463CEULL,
		0x0B744497A87643A5ULL,
		0xDD57F9C82AC621C1ULL,
		0x5AE4062D47AE4402ULL,
		0x149D8882F5C0409EULL,
		0x1508D0CC4B63E183ULL,
		0x4BF68503BD27432AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x653307373C6F320DULL,
		0x44EEB8300F99678FULL,
		0xC1552EE3A630F17CULL,
		0xC137341FD3DA4436ULL,
		0x0E5594A5F64DEE9EULL,
		0x26BC4244C1A73AADULL,
		0x62880F76E1F81FC2ULL,
		0xCF7BE838C4AF2AA8ULL
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
		0x5EDFF11553680496ULL,
		0xD143ABC6438EAEBDULL,
		0x232C104D3341504BULL,
		0x2609F0B785C2F54CULL,
		0x4533AAC1109284C8ULL,
		0x7733F95E8CAF151DULL,
		0x7C0701E0C943D0C9ULL,
		0xDA6C8B9C8D120AB7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4E3B585B0538390ULL,
		0xB8F92B2CD713E1FBULL,
		0x0150E4D55E839BDCULL,
		0xCC2FD96B6D786874ULL,
		0xA92FAEDAF6EE958BULL,
		0xE15FA545A4D3BB60ULL,
		0x2C71E7C873595C35ULL,
		0xD11D2977F26E2CFAULL
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
		0xDBAA1440D4965256ULL,
		0xCE4073BCEA1997E0ULL,
		0xC2B70412F4F9FE43ULL,
		0x48DDD305D6CD3095ULL,
		0xB76E87B8FBFA3758ULL,
		0x75E656FF1A634037ULL,
		0xB42802F838487FA9ULL,
		0x18C20445B5204C28ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x512178AEDC51168FULL,
		0x755F115C91DE5CBDULL,
		0x824D3AE9D31E826DULL,
		0xCB8445C1E2E2B240ULL,
		0x72DEC45E1BD6C6C7ULL,
		0x5461E0A37353F86FULL,
		0x19C6ABB898DA6547ULL,
		0xFF9B6A608E58187FULL
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
		0x57B7D9EAEFF7B0C8ULL,
		0x91E789850E6BC7EDULL,
		0xD60494A0362CC221ULL,
		0xE153B9D60639521DULL,
		0x539914D4232A4826ULL,
		0x19B1885CF751ECA0ULL,
		0xC0AA47DD638A2F11ULL,
		0xEDF5180C3F7AB0F8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57B7D9EAEFF7B0C8ULL,
		0x91E789850E6BC7EDULL,
		0xD60494A0362CC221ULL,
		0xE153B9D60639521DULL,
		0x539914D4232A4826ULL,
		0x19B1885CF751ECA0ULL,
		0xC0AA47DD638A2F11ULL,
		0xEDF5180C3F7AB0F8ULL
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
		0x31F99615F42296A7ULL,
		0xE14AF56BB9653344ULL,
		0xA70EFF7449BC4A70ULL,
		0x6412528E26D24730ULL,
		0x6587015597607C85ULL,
		0x7D6F88925B83E78DULL,
		0x7E95C3CBD02E2425ULL,
		0x755DF360D06962CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x26AD5CA7AF6350E9ULL,
		0xC6A1BFBF525DEDD6ULL,
		0x9C300F21DD4AB26DULL,
		0x6E0381D9D56948DBULL,
		0x8F10C633BF112A70ULL,
		0x5B961FC1EA09D003ULL,
		0x0196258351032B31ULL,
		0x6F7EDFB1224F8077ULL
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
		0x9D7EC67FCC5115CCULL,
		0x030C2828A2904C25ULL,
		0xC8FE208A4F1C21AEULL,
		0x262A4693970ADAD9ULL,
		0xCFD609F86E5C7E64ULL,
		0x97743CE616FD4F9AULL,
		0x83B392583F8138CBULL,
		0xDEC44E15E1AF879AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A17E9D450517E44ULL,
		0x054D8498809F9D5DULL,
		0x7208AD80CA5102BBULL,
		0x2470E04D1838C1BCULL,
		0xB9E2FE85F122E613ULL,
		0x0650608B5253ED6CULL,
		0x131007E39140C3C1ULL,
		0x2556393A0288D118ULL
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
		0x6B87635D630590FEULL,
		0x80A3AB3E747EED70ULL,
		0xE8321D00DBEB7FD7ULL,
		0xAFB93C5A9D12D705ULL,
		0xDF988C223FDD9761ULL,
		0x82C06D46B8E738B9ULL,
		0x2FBB9EC3C30933B7ULL,
		0xAB8801B4E3F25258ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x20AC9BD7BD267CD1ULL,
		0x877CF21955A56782ULL,
		0xA2FA3127825D7CBCULL,
		0xF9D24A168D90BF14ULL,
		0x0EA384D51A68E9A3ULL,
		0xE8E2758A8351BD9FULL,
		0xE7AD70DC59DDE4A9ULL,
		0x8173B0C2F47DFB2CULL
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
		0x5693F4347200BBE5ULL,
		0xBBF5FBF657791AB8ULL,
		0xA872422B48720ED2ULL,
		0x1F63006A1F3AD2E0ULL,
		0x2010F13A59EA3B5CULL,
		0x083AB142BF46B9A8ULL,
		0xAE301D1143E3A338ULL,
		0x478CF8EB0A0BDFE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5693F4347200BBE5ULL,
		0xBBF5FBF657791AB8ULL,
		0xA872422B48720ED2ULL,
		0x1F63006A1F3AD2E0ULL,
		0x2010F13A59EA3B5CULL,
		0x083AB142BF46B9A8ULL,
		0xAE301D1143E3A338ULL,
		0x478CF8EB0A0BDFE3ULL
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
		0x71E2A2AC18D128C1ULL,
		0xED9F3DA8F1F1DDF1ULL,
		0xA5299D75AB5CB98DULL,
		0xAAADB0FB279F1620ULL,
		0x82D387FEC6F6FAB4ULL,
		0x3B927109096F3564ULL,
		0xD808644686BFBF64ULL,
		0x5A852A139DB1C977ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBDC9ED3E88FD1EAULL,
		0xE688FED6DBED392FULL,
		0xEE58BBE063900EFBULL,
		0xF84A1529477A19A6ULL,
		0x5578A0A914BD9C31ULL,
		0xAA93E067E8951C5CULL,
		0x549363E8B63F4DCDULL,
		0x28702C99B22389AEULL
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
		0xCED9747FEDC1D456ULL,
		0x1B3CFAF4AE8928E4ULL,
		0xAA1FE5158C484839ULL,
		0xDD8D0193B0BB3495ULL,
		0x802760DA3DBB13DEULL,
		0xFAD7977E74914E54ULL,
		0xA954D3E6C009636BULL,
		0xD2DCB508F0DB23DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6F9B08D1C197A39FULL,
		0x05C224F30F5A5E77ULL,
		0xF4E1D0332DDA5136ULL,
		0x2FD89D853B6FDE5AULL,
		0xF8DCCB05AF13CBF4ULL,
		0xAE3292BD98799BCBULL,
		0x9F6244162E4807B0ULL,
		0xFDF623645DEDE52BULL
	}};
	t = -1;
	printf("Test Case 155\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xC159C45C11AA736CULL,
		0xB1A9EA0390BECB53ULL,
		0x22C973D21DA79FF9ULL,
		0x559B67A07B65C619ULL,
		0x659F6F8C9FAC5415ULL,
		0x59A46CADE4E9EE03ULL,
		0x82B78F70A90AB88EULL,
		0x5D40FDD4601F866EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x903319065817495EULL,
		0xE1A4FBA179A9721EULL,
		0xACDDA6C0EF51B4A3ULL,
		0x475C6026AC09A3ACULL,
		0xA470A7841961DBE3ULL,
		0xECDD564CCB23CD8AULL,
		0x9406DA04109F7BECULL,
		0xF6C9AE6C0D212B86ULL
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
		0x7940791B72CC9284ULL,
		0xB3CF6789B182B394ULL,
		0xCFC35536639A72BDULL,
		0xA33E9D6B8EF1283DULL,
		0x5211967E7601B36BULL,
		0x52D04479F9F20334ULL,
		0xB4EC688B1F6AE6E8ULL,
		0x7762E621F5ADEA7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7940791B72CC9284ULL,
		0xB3CF6789B182B394ULL,
		0xCFC35536639A72BDULL,
		0xA33E9D6B8EF1283DULL,
		0x5211967E7601B36BULL,
		0x52D04479F9F20334ULL,
		0xB4EC688B1F6AE6E8ULL,
		0x7762E621F5ADEA7BULL
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
		0x8207A4E2335E642EULL,
		0xA8043CA2677E07CBULL,
		0x027784EEFFB0FFBAULL,
		0x54552DE29EE28EACULL,
		0xC15B4794F050E127ULL,
		0x1364DF505CD93DB0ULL,
		0xB0870C49345198FBULL,
		0xE2BD17509A32B861ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6123929B01646162ULL,
		0x1F3BE652E34E93BCULL,
		0x94A5188122E7E589ULL,
		0x45D02A47860C31F1ULL,
		0xDEA66D706A608E0FULL,
		0xEF59BED74AA69BD5ULL,
		0xF72DD30774E87770ULL,
		0xDDDEEB0DE41F5B7AULL
	}};
	t = 1;
	printf("Test Case 158\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF5DF91E6E8CEE186ULL,
		0x2F2D16791AE72CC0ULL,
		0xDFDDA671AA39E3A3ULL,
		0xA4468115737A2B37ULL,
		0xF89D2048F8695A2FULL,
		0xD5C362A5F0B88860ULL,
		0xEB75C12571659648ULL,
		0x12701774FA860267ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74D474A9FA00FEBBULL,
		0xD91F146272D2290AULL,
		0x1637120A81C3E511ULL,
		0x5149FD6E3162F2C0ULL,
		0x0031DD82C15B8A9AULL,
		0xC0392A61EC05FA7DULL,
		0x95DBFDBC01E5F2A1ULL,
		0x4E1A97A6425B925CULL
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
		0x5C35916FE75C07E8ULL,
		0x051B5702FB7F0765ULL,
		0x923EB8DB08E3FE3CULL,
		0xAB10632C004EF4D5ULL,
		0xBABB4EE0CD277D84ULL,
		0x706D9E19B7F247B2ULL,
		0x89825C0B1CB7D02DULL,
		0x6F013AD838331837ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE221E0FED141B69EULL,
		0x88B773BD623A5AC8ULL,
		0x9566921636AAFA26ULL,
		0xA88BDD5603945C81ULL,
		0x7B65955EA5EF57E0ULL,
		0xA46108D79E40C075ULL,
		0x270862D3F7FB22C9ULL,
		0x19A6A1E037746109ULL
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
		0x9D57A8712810552EULL,
		0xDD2396E5C51B4A6DULL,
		0xC75D8E9EFF804895ULL,
		0x5EB4968D7F0403BBULL,
		0xD036FD44DAF0ED98ULL,
		0x1424C1380F6C929FULL,
		0x3B9A116A16EE0965ULL,
		0x0721C231424C1E7BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D57A8712810552EULL,
		0xDD2396E5C51B4A6DULL,
		0xC75D8E9EFF804895ULL,
		0x5EB4968D7F0403BBULL,
		0xD036FD44DAF0ED98ULL,
		0x1424C1380F6C929FULL,
		0x3B9A116A16EE0965ULL,
		0x0721C231424C1E7BULL
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
		0x2DE3D16F0E82E418ULL,
		0xC6AB60E70D118650ULL,
		0xA884CD0B3E28EBEBULL,
		0xE3B7E51D0819BE97ULL,
		0xEFBB699EE88A322EULL,
		0x85CEA383ADD4ECDCULL,
		0x32661A770E9B3E6AULL,
		0xBDB1D48C67C22A21ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8E4E7007FC3FE687ULL,
		0xB108ACC689A55573ULL,
		0x1E6A0696EFE3FCEDULL,
		0x7587479270A3361CULL,
		0x7E6863579977EBB6ULL,
		0x26780DF2F2BEEE8EULL,
		0x6F7A8AB2830FA9A7ULL,
		0x4E1B6381454CE59FULL
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
		0x67DC1B7F3E226DE6ULL,
		0xCFC4DE38329DB150ULL,
		0xFDF1478A709B645BULL,
		0x3A150E15895F3756ULL,
		0x76C4B209027EB0ABULL,
		0x3CDB1CBC87CA8E2EULL,
		0x05B00B18A3AB5B0CULL,
		0x59A63B7DB9EB74CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0A6A6693D2A397B7ULL,
		0x7EF7E228C5F7FF08ULL,
		0x9DFF8839D9C6DFD4ULL,
		0xF0A6038DD82ACFB4ULL,
		0x186B5D6AC9EE75ECULL,
		0x72739EB645F52119ULL,
		0x17DCA0326656C8F7ULL,
		0xAD0B1962786C3CBAULL
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
		0x87F4B0487D7300B2ULL,
		0xAC3DD3AE2C87C7C0ULL,
		0xBB6C1CDE0D07EF0FULL,
		0xD6B5DAE8C07673F2ULL,
		0x6654725976C23FCEULL,
		0xF737E582EEFEAED0ULL,
		0xC987ADC068AA6184ULL,
		0xF69B470C8D8731FBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x557A468EB1932D5EULL,
		0x71B92D9BC024DC9BULL,
		0xF44B66981D8C4C8FULL,
		0xE5DFAE67C5AF5C31ULL,
		0xD64EB08B437C9259ULL,
		0x222B0B4427589668ULL,
		0xE366B51E8FBD3257ULL,
		0x269D34F62E7F6D42ULL
	}};
	t = 1;
	printf("Test Case 164\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB4CCF5977DA9F39FULL,
		0x5666F9378187D332ULL,
		0xC2A3D27F925E48A8ULL,
		0xAF80B464E2073B13ULL,
		0x36108FC8BCEA3FD8ULL,
		0x2E3D1275810241A8ULL,
		0x02FF07320BF4862AULL,
		0x94189447E4778A63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4CCF5977DA9F39FULL,
		0x5666F9378187D332ULL,
		0xC2A3D27F925E48A8ULL,
		0xAF80B464E2073B13ULL,
		0x36108FC8BCEA3FD8ULL,
		0x2E3D1275810241A8ULL,
		0x02FF07320BF4862AULL,
		0x94189447E4778A63ULL
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
		0x484C2F53CF6A6EEBULL,
		0x34D086F9BECC12C5ULL,
		0x63A23AF12D95D066ULL,
		0xF13E7DA4007A8B05ULL,
		0x0B1A814D5144D706ULL,
		0xA3A03203E0F53845ULL,
		0xDC9A9B208D7B9692ULL,
		0xBF4769AFF32A2A25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6231BBAC1DDA275FULL,
		0xB3D646432591658EULL,
		0x091185AD75315913ULL,
		0x688C737DB7349E32ULL,
		0xBAF846BDB4BA7366ULL,
		0x80F1BAB51E8BED1EULL,
		0xE1F56471DC07A8F6ULL,
		0x0AC893E1EFEBCB9FULL
	}};
	t = 1;
	printf("Test Case 166\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xC4A8A1768D253A9DULL,
		0x7E252FC118BD914FULL,
		0x58048BE77A123FAFULL,
		0x2D3AAF5209216C75ULL,
		0xB01DD1A2D72D6F97ULL,
		0xD66C16AEAD51E8B5ULL,
		0x91557E6B011B762BULL,
		0xBDA76259467A844DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12CB48F30330923BULL,
		0x04181F36F5AFE02CULL,
		0x46824DBC9D97688CULL,
		0x143B4A98753A358EULL,
		0xA7C30A4A64BC16D8ULL,
		0x7A20C1475C0C717DULL,
		0xB2C8A3E7D60FD57DULL,
		0x08201C7BB09D3192ULL
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
		0x10E6B1414CFBF7DCULL,
		0xF76E18D8CE4CE796ULL,
		0x03D539CC80DBC180ULL,
		0x4FACFCA07CF9D782ULL,
		0xA90FDED0A83744D2ULL,
		0xBF9E66774E0CE731ULL,
		0x4C37FC615BB35767ULL,
		0xBF14E8E3276C6870ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2827E15C0B842DE9ULL,
		0x6A7A580CBF9D4917ULL,
		0xFB18AE2742F6AED1ULL,
		0x596BE4E7835570A2ULL,
		0xC4D13C001F9F9A00ULL,
		0x0E6F282162A2AAC8ULL,
		0xDB846C281903E4DBULL,
		0x6F3D6A82F0A8B663ULL
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
		0xB0F821688E7715CFULL,
		0x0FAED3AC512D303EULL,
		0x35F8A96F9C14120AULL,
		0x36CB460067EBDC3BULL,
		0x565C6B1CD0B16173ULL,
		0xB3A9E096DD272357ULL,
		0x80AF6C6026CE5780ULL,
		0x01AF8D9EAC2E20F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0F821688E7715CFULL,
		0x0FAED3AC512D303EULL,
		0x35F8A96F9C14120AULL,
		0x36CB460067EBDC3BULL,
		0x565C6B1CD0B16173ULL,
		0xB3A9E096DD272357ULL,
		0x80AF6C6026CE5780ULL,
		0x01AF8D9EAC2E20F5ULL
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
		0x76D7B0D0C83548E7ULL,
		0xA77264EDEA34A841ULL,
		0xE51B7A31E7DF0629ULL,
		0x21B94A80F07328B9ULL,
		0xC9D6073D5A2C4146ULL,
		0x096951960FCA9BB9ULL,
		0xE4E9BEDD3B691F58ULL,
		0x06BFD525B9029334ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE09B50921820E1A5ULL,
		0xC9AA654873DDE81FULL,
		0x749CC81FD5278013ULL,
		0x27035B15DD648900ULL,
		0x29C0AAD5DB10708DULL,
		0x41E971F1F6D5B705ULL,
		0xFB3358597DB0650FULL,
		0x0D607312DBA53458ULL
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
		0xA35A5D0303E4F79DULL,
		0x010AAE7BFF724A90ULL,
		0x7C4009E152909D10ULL,
		0xAD709EFF27B424EDULL,
		0x61460E0B469F83D5ULL,
		0x7AE9DE05FAD884BCULL,
		0xF0617863F71AEB10ULL,
		0x5C5F8566F54DC4EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB1517F3957E35B87ULL,
		0xC67228396FB23404ULL,
		0xA69A581D8CE2226EULL,
		0xFEA248C62CC70957ULL,
		0x9A6CE081AE945CCDULL,
		0xF67296A9A74F30F1ULL,
		0x73954A401CBDF4A8ULL,
		0xCF1DBAFAAC3FBDA3ULL
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
		0x44DDD65FB1B2401CULL,
		0x26D52B16586A3328ULL,
		0x51EBA6F6220EDC71ULL,
		0x27F6E077E7423ED7ULL,
		0xFA36700B8F433D60ULL,
		0xF3002A652D1B00CEULL,
		0x8E94C21C830076B7ULL,
		0x09203468A09FF979ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB94C144BC5FB178ULL,
		0x52DA5FAC8C27E64AULL,
		0xBA84EB66A304FDD3ULL,
		0xD83CFCFC0B76CC82ULL,
		0xA20C964BB4CB3F46ULL,
		0x2FB7E79ACB2B3BFEULL,
		0xDBB5D8D2508CF751ULL,
		0x6A5A61FA68EA6300ULL
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
		0xCC5C4137DF6B24FFULL,
		0x488FFA6E5369C003ULL,
		0xB4224A888747A067ULL,
		0xC97FA68DD231525BULL,
		0x4B565775430FC146ULL,
		0x90B07088EB61E079ULL,
		0x8E351AFC0AE55298ULL,
		0xB145C34BF7C515A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC5C4137DF6B24FFULL,
		0x488FFA6E5369C003ULL,
		0xB4224A888747A067ULL,
		0xC97FA68DD231525BULL,
		0x4B565775430FC146ULL,
		0x90B07088EB61E079ULL,
		0x8E351AFC0AE55298ULL,
		0xB145C34BF7C515A1ULL
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
		0x94BDF2E93BADDEBCULL,
		0x832FC299C7B99E07ULL,
		0x2586863D577E0D71ULL,
		0x29B4770006419DCCULL,
		0x03E814F2A862658CULL,
		0x9BE2DC05CB3EB63BULL,
		0xDAA96E58E3629A52ULL,
		0x5C88DF5C34EAE944ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F775A2D739E6034ULL,
		0x93C13E1BA95F35BAULL,
		0xC38BB871E702F6C8ULL,
		0xD2F4D90C457D7D5EULL,
		0x756EC023CD65DBECULL,
		0x852F2A014C92D897ULL,
		0x8ECA937AC93F21ECULL,
		0xF28FBC69CF94347CULL
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
		0x448A6A07DF478996ULL,
		0xD78CEC21DCBEAE14ULL,
		0x78F4F7717863E86CULL,
		0xCBEE2F55B8FE7CC5ULL,
		0x53CA57E46858C07FULL,
		0xAA514ADA3303D353ULL,
		0x9D51EB87135FB023ULL,
		0xAFB710652E64BD0CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x221396D85F7CD77FULL,
		0xD1C9F3328477E806ULL,
		0xA6BA46779A512871ULL,
		0xD3D21BAEFAC12188ULL,
		0x500DC3A88F2F109FULL,
		0xAC1C1BCFB792D33BULL,
		0x5D1F5253089258F7ULL,
		0x0CCE3AC50753AB65ULL
	}};
	t = 1;
	printf("Test Case 175\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x25F4FD4707C05075ULL,
		0x34EABA47C97887BEULL,
		0xD68D653A37BD47C7ULL,
		0xA9A0BFFB58D34F28ULL,
		0x3A2685EDC6C8EFAAULL,
		0x902E75D4333C3BA5ULL,
		0x023566CB57B3D74CULL,
		0x9A7418E7399AFD3CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB0E7563D719BE284ULL,
		0xCFC9761B2E1823F6ULL,
		0x8B6CA597CAE98E4BULL,
		0xF493CE2910816BCDULL,
		0x55D76F6D15164ABFULL,
		0x23A7F56DB4AB52E5ULL,
		0xF3BB8DD3EDE7E019ULL,
		0x3340ED71D18C1ABDULL
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
		0xDC328072D0859C7EULL,
		0x39859C6787DDF6ECULL,
		0xC30BD5A0785C885AULL,
		0xB0F64E7761E7CEE0ULL,
		0x86E4FE6A64D9076FULL,
		0x52EE148CD9AB493BULL,
		0x5DD01EBBF3031451ULL,
		0x5546336F794F60AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDC328072D0859C7EULL,
		0x39859C6787DDF6ECULL,
		0xC30BD5A0785C885AULL,
		0xB0F64E7761E7CEE0ULL,
		0x86E4FE6A64D9076FULL,
		0x52EE148CD9AB493BULL,
		0x5DD01EBBF3031451ULL,
		0x5546336F794F60AEULL
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
		0xA566D2D6AAFB48CBULL,
		0xFE29727651EF24B6ULL,
		0x75387CBB5432960DULL,
		0x1D7A1428A62323A1ULL,
		0x15DFE480E432C398ULL,
		0x3EB1B87BECE42C5AULL,
		0x20CDEB0ED9DBE64AULL,
		0xB3E2DAB419F0B47EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x573F90428200B6F3ULL,
		0x32D4CF1C7BB76EC5ULL,
		0x0B38BBDBBBE6D4D7ULL,
		0xBEDBB1BA8CFA6F99ULL,
		0x15F24CBD918FE32FULL,
		0x3E8F4CCAD2616815ULL,
		0x8CFF15FEE247AA3EULL,
		0x0A4E6880127ADE5FULL
	}};
	t = 1;
	printf("Test Case 178\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xFEA3DE5B4C47C133ULL,
		0xDFF3C17C509CF001ULL,
		0xA2CA83853C270262ULL,
		0xF8A7D3F4A04EB32EULL,
		0x297DB0E633B03127ULL,
		0xDBB5E5318DB17E11ULL,
		0x43EEEA969286638BULL,
		0x976E943A10AD589EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0E49F7D86FEE21F3ULL,
		0x33956D88D734B9CFULL,
		0x59C198D046BB606CULL,
		0xB2B39AD1E9702DB2ULL,
		0x945CCFEF74007960ULL,
		0xCD288ABE09F5DC46ULL,
		0x6A79613EF60F84BEULL,
		0xB5753EC8B7331537ULL
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
		0x832669500B45C81CULL,
		0x31E685FA31326EA1ULL,
		0xC8CCEB4CCAC2759AULL,
		0xA22C62D43FCF1ED6ULL,
		0xD83BAD61DF59ADB4ULL,
		0x87F7D0A0F56DAD25ULL,
		0xA780B68E6FEFB654ULL,
		0x4AB98B24667660AEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7B8594E575CCED3ULL,
		0x6781254840196E2FULL,
		0x3C6B90E985DF46E2ULL,
		0x4BEBD431F7A567D7ULL,
		0xF2BFBB14CA8A1F75ULL,
		0xFC92A05136AA6EE8ULL,
		0x4A311C811B2BEB03ULL,
		0x1428E77711BCC619ULL
	}};
	t = 1;
	printf("Test Case 180\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x104767E5772058B8ULL,
		0x8635C2673CC3CBE1ULL,
		0x8CC2339CD54D4BB6ULL,
		0x2B5B159108948A36ULL,
		0x5B108418E8C2079BULL,
		0xBE9B28F51B8F962AULL,
		0xE1486B0020ACE7A4ULL,
		0x12AA9BCDBAF5A007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x104767E5772058B8ULL,
		0x8635C2673CC3CBE1ULL,
		0x8CC2339CD54D4BB6ULL,
		0x2B5B159108948A36ULL,
		0x5B108418E8C2079BULL,
		0xBE9B28F51B8F962AULL,
		0xE1486B0020ACE7A4ULL,
		0x12AA9BCDBAF5A007ULL
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
		0x331AF4527E40E392ULL,
		0xCE1B0B0B82851460ULL,
		0x57F7C19506A9EE40ULL,
		0x0B0A4A83DD2E8A79ULL,
		0x2896CCC6D3F3F296ULL,
		0x3BEB9C68FB44ED00ULL,
		0x45A4859C65419EB9ULL,
		0xDB97AAA6AF0A0706ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DF2EF9B6887F7B6ULL,
		0x37B64C33B94F337FULL,
		0xF1481F89711BD6A8ULL,
		0xBC5CA1A1E5688F1BULL,
		0x672CF1544A5993DAULL,
		0xC28C16CD6C4FDD0CULL,
		0x445FBADB254D138BULL,
		0x74A926FFD0DF823CULL
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
		0x5390B16693A273B8ULL,
		0x51B0787B4F2291B4ULL,
		0xCDAA97D5D9E04461ULL,
		0x5820EF62F40AFCADULL,
		0x11B7090A772EBCEAULL,
		0x668422C179EE9734ULL,
		0xF8BDC51C285E5798ULL,
		0x3B6EEF450823C2C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDBD4EED6985D9082ULL,
		0x5874DA113CE7101AULL,
		0xCE45B69FB4486F54ULL,
		0x9EDA42B114B8C625ULL,
		0x1D075BDB33F21A1FULL,
		0x4FA8084754EB3BD0ULL,
		0xDC0B3049BB010601ULL,
		0x10EA134712086CD3ULL
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
		0x3BD072E367AAF53FULL,
		0xFEA26C70BFB10BF7ULL,
		0x9A00652C7F283EC2ULL,
		0x2738468B12E2257EULL,
		0x7E8F431F297A8ED7ULL,
		0xE6A563FF24790912ULL,
		0x1462D8FEA77064FEULL,
		0x6DC1E0F6B4A2795DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x60A22DE695ADC117ULL,
		0xB06D720B094C8B1BULL,
		0x5194392BF178052AULL,
		0x3EE4B1187D8BF6E1ULL,
		0xC886EB88FAF78800ULL,
		0x50B61CEEADA9D328ULL,
		0xFED2FED3240338AAULL,
		0x70570AF7C65621B7ULL
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
		0xB2D9DD8FF0E991A7ULL,
		0xE2A0239A0189E288ULL,
		0x71E39854D3E55171ULL,
		0x7821F04DA2B39330ULL,
		0x5A1B13547D75A74DULL,
		0x36AB6100C9F66C8DULL,
		0xB415633F0EC3C8BBULL,
		0x7132B6B7D7661D46ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB2D9DD8FF0E991A7ULL,
		0xE2A0239A0189E288ULL,
		0x71E39854D3E55171ULL,
		0x7821F04DA2B39330ULL,
		0x5A1B13547D75A74DULL,
		0x36AB6100C9F66C8DULL,
		0xB415633F0EC3C8BBULL,
		0x7132B6B7D7661D46ULL
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
		0xC6D8658253CFBBA2ULL,
		0x930DB44775D5BAF4ULL,
		0x3943EE49452B6B0DULL,
		0x807FC719A0756AFBULL,
		0x258C4A008A6B4825ULL,
		0x5DE36DC1BED50F6CULL,
		0x78E582361E9C1218ULL,
		0x6C23A5C820ADE79EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF3D3F3F1EA9F9DE4ULL,
		0xC3A8A7FE6E7C225AULL,
		0xCBA324B45E18D4BFULL,
		0x88AD3E8EA8AD1C48ULL,
		0x3B5775C29143C82BULL,
		0x1D93343BA290E203ULL,
		0x3E9B1AFD1BA14C8FULL,
		0xEDDAD6F01DF28159ULL
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
		0x710FBBDB12013C09ULL,
		0xD4ABD51A8CE8E6FEULL,
		0x981560880A6FB545ULL,
		0x386CC643DA1C7D4FULL,
		0x439C2F7DB2D90894ULL,
		0xCC04B1D5CBF893CFULL,
		0x27938F4982F75C71ULL,
		0x5952710A4CB1D188ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8479136F63C0546BULL,
		0x6DF45D22CEDED87CULL,
		0x56F57783A7DB7CC3ULL,
		0xA8A43A5A733D2702ULL,
		0x2378D170273868B4ULL,
		0xC6A3FC7A708A9A21ULL,
		0x63FBD6E09980DA24ULL,
		0xC9745D591061B17EULL
	}};
	t = -1;
	printf("Test Case 187\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xB7C9B5B52C8D85C4ULL,
		0x02EDF16E31F1EBC8ULL,
		0xEEB2D8DBC80E9F36ULL,
		0xF32DD3DA83484261ULL,
		0x3EACA4595E85B426ULL,
		0x736272EDC96B2272ULL,
		0x3E7B9C869A2E9E51ULL,
		0x502C3322E97D8FC2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEBE8729C5184A3A8ULL,
		0x547E2A28DCC03219ULL,
		0x268C21BD34EF2AC8ULL,
		0xC22EE23E1224B385ULL,
		0x6DF06FB6BE2E1CDFULL,
		0x80006207880DF79EULL,
		0xB81E1C03448252E8ULL,
		0x08CCB75C9D3C7ED5ULL
	}};
	t = 1;
	printf("Test Case 188\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3E968E4EB6E3C3F6ULL,
		0x8208F233D33F371DULL,
		0xBB4065A78F2DCA1EULL,
		0xF43C8D47149C0947ULL,
		0x40E00FD51DB4BB5BULL,
		0xB79D44EA41C94622ULL,
		0x29F61A91C78E9606ULL,
		0x064421DFFF840603ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E968E4EB6E3C3F6ULL,
		0x8208F233D33F371DULL,
		0xBB4065A78F2DCA1EULL,
		0xF43C8D47149C0947ULL,
		0x40E00FD51DB4BB5BULL,
		0xB79D44EA41C94622ULL,
		0x29F61A91C78E9606ULL,
		0x064421DFFF840603ULL
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
		0xBF395BB13BBD3C79ULL,
		0xD9DDEF0A66AC416FULL,
		0x0A313ED5DDEAB464ULL,
		0x53FFA0CBCA84E29CULL,
		0xF1E9C1C4EDDC1393ULL,
		0x5CBCB3FFB933F26AULL,
		0x811824116693A2C9ULL,
		0x3202A6F499F3E0F0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA9444856132599CULL,
		0xC402AE4F315D9695ULL,
		0xB9A0B282D5472F03ULL,
		0xDEEBA045581B1D52ULL,
		0xF5B6A3E358B559C7ULL,
		0xF825A3480A6C5F4AULL,
		0xE9DC5108AC7BE979ULL,
		0x62A07FDFFC33D1D9ULL
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
		0xD36B337F69A2CDD5ULL,
		0xE58955D5D6706773ULL,
		0x08846BC041691850ULL,
		0x5C7A55A2F42A0CE5ULL,
		0x7787F83669D5EB1DULL,
		0xCA750E175F29B51CULL,
		0x1E683089C67CCF31ULL,
		0x50A8A679E214CB0DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5CC4C81460A3AB33ULL,
		0xF3F15B300B5CB589ULL,
		0x4A3CF98441CEDDFBULL,
		0xCBF07D9920C3972CULL,
		0x99B42A2A28642194ULL,
		0x9BA553E693459862ULL,
		0x831B65AB67D8FCC3ULL,
		0x1F4015C4D82E2DD8ULL
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
		0x073256C6519537DBULL,
		0x4BDCA52A3DE47896ULL,
		0x2BEA21FCC6EC2445ULL,
		0xBA9570F28A5B2285ULL,
		0x62776770ED9354CDULL,
		0x7C2303E2C38B48E9ULL,
		0x6FB988F84B205F83ULL,
		0x8451752A03A41C29ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8ACBE107B9E22F8BULL,
		0xFEA8CB17F625E42BULL,
		0x3BFDAE16D893F06DULL,
		0xA7AD1E84B85DF32DULL,
		0xB679C3E4E9ADACFDULL,
		0x31F2EEA7A1DBABE1ULL,
		0x84ECCBD8B0AE42BDULL,
		0x93EF0F2204C20FE1ULL
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
		0x89EC9733A165FB7CULL,
		0xF84469CC38405579ULL,
		0xB57BCFB5F02834E8ULL,
		0x0719557CE279E87CULL,
		0x2838965E21C8C163ULL,
		0xED22A6F617CB7969ULL,
		0xC18F4032DB65DD37ULL,
		0x1A0FB304573F8A66ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89EC9733A165FB7CULL,
		0xF84469CC38405579ULL,
		0xB57BCFB5F02834E8ULL,
		0x0719557CE279E87CULL,
		0x2838965E21C8C163ULL,
		0xED22A6F617CB7969ULL,
		0xC18F4032DB65DD37ULL,
		0x1A0FB304573F8A66ULL
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
		0xA2F6782EF88CF580ULL,
		0x6FA5D1AD28587225ULL,
		0x9ACBA07FFF9B8DBEULL,
		0xB4CA63F6C5C7EBD9ULL,
		0xA7149E5D8F1457F4ULL,
		0x21A6ED5A2BA6C2DDULL,
		0xDA1ED03A016957A4ULL,
		0x4530562A1104A339ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8310C23D3E55DDEAULL,
		0x67DB661EDAD64D8AULL,
		0x0E45FDA71D30109BULL,
		0x674ACCDAD56FC11AULL,
		0x75FD58F2655ACA2AULL,
		0x2F028DC0064A650FULL,
		0x542A184AF28E17A4ULL,
		0x633EACDBAECA1BA4ULL
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
		0x0B23E2AA80CAE14BULL,
		0xEE862B74B13F25A2ULL,
		0x3A972A8DFEB5110FULL,
		0x2C146A9ADDC28588ULL,
		0x62C1C5E520E4485BULL,
		0x69A5550E4B8C00DFULL,
		0x874CE8E3E1B67415ULL,
		0x5568114BAF6DF1DCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2FD19C99586226D4ULL,
		0x21DFC7E3FBEC3F2CULL,
		0x9436C9AA4692F5CEULL,
		0x15BD4990B4E21C06ULL,
		0x69FAEE476FA3FA0DULL,
		0x69E83537E4C496ABULL,
		0x673CE17FB9BBF807ULL,
		0x3B858AD8DE7C7625ULL
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
		0xB7A1A903EEFEB5B9ULL,
		0xE401FB41A887B0B3ULL,
		0xA6EF01896EE128DEULL,
		0xD2BFE10E1FFB187DULL,
		0x1C3E18FC520AFEA6ULL,
		0xFBEA60A7D6734F92ULL,
		0x0BC74628198F5449ULL,
		0xCE6BAD8BE7E2C4DBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5EDC14FBEE17CDA9ULL,
		0xC264FDDD2A6154C7ULL,
		0x1C8F6CED2EA325ACULL,
		0x49BF9E9B92C9AC12ULL,
		0x4EA5C8C9534E52E4ULL,
		0x47DCF4091E4EEDD5ULL,
		0x3AE5A89837905928ULL,
		0x28BB4C24DFCDFAE8ULL
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
		0x4B32882FE870024CULL,
		0x5104A118E7394844ULL,
		0x64DE2EA176350E17ULL,
		0xEED179AC08ED1C06ULL,
		0xD3394CEB3A05EA19ULL,
		0x8F7A5C6335F614A9ULL,
		0xA663F8814BFD10AFULL,
		0x199066B318F22412ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B32882FE870024CULL,
		0x5104A118E7394844ULL,
		0x64DE2EA176350E17ULL,
		0xEED179AC08ED1C06ULL,
		0xD3394CEB3A05EA19ULL,
		0x8F7A5C6335F614A9ULL,
		0xA663F8814BFD10AFULL,
		0x199066B318F22412ULL
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
		0x9978789FB0C2C4C9ULL,
		0xB9AA8D40734D8779ULL,
		0x41F66D01B9C0101FULL,
		0xF7178769EA479820ULL,
		0x0B219C21BBCF33B2ULL,
		0x22A0EC1E812A6E4BULL,
		0x4F86CC178ACF990DULL,
		0xDF30FDBA390BF648ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9723ADD305E59A53ULL,
		0x556A5834E5D95065ULL,
		0xD05B76DF0CC93105ULL,
		0x90E372DCD2AA2581ULL,
		0x1C144BE7538C2EF4ULL,
		0xD7F7756574B01BEEULL,
		0x21B3C28C8577BC25ULL,
		0x09A5FA584D05B3B7ULL
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
		0x49499A497BD06475ULL,
		0xA8BF14B98A1C2C2CULL,
		0x60251D91165F6884ULL,
		0x2EFC3471EFA7BF03ULL,
		0xB3583A51C85D8524ULL,
		0x7F23C1BF691E65EAULL,
		0x706B31E556F66AC9ULL,
		0x5399AD8B7D231A61ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x588C22D5B7030B13ULL,
		0xC1CC8FDC3C605F27ULL,
		0x1E533FE4B95529D6ULL,
		0x6C5508EDF2F1D8EEULL,
		0xE411E4C87D1B0BD8ULL,
		0xF799346740F3AABDULL,
		0x46B1172BF74D10D7ULL,
		0xFB337CD8A4FC67A1ULL
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
		0xFAC4A734A387071BULL,
		0x6671903CFC15A288ULL,
		0xD0C42E7A2CAA9BE9ULL,
		0xA4C36DEFB10308A6ULL,
		0xD5EB3A36512B9A7DULL,
		0xBED8F69214C3E40FULL,
		0xA53A64E8E5DC38C7ULL,
		0xECD21B9E69B769B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6386A7C7957A166ULL,
		0x9CC8DA62DB6EF334ULL,
		0x7333570D3B057F8EULL,
		0x7BADB7D5A642381AULL,
		0xD24E0A4F3AB19C95ULL,
		0xF568F8AC114DC8F0ULL,
		0x64F83645594FF86EULL,
		0x9CE1B26E8EF5AFCCULL
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
	return 0;
}