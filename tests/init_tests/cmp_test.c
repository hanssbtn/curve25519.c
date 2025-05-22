#include "../tests.h"

int32_t curve25519_key_cmp_test(void) {
	printf("Key Comparison Test\n");
	curve25519_key_t k1 = {.key64 = {
		0x45BC40FB08415A5FULL,
		0xC11BCDEA2AC89820ULL,
		0xDD104C614315349BULL,
		0x8FCF57E2BA16ADFCULL,
		0x3C490B5F9109F89DULL,
		0x0A2322A024ABA755ULL,
		0x75598DD94E78A028ULL,
		0x69955CB2D46155AFULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xA8087080B45BF17EULL,
		0x0C132D03044BBB22ULL,
		0x53DE7876BD53C74EULL,
		0xA98037FE73AC9194ULL,
		0x5C9E09A45B4D83ECULL,
		0x5C00D7A387FE8EA2ULL,
		0x18630A7AA345243BULL,
		0x0AE10886ABAC17F2ULL
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
		0x063D30362A2A84D6ULL,
		0x505FC78E11D7AB17ULL,
		0xDF111D11BA39EC30ULL,
		0xA36EDDB2AC65250CULL,
		0xA86E80D48F5741BBULL,
		0x18105877F9E0A7D3ULL,
		0x320BD593223F7325ULL,
		0x799384114A6C53ADULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75E38EDD5C161BACULL,
		0x13020334BFFA7E95ULL,
		0x72F8668CDA339309ULL,
		0xCA69CA09D2DC048DULL,
		0x15A1E1FFD721148CULL,
		0xC92872F98E9BFCEBULL,
		0xE8F87AAB56EFFBF3ULL,
		0xA2C02455524DDD34ULL
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
		0x958C926BE41CF9DEULL,
		0x3C6223784F255023ULL,
		0xBFC7ABBEA6083B50ULL,
		0x2310DDFC2E2736D3ULL,
		0x8F90DB32736D7412ULL,
		0x9A92B3A7088C4415ULL,
		0xDD13A8C21FD56D40ULL,
		0x4CFD5CE7C17AB58CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF51CE0D167C2626ULL,
		0xDE71C62798E38B3CULL,
		0xDCA2A1F6A8CB47A1ULL,
		0x938EE5B6028C39D6ULL,
		0x89FDA3E57648D5E0ULL,
		0xB37D3B942E4A21D1ULL,
		0xEA50D7C86C4F411AULL,
		0x43ED9D9D0E88FC57ULL
	}};
	t = 1;
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x99995EBE0D49793DULL,
		0xB6B44BFE363EE50FULL,
		0x530E0C29D4683B8AULL,
		0x10FA423BDBD53211ULL,
		0xA10E0995F24A8768ULL,
		0xB2D5AC2227133769ULL,
		0xC00799543FE26EEAULL,
		0x7CAED7768641D2C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAF8E61F686249568ULL,
		0x6105DD7E4D2438BCULL,
		0xFB98252DE2DA41CFULL,
		0xE98BC9420774FA41ULL,
		0x6AF2609AF97F67D5ULL,
		0x41EF27EB6895FD88ULL,
		0x5145C03573CB9E38ULL,
		0x3CAA8C7285D2DC02ULL
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
		0xEECC0CC00187B89BULL,
		0xF3F8878A83A55928ULL,
		0x5E3B6F903DCD3384ULL,
		0x9260F0BB2BA0983BULL,
		0x492F51B5981D8CC2ULL,
		0xB184E554A52063EFULL,
		0x2766F1ABBF9039F3ULL,
		0x21A02CAD9C2E68B1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEECC0CC00187B89BULL,
		0xF3F8878A83A55928ULL,
		0x5E3B6F903DCD3384ULL,
		0x9260F0BB2BA0983BULL,
		0x492F51B5981D8CC2ULL,
		0xB184E554A52063EFULL,
		0x2766F1ABBF9039F3ULL,
		0x21A02CAD9C2E68B1ULL
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
		0x5E96B84D5200678DULL,
		0xE5F99E837059A971ULL,
		0xE385D92CAE4DF68AULL,
		0x1AFC9BA29ECDA5A7ULL,
		0x83B798CA8D373C68ULL,
		0xCBE9A46AF4A942FDULL,
		0x035C1AC4975A8746ULL,
		0x68998022D2EAC891ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA28B50F25CB2B45FULL,
		0x892B0A111F4D8C7DULL,
		0xE631F355C6EF2FF2ULL,
		0x7C802A82D9AD6A60ULL,
		0xC70F698A75C7DD76ULL,
		0xC63C48E0168ED04EULL,
		0xC22B629EAB59898EULL,
		0xB119F8FF2527473BULL
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
		0x2A171557934AE8FAULL,
		0x1C013BE24C6F07D5ULL,
		0x3AF32345BCEBB606ULL,
		0xAF8A42A7DF7BC01DULL,
		0x6F6379AE13D91C55ULL,
		0x8D0CC1E8720CF277ULL,
		0x8FA9F7BB04F3FAF1ULL,
		0x9AE631C3EDD51F4AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB181854D36C9DD62ULL,
		0x037F6634913B07FAULL,
		0x0F5EEBB2F424952EULL,
		0xFA84A70D0674EC76ULL,
		0x0652F87EA60A4405ULL,
		0xA8FAB6DE7B9F95A2ULL,
		0x5AEB36C6B6CAD8ACULL,
		0xFA85D3CEF9E04DE3ULL
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
		0x29CDD1162331D613ULL,
		0xFF2B2E79465BE777ULL,
		0x97403B63CFA8087DULL,
		0xE237307F80119AB2ULL,
		0x00962B54445464C3ULL,
		0xF5CD7046F0537029ULL,
		0xF21290E05BAEC901ULL,
		0x59D867493CE6B2E4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BB1CDE0F6E3034BULL,
		0x37850749F4FA102EULL,
		0xEB8CC5733B85A519ULL,
		0xCC8F20E0C97D5FF6ULL,
		0xFD5422383EDF0814ULL,
		0xE40129F244073B15ULL,
		0xEFA71910318530ECULL,
		0xCD7DC2DA240227E5ULL
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
		0x4A89B6A9EF0C0480ULL,
		0x27394D56E3D8AFA9ULL,
		0xE8D72E5AA74A129DULL,
		0xC2E96DF86BEFB4AAULL,
		0x0739293BDD7A38F2ULL,
		0xE6B211DC081CC3CBULL,
		0xBB6C1B976A39CC2AULL,
		0x7BE71F10DC460472ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A89B6A9EF0C0480ULL,
		0x27394D56E3D8AFA9ULL,
		0xE8D72E5AA74A129DULL,
		0xC2E96DF86BEFB4AAULL,
		0x0739293BDD7A38F2ULL,
		0xE6B211DC081CC3CBULL,
		0xBB6C1B976A39CC2AULL,
		0x7BE71F10DC460472ULL
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
		0xDE1DAEFA4128CA97ULL,
		0x6C60BBFD823F0E39ULL,
		0x90CD8F1C56B55DEAULL,
		0x678C9BC6BF8E396DULL,
		0x756F16B052FBB582ULL,
		0x51B3CDB778C1BFA2ULL,
		0x6B5F272982523CE9ULL,
		0x48B81E813ADA9A85ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3E07CF87304A7A76ULL,
		0x93A1F4CF18582F4FULL,
		0x98668603BEF64746ULL,
		0x0E893AFEF5EDD17EULL,
		0x81E533A2B5900671ULL,
		0x02F100E98C863266ULL,
		0x5AA14F85DCDA277CULL,
		0xD4E6FCE3FA0F29FBULL
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
		0xAEB097DDF8B41C1FULL,
		0x239E82E40F170564ULL,
		0xB91BDBB42C3AFF31ULL,
		0x045AB2A3EB10E215ULL,
		0xC6AEB74770FEDED8ULL,
		0xEAB48C469FA3FC39ULL,
		0xB190B6FA11A84589ULL,
		0x92D587C116A79216ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF1A15CCDCDFBC9ULL,
		0x534CBEC54CC9F4DBULL,
		0xF2AFFFF4475F368CULL,
		0x74D42120A546AC9CULL,
		0x65F0D90AB4FFC570ULL,
		0x9BADF2657A03ABDCULL,
		0xB24C65D5451C6C90ULL,
		0x019889EB959445A0ULL
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
		0xFCBC9CBE26F0FDD8ULL,
		0x64DE45B5561B4D6FULL,
		0xCEC01F9B8D35E937ULL,
		0x7D08D0EC1E98D657ULL,
		0x787BF3C1C1CEB9F7ULL,
		0xF92D76E32891467BULL,
		0xE1FF489C6CD93C1EULL,
		0x65BB0907C5E9DA01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3D53DFC59359D2EDULL,
		0x1A67C7B3D348669FULL,
		0x60DBFD6D571CC59FULL,
		0xBA6643CE6F1F1BE5ULL,
		0x2A861F9A4B1F36F9ULL,
		0x61F642380821DB48ULL,
		0xCC2943818C80379EULL,
		0xC008B9EF53E2277BULL
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
		0xE5A3B89CA581915DULL,
		0xE09E37A846EF31D8ULL,
		0x9DCC0E1965ACFD7EULL,
		0x4B641BB54CA0490AULL,
		0x958BFDDFDC44632CULL,
		0x9FE1AC9BFC90F803ULL,
		0x7592739354BC9D6EULL,
		0xF3F080EB6A1CF74CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5A3B89CA581915DULL,
		0xE09E37A846EF31D8ULL,
		0x9DCC0E1965ACFD7EULL,
		0x4B641BB54CA0490AULL,
		0x958BFDDFDC44632CULL,
		0x9FE1AC9BFC90F803ULL,
		0x7592739354BC9D6EULL,
		0xF3F080EB6A1CF74CULL
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
		0x6CB7A454E795468FULL,
		0x262CE9301DD9615EULL,
		0xF23FDA0FF2CE58D6ULL,
		0xE4A8D4E510ECB8B7ULL,
		0x73CCFB34C5FC3446ULL,
		0xB66E915406F14BF7ULL,
		0x244B828D26DAA41EULL,
		0xD7E4647B02CA7231ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA25690B29C5D48B7ULL,
		0xDA48183E9969CC0AULL,
		0x068AAA87AB22E669ULL,
		0xB524CD639C519AB7ULL,
		0xB1B781EDD44D57F9ULL,
		0xB76B914117954690ULL,
		0xB85C47FCE1B7C79CULL,
		0xE9C187EA0E943888ULL
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
		0xA2D2FC2445D93302ULL,
		0x36F726A3110173DFULL,
		0xF5142848E43B1943ULL,
		0x9EC5003D68E35164ULL,
		0xA6AC1E56ED7247C0ULL,
		0x0A21CB642AC3903CULL,
		0x5F99DEDE4D531AFFULL,
		0xD27636355038625EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD41A63744E8795CFULL,
		0x6DB95314BA26EE31ULL,
		0x8E59989BFBFEDD6EULL,
		0x9DC8F82A020DC59CULL,
		0xB3E85B0EDBCBF81CULL,
		0x56466398E42B2D9EULL,
		0x98C9E3016DE5892FULL,
		0xC8F0FF4B28D09E2DULL
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
		0x535B81AEAAB8806CULL,
		0xC3D2120CA7E8238CULL,
		0x4D15F3DB6E4CF5C0ULL,
		0xF953C88D966BAD18ULL,
		0xACCB8943A46321CFULL,
		0x4F52F65B0B9F5856ULL,
		0x8A825F73304DA3C4ULL,
		0x97656F72A2C205C9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FD182F6EEF1A97DULL,
		0xBA271D9AE9B3A356ULL,
		0x3ED3AF57C398B979ULL,
		0x2EC61EC9B46FAEBAULL,
		0x13DFA635979FFCA4ULL,
		0x9FE3C72071EE5E96ULL,
		0x760B6D3F8354ACB7ULL,
		0x18F5E253800DA7D5ULL
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
		0xBC9BBC8863485811ULL,
		0xA4D1BA4AD4F2856AULL,
		0x62DF07A51FD7F0C0ULL,
		0x487BE7E2835A4443ULL,
		0x7FC86C79AC8DD804ULL,
		0x6100E6EE7CA28CD2ULL,
		0x5474775F6D93254CULL,
		0x3B7DA741B2B635D1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBC9BBC8863485811ULL,
		0xA4D1BA4AD4F2856AULL,
		0x62DF07A51FD7F0C0ULL,
		0x487BE7E2835A4443ULL,
		0x7FC86C79AC8DD804ULL,
		0x6100E6EE7CA28CD2ULL,
		0x5474775F6D93254CULL,
		0x3B7DA741B2B635D1ULL
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
		0xEB5635D8F2A5FF2DULL,
		0x5CE4129EBB5A4CB2ULL,
		0x4179D6F58C8B49D5ULL,
		0xAEE17F7DFAE1B84AULL,
		0x3C0D7FCD38A29978ULL,
		0xD4AC7F10A55BDC52ULL,
		0xFA0AC6EEF1B642F8ULL,
		0x0E8F7FBCDB8CE851ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x08127A82A28F8805ULL,
		0x9C400DCD23CEFD5AULL,
		0x1D94F35EC17EB471ULL,
		0xB554AD7E34FA4BD8ULL,
		0x259A6300AF7E585CULL,
		0x1423812D997515D5ULL,
		0xA2488713A1445B74ULL,
		0xBCD044EE97E914BDULL
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
		0x0C55BD11873D5FA6ULL,
		0xA3E1ECAD5F48DBA9ULL,
		0x3036547D003483EAULL,
		0x2CB5502D1BF603FCULL,
		0xDAFD74BA45953BD6ULL,
		0xFDB36D70D8083F57ULL,
		0xB8CE09F9F6528E0BULL,
		0x358D213EE1712151ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBFD0A60C17EA26D3ULL,
		0x4DF0E12BE715954FULL,
		0x2F56F586F7C9787EULL,
		0xCFD875EE7BA46077ULL,
		0x9AF5CD22E8E4A36DULL,
		0x9FC2B12C4A091DC7ULL,
		0xEB72B21A2735C928ULL,
		0xF345440A5878CBBAULL
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
		0x9114C95F74A6A9C4ULL,
		0x99B3996E03D8FAD9ULL,
		0x6B8F6C810CE272FBULL,
		0x52F4EBA60297BF56ULL,
		0xAAA2A4BCA3DD4FCEULL,
		0xF5E5434497765251ULL,
		0x387E25CD48714A57ULL,
		0xA7879C62C5B16F90ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C59883156AE6535ULL,
		0x06463E03AC87E55EULL,
		0x8DCFEBA53228D9ACULL,
		0xD9E8FC8968FD8BF8ULL,
		0x980A96DFD8F9AC32ULL,
		0xD72555AF01FD9107ULL,
		0xB44A82E794F9E14DULL,
		0x042B7F7FA45614DDULL
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
		0x38C3F3829B7979DDULL,
		0x7C9B6910F7C014B7ULL,
		0x67D384A7246EE45FULL,
		0xD0CF856C695F360FULL,
		0x84E3988E1176EBDFULL,
		0xEAB88D112262FB4BULL,
		0xEF69C0FD9F1C028FULL,
		0x66893D0E84156DE4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38C3F3829B7979DDULL,
		0x7C9B6910F7C014B7ULL,
		0x67D384A7246EE45FULL,
		0xD0CF856C695F360FULL,
		0x84E3988E1176EBDFULL,
		0xEAB88D112262FB4BULL,
		0xEF69C0FD9F1C028FULL,
		0x66893D0E84156DE4ULL
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
		0x7EA974F258BB2A1EULL,
		0x1049B5E4666A0FB3ULL,
		0x1AB4B0E612F8E1B7ULL,
		0xAFA2CA078C95F0B2ULL,
		0x570DC079B191CEE2ULL,
		0x01B79BD5F82D351EULL,
		0x77B62A72B87AE9A0ULL,
		0x734161579462F3C6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x275D73BBBD77FDE1ULL,
		0x7D6871949BCD2A6BULL,
		0xF664E24597008055ULL,
		0x557A52EB4F0D7D25ULL,
		0x5516FEC18CD6D1D3ULL,
		0x881E54F3CCE61369ULL,
		0xE84A18EF6EB2C21BULL,
		0x3268161933817C4CULL
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
		0x990225DB60EAA6ECULL,
		0xC32B6801E60395A3ULL,
		0x86B94A225E40294EULL,
		0xDA1EA06DC92FD010ULL,
		0x280B72282DB74FBEULL,
		0xA9597A8C98BD2B93ULL,
		0x5753B8967FD49E2AULL,
		0x4A3DECE696CF5F0FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF35745ECC068C5A5ULL,
		0xBB644A1925EC9170ULL,
		0x0B68209279A4BB9EULL,
		0x60F4659634D33C65ULL,
		0x01D2C08AA536398CULL,
		0x182D7E08CA7E3725ULL,
		0x696D205351631770ULL,
		0x9146EA03FC1B8EB0ULL
	}};
	t = -1;
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xAC27312CB14B5CA5ULL,
		0x5061899BE28586D9ULL,
		0xEBF859424C3709C1ULL,
		0x6270DFBCFD2540DBULL,
		0x146E70FB589FF7B9ULL,
		0xDC7C4C06EC07C427ULL,
		0xF875C6EA22009A20ULL,
		0xD29FF698C9066DE9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x271451DFD2EC4528ULL,
		0x249948BDBA1B12D1ULL,
		0xFECFA13BE01925B1ULL,
		0x2C06AE150FA678D1ULL,
		0xFB17810A84705E9AULL,
		0x1759D0EE5AFE6D81ULL,
		0x8DB2ECAB8FF9E9A1ULL,
		0xBE86F1749A816EC9ULL
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
		0x95D958B762DBCF2EULL,
		0x6C10E427A1E10F90ULL,
		0x831AC42C59C9CF52ULL,
		0x677E7B23D896E27FULL,
		0xD74E4C57D4BC34C7ULL,
		0xAC4F2DD8D2B45BCEULL,
		0xC07D800B48F584DBULL,
		0x917EAF4A1BD39B9AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x95D958B762DBCF2EULL,
		0x6C10E427A1E10F90ULL,
		0x831AC42C59C9CF52ULL,
		0x677E7B23D896E27FULL,
		0xD74E4C57D4BC34C7ULL,
		0xAC4F2DD8D2B45BCEULL,
		0xC07D800B48F584DBULL,
		0x917EAF4A1BD39B9AULL
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
		0x478359B91A0CD463ULL,
		0x834F3497789BD511ULL,
		0xE2DC7A090FC49990ULL,
		0x7B365CE99B46459CULL,
		0x3E20393F4A33D698ULL,
		0x5F826DB638E0104FULL,
		0x2CD26C912D75E552ULL,
		0x3B45D35A2423BD08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FB7B1071533D9EFULL,
		0x3930ACFBAEF7A111ULL,
		0xC2EFE259460752C5ULL,
		0x3947CF4CADB69CD8ULL,
		0x80A514CD26A58E08ULL,
		0xDC0E02F1C10E0FCEULL,
		0x64B6A9B73D9AEFD8ULL,
		0xA6553518D6EA2112ULL
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
		0xD0CFC00459812370ULL,
		0xC0CFF90DD8953002ULL,
		0x73B0C8F6E88F4F02ULL,
		0xCE83E02991E2BEACULL,
		0x95EB2E6BE2FB9FE0ULL,
		0x69DA9709F38460C3ULL,
		0x2C6DD4D3EECDEDD0ULL,
		0x2B217D657FCCEEB9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCA9B5A233C2C6562ULL,
		0xB482D0FCA8FE5BA5ULL,
		0x37D833524497899BULL,
		0x616F82166FA39C83ULL,
		0x6AC4D5616D12BA6AULL,
		0x5EE49AC07B9ECA87ULL,
		0xFA09A454183F2CA9ULL,
		0x68665DD356842098ULL
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
		0xA7A546A99D36F377ULL,
		0x8C20E9C2CCD3E015ULL,
		0xE1AECC2BEE571C8EULL,
		0xDFF2A0DDA86D7CDDULL,
		0xD480FB973656F27DULL,
		0xCF7B45D9F9FE9CF5ULL,
		0xB3CD72D6FB4CF8C4ULL,
		0xCE315B6D048B036CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD05B0136EE15FE1BULL,
		0xE0CC12C2FC762FD5ULL,
		0x50EB540303913F77ULL,
		0x475CC17A8C8C2C96ULL,
		0x10327A5C67F7C323ULL,
		0x26924F148D5B878EULL,
		0xE08926A48FE83475ULL,
		0x8CC8691B55882678ULL
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
		0x8B824EE5758F9B02ULL,
		0x8A6665C67DEFFE87ULL,
		0x6E64E88F2CD71847ULL,
		0xFF47D293F508EE97ULL,
		0x1D39DDE165391BA7ULL,
		0x2DFF1FAE2BE22029ULL,
		0x417756D4BFD9F244ULL,
		0x4E993D6A06B6AD87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8B824EE5758F9B02ULL,
		0x8A6665C67DEFFE87ULL,
		0x6E64E88F2CD71847ULL,
		0xFF47D293F508EE97ULL,
		0x1D39DDE165391BA7ULL,
		0x2DFF1FAE2BE22029ULL,
		0x417756D4BFD9F244ULL,
		0x4E993D6A06B6AD87ULL
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
		0xB52CE84266B8DAD0ULL,
		0x6A6F8CF0914E2A4AULL,
		0x6849B43AF14ABE0DULL,
		0xEF9775F158F75211ULL,
		0x1E2249F910B867C6ULL,
		0x648D901CC57B12DEULL,
		0x493EC84F7158A1AAULL,
		0x4EC28FF6C67BA460ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x02ECF117433DDFF5ULL,
		0xF1074B685D088CEAULL,
		0x67E52C9375813769ULL,
		0xE29D30AA6F5BBEC5ULL,
		0xA80B77B28E31AEFBULL,
		0x859A499605EE3F65ULL,
		0xB7E8AE5FCD459B60ULL,
		0xDA5C282B9AFD074FULL
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
		0xD1F0FB37CE8DE8FBULL,
		0x26309E16A487B7F8ULL,
		0xE2384019970A7EC1ULL,
		0xAF3C21AD888B51A2ULL,
		0xA581D95CABE2E1B6ULL,
		0xA6F976421578DCF0ULL,
		0x63FCC6FB271B0905ULL,
		0x4FDE372CD42C9EDDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x522E2A5EBB2FC3B4ULL,
		0x339F51800A8D1B14ULL,
		0x5D4B1FBDE4B18AAAULL,
		0x58F2FB003A564159ULL,
		0x05A1E9BF3625302EULL,
		0xF58B4C3951BA3D2EULL,
		0xE0F31F36E287F296ULL,
		0x8F313E4E108BB427ULL
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
		0xFE2C6F84B910D8C2ULL,
		0xA7F450EA2BD2A97DULL,
		0x05E120CDBE48896AULL,
		0x8F49DF862D4FDD4EULL,
		0x94090B9D3BCE822AULL,
		0x1E363A8668F6A88AULL,
		0xFF8AEEB5BAF1E911ULL,
		0x1B50045C3B38AAE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19DB2B321AE3B053ULL,
		0x0E099404ADB252ECULL,
		0xFB0EF972289844F2ULL,
		0xEA8BB242AA98C4DCULL,
		0xCBEA3E2D7E694F1CULL,
		0x4931513BEC3E2782ULL,
		0x684DB7877797E066ULL,
		0xD00253B8E7AA0EFCULL
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
		0x5940CC0D793FDA16ULL,
		0x2DD5DCA4E2079997ULL,
		0x550535E207BFA50CULL,
		0xD2ED192393A07431ULL,
		0xDC13C01DB2CF093BULL,
		0x27C565CD27B38756ULL,
		0x2604DAC4B64F9978ULL,
		0x3501E767449C6C94ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5940CC0D793FDA16ULL,
		0x2DD5DCA4E2079997ULL,
		0x550535E207BFA50CULL,
		0xD2ED192393A07431ULL,
		0xDC13C01DB2CF093BULL,
		0x27C565CD27B38756ULL,
		0x2604DAC4B64F9978ULL,
		0x3501E767449C6C94ULL
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
		0xDF68C25A57F105FCULL,
		0x7515930CFDD5C8E7ULL,
		0x7FFF8FC93E31C769ULL,
		0x92C9D866C42580A2ULL,
		0x19BA950957F97724ULL,
		0x4E21C2271FF80EFAULL,
		0x9DDD0F83FCBF580BULL,
		0xA0B3A73C4FFBF185ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E3108C9AD80BAE0ULL,
		0xB33F3289CB959547ULL,
		0xB210ADB0289FDC2DULL,
		0x141653BC53D91BECULL,
		0x02CEBED794AB5D30ULL,
		0xA951476F0A7C0524ULL,
		0xC596CA2D09A1B06DULL,
		0x3595FD74316FA876ULL
	}};
	t = 1;
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xF58C914FC8D89F59ULL,
		0x67C22D0BFE7B15A0ULL,
		0xC327B1EE26250F46ULL,
		0x25EE25DE2CFAFA58ULL,
		0xB65A01534C77A1A7ULL,
		0x2756FFDF7E5993F3ULL,
		0x7CA2D3EE3E804F4EULL,
		0x7D4ABCA438F3B609ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4C3009F99D5B3A86ULL,
		0x23C25BCEEA647F04ULL,
		0x0A0623C1820B1524ULL,
		0x1E4FA9AB336E1C4FULL,
		0x3362773C9032894DULL,
		0x5F9E4F12A3B31E0FULL,
		0xD6332EE10E12C2B4ULL,
		0x880F39E5FA52D5B1ULL
	}};
	t = -1;
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x792078068F9E6029ULL,
		0xD4D63DD80690638DULL,
		0xCB861991A9BA4518ULL,
		0xE53E7D8152221263ULL,
		0x82BE82073783CC09ULL,
		0xEF588F5F3E14957FULL,
		0xE02667B56EBDB989ULL,
		0xC37B27590C87C842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFBF7062CD55AEB2BULL,
		0x15723062D0B83976ULL,
		0x3A11800A31263EC3ULL,
		0xCF7B0D9BF5B543C5ULL,
		0x7BA18492E2AE8510ULL,
		0xDBAC755E44A75869ULL,
		0xE97C52089A836E74ULL,
		0xAA9A12FCCF2C1DD6ULL
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
		0xE1D850F3B7994469ULL,
		0xBC109DCCF9463C4DULL,
		0x6C2C7F5A4997DD15ULL,
		0x057C34FE82D139F6ULL,
		0x6FD0D02C471D7803ULL,
		0xC4CA53069B852731ULL,
		0x6C6E66DCBD22C287ULL,
		0xBB44AA7A9912D57BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE1D850F3B7994469ULL,
		0xBC109DCCF9463C4DULL,
		0x6C2C7F5A4997DD15ULL,
		0x057C34FE82D139F6ULL,
		0x6FD0D02C471D7803ULL,
		0xC4CA53069B852731ULL,
		0x6C6E66DCBD22C287ULL,
		0xBB44AA7A9912D57BULL
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
		0xCB15F4E8B80AB064ULL,
		0xC04C7595525B0A04ULL,
		0x621B9CACBBC9622DULL,
		0x47DAE6BD6EE2E4F7ULL,
		0xEE09B1C61BB98783ULL,
		0x52418F0C99031239ULL,
		0x6ED52B789FAFC057ULL,
		0x738F9B547468D6C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B7936BC3BF50EFBULL,
		0x0474F451D003C7B1ULL,
		0xF2EE47CC2E3CD02BULL,
		0x608AE774A9404FFEULL,
		0xBF4511F7773C9562ULL,
		0x5A56E27437BE4CDDULL,
		0x298E1BAC3F36847FULL,
		0x94EA96D9AA5AF8A3ULL
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
		0x7E535954E992F0DBULL,
		0x35DD383769A44B00ULL,
		0xDF6F8E9D93F6EA52ULL,
		0x7615A2D73F9B84B4ULL,
		0xE750192B73C48D4BULL,
		0x27457C3AC93DB075ULL,
		0x8956427992FCAA8AULL,
		0x50239093B6EAB81CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCE20163BB2E91AA9ULL,
		0x10FD0FBCC2F4787DULL,
		0xA0A807DABFCCA106ULL,
		0x137295D4B08A75A0ULL,
		0x9F82935C136F5429ULL,
		0xAE84328B21E1C78FULL,
		0x84C9AFC1CDB48B9AULL,
		0x28BA3F2BE532E03AULL
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
		0x6C0EF6EA438DCC6DULL,
		0xDFCBCC46C140F9E8ULL,
		0x8BE576C8C9C3034DULL,
		0xC478F974F8CA1768ULL,
		0x1BB30EEBAA865C60ULL,
		0x92098C925B282246ULL,
		0xFE2DAE3A905292F9ULL,
		0x3C356F1ABDC51D7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2430EDB26495ABDEULL,
		0x90E70DD5A350EA94ULL,
		0x58D10FD8492C4634ULL,
		0xC324CF47EA274045ULL,
		0x522A8635CBD6DF03ULL,
		0x489C03DDD1107A97ULL,
		0xBC88FAF95C6E7981ULL,
		0x2426A7EA22D9E02DULL
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
		0xEB5EFBF8AC003711ULL,
		0x8FD4A0B14CCA3959ULL,
		0x68821189EB8C8B0AULL,
		0x0281D320033737BCULL,
		0x8FD8CC26474DC3F3ULL,
		0x3F537991E35BCFB3ULL,
		0x99887F3601F8E015ULL,
		0x0597773E6F8289D8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEB5EFBF8AC003711ULL,
		0x8FD4A0B14CCA3959ULL,
		0x68821189EB8C8B0AULL,
		0x0281D320033737BCULL,
		0x8FD8CC26474DC3F3ULL,
		0x3F537991E35BCFB3ULL,
		0x99887F3601F8E015ULL,
		0x0597773E6F8289D8ULL
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
		0x8720F2E091237B36ULL,
		0x3955B4B0A7DD0A48ULL,
		0x599EB2AAC92E51C0ULL,
		0x35874B5D055D8E7FULL,
		0x679239E3C127A5ACULL,
		0x226E4E735ADBE920ULL,
		0xD02FFC717B45EB63ULL,
		0x33BDF3A3FF00C44BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC00076E487CFA838ULL,
		0xCC93D152AEB2E1B6ULL,
		0xE4806C192547C762ULL,
		0x9F24A4C62E8AFE20ULL,
		0x4C0FE8497A465E0DULL,
		0x3F0262E7118736B4ULL,
		0xCBEC410FED29C68FULL,
		0xEDEC181D69A285E9ULL
	}};
	t = -1;
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x0349527B7E810158ULL,
		0x86016D75C09D29A1ULL,
		0xEC65B5D8110BB661ULL,
		0x24897E7459D6688DULL,
		0x95E14DCE96AA5325ULL,
		0x522DC9BFB56AF555ULL,
		0xC65BCB7EEB0A056EULL,
		0xD87AE4CAED0DFC63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC47CEC09F2A6C747ULL,
		0xECFA592548098B84ULL,
		0x0644D780F1265846ULL,
		0xCB334040F8E5F5DEULL,
		0x81DA3D84478EDD9DULL,
		0x9D212EEA70D4AEF5ULL,
		0x018E0EF7D1C44FB0ULL,
		0xB61ECC13DE996D85ULL
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
		0xD5F6B08BD537A0DEULL,
		0x6D803EA5DDAAEB3DULL,
		0xDBD9FD99C6DF3F72ULL,
		0xF549B858FB507CFAULL,
		0x3B7F6F55C61E86B3ULL,
		0xA5462E9376FDA92FULL,
		0x401E94B036784AECULL,
		0x7620C94C3927809FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC31C15252862ED2CULL,
		0x46609932AB5C1A36ULL,
		0xACCD5714FF1819E5ULL,
		0xACDD1380243F6309ULL,
		0x36985FAB476F5757ULL,
		0x89E07E47C8C20578ULL,
		0x483206596F37BB79ULL,
		0x7BC37CF3F1226371ULL
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
		0x7BCA5D715792B545ULL,
		0x1ABAA691D136FD91ULL,
		0x3D29BC1D687A32A3ULL,
		0x5D982BC8EA76E7C3ULL,
		0x54F09720379B600AULL,
		0xD67ABEBD20030AB4ULL,
		0x2B0F91F1ED0AAABFULL,
		0x8AE29AD234A657CDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7BCA5D715792B545ULL,
		0x1ABAA691D136FD91ULL,
		0x3D29BC1D687A32A3ULL,
		0x5D982BC8EA76E7C3ULL,
		0x54F09720379B600AULL,
		0xD67ABEBD20030AB4ULL,
		0x2B0F91F1ED0AAABFULL,
		0x8AE29AD234A657CDULL
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
		0x802DCB21E21215F7ULL,
		0x770827DF543FFA77ULL,
		0xC4FA76CD00E49708ULL,
		0xF7A478D60FD3B37AULL,
		0x18200695709BD35BULL,
		0x985B3F3AD77139BEULL,
		0x21F0A812F340B5ABULL,
		0x12385433F344C63CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2366E2E56CDCACC0ULL,
		0x03B9316417B32868ULL,
		0x7D05FAA2A68C629DULL,
		0x05C3DCE31024A60EULL,
		0x2785A3BBE55C2226ULL,
		0x2B6989D963F767C3ULL,
		0x44E023A3CA29CC9BULL,
		0xC2A0852B1225EF35ULL
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
		0x4BA197D3D0A0DA90ULL,
		0x761120D5967C1B74ULL,
		0xA3FE8F7B464E1F61ULL,
		0x90A30C024C50C18FULL,
		0x1EBD5CC53A169C15ULL,
		0xFA62F48A28AB2DF5ULL,
		0xA0E1BF217DE0EF94ULL,
		0x8C35F37D9EDADCC3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F0CAC1D277AAA86ULL,
		0xA9626FEE3267396BULL,
		0xAA0F722001578ECBULL,
		0x191A80840BAE08D7ULL,
		0x18080D0B8D598568ULL,
		0x7715B6F8AC504E59ULL,
		0xDC9CE9537750DC70ULL,
		0x73BE207356297D09ULL
	}};
	t = 1;
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xD25AE46954BAC72CULL,
		0x39059454126EA340ULL,
		0x5967D5361F414615ULL,
		0xFF4BA8D4685D99EAULL,
		0x2CB6CE677BEC9524ULL,
		0xF0CC57599DA5F795ULL,
		0x1F58B0107A68F992ULL,
		0x30C9B8DAC286C8C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD328F8EEB8E381CBULL,
		0xF941129F6C24E93AULL,
		0xDC02EF40D984E74AULL,
		0x756500E59718F900ULL,
		0xA6AAF05D8688ED97ULL,
		0x9B50241EB31D40C9ULL,
		0x0BDB0FF15CA0D4CAULL,
		0xCC10FD56F8DA695FULL
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
		0x18A60BA7860E3E74ULL,
		0xE69FC483DC723BA5ULL,
		0xBEC79BF46C0682F1ULL,
		0xF2AC6E25135091E1ULL,
		0xE2873CE3321F42C6ULL,
		0x986290330E1D29D7ULL,
		0x1B67837302BD43ACULL,
		0x415E93C603803264ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18A60BA7860E3E74ULL,
		0xE69FC483DC723BA5ULL,
		0xBEC79BF46C0682F1ULL,
		0xF2AC6E25135091E1ULL,
		0xE2873CE3321F42C6ULL,
		0x986290330E1D29D7ULL,
		0x1B67837302BD43ACULL,
		0x415E93C603803264ULL
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
		0x353CB71AB4934F06ULL,
		0x4C5BB8AA53783125ULL,
		0x0BC4AD3EFE6C7A4EULL,
		0xBB642781B45CC4A4ULL,
		0x84E6454EDDC67B68ULL,
		0x52A14F36A5E25656ULL,
		0x5F28233D108BB14FULL,
		0x89ED713200AB2A09ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C57CE50F85606D1ULL,
		0x8CE9959500A928FAULL,
		0x5A738393008831F6ULL,
		0x0C2453218DB9898DULL,
		0xBA8D355A8FB100E3ULL,
		0x0AEB5E65DAFF4384ULL,
		0xAA9DB80C70176FF5ULL,
		0xBFB4DF5380BDFA69ULL
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
		0x15274B3884A1F0DFULL,
		0xE3A1C071D11202A3ULL,
		0x03BD5F17B7B035ADULL,
		0xDF313B53A94E3408ULL,
		0xCA98E161E0C9C7BFULL,
		0x27B27603C2D7AC9BULL,
		0xCC9EABBCC85155D2ULL,
		0x9A26EE7191ACCDE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFFD975ED91DE7C4EULL,
		0x7452955CF3026406ULL,
		0x3F5EF178D75E18E6ULL,
		0x6B796ED1C6F3523CULL,
		0xE516D29100313BEDULL,
		0x17993CB5481C54F5ULL,
		0xA6F0B0EB4D2F8964ULL,
		0x5D11A10C05787C25ULL
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
		0x485911EFF35CEF20ULL,
		0x8EDBA2BB32011189ULL,
		0xC98B1F6CB0C11B63ULL,
		0x9E92F7F6DB0BF044ULL,
		0x387D9DA80EFE702BULL,
		0x60067FE8357AE50EULL,
		0xF89AD18A9754F368ULL,
		0x2F923939CDA0CA63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x013503F66E413298ULL,
		0xA10C13D4E669BFE7ULL,
		0xFDBC7B83E835E8F0ULL,
		0x064A8A1BC523E761ULL,
		0x40F38825C63D3C7AULL,
		0x3178F450038D2C3EULL,
		0x16DC8D20460F01D2ULL,
		0x37A69F314DB61FFEULL
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
		0x34E2689C364CB73DULL,
		0x8648BE1EE5889EBBULL,
		0x49E9AFEB37EBF714ULL,
		0x1C1CC9D4234D277AULL,
		0x2CDBECB3E5B639B4ULL,
		0x2292E94747826D64ULL,
		0x03E6B23A55CBC31BULL,
		0x106E0783A601FC42ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x34E2689C364CB73DULL,
		0x8648BE1EE5889EBBULL,
		0x49E9AFEB37EBF714ULL,
		0x1C1CC9D4234D277AULL,
		0x2CDBECB3E5B639B4ULL,
		0x2292E94747826D64ULL,
		0x03E6B23A55CBC31BULL,
		0x106E0783A601FC42ULL
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
		0xF228B92EA6E3EDC1ULL,
		0x901721386D6BE533ULL,
		0xCBDECF1132848400ULL,
		0x6C5A78203EA615E4ULL,
		0xD19D7CA8F432DCBAULL,
		0x4E60AC03D6D2128AULL,
		0xECA5E7A0715BBFD1ULL,
		0x93602E0A4713D2D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F286C206D930622ULL,
		0xE8010BFF82A7232DULL,
		0xB87CEF9707F9CE3AULL,
		0xA9B0512F33365669ULL,
		0x532E34CCF2896323ULL,
		0x23EF627B7AD636BBULL,
		0x1509441CEB92660EULL,
		0xECDCD5322B658D9FULL
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
		0x2FB9D1AA9B343DCAULL,
		0xD5D1C16C3B1D830DULL,
		0xC86CB88AF2D9ACE9ULL,
		0x72EA7B9FA98C6B6AULL,
		0xA9642A150BEA502EULL,
		0x0851A553E2A44BDCULL,
		0xB5B83409AB3C1B73ULL,
		0x69D178528E30BC95ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0510C6A729189C5ULL,
		0xA57639DC5501BC9EULL,
		0xDAD5DF3368FA4AEBULL,
		0xA9DD43E8BFA8C58BULL,
		0x5744B8EA7F526B89ULL,
		0xF8B72A8BF15EAEA6ULL,
		0x4FB4E2927516866CULL,
		0x003544D8609305A4ULL
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
		0x821FF00B3286898EULL,
		0xB93E8CD5C7F37DF8ULL,
		0x99999106AAA3D3A9ULL,
		0x51FEE9410AA2268DULL,
		0x86521CB93E651478ULL,
		0xED283F33A879BC3BULL,
		0x3CCA302159644CFBULL,
		0x77CAC2FAFC0E2012ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF572068FC5083A25ULL,
		0x23D9454807BE8BB0ULL,
		0x9CAB335047B0FECFULL,
		0x80397485994BC994ULL,
		0xB298A5324D86A461ULL,
		0x5A7681D08924F814ULL,
		0x0D5166915AFDE9CFULL,
		0xC9955128C5C7CEA1ULL
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
		0x54E7419A561C3E6FULL,
		0x3DC5841ADEA227A2ULL,
		0xEFACC815E8BA39FEULL,
		0xDEF26AD74EECAE71ULL,
		0x3833D7DA9CCBB356ULL,
		0x54747D85BF8C024CULL,
		0x2252B90A31594BC0ULL,
		0x823B07B404E9D3FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54E7419A561C3E6FULL,
		0x3DC5841ADEA227A2ULL,
		0xEFACC815E8BA39FEULL,
		0xDEF26AD74EECAE71ULL,
		0x3833D7DA9CCBB356ULL,
		0x54747D85BF8C024CULL,
		0x2252B90A31594BC0ULL,
		0x823B07B404E9D3FEULL
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
		0x46207E5661F6D52EULL,
		0xF1B4E9486528171BULL,
		0xFED352047608C6C1ULL,
		0x23B288F2DE8C3058ULL,
		0xC14D4211C45CF87CULL,
		0x8B84F4359D1D9CA1ULL,
		0x1757DDA1A6BEA34FULL,
		0x46D8CBA67190B7F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27E965C46B17113EULL,
		0x8BFE1451CB5FE5C6ULL,
		0x3FB6134B6085DF19ULL,
		0x4CE01A54D1A1E240ULL,
		0xE001961DB70C0B9AULL,
		0x65E79D8BF2347FFEULL,
		0x71B079CD55BB12E5ULL,
		0x0A0F27652844F5CFULL
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
		0x02B7BCFFFD8CF82DULL,
		0x62BD916273056F88ULL,
		0x8BA673A1EF3353CDULL,
		0xE09A9B8C4A554E55ULL,
		0xB6AC5116634897CBULL,
		0x00FCE759D60D748DULL,
		0x828B2C80B55F6559ULL,
		0x73D9058C2255C1F7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63993C7855900135ULL,
		0x3135D09B036F7795ULL,
		0x2ECACDE203C38513ULL,
		0x3ECEF66E8B4A65F0ULL,
		0x8F191BE075BEFC40ULL,
		0xB50AB7C838F780F5ULL,
		0x3DB96E7D8AE13E39ULL,
		0x2209DD6E4EB0AB20ULL
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
		0x6AB9B254F3163EC4ULL,
		0xF75BE975E2F192DBULL,
		0x6D3345A1948CCA73ULL,
		0x5E7CBA16BAD4D730ULL,
		0xD4BECE576C038CCBULL,
		0xE08EF3D15596D1A4ULL,
		0xA46327B479C47B0FULL,
		0xE6A85EBFADA56910ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45373B5A30B7435ULL,
		0x7C3515BAA8E90D59ULL,
		0x3B8A712862FD2A44ULL,
		0x12A2581DB1842FDBULL,
		0xFC7F75137FB45659ULL,
		0x35EE59DC697D8C7AULL,
		0x3BEE14EE1EF96C45ULL,
		0xC6D5CD9481FA6CE7ULL
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
		0x8407EB445E0DEA9EULL,
		0xE3FC54BC0FC9CD12ULL,
		0x352B815A85660195ULL,
		0x9AEB7ACC66578674ULL,
		0xDF0B2264BDFB0A7CULL,
		0xB067E5C12427693EULL,
		0x519BD4245E501A67ULL,
		0x83B7E82271950D0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8407EB445E0DEA9EULL,
		0xE3FC54BC0FC9CD12ULL,
		0x352B815A85660195ULL,
		0x9AEB7ACC66578674ULL,
		0xDF0B2264BDFB0A7CULL,
		0xB067E5C12427693EULL,
		0x519BD4245E501A67ULL,
		0x83B7E82271950D0AULL
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
		0x905D1795C1B7BE08ULL,
		0x77EE186CDE683524ULL,
		0x3A074C4350625DC9ULL,
		0x5D5F824640AD113DULL,
		0xB0E2E11BE50ECBBEULL,
		0xE6FA118112A03CDEULL,
		0x1F68AE66B9BF6AD9ULL,
		0xCA4AB05231713661ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E0D75D999B34B56ULL,
		0x0E73B26519710A09ULL,
		0xD0D34BDF1A69E5C4ULL,
		0x2E5E61C5856FDFF1ULL,
		0x5B696435F3DD99E3ULL,
		0x70641E928A6B3DD6ULL,
		0x32E835DB987C9B19ULL,
		0xE98EA53DCE0F7B4FULL
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
		0xB5C49DB24FFDC98BULL,
		0x284349B1BB8C7FFBULL,
		0x41DAE0418411BEC0ULL,
		0x6C0C4CF4A999C5F3ULL,
		0x71D051310A1512D5ULL,
		0x64BD6F6E681C0B68ULL,
		0x547F06EB522A0BEDULL,
		0x4633C527E13DFCB5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x493C56B5BBE42E91ULL,
		0xA8CCB776712380E2ULL,
		0x87D856770A6A7077ULL,
		0x0D1AFAFF10821ED2ULL,
		0xA9293BC4FFF4FBC2ULL,
		0x82713DECFF621832ULL,
		0x4B683A6C415AD659ULL,
		0x5CE6039A55F00C1AULL
	}};
	t = -1;
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0xA9D600DCA338F233ULL,
		0x7DF3414C9260FE49ULL,
		0x048A5F54758BBC3BULL,
		0x5DA7FC5BCC70AE54ULL,
		0xF6248F01198022B5ULL,
		0x6C2C587243E9465BULL,
		0x2314AB12EA2E18BAULL,
		0xF910D02AE83215BAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF801F96779ABF7BULL,
		0xBE4DECF39EF8E49BULL,
		0xE934A7F24FD45A89ULL,
		0x66CBC13BA6298AD0ULL,
		0x06E8AD63762F6EA3ULL,
		0x74EBBCD4B4CDF95EULL,
		0xC2BFDA868B527B25ULL,
		0x40100F82EA5A228CULL
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
		0x92A6F1CB90A49401ULL,
		0x9C510B373743EF8EULL,
		0x43673E0F85F7E733ULL,
		0xE267655FFEF69305ULL,
		0xE55B71CFA48B308AULL,
		0xCC4DF87E7246D06BULL,
		0xDE8D10E6990714A2ULL,
		0xFC07EBF86DC6BA9DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x92A6F1CB90A49401ULL,
		0x9C510B373743EF8EULL,
		0x43673E0F85F7E733ULL,
		0xE267655FFEF69305ULL,
		0xE55B71CFA48B308AULL,
		0xCC4DF87E7246D06BULL,
		0xDE8D10E6990714A2ULL,
		0xFC07EBF86DC6BA9DULL
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
		0x5A261E95EDBC26D0ULL,
		0x230272D80C3C0BE5ULL,
		0x0CF9D5FD9F6531BAULL,
		0x5F1CDB77158226A4ULL,
		0x5471BBC3E59D7CCBULL,
		0x5D72430D475E133CULL,
		0xF210E5542327BCB0ULL,
		0x550906105BE4EB9EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2E01C5573CB87818ULL,
		0x42DEEA562DC7F8E3ULL,
		0x8A84ED2B5DF70121ULL,
		0xB5C3109249398744ULL,
		0x6EF29AB12051EE38ULL,
		0x9A4F86CA04019954ULL,
		0x28AA51516A558D7FULL,
		0x526FD8FFEC2455BBULL
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
		0xF47763E88EF5BB88ULL,
		0xCAF5073A825DBA20ULL,
		0xDA3E41BF87DBF8D4ULL,
		0x73DAF8701B9974EDULL,
		0xC9FD881C03253BE0ULL,
		0x61AA867308C91765ULL,
		0x0B6FA7D21C585B1DULL,
		0x87612D2782EED007ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBEC1BFADEA0494DBULL,
		0x2E05739D3A1D81D8ULL,
		0xCC555D81D601EB56ULL,
		0x72443E4589EE7786ULL,
		0xCBCC317E552158A7ULL,
		0x93278BB00F9E3267ULL,
		0x18DCD4E3138A648DULL,
		0x234EE811EE9A8D75ULL
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
		0x1613C98D7DD6BF3BULL,
		0x309562ADFE164403ULL,
		0x56F58C2DA10DAC54ULL,
		0x5E3741AEC63FC3D5ULL,
		0xF58A061831E624D3ULL,
		0xFD2CD834AC5DA60AULL,
		0x2297B205E10B92F7ULL,
		0x5DE7D1DEB6472232ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x555AB83AA2AFE1A3ULL,
		0x9FB7DF45F0CF838CULL,
		0xE0F4C9BFD729400CULL,
		0x2375065880F9E9ABULL,
		0x8F7A9A9847930FBDULL,
		0xB1A832CD9EF307F0ULL,
		0xDE7D5326F1B65627ULL,
		0x9F27AD4898C6CA6FULL
	}};
	t = -1;
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x8136810483C1E126ULL,
		0xE127F7903867E14EULL,
		0x7D012B0CBEAC5BD6ULL,
		0xCD93073FECCFDA66ULL,
		0x7B45966C176D75CBULL,
		0xA2B6FB062769ABC7ULL,
		0x43ECB266A4985C72ULL,
		0x5C735231589ACD49ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8136810483C1E126ULL,
		0xE127F7903867E14EULL,
		0x7D012B0CBEAC5BD6ULL,
		0xCD93073FECCFDA66ULL,
		0x7B45966C176D75CBULL,
		0xA2B6FB062769ABC7ULL,
		0x43ECB266A4985C72ULL,
		0x5C735231589ACD49ULL
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
		0xDF65DF7DEAF74377ULL,
		0x071B63111A2C9E0BULL,
		0x52855D41AB0C3147ULL,
		0x100FBEC93A416D25ULL,
		0x282A33C21F2DF309ULL,
		0x6B251A28738EF0BBULL,
		0x0AAE3A2EF2DEB067ULL,
		0xFE2F95D78FB5D53AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5955D01C46629914ULL,
		0x6F2627C1016AF9B4ULL,
		0xC4CD433D21CC9F75ULL,
		0x4215DCEEABA4E16AULL,
		0x2002D5658ECD6C11ULL,
		0xABB52CB1C4AF7BECULL,
		0x2379CE7CE237B4C7ULL,
		0x36AC1EB182E465B5ULL
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
		0xE7923D610E5D7FA5ULL,
		0x889E574BFA657E1EULL,
		0xC9B1397DEDAA6754ULL,
		0xBA269F29850EE4B4ULL,
		0xD98D619B10865ABDULL,
		0x7CECDF39F13D3F14ULL,
		0x1F84C67466B44707ULL,
		0x544AD651C18CB83EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9728E4B8968B8E80ULL,
		0x9BAE6B1F49C45DD9ULL,
		0x4B23C6679F1901FEULL,
		0xF70E2875A9F095B5ULL,
		0x7922DD3AAED8E75BULL,
		0x1507C53E7070AF21ULL,
		0xA877E235962E9784ULL,
		0x40709D69F28F9163ULL
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
		0x4253F6F0F6411AA4ULL,
		0x2DD7FA9D146E97DFULL,
		0x37AA945B8B9D2FF2ULL,
		0x63F800F13ECBDE7BULL,
		0xAF7D9F4A37BC0594ULL,
		0x2F1D9E11DDA15E5AULL,
		0x4940BD966B8E2580ULL,
		0x2B3657DC728C6853ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2064F6564968886ULL,
		0x8E20B3F453BCA25EULL,
		0xC881EFFB6CE9A7BBULL,
		0xE858A763C77DF246ULL,
		0xDFEB995BB3D88E00ULL,
		0xAD2DCCB1F8048FC7ULL,
		0x71CBEFB7CA5E6317ULL,
		0x37E59E84A7A6041DULL
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
		0xD56CDA01C58A1629ULL,
		0x4D6FFD3447003805ULL,
		0xBD0FE0B7C3B22C01ULL,
		0xF5B4E323E4B96A9DULL,
		0xA10A361ED3A69B8DULL,
		0xCCA2904EBEB50942ULL,
		0xABFBE2AA212DB20BULL,
		0x0DC09EF0E2167C7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD56CDA01C58A1629ULL,
		0x4D6FFD3447003805ULL,
		0xBD0FE0B7C3B22C01ULL,
		0xF5B4E323E4B96A9DULL,
		0xA10A361ED3A69B8DULL,
		0xCCA2904EBEB50942ULL,
		0xABFBE2AA212DB20BULL,
		0x0DC09EF0E2167C7CULL
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
		0xE65962AF6CC1DC77ULL,
		0xCC95E8BBD1023D1BULL,
		0x5B6D883EDE4169A1ULL,
		0x613AFBA5E96F42BDULL,
		0xFB315940C6E7A203ULL,
		0xBE06025DC610950BULL,
		0x5E85459C7A2C51C7ULL,
		0x77992DAEA77034CEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4327FD5BB17A2A7ULL,
		0xC81D61B29E2A0030ULL,
		0xE24C2241DEF9E6ABULL,
		0x0D59C1EA3FF12D32ULL,
		0x3126C807BA798465ULL,
		0xC215DDFD46159132ULL,
		0x6CB801623E43796EULL,
		0xBC6D28CD9701E763ULL
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
		0x76450A2DC12EB069ULL,
		0xE981724D0CC23EBBULL,
		0x34E83BCCB9ADA268ULL,
		0x9B21ADB1990CB9C4ULL,
		0xC98B4049FEBE492BULL,
		0xAAD727CB490A32FBULL,
		0xEFA658345EA2FCE4ULL,
		0x202E5CA0B6037DD5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0259CA81D8EA1CCULL,
		0xC85C67DF633B7EEDULL,
		0x059050C0FBB61031ULL,
		0x6031B87A1EBFCC18ULL,
		0x86FC0A7825D95A6BULL,
		0x81D4EEB46462FCA8ULL,
		0x866A6A1E54560253ULL,
		0x3A6918A36AFF2B9CULL
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
		0x12EE980A452A3CDAULL,
		0xB48195748233B41BULL,
		0x7525E4771C938AEAULL,
		0x91ECE71B8C463709ULL,
		0x29F38A0B0DA607C7ULL,
		0x8FCC5028C06DD44CULL,
		0xA464917CB13C4FD3ULL,
		0xE45AFB7DC7DBC2ACULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF286E3C81A0672DDULL,
		0xFA19C3A37D7470D3ULL,
		0x9CC2325CDFCE4B9EULL,
		0x293B464FCCBE112DULL,
		0xD939D297CDFA32F2ULL,
		0x4560E4AB42E9C61AULL,
		0xEB603F2D3BF88016ULL,
		0x3EA41709E8312265ULL
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
		0x3437C8B28BD1581EULL,
		0x8404B4EC094B7E95ULL,
		0x5440B3C32505C099ULL,
		0x90177A3FF91247C3ULL,
		0x57797A2E1FAC090DULL,
		0x85081390744D5A5BULL,
		0xBDB7A0E8A116041AULL,
		0x10C5840F4BEF7DAFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3437C8B28BD1581EULL,
		0x8404B4EC094B7E95ULL,
		0x5440B3C32505C099ULL,
		0x90177A3FF91247C3ULL,
		0x57797A2E1FAC090DULL,
		0x85081390744D5A5BULL,
		0xBDB7A0E8A116041AULL,
		0x10C5840F4BEF7DAFULL
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
		0x04EFCBFFFADA438BULL,
		0x8E23F0267DAA3EA7ULL,
		0x438DB370E8B2197AULL,
		0x48A7BC3214E52DE3ULL,
		0xFFC77236F786C4BEULL,
		0x0DB39EF5C1097F1BULL,
		0x6ECFC7CE4B653FB1ULL,
		0x260B650FF68DC39BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF099A8D620A6D65CULL,
		0xF8980144A488AA8EULL,
		0x885B2697AC6392CEULL,
		0x2414D9B8A8AC8BC3ULL,
		0xF4AF63E523DD3A0FULL,
		0xF3AC55816896F0E9ULL,
		0xCF283CC603329866ULL,
		0xCE6D6AB594A5356BULL
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
		0x2D7699F3FE51953AULL,
		0xA7F741B150AD42B5ULL,
		0x4B8C3E7F671D5DC2ULL,
		0x7734DCC6812FF80DULL,
		0x91BDD78BC5F2E817ULL,
		0x71EE9A00ADA75EA3ULL,
		0xE4EA2D4E377AB84BULL,
		0xAD02E02A6B87C988ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAE1066CEAE4A6CA9ULL,
		0x20796F5C38DC64FEULL,
		0x30C58702D2B32C37ULL,
		0x25202EEC8A14A47DULL,
		0xA02E99B2E9F71353ULL,
		0x11F81CFE72D198B8ULL,
		0x084DFBE0F1F6E9C3ULL,
		0x28BB3D5CDCEB5343ULL
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
		0x4382D665B7CDA06FULL,
		0x35D82115630FD66CULL,
		0x73868B835321FDEDULL,
		0xCA29E9C42A6CF0C9ULL,
		0x3C4A31B80D1C703FULL,
		0xE79861D30083F4B5ULL,
		0x3CCEC9BE4817D380ULL,
		0xBA922459110F9182ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F9BA4CBE94D69E6ULL,
		0x412590B7E17DA17CULL,
		0x4850AF420980EA1FULL,
		0x41BCE8E1CE373F9EULL,
		0x9DBF5576018A5B40ULL,
		0x0C6482220D9DF948ULL,
		0x02A43919A9818DADULL,
		0xF5041CCFEEE3C6E6ULL
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
		0xCF3102013BDBA58AULL,
		0x6890E6EED31C96CDULL,
		0x1B31E47D0E4601E0ULL,
		0xA8E39F13910ED93EULL,
		0xCB71C4E06740D81AULL,
		0xDFD4C79C1E6C29B1ULL,
		0x7E25FA29AA12025DULL,
		0xF4DB649CE9A8A672ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCF3102013BDBA58AULL,
		0x6890E6EED31C96CDULL,
		0x1B31E47D0E4601E0ULL,
		0xA8E39F13910ED93EULL,
		0xCB71C4E06740D81AULL,
		0xDFD4C79C1E6C29B1ULL,
		0x7E25FA29AA12025DULL,
		0xF4DB649CE9A8A672ULL
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
		0x3A31AA0CB1E29B99ULL,
		0x57F8E4BA66474FB2ULL,
		0xAB2015DF6EDEEB3EULL,
		0x87F9EF3EBA78471AULL,
		0xE0B2790DB0B26F24ULL,
		0x8EE34A3F1DE458CCULL,
		0xA5AE9CB49972E5CEULL,
		0x7163072ECF68F1C2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x19D13AAD089BFC13ULL,
		0x209D106A3820667AULL,
		0xA07F29FFF82DC371ULL,
		0x33B0BE189727063AULL,
		0x7E7F7016AEE4F8B6ULL,
		0x27172CAB39F8F021ULL,
		0x6027F60D857EFE62ULL,
		0x2933D07723152491ULL
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
		0x46BCC659D60FB5B3ULL,
		0x2D39D3A1ACA3D7BAULL,
		0x518CB10D97AD1793ULL,
		0xA304EAD0E0056580ULL,
		0x140F7A6E2A5FCFA7ULL,
		0xAEEA6DD3EFD22A2CULL,
		0x57D6A491FDAF538EULL,
		0x1628C3615EC0B3B3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57FD9F8D3F25AAB8ULL,
		0x3BE00B019D35463EULL,
		0xA16E5971D3830C7BULL,
		0xC1234B0F92ABB5DFULL,
		0x41E54422C35F89B6ULL,
		0x49E6FBE49FBEE35BULL,
		0x8F078F3ABBFECE0DULL,
		0x99B8FC8891046A4CULL
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
		0x836C30605CE51D77ULL,
		0xC8059EFA722568D0ULL,
		0x7504B57D8D4926EEULL,
		0x37E6C5FFFF760AB2ULL,
		0x2A783803A5E508F9ULL,
		0x594CB6609AF39234ULL,
		0xBC6F58591E86331EULL,
		0x174F763F649F45EDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BE9F3D0D6EA7DDCULL,
		0x214344C4F5CF2DE5ULL,
		0x379D6990841376CDULL,
		0xC649CEB8BB81695EULL,
		0x1530414825B528CAULL,
		0xB03DB56009A22778ULL,
		0xAC69486B04030973ULL,
		0xE56C4510BFBF3C78ULL
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
		0xEDE1F9B57AC4168BULL,
		0x364C6017D58BB5AAULL,
		0x60672E1ED0228E10ULL,
		0x4013B74DD518407CULL,
		0x39746349E424FF27ULL,
		0x0E6D02564621DF5DULL,
		0x5B902E1224A14F0EULL,
		0x653BF7FFB764999AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEDE1F9B57AC4168BULL,
		0x364C6017D58BB5AAULL,
		0x60672E1ED0228E10ULL,
		0x4013B74DD518407CULL,
		0x39746349E424FF27ULL,
		0x0E6D02564621DF5DULL,
		0x5B902E1224A14F0EULL,
		0x653BF7FFB764999AULL
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
		0x3F8282EBE9E01296ULL,
		0xF2B0DD65F9980278ULL,
		0x9551F9CF4D7E86B4ULL,
		0xC2935BFE267B52EAULL,
		0xB49FF902894C2F09ULL,
		0xD8805C3E2EA72ECEULL,
		0x17DB6BE5392EACD2ULL,
		0xD8A0B7AE10627D51ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6AE6094B4066B657ULL,
		0x8E5DC0BD998EE343ULL,
		0x52CF32F63A9B3474ULL,
		0x7E3BF2C1435D2456ULL,
		0xF425449AF8DE85BCULL,
		0xDD06C5E3134B483AULL,
		0xAF2BFA985B2915B7ULL,
		0x390D4D199A27A5B6ULL
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
		0x6892CC3242100439ULL,
		0x558A4215DC396C3BULL,
		0x25DA652EC110B1C2ULL,
		0xED5DF80C0FC70BF8ULL,
		0xEA8C6D78CEDE311AULL,
		0x2F87A427220C7831ULL,
		0xA10A937EEF29590AULL,
		0x9C8A7249A1FF30ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x84EFE8B9A36D2812ULL,
		0x462970BD6BF28745ULL,
		0xD49641AB4E68D536ULL,
		0x241608E64161C63EULL,
		0x53B16E7828CC2311ULL,
		0x90177274F3D81F4EULL,
		0xB454182BD466B250ULL,
		0x75F3CB7C0FD9BD17ULL
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
		0x7B4B7193DCA2012EULL,
		0xC0393212F35DC90DULL,
		0x3580E2C2095D54D6ULL,
		0xACAADC3EFB5A5EF5ULL,
		0xE858065CF8FDADF7ULL,
		0xAF1073D7B5C3A7D3ULL,
		0xB78CE80297B37ECDULL,
		0x6F37EB6B6127C183ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0ED45E8DEC4FCADBULL,
		0xFD16404992C11AC9ULL,
		0xF206038E365522A3ULL,
		0x2CF38CF591F93BACULL,
		0x885F484105FA61FDULL,
		0xBED900473DB1547DULL,
		0xDB978C79FC33DECEULL,
		0x95BF98DD7BA4F9D3ULL
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
		0x526CBAC36E88A666ULL,
		0x692688BEB61B925BULL,
		0xE7AA784BDAB9D687ULL,
		0x0C6CE1C9B940DBF8ULL,
		0x85C1B5E600D86D32ULL,
		0xE18A4C4CD9021C84ULL,
		0xFB772E291D14A087ULL,
		0x9C434822673829C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x526CBAC36E88A666ULL,
		0x692688BEB61B925BULL,
		0xE7AA784BDAB9D687ULL,
		0x0C6CE1C9B940DBF8ULL,
		0x85C1B5E600D86D32ULL,
		0xE18A4C4CD9021C84ULL,
		0xFB772E291D14A087ULL,
		0x9C434822673829C7ULL
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
		0xABFCD69580A51D49ULL,
		0x0D175C3F2FB51A9BULL,
		0xE3BC3435161CBFBFULL,
		0x5A3E3EEF135102CEULL,
		0x723E20E4B8269C95ULL,
		0x6C31DDD03CDB5B09ULL,
		0xF42E9A1C11F3B0C0ULL,
		0xF6DFE3CB13F00F98ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81CE2CE30B6BE4BULL,
		0x27B85A49E4FE9C62ULL,
		0x3067525110336FB6ULL,
		0x5E6F254EE5FCD91FULL,
		0x3CF6BE6CDB13455BULL,
		0xF16F82EF02B2CE23ULL,
		0x3247B94B293A7B9FULL,
		0x23C6A05B8D2BDBB6ULL
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
		0xFC53EB843AE79E7BULL,
		0x1C65924BBAC8AFAEULL,
		0xC0DF4BCAE32CCBE7ULL,
		0x06367B077CE801D3ULL,
		0x3C7B0EAFF169A95FULL,
		0xD89CBA299F17E775ULL,
		0x112E1623FDF9E1F7ULL,
		0x633427A1FAD47035ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63313C6425684163ULL,
		0x773BB662B52CDE53ULL,
		0x6DAD6610DB2D1230ULL,
		0x14936A10FE7B8B84ULL,
		0x12906E4A51B17A58ULL,
		0xF6A87B7C9405B009ULL,
		0x8F57D5F4AE5C9CB9ULL,
		0x878029821520D6EFULL
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
		0x8B6D665465C93EF1ULL,
		0xB66A4E2EED591223ULL,
		0x56158EE61FA5363FULL,
		0x828DF13E39CBB212ULL,
		0x0EA0260693A77521ULL,
		0xF111771B06009C36ULL,
		0x5A599AC8F87CE49AULL,
		0x6C52DAF34F22DFD8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x53A7603E65D83CF9ULL,
		0xD33B50BEB953332AULL,
		0x7BFC9902EAC8CE40ULL,
		0xD2CB962E7887960BULL,
		0x0E4E84A9CD73EFD1ULL,
		0x2D1379B1AF67F3FCULL,
		0x6B63DCCA2CD14548ULL,
		0x9F23D7C2C384F027ULL
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
		0xD2353DA97E66651FULL,
		0xD2DFC4E85BA51F20ULL,
		0x014D95C9CD5BF696ULL,
		0x3B3491425B18DCD9ULL,
		0xBD1448437CE13EF2ULL,
		0xC4442975568F9B02ULL,
		0x75BD1B8E77FD357BULL,
		0x76D7153027C27376ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2353DA97E66651FULL,
		0xD2DFC4E85BA51F20ULL,
		0x014D95C9CD5BF696ULL,
		0x3B3491425B18DCD9ULL,
		0xBD1448437CE13EF2ULL,
		0xC4442975568F9B02ULL,
		0x75BD1B8E77FD357BULL,
		0x76D7153027C27376ULL
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
		0x94590C3D928EC2DDULL,
		0x0B419BA7BC3E88CFULL,
		0x82B8DB7C695D20E1ULL,
		0x1E6A4FA18423BA21ULL,
		0x3D80CAF2E5B82691ULL,
		0x8612A5D647FEAD51ULL,
		0xEFDCA2D4AA44B425ULL,
		0x4E5639C458C44F9CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD74758C3C1D52E5ULL,
		0x79C1F8783A41D6ADULL,
		0xA9A06C9BDEEED8C2ULL,
		0x86092825A78FF128ULL,
		0xBE40E5EAD5040553ULL,
		0x4DB9CBA34CBAC9F2ULL,
		0x8AC3492B86DF3F8DULL,
		0x0260DD4682F8545AULL
	}};
	t = 1;
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1C1BF77F3CDB3351ULL,
		0xB2C638D9EDF5B799ULL,
		0xE442B198673DE215ULL,
		0xF8B4A462344CC2B4ULL,
		0xB5E75382109DAFA6ULL,
		0xD780294274529D20ULL,
		0xFF64452BE2519555ULL,
		0x8C980ACFE730C683ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x74F30B7D3E758864ULL,
		0x5AD5501A4EC7FF74ULL,
		0x3EF9EA8275AE2405ULL,
		0x18E0D790224F9B66ULL,
		0xF4AAE513FE02FD74ULL,
		0x0FD6E2F127FE3652ULL,
		0x873F02BAF0C1E65DULL,
		0xA5A5E78541146641ULL
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
		0xC2E2548C5B7EBBB7ULL,
		0xB66AEFA817982F86ULL,
		0xB8D600FBE49474E0ULL,
		0x02F44EDD8739C258ULL,
		0xFD0676F19C0D12E6ULL,
		0x7CFC430B3E90651CULL,
		0x8A78793FD7F322C5ULL,
		0x9A8FFD275F8B1F10ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA6642C49601017FAULL,
		0x465981523352421FULL,
		0xA9D03D9C3319AF01ULL,
		0x2657D47082666151ULL,
		0xE96E749DC445DC85ULL,
		0x71C9A7BC43213E57ULL,
		0x3A6CE3E8766BCAD8ULL,
		0x7609EAFCAC19D399ULL
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
		0x1A844C631645A3ADULL,
		0x622AEEC7AA98A1C4ULL,
		0x1365D420149E40E7ULL,
		0xDE1755500815A26FULL,
		0x79762DD1737FB5B4ULL,
		0xCDA38E43D2AF59BBULL,
		0xDA5DDE4DBCA9984CULL,
		0xE7CE1A581646D96AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A844C631645A3ADULL,
		0x622AEEC7AA98A1C4ULL,
		0x1365D420149E40E7ULL,
		0xDE1755500815A26FULL,
		0x79762DD1737FB5B4ULL,
		0xCDA38E43D2AF59BBULL,
		0xDA5DDE4DBCA9984CULL,
		0xE7CE1A581646D96AULL
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
		0xD0E1315B6C808DCBULL,
		0xB39EC007025F3A45ULL,
		0x241175A5404193C9ULL,
		0x76FE4BEFC87AC252ULL,
		0x092858C5736BF9C0ULL,
		0xE422C8D83025CFFFULL,
		0xDE056F90477B83A0ULL,
		0x3615FA929CF14E25ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A780F980344726EULL,
		0x7B7000EEF154A61FULL,
		0x17D7DE079BC03116ULL,
		0xEBA1DF2F42566E35ULL,
		0x30DFA7013CED27FBULL,
		0xDE16937236981D6FULL,
		0x67F9C84B02F7A820ULL,
		0x1AB5FEDEA04C86B9ULL
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
		0x5A74E01E1E9A52EBULL,
		0xE6E943FDCF7B0DD4ULL,
		0x0AD081F45DE62FE6ULL,
		0x1495E9E4605CD438ULL,
		0x2F15A1EABE86A05EULL,
		0x599140F371DC34E3ULL,
		0x2FF918347AD09B23ULL,
		0xB8128206C180BC06ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1E9C7B47B09F09EULL,
		0x7363A4855D732D03ULL,
		0x6E1B6F5187844607ULL,
		0xD85AA75834C3002EULL,
		0xB4535A3495B4400CULL,
		0xC8E94F35B4008EC6ULL,
		0x9E60651D3C2F3F7EULL,
		0x17DD7A581662BA1AULL
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
		0x3BDFBF29FA154C41ULL,
		0x00F75219DD73EFE0ULL,
		0xD935618B0E1F2C04ULL,
		0x820A872B839897B0ULL,
		0xF42BA3FAC17CA15DULL,
		0xD005A55B8ADF40FAULL,
		0x95A5ED2F5024B512ULL,
		0x85BB87FA5B0BA7FFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x85021FC3B21675F7ULL,
		0x5482D59AD8EADD90ULL,
		0x67398D55D13D3F97ULL,
		0x1E485EA4E0BFCDC5ULL,
		0x467D99274EDB8316ULL,
		0xA4CDFF66A4A1C7EFULL,
		0x2F1A9A37FC1E1419ULL,
		0x98B78617AE98F394ULL
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
		0xEE27E1F55043AA3AULL,
		0xE975CAF2FF0CE979ULL,
		0xE2C1600635B331F6ULL,
		0x732F9236DFA8D3CBULL,
		0x9B429C8195E6FE13ULL,
		0x6B792F853C8BF386ULL,
		0x10A56EB01E5AC2C3ULL,
		0x1B35CAAD4ACF1A45ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE27E1F55043AA3AULL,
		0xE975CAF2FF0CE979ULL,
		0xE2C1600635B331F6ULL,
		0x732F9236DFA8D3CBULL,
		0x9B429C8195E6FE13ULL,
		0x6B792F853C8BF386ULL,
		0x10A56EB01E5AC2C3ULL,
		0x1B35CAAD4ACF1A45ULL
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
		0x7521945C4605F036ULL,
		0x0B2449DADB3D5677ULL,
		0xD38A753FE59C31EEULL,
		0x122EF7160394A5BEULL,
		0x9448751360C7673DULL,
		0x4D1A6F50C9FE6307ULL,
		0x5D48C105E7D06444ULL,
		0x8AFA436751F7C902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBCA70AAFCBE08B38ULL,
		0xB5A72FACEAC033A7ULL,
		0x6260CF94785C0361ULL,
		0x3DAA4DD522ECDE15ULL,
		0x381AE11FC3751317ULL,
		0xBAF99631C215FA59ULL,
		0x54EE5857D47F39DDULL,
		0x30F0ADE00D9A99D7ULL
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
		0x84554E2176AFE767ULL,
		0x90CEC49F2BE64FE0ULL,
		0x48E758EA8612E0ECULL,
		0x4D162F39E530371DULL,
		0x71F465F85060A43BULL,
		0xD63E4C931990798AULL,
		0x2711653A95D47331ULL,
		0x24CA8AACFF63371FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC0A60D5B535A738ULL,
		0x0181E040D15CF027ULL,
		0x383023B0EF5EB250ULL,
		0x08D35133D951C313ULL,
		0x408FABAF0D5EDDF8ULL,
		0x91E3DE73558DB45FULL,
		0x388CBE5968166AABULL,
		0x90CDCEC288CF590BULL
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
		0xD10361146A7F92B0ULL,
		0x68085E4D0F90A299ULL,
		0xE4725E8EC072F504ULL,
		0x54BCA2B6F47F2786ULL,
		0x82005FA6DCD9AD08ULL,
		0x8A66880B72D42D09ULL,
		0x186B1AD10DC8EE7DULL,
		0x786042622211425BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1E7EC5C6CD4B861EULL,
		0xC42F454DC153BBD6ULL,
		0x7BBE4D0610E5E8DEULL,
		0x12BC0560954C505FULL,
		0x8715CE3416CB5F7CULL,
		0xDCF0EF2860992A4DULL,
		0x9899E2ED70A5407BULL,
		0x5085ABDA4A693FAEULL
	}};
	t = 1;
	printf("Test Case 104\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x50EDB3E4253E771BULL,
		0xB1A499AAEE55EC26ULL,
		0x4BF6780DB48ED2A8ULL,
		0x26204C43D6701FCAULL,
		0xC843728A24AEC4C2ULL,
		0xF8F643F1E32938CBULL,
		0x66BC90CB4863FFAEULL,
		0x48B22D5FF8886EDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x50EDB3E4253E771BULL,
		0xB1A499AAEE55EC26ULL,
		0x4BF6780DB48ED2A8ULL,
		0x26204C43D6701FCAULL,
		0xC843728A24AEC4C2ULL,
		0xF8F643F1E32938CBULL,
		0x66BC90CB4863FFAEULL,
		0x48B22D5FF8886EDFULL
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
		0x9D33A3763976AA91ULL,
		0x1029F8AE4F7487F2ULL,
		0x596A671964824DC1ULL,
		0x8843078AAF17D6E5ULL,
		0x4FC494E3E2239688ULL,
		0x0290A6EC0D416B09ULL,
		0x62A5492B4274069BULL,
		0x8CFDA1B67D43BCEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5E935B18CB454F90ULL,
		0x114F1E05D0851B11ULL,
		0xF19D77359792F006ULL,
		0xDADD8C0E69A13758ULL,
		0x563ED901712917B0ULL,
		0xDA9707EDBB4A19FFULL,
		0x50DFDBD272E6AE4EULL,
		0x1D26725143F3EACFULL
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
		0xC1158D5BD042279DULL,
		0x48202A9AB4135AB9ULL,
		0x0B2DFD8D61E26728ULL,
		0x623B6B1CA9142050ULL,
		0x1140CEDAB9C2E1FCULL,
		0xD7F7971B6F1AFE5EULL,
		0xCE3196F16AD30612ULL,
		0xF4BC86B712D3ABA7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x14E13A68B51DF7A8ULL,
		0x9D17007E20AA2AB0ULL,
		0xED87C81A74803CF2ULL,
		0x815B926ABC62D128ULL,
		0x7D9C271C835FBAE9ULL,
		0x34885852DC8E66DCULL,
		0x7BF86C5C34A3BF20ULL,
		0x3EB9AC54E400EBCFULL
	}};
	t = 1;
	printf("Test Case 107\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x0B79ACD94B6EE1B6ULL,
		0xC26125C4A3302339ULL,
		0x99C04E30D6FC60FBULL,
		0x734F2D280D5F9EBCULL,
		0x491EF0AD05E605ECULL,
		0xB6ECA0169BFFC794ULL,
		0xF00E0B5166036572ULL,
		0xBACFD8B76A896261ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5266BAF9BF98A510ULL,
		0x8EE0E3C175C3C71FULL,
		0x6B34644EFEF55C65ULL,
		0xB8CA1CA59109BD40ULL,
		0xF50AFBC9EE780804ULL,
		0xBD6B58CAEE3FDEEAULL,
		0x2B9213283992341DULL,
		0xD805DCB6361BAD4BULL
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
		0x2D60031C4FCCA311ULL,
		0xB75F1042493855E3ULL,
		0x4AB3497FD007236AULL,
		0xC64D85E222A5D315ULL,
		0xB9447F20D8ADC7D2ULL,
		0x4019C492FE207E10ULL,
		0xF0E6AA5755671942ULL,
		0x89CD6E028C2169B9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D60031C4FCCA311ULL,
		0xB75F1042493855E3ULL,
		0x4AB3497FD007236AULL,
		0xC64D85E222A5D315ULL,
		0xB9447F20D8ADC7D2ULL,
		0x4019C492FE207E10ULL,
		0xF0E6AA5755671942ULL,
		0x89CD6E028C2169B9ULL
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
		0xCF588E8938F03B74ULL,
		0xD2581707455DD098ULL,
		0xA6BFD1CF97F4F5EDULL,
		0x42662DFE82C3997FULL,
		0x5A2DAB14E3285EF1ULL,
		0xE641E51B03A11B87ULL,
		0x5F82A970880BF5EAULL,
		0xC3779E787298CC26ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x69BDC26F4DB4B1DBULL,
		0xFE9285472903C2BEULL,
		0x210ADB069DD2941DULL,
		0xA7DB0BB34D78EEBBULL,
		0x6DC9F7243E3E3BE2ULL,
		0xE3B00947D969F793ULL,
		0xC25A43A3C2909A1CULL,
		0xC2339D37FFED560FULL
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
		0xAC6D6DAFECB3E44BULL,
		0x518512F317CB53D5ULL,
		0x11DEAECE5693828DULL,
		0x4B22B883254162CCULL,
		0x1C5D970AEB5151B1ULL,
		0xCB096FA21D12737FULL,
		0x9C1536AA0803AE76ULL,
		0x2FDBE0B1BC7B4C74ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D35712175337749ULL,
		0x497B9F30DDF837DEULL,
		0x8E146E379D0E506BULL,
		0xC909D308E77CE017ULL,
		0x611B4E113908F3B5ULL,
		0xFAE608759073F5BCULL,
		0x2A298FA0365631CBULL,
		0x97B7FFF12A9F3EC9ULL
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
		0xAC0FD508F0B7574DULL,
		0xEA03B1CCEB8C2B20ULL,
		0xFD6287A470E02E19ULL,
		0xCB29626C9658CB76ULL,
		0x213F82199ED3B12FULL,
		0x4CC3A62534164071ULL,
		0x736ACACF9738C021ULL,
		0x75D93F2F2303BFCCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x30A3C8EE3C779C5EULL,
		0xBC5B06FA48EC5CBAULL,
		0x885DF977705AB68AULL,
		0x46519AE18661E21AULL,
		0x7C7A29F51A91813CULL,
		0x0C953D8BC64B9200ULL,
		0x390556024F952A12ULL,
		0x532C30F745021D38ULL
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
		0xAA5B7F85EA44420FULL,
		0x890B3A9148BDF494ULL,
		0x3626876DFC817AF5ULL,
		0x23B65A79E223FF4AULL,
		0xFB12B16AB786B5B3ULL,
		0x1883BAC91738E9DEULL,
		0x26135B3F6D3D26D9ULL,
		0x8682452655BDD006ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAA5B7F85EA44420FULL,
		0x890B3A9148BDF494ULL,
		0x3626876DFC817AF5ULL,
		0x23B65A79E223FF4AULL,
		0xFB12B16AB786B5B3ULL,
		0x1883BAC91738E9DEULL,
		0x26135B3F6D3D26D9ULL,
		0x8682452655BDD006ULL
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
		0xA26BC6BE53C63975ULL,
		0xE60CF4BB126157CDULL,
		0x54994B7719B184CBULL,
		0x06246250C4D811FEULL,
		0x81C6720A987BA0E5ULL,
		0x2B6346C932635765ULL,
		0xF84FD8F96EDF2030ULL,
		0x1DF26960941F49C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x94ADA003AF0F9F8BULL,
		0x61C54BF38FC85F17ULL,
		0x0EDF0F3E1CCD896EULL,
		0xBC5B4E0D2E365051ULL,
		0x28716C7FA48279E6ULL,
		0xD37D2841BFE9BB17ULL,
		0x197559C52EDFE77CULL,
		0xFD02C7BDFC71F391ULL
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
		0xD3F801131F19CE04ULL,
		0xE8E5592A7B35C2E9ULL,
		0xA105624741A7D4B9ULL,
		0x9BEFFA8CFB112B4CULL,
		0x310BC73F373325D0ULL,
		0x4B3A17642782DCD0ULL,
		0xA464F270538BCFBBULL,
		0xBA1E5CC1AB3D7914ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5ED0B70E277DD4DEULL,
		0x1F7E2FC25D9159B0ULL,
		0xE48DA24E31615196ULL,
		0xC7DA919CC188CF2BULL,
		0x426F90C5B1111A1FULL,
		0x7215C8C3C2A32125ULL,
		0x9A047B1D030CA3D8ULL,
		0x71E55C7F10AFFF79ULL
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
		0xF740AAB8179C6AC3ULL,
		0x0378A948F7302E19ULL,
		0x09F0CA43200A2CE7ULL,
		0x80F6873A235653CDULL,
		0x59365F712E5EBA51ULL,
		0xFC6DFF65A8C32C15ULL,
		0xDFF6DB31BB6170D1ULL,
		0x284BBD15AFFB04E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A795B9AEF9F758EULL,
		0x3CA9280DB994D7EAULL,
		0x48F27D8F546B0CC0ULL,
		0x211C7B902EC7E481ULL,
		0x62891B7E4ABD918EULL,
		0x6868E17ACD04B349ULL,
		0x11997F32591C993CULL,
		0x3CFF08738919124EULL
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
		0xCBD69ED5CDAA778BULL,
		0xBC0FCD501E32E759ULL,
		0xB21058154C10A85DULL,
		0xB704FDECF4E66DBBULL,
		0x06B8B5791B7A2C54ULL,
		0x3AF93B258FD9D812ULL,
		0x4388D4AED6C551AFULL,
		0x63D85398FB48447BULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBD69ED5CDAA778BULL,
		0xBC0FCD501E32E759ULL,
		0xB21058154C10A85DULL,
		0xB704FDECF4E66DBBULL,
		0x06B8B5791B7A2C54ULL,
		0x3AF93B258FD9D812ULL,
		0x4388D4AED6C551AFULL,
		0x63D85398FB48447BULL
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
		0x9C251358F9B0D313ULL,
		0x4D22BE5CACC58513ULL,
		0x54DD810927D70B71ULL,
		0xF040DA10840C84B2ULL,
		0xA72D5A7333563E77ULL,
		0x61A5A20275ECF88BULL,
		0x3AF1D01BE523D986ULL,
		0x845003CD14359894ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x030CFC2C50E8AB5DULL,
		0x56276603E77B8B33ULL,
		0x56228FB61EEAB53FULL,
		0x0515B91B3DBCB168ULL,
		0xA93A1785D6E584DCULL,
		0x5CBA389BA5B466ACULL,
		0x01475B0BDF9798D7ULL,
		0x257A0267559AA062ULL
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
		0xEA6E73537F9C10AAULL,
		0xAA8BDEF8C426D732ULL,
		0x432AC206DDF766DDULL,
		0x77ADB07341585774ULL,
		0xC69E2A6D75448374ULL,
		0x7BCEF85B398154C8ULL,
		0x2E62ACE480A95F37ULL,
		0x178CBD27B8566D17ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1A28B738C58586CULL,
		0x3B0D9FC88AAC75A9ULL,
		0xAF456B7BC9CFF99FULL,
		0xDB1B411204DE334FULL,
		0x458F5287EFDE13EFULL,
		0xE6685F06423F07D7ULL,
		0xF8E4FD3C504C0212ULL,
		0x96DFB930284217BDULL
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
		0x2F22CFACDEF9A535ULL,
		0x829240F7423EAD27ULL,
		0x0F38A66EF63FA212ULL,
		0x5A34DCAA0F2854FDULL,
		0xE9F32E7C6820F3FDULL,
		0xD3E6B2FF22C9625CULL,
		0x0ACF87CB8144D390ULL,
		0xA2DB22F7E9CE28E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC8B17F1F5190C0F6ULL,
		0x05CABF355636147EULL,
		0x84979A8F02310A00ULL,
		0xACD8D6A8F22470BAULL,
		0x56A8E78F1F94625FULL,
		0x397E73C86DB40834ULL,
		0xA0D0DF03A9336CD7ULL,
		0x1DFEED7C5259BD19ULL
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
		0xC93A179BDB6784F0ULL,
		0x70747918EE2E14DEULL,
		0x56E19A7914DDF5B1ULL,
		0x833D5014824F4F9FULL,
		0x18CAFC1B00F304F5ULL,
		0x1AD3C1E3BF9EA03EULL,
		0xC26AE24108B83AA6ULL,
		0x56A200CA192BAB31ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC93A179BDB6784F0ULL,
		0x70747918EE2E14DEULL,
		0x56E19A7914DDF5B1ULL,
		0x833D5014824F4F9FULL,
		0x18CAFC1B00F304F5ULL,
		0x1AD3C1E3BF9EA03EULL,
		0xC26AE24108B83AA6ULL,
		0x56A200CA192BAB31ULL
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
		0x04D179BB00487980ULL,
		0x1B789C27BE704743ULL,
		0xFC02A1F3FB66F4FBULL,
		0x806505ACF1C573FDULL,
		0x911CE1A185A678A3ULL,
		0xE96971EECAD03344ULL,
		0x4E5652F4F2E78872ULL,
		0xED5F2C68B05F0C53ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1C4A1205CA511367ULL,
		0x5FCCF246AAF801AEULL,
		0xA41F54BBA45D3804ULL,
		0x41213D5700EDFE51ULL,
		0xED238276664CFF7CULL,
		0x0A75DBADE9CD36DEULL,
		0x74F1991291802FC1ULL,
		0x95A17E0901A5F060ULL
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
		0x49A2424BD2FC1508ULL,
		0x82F04A9B2F1DB3D1ULL,
		0xFDF9A7C8D36FD86DULL,
		0xB1766E2F65D078A1ULL,
		0xE3B5FE6B502C60F2ULL,
		0xAC235E50FC7A9095ULL,
		0x413AE7F7411C1DC6ULL,
		0xE53A5FD9A61D00C1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3791DA484FE2009EULL,
		0x568DA80FFD914ECDULL,
		0x0405718256A40FE4ULL,
		0xEA68E3DFA8F31297ULL,
		0x7990848A0E36CF64ULL,
		0xDCAD76049066F34EULL,
		0x6CE4FED7265E94EEULL,
		0x748FCCB79E06EE5CULL
	}};
	t = 1;
	printf("Test Case 123\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0xB2FD6CBF520A3ABAULL,
		0x6BEF76C78B398E21ULL,
		0xCFC64E6099F7D500ULL,
		0xCB78E75AD4B7D6EBULL,
		0xF76DCEDC9A345106ULL,
		0xEE2ED4CDCA69F2BCULL,
		0x967E75372A81660BULL,
		0xE043EEF8BA8E9CDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9A48BB9C5BDD764EULL,
		0x0FB1F0DD4C2CB381ULL,
		0xD451A9A7F07DF2D1ULL,
		0x4614C58960720A21ULL,
		0x0837A359FE884964ULL,
		0x68B905575E07A028ULL,
		0xA007292CDCA7E7FCULL,
		0xA852B169D57B50ECULL
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
		0xA7FED7B135841D5BULL,
		0x6A1197D3C34FC558ULL,
		0xF2DDED83CB798650ULL,
		0x5CCEA7FF3DF28ABBULL,
		0x8785CAC3BC336772ULL,
		0xDE01592F017DFB25ULL,
		0x32C1FE2C819700A6ULL,
		0x26A8BD31E25B036EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA7FED7B135841D5BULL,
		0x6A1197D3C34FC558ULL,
		0xF2DDED83CB798650ULL,
		0x5CCEA7FF3DF28ABBULL,
		0x8785CAC3BC336772ULL,
		0xDE01592F017DFB25ULL,
		0x32C1FE2C819700A6ULL,
		0x26A8BD31E25B036EULL
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
		0x2F41B0052AA9DAAEULL,
		0x6602D1F5371A9E54ULL,
		0xE36FD131106969B2ULL,
		0xDB159E184EE336FEULL,
		0x676C2C2F2FFE9EF4ULL,
		0x756D128C786E7B27ULL,
		0xA9017478566AB0E2ULL,
		0x75BEFFBD4DC18B54ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x49EAA7E69910CF7EULL,
		0x993F369D6EEA9BB7ULL,
		0x1C317044EED0E3C5ULL,
		0xDB3A2EAD9A63BF93ULL,
		0x6448E8EF0D38D368ULL,
		0x65DB43F4373992E9ULL,
		0x0E3F72D7393D371CULL,
		0x7F0E283CA3207798ULL
	}};
	t = -1;
	printf("Test Case 126\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x5F7CEAF647921949ULL,
		0x6C5A38BD0E17B516ULL,
		0x13B1CA5C15929134ULL,
		0x2277579F650D7847ULL,
		0x4D9A316E30A08975ULL,
		0xBDD11F85B86C9284ULL,
		0x9F9035AD0E6F064AULL,
		0x025AF3A18179DE6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BE6919C2A9FAC55ULL,
		0x69606021807120BAULL,
		0x3B539912C54B5841ULL,
		0x3DF0D7B3E61696B6ULL,
		0xDF3BF3889A470187ULL,
		0xEB7BDD9D12ADF6A3ULL,
		0x271D6376496BAF56ULL,
		0xEDA00508D3376611ULL
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
		0xDEC49F801F49BFD5ULL,
		0xFD768D7DD7AA8395ULL,
		0x478708F15597A850ULL,
		0xE6BBFE55B9FE70F4ULL,
		0xC6A2AD5CA257975CULL,
		0x6C46D81D9AA94EF0ULL,
		0x8C486F80FE64B5E5ULL,
		0x08DB38DBE531858FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32A7B36C0F057B46ULL,
		0x93488739E1A63569ULL,
		0x556CD4BAC06DB5F8ULL,
		0x0A3EF5CB615C775EULL,
		0x6D2214C195995332ULL,
		0xD7383F7A0AC8AAB2ULL,
		0x7C9132BAD09CF83DULL,
		0xE80662783FDE5FC4ULL
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
		0xD63771A7211AB701ULL,
		0xBE08B730D6C0A24EULL,
		0x0D5AA561A3300CA2ULL,
		0x701AC781B4B37AA3ULL,
		0x6D6E1146C8D901CCULL,
		0xF35E9C852053CB8EULL,
		0xEA1EAB235F74D5ABULL,
		0xD098961565451E73ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD63771A7211AB701ULL,
		0xBE08B730D6C0A24EULL,
		0x0D5AA561A3300CA2ULL,
		0x701AC781B4B37AA3ULL,
		0x6D6E1146C8D901CCULL,
		0xF35E9C852053CB8EULL,
		0xEA1EAB235F74D5ABULL,
		0xD098961565451E73ULL
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
		0x59E33F8EAA8297C7ULL,
		0x2DA50B2A45BDDAF6ULL,
		0x3EBA900A619670E4ULL,
		0x347E17964384DAA4ULL,
		0x8CE327008E6A5887ULL,
		0xED7A36FB79CE0C14ULL,
		0x4B34A1F56E1589D9ULL,
		0xCAA6A95B8B6B18D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEF319059442168EBULL,
		0x3F8C6A18A01B3C11ULL,
		0xAF815FCEF0F0B28CULL,
		0xBA902D5277EEC5B2ULL,
		0x4721EAF79C16BAC8ULL,
		0x714FCE484A61E824ULL,
		0xD11CDF6CC3FB6B07ULL,
		0x054C0868D2342488ULL
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
		0xB4CACCBF726F5B43ULL,
		0x62154529ACD16597ULL,
		0xBB1A4B8495992F3FULL,
		0x1AB303A3381BC21FULL,
		0x680E7915DF1101F7ULL,
		0x90D05810B0BAD3CCULL,
		0xD9EF75EA831159D6ULL,
		0x1AD752E78EDDF1B6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3628E7D7D993B909ULL,
		0x3FB55E04C77EA6D8ULL,
		0xAC9D119418F92F07ULL,
		0xC047E41B92D3831FULL,
		0x7C71A3D276B684FCULL,
		0x104D59E29CC04CF6ULL,
		0x20272526772FF2D5ULL,
		0x796C77EF4349AAC7ULL
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
		0x233F4A7DCE003407ULL,
		0x3B013CED685BB9D4ULL,
		0x3F3ACFC02FBDB6A6ULL,
		0xD724AF2CD03A5E8EULL,
		0x78B3745413F07C89ULL,
		0x0C2A078BBDB470C3ULL,
		0x1197B7BFCBD77EACULL,
		0xBA9B90FAF3A45F47ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC028601F10EDED34ULL,
		0xE5A454E16AB2DE5BULL,
		0xA18C369DAFA2D29FULL,
		0x7A297BA4F1DA1F2AULL,
		0x4B7FA74C85DF7FBFULL,
		0x357396FA1487A761ULL,
		0xB00A4314C1BC0A2DULL,
		0x534DF89609545CE6ULL
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
		0x6CF45FF3B58F8D49ULL,
		0x07812049CF192EC1ULL,
		0x4BB6B284B8A000DCULL,
		0x17B6D76878116B7AULL,
		0x7DE576CC92164630ULL,
		0x96B42988F7927286ULL,
		0x7B9407A20CA73921ULL,
		0xEE12C8F3A5B541E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6CF45FF3B58F8D49ULL,
		0x07812049CF192EC1ULL,
		0x4BB6B284B8A000DCULL,
		0x17B6D76878116B7AULL,
		0x7DE576CC92164630ULL,
		0x96B42988F7927286ULL,
		0x7B9407A20CA73921ULL,
		0xEE12C8F3A5B541E1ULL
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
		0x37F7759FE049C3DEULL,
		0xAE54041F7C8CE19DULL,
		0xB4A3C355DFB94CC3ULL,
		0xB3A57413DBBBC108ULL,
		0x4B6F75A085C96433ULL,
		0xF4155EFD36292C0EULL,
		0x96477E084A992E2BULL,
		0xEAA1AB183F508B52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD647F9F8EBDABE40ULL,
		0xFF5F9A041D642127ULL,
		0x705E233C45A0FFC7ULL,
		0xAEC206E496E75972ULL,
		0x076B887159791966ULL,
		0xC9248CB3530A7311ULL,
		0xED4734741EBC0354ULL,
		0xC460D79D67ADD60BULL
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
		0xB6D8ED0085293726ULL,
		0xC30D82EA811FFA20ULL,
		0x434CA94847B90D29ULL,
		0x36DCCA2675E432A5ULL,
		0x2F069CCC44CA08C4ULL,
		0xF53A628304C03D68ULL,
		0x9A9F329D6A87CD9BULL,
		0xF7261C6E2B72BD1AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA284C8C8345F8778ULL,
		0x8BA9515FDEAFE944ULL,
		0xD59351E84CAF3078ULL,
		0x769BB1266EC28A18ULL,
		0xE3ACFDB0B6FF5089ULL,
		0x70B4307444EACE88ULL,
		0x1F7489D9ADC5B6D7ULL,
		0x3ED95CD87FECAF0CULL
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
		0x72D0A4C9F6B6F7B1ULL,
		0x738DF63E249C7E44ULL,
		0x9877536D0509BDB6ULL,
		0xC8101A720DF730F8ULL,
		0x4BC02E753ACBC714ULL,
		0x0854F363A42A6224ULL,
		0x117FA3ED922AC760ULL,
		0x4BA485BF583D3FAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE08BD5C1ED2117CDULL,
		0x204071C266CC73A5ULL,
		0xF5EC70D140F55963ULL,
		0xF0AC24DF59AF4606ULL,
		0xA2FFF629E46484E0ULL,
		0xC4DDAF5921A021EBULL,
		0xA35183AC6E3184B1ULL,
		0x7119E40011F58608ULL
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
		0x476BF4473EA5C7B0ULL,
		0xD67BEC3FF90F6372ULL,
		0x19190CC92BA5B3AAULL,
		0xE0AB874B350BCEF0ULL,
		0xFE1CE936EAA44E12ULL,
		0x51D99D158F38C5CDULL,
		0x0FEAA683CF0A2E6EULL,
		0x2263A05BCAD430CBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x476BF4473EA5C7B0ULL,
		0xD67BEC3FF90F6372ULL,
		0x19190CC92BA5B3AAULL,
		0xE0AB874B350BCEF0ULL,
		0xFE1CE936EAA44E12ULL,
		0x51D99D158F38C5CDULL,
		0x0FEAA683CF0A2E6EULL,
		0x2263A05BCAD430CBULL
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
		0xD897335FA9567380ULL,
		0x4B04D852BE282ABDULL,
		0xFA740EFDA7AB5DB1ULL,
		0x8BD2895F1F674693ULL,
		0x3C6461E921FAF650ULL,
		0xA2A350CB35D687A9ULL,
		0x36D6E9D5C573AB67ULL,
		0x57CC1A078A6CE22AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4ABD4A3A6DE5D945ULL,
		0x46C05E0D9C6E9DE4ULL,
		0xBD15061A60AB7F58ULL,
		0xCCF7A91F7D7DFC7AULL,
		0x8A310073F6207A5EULL,
		0x48E551A621288714ULL,
		0x9FACF865A4724E25ULL,
		0x555D9B744F982375ULL
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
		0x774FCCC7659DD44CULL,
		0x69F354447A0D0A3BULL,
		0x442762BEE6F5F3DAULL,
		0x05D4AC308AB60B23ULL,
		0x5BA1A3C4CECBFE07ULL,
		0xEAC669843D3D83E4ULL,
		0x493E0A77A5E043C2ULL,
		0xDF7467484786DAE3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D215E3258B7DEC5ULL,
		0xA2EA9E7213816B1CULL,
		0x67F44E18453BAEC2ULL,
		0xC43234889AD507EEULL,
		0x4E4A69707D6A5EEDULL,
		0x08F2A01DFCACCDCFULL,
		0x279D876C0A23FCEEULL,
		0x93AF8529C513CACBULL
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
		0x1BA30462251CAC08ULL,
		0x9403BD937ACC495CULL,
		0x2E00F822F7C84CC2ULL,
		0x33F8404DEC68D2B2ULL,
		0xE8B283FFDBB6664CULL,
		0xBF584FE65B9B8DA5ULL,
		0x3E2E212C9CD3B368ULL,
		0xD2373B4B199DE8AFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C2E0F33FBD1B782ULL,
		0xFFB2BA541E69BB8DULL,
		0xD52E2DE28551CFF5ULL,
		0x739CDF2BFE16F42CULL,
		0xE2F7B350D7625FB5ULL,
		0xC44DC5393CF37171ULL,
		0x4A3FE3109C0A24D0ULL,
		0x79A4D5356B76A5FFULL
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
		0x3217A9AC4E54F58BULL,
		0xD09BDD016B1BDA4AULL,
		0xEA320F7D0D1F49DEULL,
		0xAC9199EE2CD7A435ULL,
		0x5FBB17DDEB06CBD0ULL,
		0x1C5517C1D3C60436ULL,
		0xA2331B344FC0C2ABULL,
		0x216F15D00B5E5A72ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3217A9AC4E54F58BULL,
		0xD09BDD016B1BDA4AULL,
		0xEA320F7D0D1F49DEULL,
		0xAC9199EE2CD7A435ULL,
		0x5FBB17DDEB06CBD0ULL,
		0x1C5517C1D3C60436ULL,
		0xA2331B344FC0C2ABULL,
		0x216F15D00B5E5A72ULL
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
		0xCBDFAC9F51B77403ULL,
		0xE453C331AA0C26D5ULL,
		0x46132C5649780136ULL,
		0x5A59B5AF8DCA6214ULL,
		0x4029B0C0E1ADC5A6ULL,
		0xC5BFB040D1D8537FULL,
		0xA0AD197EF880B7F3ULL,
		0x92037BE882E8AA87ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8C0C9807D419F4A4ULL,
		0xFDB0BB914782F9DDULL,
		0xA0ED4637E3B0EC17ULL,
		0xE0853D4EE051A351ULL,
		0x3A358820DF9744E3ULL,
		0x9AC4C84E51165669ULL,
		0x8B38ED16AEADD96CULL,
		0x8C6A3BC68AD43867ULL
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
		0x28144A661F2ADE51ULL,
		0xD6F7C3C7AE8CCF1BULL,
		0xBC0FCCF53FA20F14ULL,
		0x771F0A4ED5051737ULL,
		0xE82917E478EC1FBCULL,
		0x2AC524A2E8980E4EULL,
		0xBE2980430BFB350CULL,
		0x8F3E0E70EF019235ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x777D2E803586DF9AULL,
		0x877789A631CC203BULL,
		0x93C91BCE7BDE899CULL,
		0x239F3ABCF5FD4F6FULL,
		0x867D4D28A33BFD27ULL,
		0x45C1C7554FDFF869ULL,
		0xB84A43AFFB68E018ULL,
		0x6374EEB5A97C6745ULL
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
		0xD32C13321E16A3FAULL,
		0xC8BDFE357272A44BULL,
		0xC240A65D41A7B0F8ULL,
		0x096DCA0F5987E9ECULL,
		0x4B12150C8F906516ULL,
		0x886D0F3E44046AF0ULL,
		0xA8A8E5BE05F1A61DULL,
		0xE8E04E3305CBFD1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x992906BF3A31648AULL,
		0x75E43950A0B00B1FULL,
		0xFB9BB546CB2F551BULL,
		0x864D8C69541B445BULL,
		0x22ECA9D707851A7BULL,
		0x61A214FBC2121DBDULL,
		0x314817118A80F8BFULL,
		0x938C3DD2A4DADCC8ULL
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
		0x59AA2EDB40797CD4ULL,
		0x6364D178BD6279D6ULL,
		0x3149A0C7B45F2CBEULL,
		0xC7A47CDE82DA7B6CULL,
		0x11404DA22B9E4442ULL,
		0x9026B82A9E266F80ULL,
		0xD6E37FF4F2386824ULL,
		0x2E1B81EB4D61C067ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x59AA2EDB40797CD4ULL,
		0x6364D178BD6279D6ULL,
		0x3149A0C7B45F2CBEULL,
		0xC7A47CDE82DA7B6CULL,
		0x11404DA22B9E4442ULL,
		0x9026B82A9E266F80ULL,
		0xD6E37FF4F2386824ULL,
		0x2E1B81EB4D61C067ULL
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
		0xAF547A0014CCE573ULL,
		0x274C41C97CA1F8ABULL,
		0xFF515260CE470921ULL,
		0x3210A7700BBC7826ULL,
		0x3251834939818D20ULL,
		0xB00B09DE184CF3DEULL,
		0xEF2419832E225208ULL,
		0xEA158860A5A43C63ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD94122DBF73DE66AULL,
		0x5ADA8076FE2EE342ULL,
		0x9A1EB8F965F7875FULL,
		0xC8C96F1911035D89ULL,
		0xC9A448BD8AB1644DULL,
		0x2966480F66694D6FULL,
		0x75661C24300D9ACCULL,
		0x7627D95FA13A9E34ULL
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
		0x07525388BC424220ULL,
		0x10E0A4771B8E7314ULL,
		0xA53945F868D3A2DDULL,
		0x7BB96C9C54A0F01CULL,
		0x790E0EEF1B6C06DAULL,
		0x43A0DFCFE0A5F7FBULL,
		0x003AD26ACF9DE665ULL,
		0x749BA1F0F61D8FCEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x89227F3633E58F4FULL,
		0x3FA53545CBBBB971ULL,
		0x576C864925F43C84ULL,
		0x77F07CF9233B324BULL,
		0x9983982DEDE050ABULL,
		0xB5771F0E9F9111E7ULL,
		0x63B67D48CB226EA5ULL,
		0x2B6C61C3C28340BCULL
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
		0x81B80C859B788CAAULL,
		0xDC4526846BDF0DD7ULL,
		0xDA1214BC5F04F05EULL,
		0x6D545ABD47C8195FULL,
		0xF7F0EADBAA9CB052ULL,
		0x8B5CFB731054100FULL,
		0xCE02F9C8835AE29AULL,
		0x88728776322A65F3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCED75D08FE948EEAULL,
		0x34C28DD0112DF391ULL,
		0x6614E7092A277BE0ULL,
		0xBFA720B54062EBF0ULL,
		0x11C68C63DAB89952ULL,
		0x3F9A5BFB3CF4BB50ULL,
		0x4EE8207F1935F0EEULL,
		0xFEB6C095FC0DA68DULL
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
		0x3BBFF017533C19A8ULL,
		0x92FF0454771E2707ULL,
		0x3E63B3C7A0CAB5E4ULL,
		0xB09D755B22258170ULL,
		0x876F8A6D09873738ULL,
		0xA4B08604739B561BULL,
		0x8C28FD20F58BAE53ULL,
		0x5750D66B8549FED4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BBFF017533C19A8ULL,
		0x92FF0454771E2707ULL,
		0x3E63B3C7A0CAB5E4ULL,
		0xB09D755B22258170ULL,
		0x876F8A6D09873738ULL,
		0xA4B08604739B561BULL,
		0x8C28FD20F58BAE53ULL,
		0x5750D66B8549FED4ULL
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
		0xE29358F479389455ULL,
		0x18DB61BCB1D85A97ULL,
		0x624E7506E28DCB57ULL,
		0x34BDC73C0D555C1DULL,
		0x54A53248A5F85AD7ULL,
		0x21AFF850C954E811ULL,
		0x780CD660BDCD1FC8ULL,
		0x8A68C284E5AAAA6DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6E1B1DE221424356ULL,
		0x775C7E401F1FEDAEULL,
		0x396FE05FDC206676ULL,
		0xA095DDDE11609A2DULL,
		0x8A6A57FB9A1B6DB1ULL,
		0xA172D0F562E41DF0ULL,
		0xC99110BAE5A9651CULL,
		0x39126E703BE1B33DULL
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
		0xBF3A4897B371010FULL,
		0x96EBAC50D49633F9ULL,
		0x2E4CFD18279B6ACFULL,
		0x124A9CEB50F1E7EAULL,
		0x1C1369A304BCAD4CULL,
		0x736F3D6FBD7D15B3ULL,
		0x840077F2F4DAC5A9ULL,
		0x9698C0C4F4639CAEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD73668C0444C8617ULL,
		0x4CD5D7D702E611ADULL,
		0x430726B2114D4521ULL,
		0x3B4FBD30F8EA9B68ULL,
		0x2BAA1DE0E9C3CDA5ULL,
		0x5377486296F08A46ULL,
		0x2B3EAAE8246CD053ULL,
		0xD302AED1C4DF22C3ULL
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
		0x9D56AD107DCEDC33ULL,
		0xFDD0F5D108744DE8ULL,
		0x0FE389B7A48576ECULL,
		0xDF810864C1F66978ULL,
		0xAA194853C663B985ULL,
		0x67589906DA0F5F34ULL,
		0x42EAF35665EA5E4FULL,
		0xF7295117E1CB54D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF6E4CE63F6DB58ADULL,
		0x7DDF0CE7570D1CADULL,
		0x3F4D592FC5C40F9DULL,
		0xC4509E2324AAF5E6ULL,
		0x09FF393C91D3E822ULL,
		0x21F163E49E2A18D4ULL,
		0x0A3B8E203B720767ULL,
		0x2417853A1D98447CULL
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
		0xD2A5737CB40DABF8ULL,
		0xA2E227CB2AD21A5DULL,
		0x0FA5881A57BFCB1AULL,
		0xCD137F8688662424ULL,
		0x8EB95EEC1D6D5658ULL,
		0xCD493FFC6C705E82ULL,
		0xF9900952B331BF94ULL,
		0x0335F9D914B536EAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2A5737CB40DABF8ULL,
		0xA2E227CB2AD21A5DULL,
		0x0FA5881A57BFCB1AULL,
		0xCD137F8688662424ULL,
		0x8EB95EEC1D6D5658ULL,
		0xCD493FFC6C705E82ULL,
		0xF9900952B331BF94ULL,
		0x0335F9D914B536EAULL
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
		0x05526CD86B78109EULL,
		0x6A56DC7B12DB9300ULL,
		0xC70FEA91BA38DECEULL,
		0xF2694FEF740EFEE6ULL,
		0x9DD9A56B824EC030ULL,
		0x4E5E0D2B88753392ULL,
		0xBB797EFC47A93ADDULL,
		0xC2087736C71E59ABULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA8714CA6491B8DF9ULL,
		0x33C5C5AD65B281A7ULL,
		0x6CE1270043CA5581ULL,
		0x90F9B5F5AB48E2BFULL,
		0xB1551CFC9CC94B2FULL,
		0x6E57D75B1F41CD3AULL,
		0xECF9275E10083CD2ULL,
		0x72696949310D6703ULL
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
		0x1C9054C61E43FF08ULL,
		0xE264A2CD02859F23ULL,
		0x392E39BFDC4F5DF7ULL,
		0x28A41EAD789AF9F3ULL,
		0xAEECF5062D37EA51ULL,
		0x26BAE141D6105600ULL,
		0x9070A0F46C618A3DULL,
		0x9129534101FEFCA5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x29BBF52F1BCA788DULL,
		0xAD0779744A348280ULL,
		0xC2E8CAAB1BE75BB5ULL,
		0x381E27742F1A57D4ULL,
		0x983364BA8CD7C2BBULL,
		0x48F261FCE66FC6B5ULL,
		0x965F982332AD3BE0ULL,
		0xCC1187ECF32D76FDULL
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
		0x833C89CAE1E870C7ULL,
		0x90DD4C35216F6A43ULL,
		0x67FC2092BE68DA5CULL,
		0x86B3C3A323075262ULL,
		0xD437B72AAA83D373ULL,
		0x0E8B69A9716D3CF9ULL,
		0x1942C8F3CBA17F7FULL,
		0x3C9F04E56E9D7772ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE3996F149460F4DULL,
		0xFDAAC472082CE62EULL,
		0x5077F1F39110EF10ULL,
		0xF869BF4211F8949AULL,
		0x0FE786EF2D51523DULL,
		0x4A5559C3709A1D77ULL,
		0x12959211DA17F24AULL,
		0x79FF4D02961BAEFFULL
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
		0xE67410883C8B197CULL,
		0x1FCC1751D32B6014ULL,
		0xC6EBFEBF3CB6DC30ULL,
		0x422637601877789FULL,
		0xBA8315F249EC224EULL,
		0xD0C34B93E006490BULL,
		0x4E51AF8CA82EE013ULL,
		0xADF14E5D9A347197ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE67410883C8B197CULL,
		0x1FCC1751D32B6014ULL,
		0xC6EBFEBF3CB6DC30ULL,
		0x422637601877789FULL,
		0xBA8315F249EC224EULL,
		0xD0C34B93E006490BULL,
		0x4E51AF8CA82EE013ULL,
		0xADF14E5D9A347197ULL
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
		0x3019F17C506F4A86ULL,
		0xF1F0FE96AE45213BULL,
		0x07019FCE06E7878FULL,
		0x4C71F31764725567ULL,
		0x929D10173A3174B8ULL,
		0x7B09ED7D7ADAB789ULL,
		0x04D52750F68E5D43ULL,
		0x777E6B15332417E5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x67CECB50A2850690ULL,
		0xC7C2AF4EA2FF66C1ULL,
		0xBA4E4AC09AD88FA0ULL,
		0x41BFFA87C49B076FULL,
		0x89A99CE487F68418ULL,
		0x1DC23C31A9A9DD53ULL,
		0x7F5E4065302CCE54ULL,
		0x83BD25D3D36F9027ULL
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
		0x2930D346C2FA66A4ULL,
		0xE7C8447447E7E08CULL,
		0xB34A874AAD0A06FCULL,
		0x1252E30B95E75957ULL,
		0x8236ECB385B37B9BULL,
		0x681EA1E001484686ULL,
		0x28C20AC9100A741BULL,
		0xAB8A9BF9E3C0CD08ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9C4BECC8E05CAF77ULL,
		0xDBBCF225D6714481ULL,
		0xE3A4F81AB7331A0EULL,
		0xADAF3597335535DCULL,
		0x6095598800458B8DULL,
		0xB888E813AB776CBBULL,
		0x11EEFC41F09CCCBEULL,
		0x3FF59F7D301991FDULL
	}};
	t = 1;
	printf("Test Case 159\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x3744604975355CB6ULL,
		0x654ABFE954C5629BULL,
		0x74FDB71B881CCF26ULL,
		0x25053C96B4F322A9ULL,
		0xC96B496DA90CB649ULL,
		0x75FA297058383778ULL,
		0x76088E35BAFA4300ULL,
		0x41BA01AF37B52307ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACE102CC6877336CULL,
		0x6A8D1B39B3F01C14ULL,
		0xE56FD4A8E720A348ULL,
		0x36587C53E417B856ULL,
		0xDDF30700F1474FE3ULL,
		0x4425374CF94FAF53ULL,
		0xC3923DDE68167EFBULL,
		0xA4F919A07E71DFFDULL
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
		0xE0C096BE453C9659ULL,
		0xE838214C4715576AULL,
		0xB11118F57A869272ULL,
		0xEC9004B8E1D54CF5ULL,
		0x68AC8182E53230D8ULL,
		0x2558A02B6840F7C5ULL,
		0xB6955A58FC893728ULL,
		0xA0D34DFC215BE665ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0C096BE453C9659ULL,
		0xE838214C4715576AULL,
		0xB11118F57A869272ULL,
		0xEC9004B8E1D54CF5ULL,
		0x68AC8182E53230D8ULL,
		0x2558A02B6840F7C5ULL,
		0xB6955A58FC893728ULL,
		0xA0D34DFC215BE665ULL
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
		0xCE630186B84BFBB9ULL,
		0x64C7971411B42E80ULL,
		0x3709FBEB47FDF41BULL,
		0x4C5581F246E8A5D0ULL,
		0x0288CF61F63DC06DULL,
		0x3F300673B491531FULL,
		0xE193B740877EEC8EULL,
		0xFBBD528ED0A730E1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE22B4F4565AD503BULL,
		0x63318E84C6317473ULL,
		0xE5FB25C8EEE69DCAULL,
		0x7E6FD69D22209139ULL,
		0xDC5E6931C28725C7ULL,
		0x6DD61D82CDBD7C9CULL,
		0x1E7FA4420FB213B7ULL,
		0xA2B26A5A8E15DE13ULL
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
		0x7CC953209BB47736ULL,
		0x66FF627720CB816EULL,
		0xEA1230DD36D7762EULL,
		0x4065576B3D591FF0ULL,
		0x43B00F49BEB5AD5BULL,
		0x74EA6E41A47A0943ULL,
		0x808D628C36ADF412ULL,
		0x3EC0F891C59EED11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x926301E602F081A3ULL,
		0xB611E490372031CEULL,
		0x71E39392CA8F1CB3ULL,
		0x242B08EE712B1678ULL,
		0xAB530EC172D95FF5ULL,
		0x9991D4FD3ED3A477ULL,
		0xF0CCDA547AB49971ULL,
		0x20C3AD35F1656DCAULL
	}};
	t = 1;
	printf("Test Case 163\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x5488364B8C243887ULL,
		0x1633ABC0D91D5F6EULL,
		0xE0E857B2C51781CBULL,
		0x3457D5C6147F5C51ULL,
		0x86AB9B0C28C6F83FULL,
		0x0D73411E000B12ABULL,
		0x7814BA5171576DBDULL,
		0x0D4BCFE95D1663E2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3C605E565CB7ABCFULL,
		0x008D31A079E482E1ULL,
		0x5DC09A5DFD0D57F1ULL,
		0x80855320929E3113ULL,
		0x935ED266D4CEE284ULL,
		0x502E05A8663980E0ULL,
		0x1E350939BFC3A69FULL,
		0xE4EFA08FD0D3CB02ULL
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
		0xA1248064D0D5BAB3ULL,
		0x71875641E1866E26ULL,
		0xD88C80305BDECAC7ULL,
		0xEA30023AEBD58CB1ULL,
		0x4633D92A0961F4A5ULL,
		0xB74DC4F61298DCE9ULL,
		0x5D33AA707E73A0B7ULL,
		0x973E964B7DC1E403ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA1248064D0D5BAB3ULL,
		0x71875641E1866E26ULL,
		0xD88C80305BDECAC7ULL,
		0xEA30023AEBD58CB1ULL,
		0x4633D92A0961F4A5ULL,
		0xB74DC4F61298DCE9ULL,
		0x5D33AA707E73A0B7ULL,
		0x973E964B7DC1E403ULL
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
		0xDF75384C2E090BFCULL,
		0xA4E3B8B3264077CCULL,
		0x5F4BCF4AD74F6B2FULL,
		0xE26AAE149F714946ULL,
		0x84713F4153BFB71DULL,
		0xC1FCB02FF3A33A95ULL,
		0x50311565C41080C4ULL,
		0x67BD136EE25781D0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFF2A13F5C69FE84ULL,
		0x54B746797283CC5CULL,
		0xC4147F82C1B8606FULL,
		0x69950DE7723C7DFCULL,
		0xA94180307705292DULL,
		0xF85CEA837B1C0E68ULL,
		0xEED641FE3E393E11ULL,
		0xC8336ECE111A299CULL
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
		0x1B94CE58553F4B03ULL,
		0x3B7CDCD17D1C3B91ULL,
		0x666C277AFBAE7E3AULL,
		0x899AAE6E32B3FBD5ULL,
		0x0FF462E0FE8F7BE1ULL,
		0xD416BE79EA6AA2A4ULL,
		0xE4ECA543D3013465ULL,
		0xA0690D9EC95277D6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B4D3AE01C294F41ULL,
		0xADA834147422140AULL,
		0xD03F09F1CC6407F1ULL,
		0x50FE0BCC660F40EDULL,
		0x82EE7A2C3EFEE01FULL,
		0xC5CCE7AEFF6A9E84ULL,
		0x96D4FC495CD78724ULL,
		0x8BB2BA3CCD6BCA63ULL
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
		0x2A3C90CABD4E9877ULL,
		0x2BB047FA700854ECULL,
		0x3CBFBBD5A42F5085ULL,
		0x19AC07A1D8154FE7ULL,
		0x9F9ABED2A61F6938ULL,
		0x91537507BA5FCD51ULL,
		0xFE2B5CD2D95994B2ULL,
		0xEAB768BA36B017B7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x865CCE4E12A56690ULL,
		0x072B7A4509A6E145ULL,
		0x35DEE6E660A52486ULL,
		0xA5D801C6C6217480ULL,
		0x91B7DDC1EA7911B3ULL,
		0xF9B9FCDBD42F8D48ULL,
		0x0630600F8FF470BCULL,
		0x3D4C782A18D3D019ULL
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
		0xE0E4CA88864E0A9FULL,
		0x8B793A3DCC388C2AULL,
		0x2F81B1BBEBB33EA9ULL,
		0x39BD0CC16D014CC1ULL,
		0x8CB9C6BD922E0684ULL,
		0x2E9A5F1448CBDAA0ULL,
		0x2506BBB8B8322CDBULL,
		0x3EC07BE8DB0090F1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE0E4CA88864E0A9FULL,
		0x8B793A3DCC388C2AULL,
		0x2F81B1BBEBB33EA9ULL,
		0x39BD0CC16D014CC1ULL,
		0x8CB9C6BD922E0684ULL,
		0x2E9A5F1448CBDAA0ULL,
		0x2506BBB8B8322CDBULL,
		0x3EC07BE8DB0090F1ULL
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
		0xD43005EE65F32093ULL,
		0x4EF9375A5AFEF50BULL,
		0x89DB0C19AECD91A3ULL,
		0xC81581C5D4E1E8CDULL,
		0x343B6F4C0DA74BC0ULL,
		0x6BA9FEEEC84E0175ULL,
		0x1A81A95F4E9A7DA5ULL,
		0x0C7B388E34FE435EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8BF71DAC9403F50AULL,
		0xD62AB808A3F8B6E3ULL,
		0xAF159BA867829252ULL,
		0x08A342C91D156B64ULL,
		0x52316F814E86F791ULL,
		0x56632F54B629D1B4ULL,
		0x683F0C979DA8C1CFULL,
		0xD32C6CDCA2ADF003ULL
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
		0xBF04E691E8D49394ULL,
		0x514926ACDDE1488CULL,
		0x2B13B08D4C4042C9ULL,
		0xFFFCF49292CBDE86ULL,
		0x81C6870B50F530B0ULL,
		0x13C2CA5A4A1B69CAULL,
		0x0FD1E5A7E4522F28ULL,
		0x1E9F92A6614C3359ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x21130659D09B3159ULL,
		0xDB51A1D9A4B08985ULL,
		0xC103345319FD769FULL,
		0xB6147130D07EFB5EULL,
		0xAFF1121A08F12B3BULL,
		0x04B698403F3508A4ULL,
		0x35E0DE0D03AAFEADULL,
		0x696A4578111A6382ULL
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
		0x6C89EC6AD1033799ULL,
		0x9CFBAD487DBC6B13ULL,
		0xF88F38F4D0EFFF98ULL,
		0xA2ACF570F5BF913DULL,
		0xF5282B9D65E3A7DEULL,
		0xB50F76603D4D76BBULL,
		0x3B00ED176B2DBD23ULL,
		0x7B75FA5E2D264D3EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x28ED658765CCE264ULL,
		0xCF8BF31025F3E021ULL,
		0xF8817C6BBEEBAAC9ULL,
		0x43758F7A5787F414ULL,
		0x7420409FC20CE288ULL,
		0xA2C48A93F26755A0ULL,
		0xE26DA323ED954346ULL,
		0xBE394F18004E15A8ULL
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
		0xCBE72DE710AC87CDULL,
		0x914DA5ED485F4261ULL,
		0x2D1DF3092814F4A6ULL,
		0x23D0F52D4D8684CFULL,
		0x2AF077811FC5AD38ULL,
		0x7F86D356F59ADDF3ULL,
		0x7797F5358832FDB4ULL,
		0x50E472F085E26E7FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCBE72DE710AC87CDULL,
		0x914DA5ED485F4261ULL,
		0x2D1DF3092814F4A6ULL,
		0x23D0F52D4D8684CFULL,
		0x2AF077811FC5AD38ULL,
		0x7F86D356F59ADDF3ULL,
		0x7797F5358832FDB4ULL,
		0x50E472F085E26E7FULL
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
		0x039EA4D16782FC76ULL,
		0x9E1627B0BEEEC2D7ULL,
		0xDA0C9A6AF7E26759ULL,
		0x475A1700E0DFA755ULL,
		0x5DC6E8B48C7958A2ULL,
		0xA1BD444559E598DFULL,
		0x7A69B64DE68ACE8FULL,
		0x3E31022C21C9B86EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFE4AD5513C5B1756ULL,
		0xD832277C8D745EF3ULL,
		0xECFA149618F88DBEULL,
		0xE44AB874145CE462ULL,
		0xDBB9EA0B56564A75ULL,
		0xFCFF714D7DE7B874ULL,
		0x56C42B4B01CE2090ULL,
		0xAB6A6D7DCA87EA70ULL
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
		0x10DF4101F3A36AF4ULL,
		0xDB2E7E49702BD5C9ULL,
		0x0AC4B59F7EF109F8ULL,
		0x9E85CF6895690035ULL,
		0xC4D9FEC38EDCCEDFULL,
		0x218676F2CB757AF7ULL,
		0x2F0195D406BDFE08ULL,
		0x7B92951ED8DC5059ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x54046F5F958E73F9ULL,
		0xBDD8462CA883CCB6ULL,
		0xA240BB647C2E406DULL,
		0xAAAD6B64270477C0ULL,
		0xF7E7C020E6A3EFA3ULL,
		0x964138FFFC5F8262ULL,
		0x99C1E8508ECCB58EULL,
		0x5AD00E7B190C3197ULL
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
		0xBF7B77E8F0C62584ULL,
		0x23EC599903B89B52ULL,
		0x91366D0BD49C7D03ULL,
		0xBB0723C406E97BD6ULL,
		0x554F1E20C9B60737ULL,
		0x412C78D792480AF8ULL,
		0x6B0BFB046FCDF1FDULL,
		0x772272A886A17825ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB6680724610A665CULL,
		0x4CC6C57299948544ULL,
		0x73DEDF6E915A0896ULL,
		0x66BE19EC62934FFAULL,
		0x1638BE13321CAA3CULL,
		0x457772DCFF0F0A92ULL,
		0x9819D0592AB78A67ULL,
		0x29BA9616FBE37FCBULL
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
		0x5A3920730C6CDB90ULL,
		0x780AD5DA6BC37895ULL,
		0x6798484FB48309BFULL,
		0x9B12C825F97A6319ULL,
		0x6010983341F8C302ULL,
		0x8EFE1AB6587AE2E0ULL,
		0x342F60EA034AD1ADULL,
		0x80F47DC0BD341E64ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5A3920730C6CDB90ULL,
		0x780AD5DA6BC37895ULL,
		0x6798484FB48309BFULL,
		0x9B12C825F97A6319ULL,
		0x6010983341F8C302ULL,
		0x8EFE1AB6587AE2E0ULL,
		0x342F60EA034AD1ADULL,
		0x80F47DC0BD341E64ULL
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
		0xBC054D16F29F9EE7ULL,
		0x98DF9E9D488DFDA2ULL,
		0x40A311F123EFC742ULL,
		0x96A5AA8BB41CD28DULL,
		0xC1AC88CA7394586BULL,
		0x6A19BFADB8185DC2ULL,
		0x65318D7EF0100D6EULL,
		0xBC64C3E1B0112D30ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE11A96B697AC3AF4ULL,
		0x3CE9711A6E8F04A8ULL,
		0x67900EDAEEBFD137ULL,
		0xEE4C2E8157326187ULL,
		0x88FFFB142F70B119ULL,
		0x25EFE9790A478F5EULL,
		0x7DD11EE188A3D2BBULL,
		0x363B3530C010406DULL
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
		0x5727AFC33D949834ULL,
		0xC2FD0D4EF46BE594ULL,
		0x619B45979407AEF0ULL,
		0xC9458C75579B2DEEULL,
		0x5142D7F86AFCF5FEULL,
		0x53B9D644D65B725CULL,
		0x2398367A34296B40ULL,
		0x3DC354A52DEDB818ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF24BAEBE1135C16ULL,
		0x9DE8C2BDBC834177ULL,
		0x9C2D0CDC8EB89000ULL,
		0x91903ADBEC6434C0ULL,
		0xD9DE9AB94F6C5482ULL,
		0x5F094BDF5ED646DCULL,
		0xBACFE87F3F695656ULL,
		0xD3A7717B7EB1E52EULL
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
		0xD88603EEEBBD9DE4ULL,
		0x3BDE2821819471F7ULL,
		0xA66E550F9FF6B3CAULL,
		0x1D3991F662548373ULL,
		0xBC1075A7350D0D36ULL,
		0xDDA30E2E212DE9DDULL,
		0x8B3A16AEE1B48EECULL,
		0x154BBCC83A028D11ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x87D19BCD88A85AD9ULL,
		0xAF5070A8B3D1431FULL,
		0x03CDBD24B7233F4DULL,
		0x8E93E9AF58B00E7BULL,
		0x2A4D0ABBF78B3BEBULL,
		0xF2AC67264BED758CULL,
		0xCF8B376B16F232C6ULL,
		0x8FC1FA432B58F268ULL
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
		0x00AF69483A02EF91ULL,
		0xEEA4A81B607E2EA4ULL,
		0x03F7EAAF0471EDC2ULL,
		0x01A40D98C9C626FBULL,
		0x905A56BE3C73C2DCULL,
		0x07D099B5752A007AULL,
		0xF79BFDC6B64CAAADULL,
		0xF1913966D52BF548ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00AF69483A02EF91ULL,
		0xEEA4A81B607E2EA4ULL,
		0x03F7EAAF0471EDC2ULL,
		0x01A40D98C9C626FBULL,
		0x905A56BE3C73C2DCULL,
		0x07D099B5752A007AULL,
		0xF79BFDC6B64CAAADULL,
		0xF1913966D52BF548ULL
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
		0x44EA36D40220D455ULL,
		0x112C3DAE91D2B8F7ULL,
		0x6CA2073A594225F4ULL,
		0x767BD8E902E2ED39ULL,
		0xA35623CAA238B933ULL,
		0x7E461B5DDB1C15FCULL,
		0x2038DB6FD5FCAB6DULL,
		0xA313AB4E06A5B688ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF01ECBC7D43B0993ULL,
		0xB71B825187D0B2A3ULL,
		0x305E4B522B9B41D4ULL,
		0xC0B646F9CA2171A2ULL,
		0x64A44246CC243326ULL,
		0xEA748943711C18F5ULL,
		0xBCF034BB77D848B8ULL,
		0xFCC18C42A10126FFULL
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
		0x7740E0CE5FA2C3BEULL,
		0xA7907610C8705E10ULL,
		0x027CC7F317CF37F9ULL,
		0x43B889ABB7D7502CULL,
		0x384AF15FDA0AC88EULL,
		0xB06EFAE6BADBDEBFULL,
		0x65190E6C6C485A92ULL,
		0x9AACA0E2E9F4E123ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9725A090DAC06BCBULL,
		0xE3C76A61860F5D8CULL,
		0xFE70619A86A98999ULL,
		0x755F9C59CA331C66ULL,
		0xF536EB07EF500C9EULL,
		0xFA1758CA12486039ULL,
		0x1C7D01DD691FE6F0ULL,
		0x143E633455049C5DULL
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
		0xF890C012D7E76FC8ULL,
		0xE25CB6341094405CULL,
		0x3033EA16E1A32E60ULL,
		0x0F5C93EC3047E0F0ULL,
		0x3EA22086D81C3D6AULL,
		0x54464F208CD9EC6DULL,
		0x1A18F04CC5173EEFULL,
		0x5AED62119EE6AFC6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5347C29D03892727ULL,
		0xA7AC2F11AE2ECB6FULL,
		0x98FFCCC2C8CCE609ULL,
		0x9B7D93161B838ACEULL,
		0xFCF1C0DF00BD0D10ULL,
		0x18923093B07E2963ULL,
		0xCF14C5D6478E8A2DULL,
		0xD1ECD68E06524750ULL
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
		0x232E23D128AD5D91ULL,
		0x5B334EE4B74A9C66ULL,
		0x81C679FE66A6AA5CULL,
		0x4E2B81220C0D17E4ULL,
		0xDDE12804C32848D3ULL,
		0xC5FF761329019E33ULL,
		0x7348E9B67160E8CEULL,
		0xE4478D843E8CBFE8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x232E23D128AD5D91ULL,
		0x5B334EE4B74A9C66ULL,
		0x81C679FE66A6AA5CULL,
		0x4E2B81220C0D17E4ULL,
		0xDDE12804C32848D3ULL,
		0xC5FF761329019E33ULL,
		0x7348E9B67160E8CEULL,
		0xE4478D843E8CBFE8ULL
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
		0xCC4B434CAE7FA6E2ULL,
		0xF3DF76AF21FDCC6BULL,
		0xC0A671978FC16A30ULL,
		0xC52BCC84FFD83C0FULL,
		0x7C74268266198947ULL,
		0x0E8D31EDE66EC8F5ULL,
		0xAA200F2F9F7C3CDBULL,
		0x79B21349384A5259ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC897EE391DAA6BDULL,
		0x95707526DA93D0BFULL,
		0xECE107DACA38A09CULL,
		0x2A2F0B8425107FCEULL,
		0x49BE5C29F5D2436DULL,
		0x30CDC2782CA3D860ULL,
		0x0A9F118F7286E253ULL,
		0x2B3FC7A66504B69EULL
	}};
	t = 1;
	printf("Test Case 186\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: > 0\n");
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
		0x1FFD6C35D9A89536ULL,
		0x4DBF961053ABD60EULL,
		0xB7DF5C1B416EC6EBULL,
		0xC2946E0B7B4F6B3CULL,
		0x129B4F2635EE5964ULL,
		0xCAD2DE89DB5D0B08ULL,
		0x15A1A16B76EA83AEULL,
		0xFE2D4ED1C5E47057ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A6DBCFDD21F7C85ULL,
		0xF3549961095B0D8EULL,
		0xFBB1957633C5857CULL,
		0x26D1B6AE6369E68AULL,
		0xB25EB4A357307CC8ULL,
		0x1B36E8B62AF61CDFULL,
		0xD4EB7B8020CCEDB7ULL,
		0x79336123A8A52826ULL
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
		0x1132C464FDBB184BULL,
		0x269D00279E30D771ULL,
		0xA525256C8268F482ULL,
		0x328A1713D9DDB910ULL,
		0x7A8C88B97474FFE7ULL,
		0xCF3D161B080DD572ULL,
		0x909E1C104888DEEBULL,
		0x624C8EA1B442409CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x32123350D4E6A066ULL,
		0xB329E78784F5FCC8ULL,
		0xAAACFDF9DBA8A805ULL,
		0x7F6F07117E145357ULL,
		0xC253D1CA515E77CBULL,
		0xFA9BFD602FA46928ULL,
		0x97808DAD70B2905CULL,
		0x4AE8C102E101D34FULL
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
		0xD4579EEEE4C71FE8ULL,
		0x1D7BE2CB045E29EFULL,
		0xD6BF15429AB7AAD3ULL,
		0x546D27745E9EC499ULL,
		0x6350CE84B89BC8C2ULL,
		0x34AB1AC42B538F02ULL,
		0xDD7EF9D467341DD4ULL,
		0xEE298641FD68A005ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD4579EEEE4C71FE8ULL,
		0x1D7BE2CB045E29EFULL,
		0xD6BF15429AB7AAD3ULL,
		0x546D27745E9EC499ULL,
		0x6350CE84B89BC8C2ULL,
		0x34AB1AC42B538F02ULL,
		0xDD7EF9D467341DD4ULL,
		0xEE298641FD68A005ULL
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
		0x985597ADF70218E6ULL,
		0x5DBDEA6064068C32ULL,
		0x18F0F4609E6CEEBAULL,
		0xA938665C6D71FC98ULL,
		0xCE2B6885116F1FF1ULL,
		0xD8C7B22F10ADE441ULL,
		0x28873E7CA47EAC57ULL,
		0x3628509A8FB7FCDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4AB4DE407A32EC47ULL,
		0x3B43FA4E337D2E69ULL,
		0x46DD9DA2C0165838ULL,
		0x186DE8674B8589CEULL,
		0xE1322F4934E88948ULL,
		0xF063D80510E31FAAULL,
		0x5DAC26C5B4BA3C8DULL,
		0x5010C285EA7F2359ULL
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
		0x1854D71DCA6B9616ULL,
		0xC839E84F8AA7EE54ULL,
		0xE896BCF5645294A2ULL,
		0xE2170E87C5FE498FULL,
		0xBB52EC88BC27F929ULL,
		0xC822778664BCBCE2ULL,
		0x9C627FE88E7F184BULL,
		0x5632CF8A43292DEAULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB4258248996C7B35ULL,
		0x9B24AC1D0F7FAFCEULL,
		0x6E80ECA4B2ED6C5CULL,
		0x8971D5FC6733F052ULL,
		0x8C98BEB5FC06CB57ULL,
		0xFFA44C6B73306C54ULL,
		0x81B7EEA3832CFB03ULL,
		0x25985FAA82E731C6ULL
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
		0xCC9B21451ADAFF32ULL,
		0x4A07BC4F467AFADBULL,
		0x5E6C9F857336A6E2ULL,
		0xAA597E8D9E3F61C4ULL,
		0x1C9A83C2B52963E2ULL,
		0xCEF96B65BA405E86ULL,
		0xC1E364958F84F519ULL,
		0x1C536C60A32E4EDBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD0B81F54A19E445DULL,
		0xA4B1D26FEB23E4DBULL,
		0xBBC6C470A116FE97ULL,
		0x7BC7A0FC56628BAEULL,
		0x703DAFA9426CDDF7ULL,
		0xC0017DBAA5FAE430ULL,
		0xB6B0CB56BC4D9789ULL,
		0x7EF80612FBA3C6BDULL
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
		0x4286635CE402433CULL,
		0xFB91993F4DBBE658ULL,
		0xD016452F3E1AD53AULL,
		0xCEBCA42ABE28491BULL,
		0xB126615970990E66ULL,
		0x43A1A96E1D346D9EULL,
		0x1DF5DC7235C5829CULL,
		0xF1215E9A18E726A2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4286635CE402433CULL,
		0xFB91993F4DBBE658ULL,
		0xD016452F3E1AD53AULL,
		0xCEBCA42ABE28491BULL,
		0xB126615970990E66ULL,
		0x43A1A96E1D346D9EULL,
		0x1DF5DC7235C5829CULL,
		0xF1215E9A18E726A2ULL
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
		0xE04215D122687E13ULL,
		0x0C5950C3EDAAA2BBULL,
		0xBEA8E0B4BBADEFBCULL,
		0x6C784F17FDEC767EULL,
		0xB90DE96AAB877976ULL,
		0x4E769A7AF635D89AULL,
		0x081F12B9C4188C32ULL,
		0x5AA626B355014627ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xACBC0B6900849E70ULL,
		0x89F12515D55040CFULL,
		0x76B6F90289F97B46ULL,
		0x1599A25FC39BA43FULL,
		0x858973A7E2C22990ULL,
		0x04A20B76807B71C4ULL,
		0xF85ED78BDE66B0EEULL,
		0x92701B9C5A29C18CULL
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
		0x8CB622A091219714ULL,
		0x87E0A5A703891FA0ULL,
		0xD3B0DB516E07EF53ULL,
		0xD846FC855DB2EFCBULL,
		0xEDDAC2A26F48BD5BULL,
		0xA727AD6D3F663656ULL,
		0xCD295F98F556445FULL,
		0x164C88C0A836127EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC1897D300AF49B11ULL,
		0xD024590D627D2BD5ULL,
		0xC59248A7FCCDA08DULL,
		0x9FBFF72D8E390F01ULL,
		0x637A5BB9C442CA72ULL,
		0x2DC39C6BD6D63C31ULL,
		0xB4587718EB888F96ULL,
		0x60777BABC8074B3EULL
	}};
	t = -1;
	printf("Test Case 195\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, COMPLETE);
	printf("k2:\n");
	curve25519_key_printf(&k2, COMPLETE);
	printf("Expected: < 0\n");
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
		0x7C64188F78545BCEULL,
		0xD7EAA6A223638081ULL,
		0x77DB726A916FD747ULL,
		0x9416B49B03EF57A5ULL,
		0x41906FBE8EEE997FULL,
		0x31BE83D8018FF280ULL,
		0x4678CB20A820C9AFULL,
		0x044F588D062003EBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8DA9238E3D1F75E6ULL,
		0x52FFFB9228933935ULL,
		0x2B6541891DB36040ULL,
		0x048F359A4595369CULL,
		0x19EDE36DF1A9E736ULL,
		0x06F1FFB6EF22CED1ULL,
		0x1B5BFC23A19EE8C2ULL,
		0x70507488271C8826ULL
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
		0xBF7C9220135F7108ULL,
		0xD85B6F410F027F4CULL,
		0x80391DFD91413C11ULL,
		0xC3228E7BACEC85FDULL,
		0x0D3F05CB86962CE9ULL,
		0x69A8DE2DFE8EBEC3ULL,
		0xE8E6EC3151C6C5EDULL,
		0x58336DE0C5C84A5AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF7C9220135F7108ULL,
		0xD85B6F410F027F4CULL,
		0x80391DFD91413C11ULL,
		0xC3228E7BACEC85FDULL,
		0x0D3F05CB86962CE9ULL,
		0x69A8DE2DFE8EBEC3ULL,
		0xE8E6EC3151C6C5EDULL,
		0x58336DE0C5C84A5AULL
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
		0x38E2F8BB7ABF4479ULL,
		0xB4BA58EEC57650CCULL,
		0x8869314B88D1B523ULL,
		0x30E1CDAC36C44CB0ULL,
		0xE91ED590B59CFAABULL,
		0x30AA2683858F32A9ULL,
		0xEF2B4B3AD908E4DDULL,
		0x831EF1B24FC0E7A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD748107C028C509FULL,
		0x917E35C013621C66ULL,
		0xD2AFD1F713C18C40ULL,
		0x1B2E9485A3AD742DULL,
		0xF3F60606B1A1D2B8ULL,
		0x71424BA39F72CCE0ULL,
		0x52BEC5460363A705ULL,
		0xA571543DD8F2BD14ULL
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
		0x4B61814CBB45E20EULL,
		0x9C483B88A7A2894EULL,
		0xDB6E8E32887D251EULL,
		0x7C84F2E2AA3F5397ULL,
		0x99DC30C80FCF3943ULL,
		0x64294F2D17DADAA3ULL,
		0x0A5AAF411B7C505DULL,
		0x2EB5BB59FA59754DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x381FF1175B41091AULL,
		0xB990258500414D8FULL,
		0x4CC52C1823BFED96ULL,
		0xCA128C6585A6E83FULL,
		0x5526CB7D1A231CD1ULL,
		0xA9BEBC03884A8475ULL,
		0xCE77FB5BB3289D5CULL,
		0x03F04D96DAE51607ULL
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
		0x9431326CD1F9F691ULL,
		0xEE4C8CFA474778C3ULL,
		0xABB30ACD4A484900ULL,
		0xB7E31345DF13DDA4ULL,
		0x5092BAAB76C173E7ULL,
		0xC36C6586E3D30DDFULL,
		0xF3D4FB7F7DE5EB8EULL,
		0xBFE4F368F0380F0AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE743D7AAF9501FB1ULL,
		0xED5E51FC33F6F940ULL,
		0x73F5487636090CE9ULL,
		0x616671FFED362CAAULL,
		0xECB6CD853F6BC5DDULL,
		0x4A9FF09A1EC6990CULL,
		0x80C2F94D4D5393DFULL,
		0xACFF65538461E4E6ULL
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