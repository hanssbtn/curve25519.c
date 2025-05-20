#include "tests.h"

int32_t curve25519_key_sub_test(void) {
	printf("Sub Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0xC69D82C68CD0C2D6,
		0xF34BDCAFE185D8BC,
		0x7ACC74A392FB255D,
		0x4310595072C4039F
	}};
	curve25519_key_t k2 = {.key64 = {
		0x3A8E9F5D2252B66F,
		0x3C91E45DB49BD9D0,
		0x1E205E56A86E0D1C,
		0x5BADBBDE027B3E34
	}};
	curve25519_key_t k3 = {.key64 = {
		0x8C0EE3696A7E0C54,
		0xB6B9F8522CE9FEEC,
		0x5CAC164CEA8D1841,
		0x67629D727048C56B
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x020E4353C2D8DCE9,
		0x2F52E4362BF45CCD,
		0x88CFE00614F38368,
		0x09451160F0CB5E7D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3F90DD2FF314A29,
		0xC19F9DE082EC63DD,
		0xB1D372BCB311ABAA,
		0x2DC00963455330BB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E153580C3A792AD,
		0x6DB34655A907F8EF,
		0xD6FC6D4961E1D7BD,
		0x5B8507FDAB782DC1
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xF08ACA7D0A0ED18E,
		0xE2314BBE3F05ED43,
		0x664523D371B063B4,
		0x20A642185E709E3A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE91FAC64F0EB1C7,
		0x7E5D5D86F5E59987,
		0x505DF3835EDBFE39,
		0x165944EDF59916CB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11F8CFB6BB001FC7,
		0x63D3EE37492053BC,
		0x15E7305012D4657B,
		0x0A4CFD2A68D7876F
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xF05DB14E32BEEA6A,
		0x2EA8FE49C4DF9EEF,
		0xA5CB80AC2E77DD49,
		0x2223CFDA742C1C41
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFB2CC6B7DF732E99,
		0x5F7D3028381304AD,
		0x943242A92983214B,
		0x2D303D84A6ED0CAE
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF530EA96534BBBBE,
		0xCF2BCE218CCC9A41,
		0x11993E0304F4BBFD,
		0x74F39255CD3F0F93
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x161B360E0E95BA64,
		0xDCD0DC4BBDC765AD,
		0xDD91D0D8BB07BD83,
		0x12C6157D16E6F92B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6A11BA0BE459CF77,
		0xE111A3E0E1B23D8D,
		0xCAE4BA70852A6D1E,
		0x19341EC24B049871
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAC097C022A3BEADA,
		0xFBBF386ADC15281F,
		0x12AD166835DD5064,
		0x7991F6BACBE260BA
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x20C0AE528E35219A,
		0x838831E6E50587BE,
		0x4ECEFA9CDE7C3810,
		0x3483ADC93703FB89
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D1416E611689A16,
		0xA3A3EA476B61FC4E,
		0x48CF1E66F21FDF19,
		0x3C8B7496EE043BD1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93AC976C7CCC8771,
		0xDFE4479F79A38B6F,
		0x05FFDC35EC5C58F6,
		0x77F8393248FFBFB8
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xA2A3522F4B574695,
		0x7A1E5618AEC3A390,
		0xD6FE84C686286BC3,
		0x1D78B329C5A3BA28
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6C9BE5F36BA2D63,
		0x6F41FDC3DE0BE364,
		0xF2BE051FC39AB0E6,
		0x509D26439B607C8D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBD993D0149D191F,
		0x0ADC5854D0B7C02B,
		0xE4407FA6C28DBADD,
		0x4CDB8CE62A433D9A
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x69A618582810221B,
		0xE9E8C987499E9679,
		0xCD589BDAA34FB2BC,
		0x4071EBB224D202F1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0219AC1CC92A4CF7,
		0x6A4A5D065C0DB358,
		0xB4D61CC61B5EDC36,
		0x51A4FB111CBD0AE7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x678C6C3B5EE5D511,
		0x7F9E6C80ED90E321,
		0x18827F1487F0D686,
		0x6ECCF0A10814F80A
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xE111D99BAB8C9CAF,
		0x948151D6FED3A632,
		0xA6CFE2BC402A973B,
		0x60B95804AE35F58C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB15F22E56D675152,
		0xEEAC8C1BB20C4110,
		0x23D850FF3C6906BC,
		0x4BE9602DBD4F7FFC
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FB2B6B63E254B5D,
		0xA5D4C5BB4CC76522,
		0x82F791BD03C1907E,
		0x14CFF7D6F0E67590
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x1765037F94D03149,
		0x09D6C1ADEE65EDAC,
		0x61C13016716B6DA1,
		0x1FC51E9C5B379FF1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDA4E4EA878989F8B,
		0x838E4275B7CA73CD,
		0x5CF030197BF03135,
		0x15A4671EE9F2F448
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D16B4D71C3791BE,
		0x86487F38369B79DE,
		0x04D0FFFCF57B3C6B,
		0x0A20B77D7144ABA9
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x6B6A67ED24132778,
		0x6AF41D9AE150C8F0,
		0x33D562446186EEF6,
		0x3851638865307C3C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEAE1DCCA15B0E97,
		0xF04F26C20079C23E,
		0x5145927E082A1A5E,
		0x39A91225E7F3E621
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8CBC4A2082B818CE,
		0x7AA4F6D8E0D706B1,
		0xE28FCFC6595CD497,
		0x7EA851627D3C961A
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x521C84ACFA16271A,
		0xC722F3D39D928CDB,
		0x8BB1D4EAA5255DE0,
		0x6EB350763833B0A6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x78755395E4B0CD6E,
		0xA4EE355E0EF13975,
		0x2D4FD8DDFFF7A17F,
		0x6B776EE8B37EDC77
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD9A73117156559AC,
		0x2234BE758EA15365,
		0x5E61FC0CA52DBC61,
		0x033BE18D84B4D42F
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x809D8B155C4F667D,
		0xA5286E758057BECB,
		0xCC5284DEC75E8B88,
		0x36EA7FBA24D6B1C6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xAC7381B26CD7BE0F,
		0xD873B55212AE77D5,
		0x99D59BDACEEEEB73,
		0x7556974AF03C9DF4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD42A0962EF77A85B,
		0xCCB4B9236DA946F5,
		0x327CE903F86FA014,
		0x4193E86F349A13D2
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xDBA511E25390BEAC,
		0x6FA3B4FE565BBC64,
		0x3206C696F7F0FF1D,
		0x749E9C679C9B79A6
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3108768B8B3649D8,
		0xEBCF06BFC93E401E,
		0xE692A2735F4E7108,
		0x04BDDE410875F090
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA9C9B56C85A74D4,
		0x83D4AE3E8D1D7C46,
		0x4B74242398A28E14,
		0x6FE0BE2694258915
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xD149F464ACEEAF48,
		0x290D01F701383B0D,
		0xB12593906EA08EA5,
		0x18280F9EAEDFB880
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD45B663AD1B82E2C,
		0xF5F9A9DDA9D9C16A,
		0x8CC125E9775819E8,
		0x73CA36A31FE6851B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFCEE8E29DB368109,
		0x33135819575E79A2,
		0x24646DA6F74874BC,
		0x245DD8FB8EF93365
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5D3B98E912192A7E,
		0x9851B574D2AB7E1F,
		0x1E3D33EDC04690D6,
		0x738C16DF7E126CFC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4B5284835DA651D9,
		0xCD67F420CF9AE50C,
		0x7D7049B09F494220,
		0x24C6BA980F417E43
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x11E91465B472D8A5,
		0xCAE9C15403109913,
		0xA0CCEA3D20FD4EB5,
		0x4EC55C476ED0EEB8
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x2A0CDBB39F779F05,
		0x94D09FA5CE3A042A,
		0x5EAF3C2DF7AA338D,
		0x393AA805B3189C97
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA4560A66257E62BF,
		0x3A70DF7721CA4790,
		0xA233C780521DED48,
		0x1AE0ED687FDF268E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85B6D14D79F93C46,
		0x5A5FC02EAC6FBC99,
		0xBC7B74ADA58C4645,
		0x1E59BA9D33397608
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5502650F15B0F3BB,
		0xD3F4571E835BB31A,
		0x5268ABBE8662E365,
		0x3AB2DCBB3BBE9B32
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x412CE7497B4B77F9,
		0x41BE3F4497D2F80F,
		0x6DBD497A7C06EEE3,
		0x485452B2FCFC7EA6
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x13D57DC59A657BAF,
		0x923617D9EB88BB0B,
		0xE4AB62440A5BF482,
		0x725E8A083EC21C8B
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xFBF6376954CD711C,
		0x651BD6F644FA8F0E,
		0xD01671951BB9B079,
		0x41752EB90427D7CC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC81D39A522DB52CF,
		0x6E19B8034F327789,
		0x604DFCFEBA12B8D8,
		0x7C15D56647CCEE30
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x33D8FDC431F21E3A,
		0xF7021EF2F5C81785,
		0x6FC8749661A6F7A0,
		0x455F5952BC5AE99C
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xC73DB400BF314D66,
		0xC2B526E4CD2096AB,
		0x344085D3293938FD,
		0x58500E05CEF4DC74
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x27D1FEFCEE21B862,
		0x921C9DC9D1015451,
		0x01C567915886BC58,
		0x51479A3B67EEEC15
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9F6BB503D10F9504,
		0x3098891AFC1F425A,
		0x327B1E41D0B27CA5,
		0x070873CA6705F05F
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x3C0672861D213887,
		0x488A1F7FB07B3E4C,
		0x47922D7AA89EC9D9,
		0x4C36B90BE734758E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B7496EC2CBEF420,
		0x2B8CFF703EDE747D,
		0x36B41558CE7DB971,
		0x60F92CEBA3F75FBF
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC091DB99F0624454,
		0x1CFD200F719CC9CE,
		0x10DE1821DA211068,
		0x6B3D8C20433D15CF
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x03DD4293CF4BFA02,
		0x54550DC1CB581D76,
		0x00C3B8F0DD76BE33,
		0x7CD91BBEE813211C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE55165BC5195675F,
		0x884942C9457192F6,
		0x903E31A1D5E74216,
		0x1E20052D711DEBC3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1E8BDCD77DB692A3,
		0xCC0BCAF885E68A7F,
		0x7085874F078F7C1C,
		0x5EB9169176F53558
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xE46480F13C6449C9,
		0x428E6669484F5453,
		0x7F4D7C192564410F,
		0x4A7D8F87DED14475
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x100F423CEFA72A05,
		0xB10DABE5AABCEC00,
		0x66D20D12D7CEBEE9,
		0x696E8C085B2C56DA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD4553EB44CBD1FB1,
		0x9180BA839D926853,
		0x187B6F064D958225,
		0x610F037F83A4ED9B
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5DD0E8104133F1CC,
		0xEC70E8E5B5661DEF,
		0xAF2DAD2907DD3B87,
		0x34965702279D4BAF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF900FEDE78906EC,
		0x43EBB47433232464,
		0x1197C24A401996D2,
		0x718142E89948AE1F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E40D82259AAEACD,
		0xA88534718242F98A,
		0x9D95EADEC7C3A4B5,
		0x431514198E549D90
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x8E358CF775CB313B,
		0x2E37CA55F5B7B6BB,
		0xA0A18DFE69A510FD,
		0x23D5EBDAB6B9DB01
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3FE29B9792C6E74,
		0x3B9DC548C5645433,
		0x6E4D676B3BC02337,
		0x259B25A570FB949F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAA37633DFC9EC2B4,
		0xF29A050D30536287,
		0x325426932DE4EDC5,
		0x7E3AC63545BE4662
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xD0DBEAE7CE658A94,
		0x66CB2A4595E89A4A,
		0xDDE157C03460D901,
		0x3CA2680F6CD7445B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7D724469B40664E5,
		0x59000FD9EE4B89D8,
		0xFCC7C0E9FF65247C,
		0x3BB123C5A5786401
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5369A67E1A5F25AF,
		0x0DCB1A6BA79D1072,
		0xE11996D634FBB485,
		0x00F14449C75EE059
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x8E1DA56F7532D77D,
		0x7863B8A92BB1C973,
		0x12AADD8B01CEC05E,
		0x012EEA5A09A2E719
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4E19167054FA91F3,
		0xD5A1F90E751FE787,
		0xAB46FC75C97A87DD,
		0x1E53CE3AE0E74A75
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x40048EFF20384577,
		0xA2C1BF9AB691E1EC,
		0x6763E11538543880,
		0x62DB1C1F28BB9CA3
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9DDC265A1BFCA492,
		0x4CAD2894F589387C,
		0xD7174D517C67F797,
		0x6111F2C9AEFA09EE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCD4715517EAF658E,
		0x0252E6EF3530CEA1,
		0x0F48C1D97D051FE1,
		0x4238CF37969339BA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD09511089D4D3F04,
		0x4A5A41A5C05869DA,
		0xC7CE8B77FF62D7B6,
		0x1ED923921866D034
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xB61EB4EF767FCF00,
		0x3B0A0657B398B614,
		0xA9692A4586D7C241,
		0x0E91CDD14BB8ABF1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC806E2326B4E7219,
		0x0E0422463CF08718,
		0x87C27331A1595EC1,
		0x766E651B50CC5A84
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEE17D2BD0B315CD4,
		0x2D05E41176A82EFB,
		0x21A6B713E57E6380,
		0x182368B5FAEC516D
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x1C4EA523851617F7,
		0x6EC54EACDE78107B,
		0x49BF9A37E20FD7CD,
		0x3F72DF58DF724FF0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x239288FB8E42B6D5,
		0x4DC4BED4B78701F2,
		0x28CEC4C934DC7802,
		0x29769F69016A28E7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF8BC1C27F6D36122,
		0x21008FD826F10E88,
		0x20F0D56EAD335FCB,
		0x15FC3FEFDE082709
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x329AD6B9C5E11AD9,
		0x124977BDF715C357,
		0x7E166C9CD8AA003C,
		0x2ED6DE12D59C95F1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7DF03A6731684AB3,
		0x7D16ED499D9942C1,
		0x403887CAF33AD27F,
		0x092760A19A6A6EEB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB4AA9C529478D026,
		0x95328A74597C8095,
		0x3DDDE4D1E56F2DBC,
		0x25AF7D713B322706
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x1203D3004770ED3F,
		0x820D67543CB9BBB7,
		0xFEB0743B5D93909F,
		0x486D6CCD2E6585EF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x376A24BF40662186,
		0x95531840FF27FA03,
		0x9CC0C27221168F16,
		0x253900803A405813
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA99AE41070ACBB9,
		0xECBA4F133D91C1B3,
		0x61EFB1C93C7D0188,
		0x23346C4CF4252DDC
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x13CBD6C19A806BBA,
		0x6BE4462FE3570536,
		0x778B263CD45A61AB,
		0x4ADCFA0A217399F8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1FABAC111ACCA8BC,
		0xEC7A8FC517522E81,
		0xF77F4F5394C92009,
		0x5A905A194B0B449B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF4202AB07FB3C2EB,
		0x7F69B66ACC04D6B4,
		0x800BD6E93F9141A1,
		0x704C9FF0D668555C
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x8427FF7C9A466D5F,
		0x2748F87DDAC3852A,
		0x290DE4D0EED25C0E,
		0x5259B764ACCB3E36
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x334DA4C68AD3547A,
		0xA73D7115EA63E787,
		0xA345C31E9AF7C010,
		0x0AA77D3BAAB4E925
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x50DA5AB60F7318E5,
		0x800B8767F05F9DA3,
		0x85C821B253DA9BFD,
		0x47B23A2902165510
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x04BA2B8ED8DB7B1B,
		0xE3DB66CD565165D6,
		0x4BB6651EEDE7BE97,
		0x5F6D1031062E9DDF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7F0210B2967FE781,
		0x2935F6AF90AA0D57,
		0xE8FD8BBA46C30F6D,
		0x33AB5B1B5AFF581A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85B81ADC425B939A,
		0xBAA5701DC5A7587E,
		0x62B8D964A724AF2A,
		0x2BC1B515AB2F45C4
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xE7170C13539978CF,
		0xD3BC3B8BF6D9FACF,
		0x70C3E4E8E4ED2E57,
		0x2289D80265AEB80E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBE5DDD030F5BC628,
		0x5D0258D244DD4904,
		0x921AB18E74803369,
		0x4302622A95A05DFD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x28B92F10443DB294,
		0x76B9E2B9B1FCB1CB,
		0xDEA9335A706CFAEE,
		0x5F8775D7D00E5A10
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x59CAE4A5653DC624,
		0xA9EE292D188BFCD8,
		0x6E69186CD93A0E03,
		0x2AF52F088AAE70D0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1A547CD327A09BF4,
		0x7CF245E044FFD408,
		0xBC707A21921E6BDB,
		0x7E0B6E34129F3D04
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F7667D23D9D2A1D,
		0x2CFBE34CD38C28D0,
		0xB1F89E4B471BA228,
		0x2CE9C0D4780F33CB
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x610F13047AECA7D9,
		0xBA8001A00B8266F7,
		0x17FCCBBC53FB9C41,
		0x5192CAC23FD3FC81
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB9A3B0F879956386,
		0xB41D3CFE83D34096,
		0x7C31C0D5501DBEF7,
		0x72EC11F2F0BBCB60
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA76B620C01574440,
		0x0662C4A187AF2660,
		0x9BCB0AE703DDDD4A,
		0x5EA6B8CF4F183120
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x6A390D85B50AFB9E,
		0x15E6BEE5BC17AB33,
		0xDAA3D33FF8FE0434,
		0x2498FD0490533358
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x736C15B3F4ACC87F,
		0x01127AD658FB1FF9,
		0x66CF4F382AE89D73,
		0x0FE8264CDD14D10B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF6CCF7D1C05E331F,
		0x14D4440F631C8B39,
		0x73D48407CE1566C1,
		0x14B0D6B7B33E624D
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xC62C5C0414AC0D7D,
		0x156FB12E5F9BD65B,
		0x5DC1EE5725A3E6B1,
		0x2387BF4564646B24
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4CC05EEC82E4A04A,
		0x1BE83D5D56C4FB6A,
		0x9F1BF7105E0D15D9,
		0x64F9B43DDAE994F9
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x796BFD1791C76D20,
		0xF98773D108D6DAF1,
		0xBEA5F746C796D0D7,
		0x3E8E0B07897AD62A
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x4901AD4E2AF375D8,
		0x1F71CE8E614DEF42,
		0x101D477FC9D778C7,
		0x61ADE3624BD5519C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF1A7FCD66C0C64E,
		0xE213267E65BDB134,
		0x8AC0C40EB2C5636A,
		0x5A6663AFDD15CEEA
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x69E72D80C432AF8A,
		0x3D5EA80FFB903E0D,
		0x855C83711712155C,
		0x07477FB26EBF82B1
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xCCB245E8FE79729C,
		0xC702D8AC911718F2,
		0x077DFCDB7CB493A1,
		0x6682489C807002FB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD055F9BA79BA0D82,
		0xAF11E4E61F3B480B,
		0x4D40D962DC6487D3,
		0x63CB7A70AA3A0088
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFC5C4C2E84BF651A,
		0x17F0F3C671DBD0E6,
		0xBA3D2378A0500BCE,
		0x02B6CE2BD6360272
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x2BF5604674CFB8B0,
		0x38C102C57334E145,
		0xE7C6F3263EBBE2E0,
		0x15A01EB1D4E78A85
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3F84EEA37B5FAAD2,
		0x9155B1CA7CDDCA30,
		0xD2934B4A6CA6B188,
		0x6A8E15DD3D3BC0A4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEC7071A2F9700DCB,
		0xA76B50FAF6571714,
		0x1533A7DBD2153157,
		0x2B1208D497ABC9E1
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xAF1720554BE06CB4,
		0xB375834E06F6A40B,
		0xF35294B1E11CD1E0,
		0x120328BE891F0EBC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD50317DC61F641B5,
		0xAFDF58C6BAE95AEC,
		0x421B55CD8BEAF6C1,
		0x0E0427362CAA7E41
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDA140878E9EA2AFF,
		0x03962A874C0D491E,
		0xB1373EE45531DB1F,
		0x03FF01885C74907B
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xDA3009C754594527,
		0x09BC6FC9C8B3CE9A,
		0xC1ABD0D5028912A3,
		0x4C355B3DDF808CFB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3A6178C581FC018A,
		0x1A350171F8D60305,
		0x619F69E83F974CDD,
		0x1F54568F4AF4306B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9FCE9101D25D439D,
		0xEF876E57CFDDCB95,
		0x600C66ECC2F1C5C5,
		0x2CE104AE948C5C90
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9AA9A2CB600DE60D,
		0xDE66DE1E8F4095FE,
		0x0D55F7250DC0F00C,
		0x6BAC65A6D0C4041D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB136A481DE4233F8,
		0x230B795D31A9A575,
		0x050709A87683441D,
		0x478A56FE721CB1A1
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE972FE4981CBB215,
		0xBB5B64C15D96F088,
		0x084EED7C973DABEF,
		0x24220EA85EA7527C
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xDE6A269693103997,
		0xAA4346341E4FFFAA,
		0x989D4F6645E36344,
		0x7A2C5CE105000C88
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x719EBE676ED9D2B8,
		0x49F1C9560F5CADA0,
		0xE636E43C18B33CA7,
		0x3FED9976C7096BEC
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6CCB682F243666DF,
		0x60517CDE0EF3520A,
		0xB2666B2A2D30269D,
		0x3A3EC36A3DF6A09B
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x6926341A24AADE9C,
		0x2678B8D26C222507,
		0xDFFB4B248E3CACF4,
		0x12BAFFA70E444AAB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2324BA8DC9C3A286,
		0x8F036D09628C79C0,
		0x1CA2AEE9583C6717,
		0x3C481677662B28B2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4601798C5AE73C03,
		0x97754BC90995AB47,
		0xC3589C3B360045DC,
		0x5672E92FA81921F9
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5AA3137A2B8E4BFF,
		0xAB05568B30C0464E,
		0x24F225A9A3118FD7,
		0x60A2945067B57769
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3937326D1C08617,
		0xCFA5B6BCE9D0DC1C,
		0x25EC4A1C6F636E78,
		0x5350A579083D275F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x770FA05359CDC5E8,
		0xDB5F9FCE46EF6A31,
		0xFF05DB8D33AE215E,
		0x0D51EED75F785009
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xB65E32604E102426,
		0xEA872803758800C0,
		0x305DA5D6A6CBA77C,
		0x74BC8DAA0324192A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF35AAF19F47F3FA,
		0xFE5E360AD0087D8A,
		0x0FB3E171C08E2860,
		0x02F3B2B3018DE016
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD728876EAEC8302C,
		0xEC28F1F8A57F8335,
		0x20A9C464E63D7F1B,
		0x71C8DAF701963914
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5D39A28D87FB016A,
		0xBF9F4298C9E8D014,
		0x18480B3DC66B39CE,
		0x4790BB1BB451FF2F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0BF4DDA259EE0600,
		0x641EB1865C8ED0AD,
		0x03C895913C32FD0D,
		0x1CBD8C8F4ECCCE35
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5144C4EB2E0CFB6A,
		0x5B8091126D59FF67,
		0x147F75AC8A383CC1,
		0x2AD32E8C658530FA
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x65F40F7828CF1371,
		0x302308D36145D2F1,
		0xDF27136724FE291D,
		0x1B8FB8311FF2D4B5
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC259A7DCF189DBBF,
		0xFDFFCB443ADDB57F,
		0x89894E3DD8023F87,
		0x43602A452BDEBE88
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA39A679B3745379F,
		0x32233D8F26681D71,
		0x559DC5294CFBE995,
		0x582F8DEBF414162D
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x42DF9AC9C72CC81E,
		0xAE755138544D7F18,
		0xB7F0268AA1DD7FB7,
		0x07EA6B3B80018B3C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD9D7F918788203DA,
		0xF5603AE844FC6A3B,
		0x7C473B99437DD4D5,
		0x10E9053DC2A82946
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6907A1B14EAAC431,
		0xB91516500F5114DC,
		0x3BA8EAF15E5FAAE1,
		0x770165FDBD5961F6
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xFCD2B41B3281630C,
		0x7A52E85AED59F63A,
		0xB9094BA4952F1621,
		0x0028FF28E44CFCAC
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD8B7F49EEAE2F640,
		0x94927F7CE1ACB817,
		0x16E792937B1B117F,
		0x79B547488104FFC7
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x241ABF7C479E6CB9,
		0xE5C068DE0BAD3E23,
		0xA221B9111A1404A1,
		0x0673B7E06347FCE5
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x8A9CFDB7FAD2B538,
		0xB58EC6F02A66C363,
		0x2DD099D941572DEA,
		0x61F57858D72F31CE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D4FC2862D4136C3,
		0x5F080645AFB26F19,
		0x5F6B4588BC83755D,
		0x467F6361AE6FE1BC
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6D4D3B31CD917E75,
		0x5686C0AA7AB4544A,
		0xCE65545084D3B88D,
		0x1B7614F728BF5011
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x3A2650BD2AF2C8AD,
		0xCC7740EC59003A7E,
		0xF430B89A5D1695C2,
		0x18F5C38822F8577E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x13E0AC27E08AA872,
		0xCF78585C7C75AB5D,
		0xEBDD40874368BEBA,
		0x52E9EADBA3F8237D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2645A4954A682028,
		0xFCFEE88FDC8A8F21,
		0x0853781319ADD707,
		0x460BD8AC7F003401
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x060E9363CA9F244E,
		0x50F418E407D6DF0F,
		0x5066F63FBDEA5353,
		0x28893EF60BEA978D
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65D094F57E28EE5C,
		0x5E0376D0D8A572A5,
		0x880846C060C0A071,
		0x7203DDF590995D63
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA03DFE6E4C7635DF,
		0xF2F0A2132F316C69,
		0xC85EAF7F5D29B2E1,
		0x368561007B513A29
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x0AE08E4AF740F6BD,
		0x9C7187DBBF858B47,
		0xCF746C495A2F8E9A,
		0x0260AD0A2563C5F0
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0098FAF6E32E7E12,
		0x31520BA51F06BB7D,
		0xA95571224FAB0F09,
		0x258DB1C4CFB79D2D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0A47935414127898,
		0x6B1F7C36A07ECFCA,
		0x261EFB270A847F91,
		0x5CD2FB4555AC28C3
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xBC7250469BC4F09D,
		0x5CA9D2B11FD16D6E,
		0xDED3ECA68D5A48BC,
		0x4DD89154CA15A222
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x139BFEFC43E49E9E,
		0x280142745ECFA7ED,
		0xBDE8113DC9A38FC5,
		0x65977D8A257CC116
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8D6514A57E051EC,
		0x34A8903CC101C581,
		0x20EBDB68C3B6B8F7,
		0x684113CAA498E10C
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x769A77902BF0D14C,
		0xAC180C3E13860655,
		0xE09098EBA59796CB,
		0x267CC4A4060979CF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44DEB9371A4E5005,
		0x0EB02E7A513E550B,
		0x7D1D88304ED45F0A,
		0x56372991EBC5110D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x31BBBE5911A28134,
		0x9D67DDC3C247B14A,
		0x637310BB56C337C1,
		0x50459B121A4468C2
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x801527BAB76F4849,
		0x824820F61F082CFD,
		0x3457E9E9E30610E4,
		0x537593FC5317DA25
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x00E8A4A7C880186F,
		0xA0E3235C95EB16F4,
		0xE444D8ED35EF1965,
		0x6E67FECC50C0C708
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7F2C8312EEEF2FC7,
		0xE164FD99891D1609,
		0x501310FCAD16F77E,
		0x650D95300257131C
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x162939CD0B812EFF,
		0xBC4FC91BA4DD4116,
		0x0FE5011FA0E0C70E,
		0x3FC184343C6024D8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9B43057DBBA609A5,
		0x97CAB4FC41FAB46D,
		0x2481B94214BC94B8,
		0x2EBA3F3FE0400930
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7AE6344F4FDB255A,
		0x2485141F62E28CA8,
		0xEB6347DD8C243256,
		0x110744F45C201BA7
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x376D093857719AC2,
		0xF866FE3D4BF3CB6C,
		0xFD16C41FAAFA01D4,
		0x38837A6EE58D41FA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA09FFBF54CB5DAB5,
		0x534685950A8E7D1C,
		0xC1D07633832E7497,
		0x0140F75D79470440
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96CD0D430ABBC00D,
		0xA52078A841654E4F,
		0x3B464DEC27CB8D3D,
		0x374283116C463DBA
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x0C399635F90F2363,
		0xA8F5BDE0D058C41E,
		0xE585D6542ECC6666,
		0x44058F5A9904BCB4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7959B8C902FC2514,
		0x23CC9BFB72B6D576,
		0x69FF9FE747A2DBE1,
		0x6618694A49E6580C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x92DFDD6CF612FE3C,
		0x852921E55DA1EEA7,
		0x7B86366CE7298A85,
		0x5DED26104F1E64A8
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xB25FDF7A384017B8,
		0x1CEF69E36FE4B884,
		0x565801CF2AED2324,
		0x32CB7914E598DB03
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2C0BC5D5BBE9B659,
		0x427FC476A1A91F50,
		0x9CEA6692FE86BE5B,
		0x17059E9853D442A0
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x865419A47C56615F,
		0xDA6FA56CCE3B9934,
		0xB96D9B3C2C6664C8,
		0x1BC5DA7C91C49862
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x7C49669BE64182CE,
		0x6C894B19969FA456,
		0xEBA72BF81B031415,
		0x3F9DA9AAAC127E97
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5F72754F8C930AE,
		0x0763294D10BBB006,
		0xF6A0FB0F827BF586,
		0x1AEC7E7CBA828285
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x96523F46ED785220,
		0x652621CC85E3F44F,
		0xF50630E898871E8F,
		0x24B12B2DF18FFC11
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x34577E65377E0856,
		0x1E43FECB62C6277A,
		0xED2B8120E1FB2B4A,
		0x0409C290E07973F4
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x75888EE8324441AE,
		0xEFA75B0AC72714F5,
		0xF1E519BB5D1399EC,
		0x1008F9CE0AF5F3D8
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBECEEF7D0539C695,
		0x2E9CA3C09B9F1284,
		0xFB46676584E7915D,
		0x7400C8C2D583801B
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x423A789BB67DC8EA,
		0x8467C3BA225CDDD3,
		0xE2FACC9D7D3B31AE,
		0x09FDE0B9A43505B9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x691F92EAF479C97B,
		0x1EA4A093F643A391,
		0xDFBD9D087B793004,
		0x5CF3DA154D908035
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD91AE5B0C203FF5C,
		0x65C323262C193A41,
		0x033D2F9501C201AA,
		0x2D0A06A456A48584
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xF08E7C5E79FB0105,
		0x42B1E84EEADAAC5D,
		0xCD4CCFBFD972EC29,
		0x440DE7DC3CBEADFE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x423AA6424573338A,
		0x1E2A6DC3691C65F0,
		0xA5A07483AC71607D,
		0x7159BBBB4E81C0F4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAE53D61C3487CD68,
		0x24877A8B81BE466D,
		0x27AC5B3C2D018BAC,
		0x52B42C20EE3CED0A
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x99A33786D0C92EC2,
		0xC862EEB5241AABAF,
		0x100C88BFC336E67C,
		0x5AC6ABCB545290BF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0445A5C2759CEEBC,
		0xA81E142BBCC7B282,
		0x80515965F57A7A2A,
		0x358AC5B3FFD4184A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x955D91C45B2C4006,
		0x2044DA896752F92D,
		0x8FBB2F59CDBC6C52,
		0x253BE617547E7874
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x26A8DC25BECB0B4B,
		0x9992AFC57E9237EE,
		0x8C832761E0BE1F8D,
		0x0FABF785983A7575
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6626CBD204D75BBB,
		0xFBC02D065FA7D8B7,
		0x6962A01C755F67BE,
		0x61413755F6ECA98C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC0821053B9F3AF7D,
		0x9DD282BF1EEA5F36,
		0x232087456B5EB7CE,
		0x2E6AC02FA14DCBE9
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x45D8AE028101815B,
		0xB24715AB21010797,
		0x8FA5269D83DA446B,
		0x0E27C815A208F15B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x63C261FB0CF000EF,
		0x1E1EACEEC9060437,
		0x1F90F17DE38E5A75,
		0x793F52026EB2F20A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE2164C0774118059,
		0x942868BC57FB035F,
		0x7014351FA04BE9F6,
		0x14E876133355FF51
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xCF02204D71E9958A,
		0x15498C6377E76100,
		0x43AA64BBDE3D6E15,
		0x6250299E9FD95F14
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x255CC7F665D5E664,
		0xAE918A8991283E85,
		0x510A7091336252E5,
		0x03195674CDB4B050
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA9A558570C13AF26,
		0x66B801D9E6BF227B,
		0xF29FF42AAADB1B2F,
		0x5F36D329D224AEC3
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x3693B805220F0B94,
		0xB3D24C46AE2B39F1,
		0xA0A9A4FDB4BD2020,
		0x0FAB9435E7D6F5B8
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x68C30B8388480CAD,
		0x7188CF2D32A42763,
		0x6CFAF4686336FC06,
		0x7F1ACD2DF7D1F79A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDD0AC8199C6FED4,
		0x42497D197B87128D,
		0x33AEB0955186241A,
		0x1090C707F004FE1E
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xFF8D8BE3C5F49C3B,
		0x058F630EE975ADBA,
		0xF2F9EB3A966D3F01,
		0x5F668083EB9B2F9B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFA0A898707424BE,
		0x32DA01AE1E12C3EC,
		0xEC9BE4EBEC4D950A,
		0x3813AD6F3A1DD15F
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2FECE34B5580777D,
		0xD2B56160CB62E9CE,
		0x065E064EAA1FA9F6,
		0x2752D314B17D5E3C
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9C4335D560E34039,
		0x638F19897DC25B47,
		0x03D9A8634B60D2E4,
		0x4E97609EFE87D37A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFDF29BE700942E73,
		0x31A18CC327886F01,
		0xC8C89779A27E4CEC,
		0x666A5CBAB2BDADB3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9E5099EE604F11B3,
		0x31ED8CC65639EC45,
		0x3B1110E9A8E285F8,
		0x682D03E44BCA25C6
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x41DBE3D43ED54BB4,
		0xB84B68FEA06F9E43,
		0xB6BF70C5C866B452,
		0x50F811161D6491AE
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x18230369F0512C19,
		0x32A52C49DEA9B758,
		0xC722E45088069F36,
		0x2CB9F455E7BD1B06
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x29B8E06A4E841F9B,
		0x85A63CB4C1C5E6EB,
		0xEF9C8C754060151C,
		0x243E1CC035A776A7
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xA2A9FD202F03738B,
		0xA635DC12DCBB2DA4,
		0xD96FC9BC0FBD21DF,
		0x27A74B9660C9FD7E
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E9A68706539AACF,
		0x801FCB410D62A4CA,
		0x084DA96F2459D145,
		0x47E6EF908A45CEC2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x040F94AFC9C9C8A9,
		0x261610D1CF5888DA,
		0xD122204CEB63509A,
		0x5FC05C05D6842EBC
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x81BEC7841F052017,
		0xB69842F6B912B9F2,
		0x97D392D78B4B9125,
		0x2BCE42AB862A38C9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9DA4A6A1B080BEF1,
		0x18A30B39D05435A0,
		0x1EA5D17213DCC282,
		0x77EEAAB439EEA99A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE41A20E26E846113,
		0x9DF537BCE8BE8451,
		0x792DC165776ECEA3,
		0x33DF97F74C3B8F2F
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x8C56EA88689E10C1,
		0xECD3DCFA37C30680,
		0x597D4E5A4E5B97A3,
		0x68B3CFCF6975C7A2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9BBA9390D2E0217F,
		0x9ED5DA04D06221A8,
		0x69F5CE0B3DDA4F80,
		0x5E15049CFB1AB401
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF09C56F795BDEF42,
		0x4DFE02F56760E4D7,
		0xEF87804F10814823,
		0x0A9ECB326E5B13A0
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9679CF69ACC732BD,
		0x1C3F65C035498D6A,
		0x5A00F4B19FD2EB06,
		0x1C00B18BDE9FAB62
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3AC066B1B65A38FE,
		0x1A262353DE6C8E51,
		0xA766CD2F1256FE86,
		0x0FA5161684AAD008
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5BB968B7F66CF9BF,
		0x0219426C56DCFF19,
		0xB29A27828D7BEC80,
		0x0C5B9B7559F4DB59
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5865F9B879618207,
		0x21449F4A054767A7,
		0x5927A49AAB0E327D,
		0x28AB33B7000E7E45
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xBF32883B0C40D725,
		0xA23754A29F859F61,
		0xC014317120B546F7,
		0x589A36DAF2BB04E2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9933717D6D20AACF,
		0x7F0D4AA765C1C845,
		0x991373298A58EB85,
		0x5010FCDC0D537962
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x273EA5C5FA8075A2,
		0x1FB1F0CDAF0755E1,
		0x472CD8D4E403C146,
		0x107E8745FDE0894C
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1908DE7106EF9C50,
		0x856245AE7E6E3C9C,
		0xB21EC40C2268B97A,
		0x3C92398DC84557C3
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0E35C754F390D93F,
		0x9A4FAB1F30991945,
		0x950E14C8C19B07CB,
		0x53EC4DB8359B3188
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xA51729CAEEEA0934,
		0xEF0A5D56D9ECEEC5,
		0xE3A4A30DF2A3D0D9,
		0x075752A908F9B3C2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x12BFD39CC83930DC,
		0x5ACB08F5D1768290,
		0x9AC09FE85C734AC8,
		0x6698751CF97FB917
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9257562E26B0D845,
		0x943F546108766C35,
		0x48E4032596308611,
		0x20BEDD8C0F79FAAB
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9B8A86837BAA48B5,
		0xA181FD6EA66AD448,
		0x346EE10E5DA1F196,
		0x6A80D27F1947C116
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C99F9128D8B5245,
		0x23BE66A5B1DB2516,
		0x7455181105909A42,
		0x558115E0AD985E1E
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EF08D70EE1EF670,
		0x7DC396C8F48FAF32,
		0xC019C8FD58115754,
		0x14FFBC9E6BAF62F7
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x0EFA929C0D4925EC,
		0x16F2C5F0555C5049,
		0x9FBB5EDD7F946471,
		0x6B470B4C5301144F
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8D4E45387CC24B57,
		0x64D452190EAD6D22,
		0x464E563B4CD09DEE,
		0x130365477776B9FB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x81AC4D639086DA95,
		0xB21E73D746AEE326,
		0x596D08A232C3C682,
		0x5843A604DB8A5A54
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x9278F3FF2DD5DE05,
		0x1D89B51265BDA9CD,
		0xD5932180CC867F08,
		0x6C24AA5228BE8EDA
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA148CD8855192948,
		0x37DF8E6AD7FC4698,
		0x8BB9ECBD6018074E,
		0x12381F3DF9392FD8
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF1302676D8BCB4BD,
		0xE5AA26A78DC16334,
		0x49D934C36C6E77B9,
		0x59EC8B142F855F02
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x5983ADE23C3048FF,
		0xE36459CEBF5E0289,
		0x55DA914FAF458D7A,
		0x4C2C7EF775BAF2A9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEA914894FC8A66A7,
		0x4759EDB979D3EB08,
		0x97B6C88F97746C1D,
		0x7C5385D4CFB6247D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EF2654D3FA5E245,
		0x9C0A6C15458A1780,
		0xBE23C8C017D1215D,
		0x4FD8F922A604CE2B
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x7E6FB3A45B32ABA1,
		0x66DD974CA5368F3E,
		0xEA122C1BC5A901CA,
		0x5D2ECF04E2D003DB
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE5B568D4C4D3B067,
		0x9CE9236D01EEF6AF,
		0x776EC18007EC6E85,
		0x23051392AC52DECB
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98BA4ACF965EFB3A,
		0xC9F473DFA347988E,
		0x72A36A9BBDBC9344,
		0x3A29BB72367D2510
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x65077B6776474890,
		0xDE59FEA2D41B7D12,
		0x608E99C95EABBF71,
		0x3F4BDB13EA9FA63B
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCC9608F055DB72C5,
		0x3EBAADE2D885E453,
		0x0E3ABF67C66EA771,
		0x331548090FE52E82
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x98717277206BD5CB,
		0x9F9F50BFFB9598BE,
		0x5253DA61983D1800,
		0x0C36930ADABA77B9
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x6A8A83A7A923A554,
		0x4BFD9B26E197CBE8,
		0xC4369EB18E26BEB5,
		0x51BF148A2F5AB6D3
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B8FF8B95064071F,
		0x172C859322EBDB4F,
		0xDBB3D1E108A084A6,
		0x37184C125B3A2E20
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0EFA8AEE58BF9E35,
		0x34D11593BEABF099,
		0xE882CCD085863A0F,
		0x1AA6C877D42088B2
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x78467C747DA2124F,
		0xC6CD9218E7B85287,
		0xCE0364DD8416ACB4,
		0x4D0A430FB272FC23
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEAACA365A0B89C76,
		0xBC68AB57BD2B02ED,
		0x1205D6E5E801C792,
		0x6F1740FA7A3A148B
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8D99D90EDCE975C6,
		0x0A64E6C12A8D4F99,
		0xBBFD8DF79C14E522,
		0x5DF302153838E798
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xD0DA67D3FE406E05,
		0xB35ACA356D0EAFCD,
		0x43F67D1D43CCE922,
		0x5C2B0BC8FF69A2D2
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3CD14B497E5C452D,
		0xC134BC660786A5DC,
		0xB69D225198A8F1BE,
		0x34B93AD4D472FDDF
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x94091C8A7FE428D8,
		0xF2260DCF658809F1,
		0x8D595ACBAB23F763,
		0x2771D0F42AF6A4F2
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xEB845034D74A1DDB,
		0xA7DAF00FFF684CD5,
		0xE152452FE520658A,
		0x759D635B53206A54
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7219FE4350D82ED0,
		0x962EA02177568135,
		0xF92932604444CC8F,
		0x54CDE81F2D0F720D
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x796A51F18671EF0B,
		0x11AC4FEE8811CBA0,
		0xE82912CFA0DB98FB,
		0x20CF7B3C2610F846
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x614A5C43DCE6141C,
		0x938D7DECF1053FA9,
		0xE788337360A300DD,
		0x1CB56BE8D3CF3CEF
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC912B1E815B7A706,
		0xC6CC6BFE3E413913,
		0x68FAE6F5CB30FBF5,
		0x5B3BB7DAC2E7175A
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9837AA5BC72E6D03,
		0xCCC111EEB2C40695,
		0x7E8D4C7D957204E7,
		0x4179B40E10E82595
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xE2184F10016E4094,
		0x93817BA268F13DEF,
		0x7C474E9CC1387235,
		0x08C0C2ACD1A2C950
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD2EA1CF38ACD96F3,
		0xD18D5948313ED17A,
		0x26C27CD2C3C140AF,
		0x0FA9A48FD90402DD
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0F2E321C76A0A98E,
		0xC1F4225A37B26C75,
		0x5584D1C9FD773185,
		0x79171E1CF89EC673
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xCCB725FB36A5A380,
		0xD129972DEC742F0B,
		0x11AB61574E342004,
		0x6201AF5C8F4033F1
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADFCEE154066906E,
		0x404FCE001AE42F12,
		0xC92FF62C5D72CA5D,
		0x5D2C01D4FB784AF2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EBA37E5F63F1312,
		0x90D9C92DD18FFFF9,
		0x487B6B2AF0C155A7,
		0x04D5AD8793C7E8FE
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xA354098388F1A1AD,
		0xE632933EB392BC40,
		0xADAF3246EB889364,
		0x4F3784056719E38A
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0FECAAE14E00A4A0,
		0xEAFC7AB274DF2238,
		0x32753B7DA78F057A,
		0x32986DD0E6F19C4C
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x93675EA23AF0FD0D,
		0xFB36188C3EB39A08,
		0x7B39F6C943F98DE9,
		0x1C9F16348028473E
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0xDF9649BE80C574CE,
		0x94BAC531DF9804C0,
		0xF5654DED3A8BEF64,
		0x42935FE3674E03C9
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4A49A477CCAB8B52,
		0x7F96455D1EA78C1D,
		0x1B99323185FDA079,
		0x67CB749DF3BD0CE2
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x954CA546B419E969,
		0x15247FD4C0F078A3,
		0xD9CC1BBBB48E4EEB,
		0x5AC7EB457390F6E7
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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
		0x884B2F35003ACB15,
		0xB251374DF23BF075,
		0xF65DA7F9C4546F49,
		0x614CBEB04C707880
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7405E5C92855F161,
		0x0E6F0D2980BDCD00,
		0xFB66A0850B61694D,
		0x7B84D2747C4AC3D4
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1445496BD7E4D9A1,
		0xA3E22A24717E2375,
		0xFAF70774B8F305FC,
		0x65C7EC3BD025B4AB
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_sub(&k1, &k2, &r);
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