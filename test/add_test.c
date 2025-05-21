#include "tests.h"

int32_t curve25519_key_add_test(void) {
	printf("Add Test\n");
	curve25519_key_t r = {.key64 = {0, 0, 0, 0}};
	curve25519_key_t k1 = {.key64 = {
		0xABA33D777828D022ULL,
		0xF7AEAC1D90083975ULL,
		0x0D170C5AC5B45060ULL,
		0x61EB8BB2D996E9A4ULL
	}};
	curve25519_key_t k2 = {.key64 = {
		0xF14B27EFCDD088A3ULL,
		0xE9A1C09F25BA250DULL,
		0x6AE50F6F9C0A1D41ULL,
		0x2BAFE908CCE753C7ULL
	}};
	curve25519_key_t k3 = {.key64 = {
		0x9CEE656745F958D8ULL,
		0xE1506CBCB5C25E83ULL,
		0x77FC1BCA61BE6DA2ULL,
		0x0D9B74BBA67E3D6BULL
	}};
	printf("Test Case 1\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xC4FEFED815E16EAAULL,
		0xCA72AC55A354878BULL,
		0x246EE2E4D67AD269ULL,
		0x0FCFF2E86A4CF600ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED35F0BEB6A6C359ULL,
		0x4C5CB8DC1CDF197DULL,
		0x2F7D1F850A007831ULL,
		0x7994A15EF57F74B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB234EF96CC883216ULL,
		0x16CF6531C033A109ULL,
		0x53EC0269E07B4A9BULL,
		0x096494475FCC6AB7ULL
	}};
	printf("Test Case 2\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xCE8EB2541A189571ULL,
		0x0C03F3921270B521ULL,
		0xE0E58EEA60ABAF6EULL,
		0x5C29C2A5508CF4BFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2CC77D3DE1E1BECDULL,
		0x96166F5AB652674BULL,
		0x02700D457B0F8C83ULL,
		0x235E972AF4F3DAC0ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFB562F91FBFA543EULL,
		0xA21A62ECC8C31C6CULL,
		0xE3559C2FDBBB3BF1ULL,
		0x7F8859D04580CF7FULL
	}};
	printf("Test Case 3\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7502738FFD491B81ULL,
		0xC918894C4E2F1EB5ULL,
		0x128AC6DBE59E6199ULL,
		0x38DB2A5113372362ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x088DA04E8879E522ULL,
		0x1B3F6233018F9B11ULL,
		0xADCDB684F18556FBULL,
		0x2EB894355E792908ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7D9013DE85C300A3ULL,
		0xE457EB7F4FBEB9C6ULL,
		0xC0587D60D723B894ULL,
		0x6793BE8671B04C6AULL
	}};
	printf("Test Case 4\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x3496BDDE88141EC9ULL,
		0xB8228E1E26685BD3ULL,
		0x094AD318E3A6A090ULL,
		0x6DCA080B2CA669BDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7452991A3B2A5910ULL,
		0x06002B4B66091186ULL,
		0xAB3AD1839C0B56FFULL,
		0x1D28A8F33342D2E9ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA8E956F8C33E77ECULL,
		0xBE22B9698C716D59ULL,
		0xB485A49C7FB1F78FULL,
		0x0AF2B0FE5FE93CA6ULL
	}};
	printf("Test Case 5\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x63312CCA0CEAEFA6ULL,
		0x3450B29602E13885ULL,
		0x968B5B55532D4837ULL,
		0x6D35152ED8DEEE41ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x486B94EA5A22FC31ULL,
		0x3677945393E52CAFULL,
		0xEC26153D086CE50DULL,
		0x005148BF946F78A5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB9CC1B4670DEBD7ULL,
		0x6AC846E996C66534ULL,
		0x82B170925B9A2D44ULL,
		0x6D865DEE6D4E66E7ULL
	}};
	printf("Test Case 6\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x063331AEC044AA1FULL,
		0xE326FD5F5C73DC00ULL,
		0x92E8F7A34DA78EBBULL,
		0x73D14302155039E0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x57576ABF9AB6B975ULL,
		0xE9700D156B9BBB65ULL,
		0xD18AB053AE7EAE65ULL,
		0x2F74DCE3F574294BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5D8A9C6E5AFB63A7ULL,
		0xCC970A74C80F9765ULL,
		0x6473A7F6FC263D21ULL,
		0x23461FE60AC4632CULL
	}};
	printf("Test Case 7\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x6824301B968DD88AULL,
		0xA85772860C907181ULL,
		0xE8503CFAE62D49E9ULL,
		0x0C4D9F567500B696ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB87CE930619B1EE0ULL,
		0x2E3C7121CE1A3A2DULL,
		0x8BB0406A36B5988BULL,
		0x52BC31897878121DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x20A1194BF828F76AULL,
		0xD693E3A7DAAAABAFULL,
		0x74007D651CE2E274ULL,
		0x5F09D0DFED78C8B4ULL
	}};
	printf("Test Case 8\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x074CE02217790B8CULL,
		0xDFCDE0393CFF9DB3ULL,
		0xA3286403FF1625A6ULL,
		0x6968529B8AEABAEEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEE06408DB0391BE2ULL,
		0x25C7BA7E5FB50239ULL,
		0x805850598C371893ULL,
		0x09F930C8F7D41B2BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF55320AFC7B2276EULL,
		0x05959AB79CB49FECULL,
		0x2380B45D8B4D3E3AULL,
		0x7361836482BED61AULL
	}};
	printf("Test Case 9\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xBCF63D2B8F5E523CULL,
		0xA2D2BA78239542EFULL,
		0xC4C138AC87066385ULL,
		0x6615AEB586508253ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE768DE86ADDA6A60ULL,
		0xA286847E5CB1A752ULL,
		0x2558DFBF479ECF1BULL,
		0x746A482A8C2C63DCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA45F1BB23D38BCAFULL,
		0x45593EF68046EA42ULL,
		0xEA1A186BCEA532A1ULL,
		0x5A7FF6E0127CE62FULL
	}};
	printf("Test Case 10\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x9FE2159932A142F1ULL,
		0x9E209DA0B901C3D0ULL,
		0x008F962251FB61ABULL,
		0x2C964A5E47F9200EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6766511B8F298390ULL,
		0x094B660FCFF02A44ULL,
		0x4052DF6D2230A1D8ULL,
		0x52BD1F49994EE069ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x074866B4C1CAC681ULL,
		0xA76C03B088F1EE15ULL,
		0x40E2758F742C0383ULL,
		0x7F5369A7E1480077ULL
	}};
	printf("Test Case 11\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB3F2C726C1E2E2B5ULL,
		0x44A9236CF1A786AFULL,
		0x5C1071E903293526ULL,
		0x70904659597C442EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7525AF4787F186FCULL,
		0x77B5A2033094198DULL,
		0x8B13D153DC90120EULL,
		0x11269727219B59A3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2918766E49D469C4ULL,
		0xBC5EC570223BA03DULL,
		0xE724433CDFB94734ULL,
		0x01B6DD807B179DD1ULL
	}};
	printf("Test Case 12\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xED066CC4FCCA348CULL,
		0x7FBF6475F3EBBD49ULL,
		0x7C89F0E3CFF4362BULL,
		0x30CDC9A49D7411F6ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10D6055F1447E080ULL,
		0x4F54ED364CCC3585ULL,
		0xDB01903EC151340AULL,
		0x41646E84FFEB0EB2ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFDDC72241112150CULL,
		0xCF1451AC40B7F2CEULL,
		0x578B812291456A35ULL,
		0x723238299D5F20A9ULL
	}};
	printf("Test Case 13\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x98A6BBB8BF2A5C13ULL,
		0xE2515742A22609E6ULL,
		0xF04F9E6727BB13FCULL,
		0x7DF463123B3680D3ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA18155B4BB576D84ULL,
		0xC46FDC77F205EE17ULL,
		0x5D9EA1A958BEBE47ULL,
		0x0F7446DDF270649DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3A28116D7A81C9AAULL,
		0xA6C133BA942BF7FEULL,
		0x4DEE40108079D244ULL,
		0x0D68A9F02DA6E571ULL
	}};
	printf("Test Case 14\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD795B50A6F1EF933ULL,
		0xC52F39C61BC39EF7ULL,
		0x700EE4C2EC443CBAULL,
		0x5C063ABDF71EA0D2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC05C23DC7C74E231ULL,
		0x542DA8B6BF910857ULL,
		0x0FBDB2432588A9E0ULL,
		0x25FBD4D8C23EF91BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x97F1D8E6EB93DB77ULL,
		0x195CE27CDB54A74FULL,
		0x7FCC970611CCE69BULL,
		0x02020F96B95D99EDULL
	}};
	printf("Test Case 15\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x8734B95D4EA43B67ULL,
		0x96F9D926D7AE56A0ULL,
		0x41F81FD447E4BF5FULL,
		0x0C0B7063F67D21D4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F47BC1D5ED9A06FULL,
		0xE237E6583B49A9C5ULL,
		0x8A883B197FF14B2EULL,
		0x5944D784F9385C4EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD67C757AAD7DDBD6ULL,
		0x7931BF7F12F80065ULL,
		0xCC805AEDC7D60A8EULL,
		0x655047E8EFB57E22ULL
	}};
	printf("Test Case 16\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xBBBEA64135E86CAEULL,
		0x507997D7EA1227A1ULL,
		0x1AC4132432210A63ULL,
		0x71FCDD9273E94099ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xABC4A73CD6012FF9ULL,
		0x223B26A0B813517DULL,
		0x8F40AE252E08B4CFULL,
		0x651241D6F904B06CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67834D7E0BE99CBAULL,
		0x72B4BE78A225791FULL,
		0xAA04C1496029BF32ULL,
		0x570F1F696CEDF105ULL
	}};
	printf("Test Case 17\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xA676D3C237A99C71ULL,
		0x235B2458C0F199E1ULL,
		0x0F0605DF978084B5ULL,
		0x2C9FC9B88F106A23ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x092753222E70C1E7ULL,
		0x928BD325B95CA9C3ULL,
		0x01BB71F1C0F01323ULL,
		0x0E25732DE6550CADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAF9E26E4661A5E58ULL,
		0xB5E6F77E7A4E43A4ULL,
		0x10C177D1587097D8ULL,
		0x3AC53CE6756576D0ULL
	}};
	printf("Test Case 18\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xC6D76A507345EDA0ULL,
		0x04F0692F62DAB78CULL,
		0x0AAFD5DC2CB422BFULL,
		0x2DAE6F8B5CA513EEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x247B96DC2F94C70DULL,
		0xCC62CE326336BFBBULL,
		0xD35454A066421421ULL,
		0x55858507FC647E8FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xEB53012CA2DAB4C0ULL,
		0xD1533761C6117747ULL,
		0xDE042A7C92F636E0ULL,
		0x0333F4935909927DULL
	}};
	printf("Test Case 19\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x0EC34A30B741447AULL,
		0xACE4E4536FF4A471ULL,
		0x856D4957C2B7CF55ULL,
		0x3A593DE51338902FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5FB85CE1233565F5ULL,
		0x241DF21B362E6EA7ULL,
		0x779225F1BA9C08C1ULL,
		0x67A010DB60E4F2ABULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6E7BA711DA76AA82ULL,
		0xD102D66EA6231318ULL,
		0xFCFF6F497D53D816ULL,
		0x21F94EC0741D82DAULL
	}};
	printf("Test Case 20\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x769CB70501F7C98AULL,
		0x4B471CF3362A12DAULL,
		0x87690259CAC4F818ULL,
		0x28F595A61EF08574ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE575E704783D2E2CULL,
		0x00EE26AE034BDAB7ULL,
		0xB8397247BF5A8F92ULL,
		0x73EC7FFE4C9A6C3FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5C129E097A34F7C9ULL,
		0x4C3543A13975ED92ULL,
		0x3FA274A18A1F87AAULL,
		0x1CE215A46B8AF1B4ULL
	}};
	printf("Test Case 21\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x2F86B6DF621D5691ULL,
		0x244A3C78C4582C43ULL,
		0x4B0B3EBAF72CF117ULL,
		0x51E00D66F3EF5204ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5B05834C0BBC905FULL,
		0x6484394430D7E41AULL,
		0x447B23D2EBC8A180ULL,
		0x0C9C758D9758FB90ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8A8C3A2B6DD9E6F0ULL,
		0x88CE75BCF530105DULL,
		0x8F86628DE2F59297ULL,
		0x5E7C82F48B484D94ULL
	}};
	printf("Test Case 22\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x07D04D965E052231ULL,
		0x84F24B456172FF6AULL,
		0x1530F4F3699B1F94ULL,
		0x75E973916A3919C7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA5AC67A1400E7D87ULL,
		0x885642C56800163EULL,
		0xB2EBAF8FA74E4C44ULL,
		0x0576EF6B8FE34C75ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAD7CB5379E139FB8ULL,
		0x0D488E0AC97315A8ULL,
		0xC81CA48310E96BD9ULL,
		0x7B6062FCFA1C663CULL
	}};
	printf("Test Case 23\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xEB0B31637CAC0116ULL,
		0xD7B8D6E60E0A433FULL,
		0x5B03231078AEDD56ULL,
		0x5EF8000A9A430A5DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB97A517A957D4707ULL,
		0x3CB489B1FC174E3EULL,
		0x2B56EF5342D4BD03ULL,
		0x77BF2D817ED01297ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA48582DE12294830ULL,
		0x146D60980A21917EULL,
		0x865A1263BB839A5AULL,
		0x56B72D8C19131CF4ULL
	}};
	printf("Test Case 24\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x97DAB54D4662D9D7ULL,
		0x6C3149CCF3EC41ABULL,
		0xC2294F03827980EBULL,
		0x086B69A9A398CCC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA0D5945E42752B59ULL,
		0xB23CCA5A87B4EF59ULL,
		0xD48CAF7177406660ULL,
		0x700BFC2A21C45BEEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x38B049AB88D80530ULL,
		0x1E6E14277BA13105ULL,
		0x96B5FE74F9B9E74CULL,
		0x787765D3C55D28B6ULL
	}};
	printf("Test Case 25\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x296BC127C248DA3FULL,
		0x28C842EF0523C9CBULL,
		0xD0BA7ADAFFE6F7A0ULL,
		0x67B9E91BB46759FEULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7AD05C4FD3A288FBULL,
		0x08E45021AFE08435ULL,
		0x5989E6F5186AE11FULL,
		0x3F148A6CF5BB2411ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA43C1D7795EB634DULL,
		0x31AC9310B5044E00ULL,
		0x2A4461D01851D8BFULL,
		0x26CE7388AA227E10ULL
	}};
	printf("Test Case 26\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xDACEC317AFFA80CFULL,
		0x272CE1887AE3BD72ULL,
		0xF0AA58ADCD880176ULL,
		0x0322319F7D6069FDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4FE97F7BAACFFC9FULL,
		0x2274884CCDE920CEULL,
		0x7BEED67451C463FBULL,
		0x62231E1EE4C525AFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2AB842935ACA7D6EULL,
		0x49A169D548CCDE41ULL,
		0x6C992F221F4C6571ULL,
		0x65454FBE62258FADULL
	}};
	printf("Test Case 27\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xDD52EECB3547D3EEULL,
		0x5E1F6928411A078FULL,
		0x0DA186F0719EF512ULL,
		0x17CD6DB6BC3EDCB0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EE049E27A42E7BCULL,
		0xA8716E73220F6C2FULL,
		0x64CD01B7F757971AULL,
		0x75796654B5F0EC1DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0C3338ADAF8ABBBDULL,
		0x0690D79B632973BFULL,
		0x726E88A868F68C2DULL,
		0x0D46D40B722FC8CDULL
	}};
	printf("Test Case 28\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x9517C34DABCB685EULL,
		0x06A1545F879CA7C5ULL,
		0x52BB6D746B12877FULL,
		0x69D6557913BFCA7CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA843254EB6B4C9DAULL,
		0xF4A9C422BF1F8A81ULL,
		0x5F1FE14743294588ULL,
		0x42071ADBC67F7C40ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3D5AE89C6280324BULL,
		0xFB4B188246BC3247ULL,
		0xB1DB4EBBAE3BCD07ULL,
		0x2BDD7054DA3F46BCULL
	}};
	printf("Test Case 29\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x10486FBB36438816ULL,
		0x78CEF9E02C1119B6ULL,
		0x70574A4FFDB68E10ULL,
		0x0746DFC1DEC1BE18ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x73B234B808215543ULL,
		0x7981E61C8A3465DEULL,
		0xB1F3982B92CC2CBDULL,
		0x7386B92093C21856ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x83FAA4733E64DD59ULL,
		0xF250DFFCB6457F94ULL,
		0x224AE27B9082BACDULL,
		0x7ACD98E27283D66FULL
	}};
	printf("Test Case 30\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x69E97390FA4225D4ULL,
		0x80439EB5C08D9D5BULL,
		0xC8483E5102A62570ULL,
		0x44A121681C90DDC7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7B2F72DD95B38FE5ULL,
		0xA1CC5A1C55EE22DCULL,
		0xE80FCDB74961C047ULL,
		0x715BBCAEF2C9CBEAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE518E66E8FF5B5CCULL,
		0x220FF8D2167BC037ULL,
		0xB0580C084C07E5B8ULL,
		0x35FCDE170F5AA9B2ULL
	}};
	printf("Test Case 31\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB3A4A954E3C2BC2BULL,
		0x041D7535C4025CB3ULL,
		0x878E6BF19B9FC40AULL,
		0x7F2B7CF195087CA1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD1E22607FB5FCAD7ULL,
		0xFE1CB5B24A11FFF2ULL,
		0xDEBA60109A3808E3ULL,
		0x7FA5E270621DD397ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8586CF5CDF228715ULL,
		0x023A2AE80E145CA6ULL,
		0x6648CC0235D7CCEEULL,
		0x7ED15F61F7265039ULL
	}};
	printf("Test Case 32\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD419E58670CBAC86ULL,
		0x85C008176BAC3426ULL,
		0xF3796F5828BABE59ULL,
		0x486B75C34697A02EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x83C1CBC202CD4C5BULL,
		0xC57606AA8F2854F3ULL,
		0x9E8237C5FCDD84B8ULL,
		0x551A4D1DCA82BE59ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x57DBB1487398F8F4ULL,
		0x4B360EC1FAD4891AULL,
		0x91FBA71E25984312ULL,
		0x1D85C2E1111A5E88ULL
	}};
	printf("Test Case 33\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xE9EAEBCCB04B2A2BULL,
		0xDAE3020CD4600B0AULL,
		0x436CA21EEC66A28EULL,
		0x285905776317F949ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x44D4952AA6528ECCULL,
		0x586AE564F845B375ULL,
		0x48C3E911ADE119EEULL,
		0x05279AD0EB0CD49CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x2EBF80F7569DB8F7ULL,
		0x334DE771CCA5BE80ULL,
		0x8C308B309A47BC7DULL,
		0x2D80A0484E24CDE5ULL
	}};
	printf("Test Case 34\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x97B403A58F6E37D3ULL,
		0xFA17BF4C4935471EULL,
		0x4209DE1B5F5B0D0DULL,
		0x6B045F5B2699231AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3EF10D928AA4F0F4ULL,
		0xCA9AA5C073D78B8AULL,
		0xBA74E07213ECB71BULL,
		0x23E927BDB58828CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD6A511381A1328DAULL,
		0xC4B2650CBD0CD2A8ULL,
		0xFC7EBE8D7347C429ULL,
		0x0EED8718DC214BE8ULL
	}};
	printf("Test Case 35\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xA8A1B1D953741F6EULL,
		0x53E1D958BE0288EEULL,
		0x585E60844E456D4BULL,
		0x7040F98B6CD915B8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4419918F454F47C8ULL,
		0x7508ADD0F5CCCDE1ULL,
		0x22FB8FFDE6D05181ULL,
		0x1AB50E1544397B3AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xECBB436898C36749ULL,
		0xC8EA8729B3CF56CFULL,
		0x7B59F0823515BECCULL,
		0x0AF607A0B11290F2ULL
	}};
	printf("Test Case 36\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x5A01129A6239647BULL,
		0x553369F186AC866DULL,
		0x292783FD6164AA58ULL,
		0x48AD8BFEEA34AB93ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDF9D22C6A089BD2FULL,
		0x2C210523E617F0B2ULL,
		0xC2A4667F4209694DULL,
		0x539BC35D133FED9DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x399E356102C321BDULL,
		0x81546F156CC47720ULL,
		0xEBCBEA7CA36E13A5ULL,
		0x1C494F5BFD749930ULL
	}};
	printf("Test Case 37\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xFD333BB78D87D9C1ULL,
		0xF416F6087513F144ULL,
		0x43E7AAEA23E9EB21ULL,
		0x4E4993A5AC649B4CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7C55C31CED565227ULL,
		0x50345CF888CFCCECULL,
		0xA918B1167290D2A0ULL,
		0x79CF1F1BDB049B5BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x7988FED47ADE2BFBULL,
		0x444B5300FDE3BE31ULL,
		0xED005C00967ABDC2ULL,
		0x4818B2C1876936A7ULL
	}};
	printf("Test Case 38\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x8B034A8CB92DD85CULL,
		0x8BDCC93A8859FB7FULL,
		0x0F257F93AA19CBBFULL,
		0x75AB334B31E2D4F4ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x37F54D775B9E98BDULL,
		0x10E18F75F4F14DC8ULL,
		0xEEA7186137A36FD2ULL,
		0x58772BEF92BCE5D3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC2F8980414CC712CULL,
		0x9CBE58B07D4B4947ULL,
		0xFDCC97F4E1BD3B91ULL,
		0x4E225F3AC49FBAC7ULL
	}};
	printf("Test Case 39\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x049721C1B0B87886ULL,
		0xA20446A3889E023DULL,
		0xB9E50C138C370A3FULL,
		0x468A0840FDADDE52ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA36072CE8CB8AD57ULL,
		0x1C7D96ED6EA9DEADULL,
		0xDD7E156DE2DF8527ULL,
		0x20E9230874EBF613ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA7F794903D7125DDULL,
		0xBE81DD90F747E0EAULL,
		0x976321816F168F66ULL,
		0x67732B497299D466ULL
	}};
	printf("Test Case 40\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x577E0E8FC725FF6DULL,
		0x0885526294A7FFA4ULL,
		0x1393D5A7FB2EE350ULL,
		0x565D6CFB422F7485ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2EC5E2B110F90CC9ULL,
		0x9E6615F7464625E3ULL,
		0xF4632711B88C0946ULL,
		0x1D43987FB1C09FFCULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x8643F140D81F0C36ULL,
		0xA6EB6859DAEE2587ULL,
		0x07F6FCB9B3BAEC96ULL,
		0x73A1057AF3F01482ULL
	}};
	printf("Test Case 41\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7C67C350A36CFD82ULL,
		0xE5BB6D7396710A8AULL,
		0x5FC6803FD6F3F6C3ULL,
		0x3BFCDCD95F52DA6CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3DE0CC686BC4F039ULL,
		0x0E65238069A697CAULL,
		0xE9F3D02E05FE1189ULL,
		0x7300C5EFD05162C5ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBA488FB90F31EDCEULL,
		0xF42090F40017A254ULL,
		0x49BA506DDCF2084CULL,
		0x2EFDA2C92FA43D32ULL
	}};
	printf("Test Case 42\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x0FBFDCD86428F273ULL,
		0xD0EB677C47088284ULL,
		0xF4E6610C7D617165ULL,
		0x4F0A29B18E15DD81ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x45019BA32C534FF1ULL,
		0xC51844E15C732227ULL,
		0xA1C3E2B4D2E2A8DDULL,
		0x23D29A6663242F85ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x54C1787B907C4264ULL,
		0x9603AC5DA37BA4ABULL,
		0x96AA43C150441A43ULL,
		0x72DCC417F13A0D07ULL
	}};
	printf("Test Case 43\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x1C4B53A9939896DBULL,
		0x4826E7E694FB5AEFULL,
		0xCB70E16D07828725ULL,
		0x0A716073BFBFADC0ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x5051CDF72508C9E9ULL,
		0x2791BB62EEB31550ULL,
		0xABA4FBAFD28C1011ULL,
		0x482344127F843948ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6C9D21A0B8A160C4ULL,
		0x6FB8A34983AE703FULL,
		0x7715DD1CDA0E9736ULL,
		0x5294A4863F43E709ULL
	}};
	printf("Test Case 44\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7632453D0A222D6FULL,
		0x5EF39F86B86B41D3ULL,
		0xA015F4C699C43869ULL,
		0x20705D0E348B1C76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0B2D4983E2E9CB94ULL,
		0x026749524ED64BDBULL,
		0x54A9349B3F24AC8CULL,
		0x7E28A112FF9EF11DULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x815F8EC0ED0BF916ULL,
		0x615AE8D907418DAEULL,
		0xF4BF2961D8E8E4F5ULL,
		0x1E98FE21342A0D93ULL
	}};
	printf("Test Case 45\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xBE477847E3D65FD0ULL,
		0xB9CF10F29D9A559CULL,
		0x3F0284605DFC9F0EULL,
		0x53903D673C057C01ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE05FE6349FFBF6BULL,
		0x06BCCBD2388B26FDULL,
		0xDF79006A050CA82DULL,
		0x6E54832CFD445632ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C4D76AB2DD61F4EULL,
		0xC08BDCC4D6257C9AULL,
		0x1E7B84CA6309473BULL,
		0x41E4C0943949D234ULL
	}};
	printf("Test Case 46\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xAC64D01B1A7995E0ULL,
		0xD08D2426BF707ACCULL,
		0xA273263AEB48D0A5ULL,
		0x4D972C87614A1B1EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFE7132ECF2E6A2DULL,
		0xFCF6F0C6501E6709ULL,
		0xDED1B30570E73281ULL,
		0x2A2F02AD49696EBEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9C4BE349E9A8000DULL,
		0xCD8414ED0F8EE1D6ULL,
		0x8144D9405C300327ULL,
		0x77C62F34AAB389DDULL
	}};
	printf("Test Case 47\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD06450A694AFCCBFULL,
		0x8312130C02BCC391ULL,
		0x4EBA74960CDB31EDULL,
		0x39DCA05FB5652DCDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4F67D8F631631752ULL,
		0x99B6797A0043B736ULL,
		0x41D2BBFF81B9AD96ULL,
		0x1EA3704190EB639FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1FCC299CC612E411ULL,
		0x1CC88C8603007AC8ULL,
		0x908D30958E94DF84ULL,
		0x588010A14650916CULL
	}};
	printf("Test Case 48\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD10BAAD1B9EA0CACULL,
		0x11742064DBD7D50AULL,
		0xD4C3B509E9742892ULL,
		0x53FC9E66EE393DDFULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xCFACDCE82E1736FBULL,
		0xE0E4B80F1317F7B9ULL,
		0xFCB49DF94DDAB725ULL,
		0x14B225A02EA42F1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0B887B9E80143A7ULL,
		0xF258D873EEEFCCC4ULL,
		0xD1785303374EDFB7ULL,
		0x68AEC4071CDD6CFEULL
	}};
	printf("Test Case 49\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x460E86E7A11DC7D8ULL,
		0x77A32CB89A4CA989ULL,
		0x3DCA4CE413C9A10AULL,
		0x5394B7A403F14468ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1380BFFB8D98945DULL,
		0x8DE7A101B5684FAFULL,
		0x01084A04F20972BEULL,
		0x5FE52221282D56EAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x598F46E32EB65C48ULL,
		0x058ACDBA4FB4F938ULL,
		0x3ED296E905D313C9ULL,
		0x3379D9C52C1E9B52ULL
	}};
	printf("Test Case 50\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x2E318D5BF75B6EC4ULL,
		0x2A0340CAFCA0BF33ULL,
		0xA7169B7B373823E2ULL,
		0x202BDCC2FF7C431CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB8D908B5D9DC6744ULL,
		0x2581C678862C1E29ULL,
		0x9E6B170F76C1B49AULL,
		0x3C21D6EB08531C08ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE70A9611D137D608ULL,
		0x4F85074382CCDD5CULL,
		0x4581B28AADF9D87CULL,
		0x5C4DB3AE07CF5F25ULL
	}};
	printf("Test Case 51\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xF6918DA6179639B1ULL,
		0x05008C8B07AA0F1CULL,
		0x0D5E298B9AF250AEULL,
		0x73E085D42BBAA3A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xC177BED34BDB2599ULL,
		0x682C319F7DB9F8E8ULL,
		0x7C2DEC397E17F83AULL,
		0x4EB9B00669B168B7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB8094C7963715F5DULL,
		0x6D2CBE2A85640805ULL,
		0x898C15C5190A48E8ULL,
		0x429A35DA956C0C58ULL
	}};
	printf("Test Case 52\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x965134306B5A5E5AULL,
		0x17A1AF3F0117160FULL,
		0x2CBA45811E1676BAULL,
		0x583E02DE4EFA2ACDULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB732ECC23AC2B900ULL,
		0x08F4151AB227AD1EULL,
		0xB45484E8337CF3FBULL,
		0x3D3EF44688DC1EB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4D8420F2A61D176DULL,
		0x2095C459B33EC32EULL,
		0xE10ECA6951936AB5ULL,
		0x157CF724D7D64980ULL
	}};
	printf("Test Case 53\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB239D5789B2CDCC7ULL,
		0x9A65EC98D3DC594AULL,
		0xD5AE3EBB46958828ULL,
		0x66F0DB8631B81992ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9E0919A24F3CBDC9ULL,
		0x7EBB344C6F0464F4ULL,
		0xAF31EF0164302785ULL,
		0x6E357A6A4FDCC01FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5042EF1AEA699AA3ULL,
		0x192120E542E0BE3FULL,
		0x84E02DBCAAC5AFAEULL,
		0x552655F08194D9B2ULL
	}};
	printf("Test Case 54\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x93635BDD0AFA48C4ULL,
		0x9013413A0F0C07F4ULL,
		0x085CB336696FBB17ULL,
		0x49D995080E97575FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE3FEEABAAF348921ULL,
		0x336D9AC5D54E635CULL,
		0x20C20D426578650AULL,
		0x1255661AB34EFE5EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x77624697BA2ED1E5ULL,
		0xC380DBFFE45A6B51ULL,
		0x291EC078CEE82021ULL,
		0x5C2EFB22C1E655BDULL
	}};
	printf("Test Case 55\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xA552FD0A7C6F68C5ULL,
		0xE51C7746E4E0E2FAULL,
		0x5A587A382ABF4C25ULL,
		0x37ED7FF89FC39F12ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x71DD1233A327A8B4ULL,
		0xDCFBF30F18BDBFD7ULL,
		0x161FE672934FFC79ULL,
		0x10A0444DBD0A0792ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x17300F3E1F971179ULL,
		0xC2186A55FD9EA2D2ULL,
		0x707860AABE0F489FULL,
		0x488DC4465CCDA6A4ULL
	}};
	printf("Test Case 56\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x162ED2F4C1B847ADULL,
		0xB74A361B12C99F13ULL,
		0x956C1E674EF1CA04ULL,
		0x226B3383CE799457ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF7A6E527B2227581ULL,
		0xF7760D77AA9E8AD7ULL,
		0xEFC20D1E6A296D66ULL,
		0x48640A847DB43ED1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0DD5B81C73DABD2EULL,
		0xAEC04392BD6829EBULL,
		0x852E2B85B91B376BULL,
		0x6ACF3E084C2DD329ULL
	}};
	printf("Test Case 57\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xA8AF067A7A1320F2ULL,
		0xBFBCED9BD473620EULL,
		0xE3C8D4809A6E3112ULL,
		0x1B42DE61A5CE03A5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xEFC1B7E40E08BA2EULL,
		0xB787A7ED00BA54D4ULL,
		0x27EC624C3CF6DBA4ULL,
		0x705BE1BFC43A523BULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9870BE5E881BDB33ULL,
		0x77449588D52DB6E3ULL,
		0x0BB536CCD7650CB7ULL,
		0x0B9EC0216A0855E1ULL
	}};
	printf("Test Case 58\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x19FACB5823F0C833ULL,
		0xCCF79F15352B4465ULL,
		0xABFF1706BF9FC250ULL,
		0x4FDF223AFF8B42A1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xD3055D03B982B6F7ULL,
		0x3AEEF733F7D62520ULL,
		0xDA7DEA71F97B4C5CULL,
		0x1E2D20CBD4E114AAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xED00285BDD737F2AULL,
		0x07E696492D016985ULL,
		0x867D0178B91B0EADULL,
		0x6E0C4306D46C574CULL
	}};
	printf("Test Case 59\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xF5927D7FB3BD70A2ULL,
		0x51A61E580D49125BULL,
		0x1FFA0460A90C79DDULL,
		0x102DC9E204FBA4B2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x089C701C7E019A05ULL,
		0x7E6426D564DDF3F7ULL,
		0x24487A011A1B5100ULL,
		0x5AC2C81C104B9EADULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xFE2EED9C31BF0AA7ULL,
		0xD00A452D72270652ULL,
		0x44427E61C327CADDULL,
		0x6AF091FE1547435FULL
	}};
	printf("Test Case 60\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x5EE0D07859C2E7A5ULL,
		0xE8E8FA2A3126238CULL,
		0x9570DAF3F1F89809ULL,
		0x05157B23483A4B04ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x885D29C579F89B71ULL,
		0x07AC4903465BD24FULL,
		0xD2C1391DC86BB2ABULL,
		0x6380C9578E4F2AF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE73DFA3DD3BB8316ULL,
		0xF095432D7781F5DBULL,
		0x68321411BA644AB4ULL,
		0x6896447AD68975F9ULL
	}};
	printf("Test Case 61\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x6FB28C5AD6638FABULL,
		0x6001DAA4D647C182ULL,
		0x2227EF1A31A95DCAULL,
		0x1A135F2465949518ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x3BB5D0AFD306442FULL,
		0xE5AE8023EA5390D4ULL,
		0x3B014F60A4AF4EDEULL,
		0x067A7E3B1BF23370ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xAB685D0AA969D3DAULL,
		0x45B05AC8C09B5256ULL,
		0x5D293E7AD658ACA9ULL,
		0x208DDD5F8186C888ULL
	}};
	printf("Test Case 62\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x54537FAFBF629C8AULL,
		0x058FEA378A4F64FEULL,
		0xD255504CB2A1899AULL,
		0x194964F8963D776CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9069235F63EDEE63ULL,
		0x59BDC503652C00D5ULL,
		0xA1B26008A3CED4B3ULL,
		0x645CEC6A1DF206FDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xE4BCA30F23508AEDULL,
		0x5F4DAF3AEF7B65D3ULL,
		0x7407B05556705E4DULL,
		0x7DA65162B42F7E6AULL
	}};
	printf("Test Case 63\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7144524E08023113ULL,
		0xF2143E60961D4922ULL,
		0x2D370B4EB1B791C4ULL,
		0x539D58328460F951ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x842C2FC5064D71CCULL,
		0xB3891F48CF9FF68CULL,
		0xEF60E06BCD3704B6ULL,
		0x0F3611E720526278ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF57082130E4FA2DFULL,
		0xA59D5DA965BD3FAEULL,
		0x1C97EBBA7EEE967BULL,
		0x62D36A19A4B35BCAULL
	}};
	printf("Test Case 64\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x55F97857C58D36A5ULL,
		0x7D99C92493B6201BULL,
		0xCDFDC59ECDC3AFDDULL,
		0x5717612059CAB902ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0C8F7946B99D7440ULL,
		0x3F404C215ED21B39ULL,
		0x9026EAD41E40DC98ULL,
		0x641D7CBC4C0BD68EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6288F19E7F2AAAF8ULL,
		0xBCDA1545F2883B54ULL,
		0x5E24B072EC048C75ULL,
		0x3B34DDDCA5D68F91ULL
	}};
	printf("Test Case 65\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x14FABA47888D0177ULL,
		0xFF571F8BFDDDA275ULL,
		0x9BB4CF404035938CULL,
		0x0B7092111ADB335FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xED7376C9359891CDULL,
		0xD9515A7E53410C9DULL,
		0xB03BB50E6B5BF1DFULL,
		0x736339F8BD576743ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x026E3110BE259344ULL,
		0xD8A87A0A511EAF13ULL,
		0x4BF0844EAB91856CULL,
		0x7ED3CC09D8329AA3ULL
	}};
	printf("Test Case 66\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7494345A265BD3BEULL,
		0x6132552794D2E542ULL,
		0x33D52EA0D90A5463ULL,
		0x330E9869A4D3D3C8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xADC35C1C0E09ADDCULL,
		0x84AA523DC3479FF7ULL,
		0x86FFB8D8BBF097F9ULL,
		0x0BB2A59D521AEEA4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x225790763465819AULL,
		0xE5DCA765581A853AULL,
		0xBAD4E77994FAEC5CULL,
		0x3EC13E06F6EEC26CULL
	}};
	printf("Test Case 67\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xCE724489A6677360ULL,
		0xE6F4149694132936ULL,
		0xE442626DF98A0FF9ULL,
		0x0BB7F1D5031DBC40ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0DDE95A87B48C72DULL,
		0x16F851991E018C77ULL,
		0x35CC81698699118FULL,
		0x63427519E2E147BEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDC50DA3221B03A8DULL,
		0xFDEC662FB214B5ADULL,
		0x1A0EE3D780232188ULL,
		0x6EFA66EEE5FF03FFULL
	}};
	printf("Test Case 68\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB53F8E379F279EA3ULL,
		0xEC0B81CF9D19B4C1ULL,
		0x7CE16292190313A1ULL,
		0x1A6B604A1B0E18F5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x8A56F44F4895777AULL,
		0xF1199B2D59B9A567ULL,
		0x6BCBAE672FF23652ULL,
		0x27D20902B726A977ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x3F968286E7BD161DULL,
		0xDD251CFCF6D35A29ULL,
		0xE8AD10F948F549F4ULL,
		0x423D694CD234C26CULL
	}};
	printf("Test Case 69\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x8AB1AFD49ECB3BFCULL,
		0x8F901296DBF78260ULL,
		0x596D6D61A4B31EDAULL,
		0x467B5759C544F770ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE44A06AA858F2B0FULL,
		0x46F25D1BA1425AA4ULL,
		0xFC72FC0152C85965ULL,
		0x6D3EB99163CA30BFULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6EFBB67F245A671EULL,
		0xD6826FB27D39DD05ULL,
		0x55E06962F77B783FULL,
		0x33BA10EB290F2830ULL
	}};
	printf("Test Case 70\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x086A859AFBC8D299ULL,
		0x4CE68CFB4BFAC402ULL,
		0xC9A808B3FBA81D55ULL,
		0x0079F6EF058402BCULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA491F09FA6402653ULL,
		0x7B2569B69F5A5495ULL,
		0x9531F1FD47815A38ULL,
		0x1AD984005F2D48A4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xACFC763AA208F8ECULL,
		0xC80BF6B1EB551897ULL,
		0x5ED9FAB14329778DULL,
		0x1B537AEF64B14B61ULL
	}};
	printf("Test Case 71\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x21D6FAA63F512433ULL,
		0x502C98CF4348B075ULL,
		0xC9F8FD69E57ADD4CULL,
		0x78BD429B10AAF4BBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x65C9B1314B5E47BCULL,
		0x9D2502D7208343E3ULL,
		0x03E2DB77968E4D8CULL,
		0x7347671407CC9312ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x87A0ABD78AAF6C02ULL,
		0xED519BA663CBF458ULL,
		0xCDDBD8E17C092AD8ULL,
		0x6C04A9AF187787CDULL
	}};
	printf("Test Case 72\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x7744656D27DC672EULL,
		0x310CC58793974E16ULL,
		0x56B6180D87D271B9ULL,
		0x65850633DB5EB046ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFD8ADD93DBE06CCEULL,
		0x270F2D8CF880FE9BULL,
		0x17375FF7A459004DULL,
		0x681046CB376CA896ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x74CF430103BCD40FULL,
		0x581BF3148C184CB2ULL,
		0x6DED78052C2B7206ULL,
		0x4D954CFF12CB58DCULL
	}};
	printf("Test Case 73\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB3A0065A91AFFBA1ULL,
		0x92FEE172DFAEA00FULL,
		0x4432B85B6A176CDBULL,
		0x366E2721F4D7B400ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x03E5130AAD5C752AULL,
		0xD0EF904EDF89C838ULL,
		0xF5BF69308EFD2F33ULL,
		0x53CF2A6C2A5410F3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB78519653F0C70DEULL,
		0x63EE71C1BF386847ULL,
		0x39F2218BF9149C0FULL,
		0x0A3D518E1F2BC4F4ULL
	}};
	printf("Test Case 74\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x6CAB8BA2B5811A82ULL,
		0xD1199B00FAA7BB9CULL,
		0xBFA673A297A408E9ULL,
		0x7F3CC17CD10B1716ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2D980EA5E07407C9ULL,
		0xFD0076735F52E432ULL,
		0x05CFAFF967D8A145ULL,
		0x06D7D7779FC0C744ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x9A439A4895F5225EULL,
		0xCE1A117459FA9FCEULL,
		0xC576239BFF7CAA2FULL,
		0x061498F470CBDE5AULL
	}};
	printf("Test Case 75\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x80D7DE78B88DA516ULL,
		0xFDE9FC3ABD39B8AEULL,
		0xC338C9D20FB63D81ULL,
		0x3A4301BF40C79E76ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE6703CBAD46EE511ULL,
		0x6CEE53884A51C4E1ULL,
		0x2DA5D449691D0FA7ULL,
		0x6AEEA81E6DBF053AULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x67481B338CFC8A3AULL,
		0x6AD84FC3078B7D90ULL,
		0xF0DE9E1B78D34D29ULL,
		0x2531A9DDAE86A3B0ULL
	}};
	printf("Test Case 76\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x825E36521C74D800ULL,
		0xA555EA63C9DA6915ULL,
		0x0D40285797C163CBULL,
		0x24DCC43C74DE1BB8ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x0385B0AD91CA5BA6ULL,
		0x710959A203F38E25ULL,
		0x37F8262D555CDEF3ULL,
		0x5AA2E16A6345C640ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x85E3E6FFAE3F33A6ULL,
		0x165F4405CDCDF73AULL,
		0x45384E84ED1E42BFULL,
		0x7F7FA5A6D823E1F8ULL
	}};
	printf("Test Case 77\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xCD637364CA3F0A97ULL,
		0x1CB57DB8D2A9C571ULL,
		0x66F0ED16D91F07BCULL,
		0x6F01008DC1538DE1ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6C3D463CA2A5A86FULL,
		0x0448CCA59D492A28ULL,
		0xF8F4C6E83D503537ULL,
		0x30F9F1E207DB056CULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x39A0B9A16CE4B319ULL,
		0x20FE4A5E6FF2EF9AULL,
		0x5FE5B3FF166F3CF3ULL,
		0x1FFAF26FC92E934EULL
	}};
	printf("Test Case 78\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xE8D944D7400DB79EULL,
		0xD5C73FD07EF9C74CULL,
		0x29D34717A5DC18A2ULL,
		0x396A380B2D2EB978ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x6268E1E0DD1AE93FULL,
		0xDCFB02F5B075CC81ULL,
		0x729258B40763B36DULL,
		0x3BD13BAE18728CF4ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x4B4226B81D28A0DDULL,
		0xB2C242C62F6F93CEULL,
		0x9C659FCBAD3FCC10ULL,
		0x753B73B945A1466CULL
	}};
	printf("Test Case 79\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xBB5CD214C11FA745ULL,
		0xA85BF61505880971ULL,
		0xC6131F01D944C400ULL,
		0x072E3BF1F76AF832ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x10A3E23160E44527ULL,
		0xF6581EF1AA154FB6ULL,
		0xE0B818A5BF4F1A4BULL,
		0x0FE8CF29D99C2953ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCC00B4462203EC6CULL,
		0x9EB41506AF9D5927ULL,
		0xA6CB37A79893DE4CULL,
		0x17170B1BD1072186ULL
	}};
	printf("Test Case 80\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x4D2089557F358DF3ULL,
		0xA0C76E73E8A4650EULL,
		0xF16A23B935AE1E73ULL,
		0x7ABF3C258D22CBF9ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x585537B1B58EFFF7ULL,
		0x41038BF06A281A6CULL,
		0x8DCCE6341AC49074ULL,
		0x030941BBC1415610ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA575C10734C48DEAULL,
		0xE1CAFA6452CC7F7AULL,
		0x7F3709ED5072AEE7ULL,
		0x7DC87DE14E64220AULL
	}};
	printf("Test Case 81\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x19FFE47EB5C73660ULL,
		0x6E470E7F7581B77BULL,
		0xF3BD1B9688198300ULL,
		0x4B8D6D03CCA72FFBULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x16F04F6627175A40ULL,
		0xF11D4783034A80F9ULL,
		0x8992E335FE23A87CULL,
		0x38F79F0347C5281FULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x30F033E4DCDE90B3ULL,
		0x5F64560278CC3874ULL,
		0x7D4FFECC863D2B7DULL,
		0x04850C07146C581BULL
	}};
	printf("Test Case 82\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x9B22B266908ADBECULL,
		0x8467CA62E388761CULL,
		0xFCA89133DC0C64AAULL,
		0x311D89A544D5D606ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x38E8BA722D93C2FFULL,
		0x8430AFDE69657103ULL,
		0x3C5BA70BE4F5D6C4ULL,
		0x1D5458118CD43BD3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xD40B6CD8BE1E9EEBULL,
		0x08987A414CEDE71FULL,
		0x3904383FC1023B6FULL,
		0x4E71E1B6D1AA11DAULL
	}};
	printf("Test Case 83\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x9DA14472E9F37BB8ULL,
		0x0727168BDC4DDF78ULL,
		0xAF3F42F8EA769C0DULL,
		0x38ABAC818963B86AULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2BF4F96B197E5D88ULL,
		0x41BBEFA93EBABD4CULL,
		0x55433C59F032DF2CULL,
		0x48A2052D6BF03D17ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xC9963DDE0371D953ULL,
		0x48E306351B089CC4ULL,
		0x04827F52DAA97B39ULL,
		0x014DB1AEF553F582ULL
	}};
	printf("Test Case 84\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x5274EC64DAB42BEEULL,
		0x75975C3F3D7B3280ULL,
		0x6AE835C66079B24EULL,
		0x19336FE926DB173CULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3B17BD708E8A4A5ULL,
		0xFF3AE8735808B88DULL,
		0x3D2DE530631837A7ULL,
		0x094F28FDC70916A1ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x0626683BE39CD093ULL,
		0x74D244B29583EB0EULL,
		0xA8161AF6C391E9F6ULL,
		0x228298E6EDE42DDDULL
	}};
	printf("Test Case 85\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x9E16C32BED71D2ECULL,
		0xB7059B940911FCF9ULL,
		0xF2F319F48D83AA29ULL,
		0x12C44D42021D6B32ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x407C98897CE45198ULL,
		0x80041B7F3B10694DULL,
		0xA9833398B43A9E1CULL,
		0x7456C4F0FE6652DDULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xDE935BB56A562497ULL,
		0x3709B71344226646ULL,
		0x9C764D8D41BE4846ULL,
		0x071B12330083BE10ULL
	}};
	printf("Test Case 86\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x30E7B2C7C93A0317ULL,
		0x18C23038BFE1E890ULL,
		0x4A10DD3DAB8D2DC3ULL,
		0x6DA18620B0C8BAE2ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x9D09E6896C794FB3ULL,
		0x652AF9805D91627DULL,
		0xBAD3D1D435A9FA9EULL,
		0x06DBD4158DE6E482ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xCDF1995135B352CAULL,
		0x7DED29B91D734B0DULL,
		0x04E4AF11E1372861ULL,
		0x747D5A363EAF9F65ULL
	}};
	printf("Test Case 87\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x54C5C90A96EB6153ULL,
		0x95EB375EF8BE5CBCULL,
		0x1E31F249487DD4F1ULL,
		0x24444939720E8842ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x4BE13F73198EB875ULL,
		0x9B4D1E7A29E6B811ULL,
		0x15B6E52C543DB7DFULL,
		0x0DB368A679905E1EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xA0A7087DB07A19C8ULL,
		0x313855D922A514CDULL,
		0x33E8D7759CBB8CD1ULL,
		0x31F7B1DFEB9EE660ULL
	}};
	printf("Test Case 88\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x521C0DECB91968BEULL,
		0x9F71BEC28C9AF111ULL,
		0x2D72092342ABC469ULL,
		0x468BFEB6E3746332ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xA315F2E25A107395ULL,
		0xB5F86D825FF4C13BULL,
		0x3BE19E674CD0F71DULL,
		0x32B4446DF6C69A6EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xF53200CF1329DC53ULL,
		0x556A2C44EC8FB24CULL,
		0x6953A78A8F7CBB87ULL,
		0x79404324DA3AFDA0ULL
	}};
	printf("Test Case 89\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x1C73562CCC9A4B07ULL,
		0x918D641C75938B4AULL,
		0xD6F58CFCB316731EULL,
		0x42146AB056EBC9D7ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x39A3F77EEFA3844FULL,
		0x51645846A02A71E0ULL,
		0x9EFF7BC499776B38ULL,
		0x5CCEFCB0E5331087ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x56174DABBC3DCF69ULL,
		0xE2F1BC6315BDFD2AULL,
		0x75F508C14C8DDE56ULL,
		0x1EE367613C1EDA5FULL
	}};
	printf("Test Case 90\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x719D38C9988D2195ULL,
		0x27463C0C2AB37B65ULL,
		0x7AF460B93FD1EC16ULL,
		0x41FD9433EC8EFD83ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDEDC763256B70D24ULL,
		0xC21CF14CA8F597FCULL,
		0x725F3FE340EF156EULL,
		0x0ED23B5111D22D09ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x5079AEFBEF442EB9ULL,
		0xE9632D58D3A91362ULL,
		0xED53A09C80C10184ULL,
		0x50CFCF84FE612A8CULL
	}};
	printf("Test Case 91\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x6D065E755CE9DD3BULL,
		0x856E9946FCAADD0AULL,
		0x7E9D5B4CA55292B6ULL,
		0x6AE21C9B670E6D7EULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x2B85325FCC98E68BULL,
		0x1128B21EDE2A6E94ULL,
		0x6F8BFC9397107149ULL,
		0x61A162F4A775F9AEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x988B90D52982C3D9ULL,
		0x96974B65DAD54B9EULL,
		0xEE2957E03C6303FFULL,
		0x4C837F900E84672CULL
	}};
	printf("Test Case 92\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD10A4B4680AF5998ULL,
		0xAADBD5F1437EFD0AULL,
		0xA58753247AB811A7ULL,
		0x72B68EB295548720ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE4A3D9C1D74A3AE8ULL,
		0xCBBF26C8B3CDD7D3ULL,
		0x299BFB0EF8E93466ULL,
		0x0CC8883A8C98FFDEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xB5AE250857F99480ULL,
		0x769AFCB9F74CD4DEULL,
		0xCF234E3373A1460EULL,
		0x7F7F16ED21ED86FEULL
	}};
	printf("Test Case 93\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x663669F7EE3F7414ULL,
		0x7996DDFF4E05F9C4ULL,
		0x32B0470B804AEC01ULL,
		0x265046FA0D459424ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x1D0CC86C7A456876ULL,
		0x51476256F6623C64ULL,
		0x9DB4FF11C6995CCFULL,
		0x379DF610199C40CEULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x834332646884DC8AULL,
		0xCADE405644683628ULL,
		0xD065461D46E448D0ULL,
		0x5DEE3D0A26E1D4F2ULL
	}};
	printf("Test Case 94\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x2E39DC928573AB31ULL,
		0x161DC1262B6CE148ULL,
		0x1800689F42F0403FULL,
		0x2E95C0897671C21FULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xF06A74579387AD33ULL,
		0x5174D755D266F84BULL,
		0xE11B18C8B4C7A02FULL,
		0x60A23D5E65C55EFAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x1EA450EA18FB5877ULL,
		0x6792987BFDD3D994ULL,
		0xF91B8167F7B7E06EULL,
		0x0F37FDE7DC372119ULL
	}};
	printf("Test Case 95\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x6B2FF91B40A1166CULL,
		0x9E266920300E10DEULL,
		0xCB2ACE3CEA4E880CULL,
		0x238AC520B77B04B5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xDE44677B43AD6A75ULL,
		0x4BBD56D5F8C65104ULL,
		0x3B32267064E87117ULL,
		0x3E7ACF98500066CAULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x49746096844E80E1ULL,
		0xE9E3BFF628D461E3ULL,
		0x065CF4AD4F36F923ULL,
		0x620594B9077B6B80ULL
	}};
	printf("Test Case 96\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xB7B72E43D9535580ULL,
		0xC78250E3381CE303ULL,
		0x0B0FB99FE9B0C47BULL,
		0x1F91B988DA58BDF5ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xB3F3287B186F6B08ULL,
		0xD9E344A651E280D5ULL,
		0xCF6AD1135561D90BULL,
		0x56C35EA7CE871BE7ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x6BAA56BEF1C2C088ULL,
		0xA165958989FF63D9ULL,
		0xDA7A8AB33F129D87ULL,
		0x76551830A8DFD9DCULL
	}};
	printf("Test Case 97\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xA68AFC13915DA36CULL,
		0x2674260B608D9973ULL,
		0x1242229A29F8ABD8ULL,
		0x6524F29B3EF60410ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0x7E279C9162DFB5E1ULL,
		0x538C23FCE6C95294ULL,
		0x3ABE4804671EE8EFULL,
		0x0969820321A5240EULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x24B298A4F43D594DULL,
		0x7A004A084756EC08ULL,
		0x4D006A9E911794C7ULL,
		0x6E8E749E609B281EULL
	}};
	printf("Test Case 98\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0x584CD93C42D9E84EULL,
		0xD6C8B1C2E0EF0666ULL,
		0xD097BA3DFC7CA3A9ULL,
		0x2F78020C22043226ULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xFC2031AB8875CE08ULL,
		0xDF9B8E4491022043ULL,
		0x50E27A288FD12986ULL,
		0x3F3900DE3C474BB3ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0x546D0AE7CB4FB656ULL,
		0xB664400771F126AAULL,
		0x217A34668C4DCD30ULL,
		0x6EB102EA5E4B7DDAULL
	}};
	printf("Test Case 99\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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
		0xD5AE81E32E55F221ULL,
		0x83F0A6B74790AA0BULL,
		0x67415E21ECFDE986ULL,
		0x3BC87862D74BE27DULL
	}};
	k2 = (curve25519_key_t){.key64 = {
		0xE63332DC203C097AULL,
		0x20C25FDDDC30628BULL,
		0x7A7B512DCF3F74CFULL,
		0x00A94E389B912881ULL
	}};
	k3 = (curve25519_key_t){.key64 = {
		0xBBE1B4BF4E91FB9BULL,
		0xA4B3069523C10C97ULL,
		0xE1BCAF4FBC3D5E55ULL,
		0x3C71C69B72DD0AFEULL
	}};
	printf("Test Case 100\n");
	printf("k1:\n");
	curve25519_key_printf(&k1, B64);
	printf("k2:\n");
	curve25519_key_printf(&k2, B64);
	printf("Expected: \n");
	curve25519_key_printf(&k3, B64);
	curve25519_key_add(&k1, &k2, &r);
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